import datetime

from udata.core.dataset.api import DEFAULT_SORTING, DatasetApiParser
from udata.core.dataset.constants import (
    LAST_UPDATE_RANGES,
    FormatFamily,
    get_format_family,
)
from udata.core.organization.constants import PRODUCER_TYPES
from udata.core.organization.helpers import get_producer_type
from udata.core.spatial.constants import ADMIN_LEVEL_MAX
from udata.core.spatial.models import admin_levels
from udata.core.topic.models import TopicElement
from udata.models import Dataset, GeoZone, License, Organization, Topic, User
from udata.search import (
    BoolFilter,
    Filter,
    ListFilter,
    ModelSearchAdapter,
    ModelTermsFilter,
    TemporalCoverageFilter,
    register,
)
from udata.utils import to_iso_datetime
from udata_search_service.consumers import DatasetConsumer
from udata_search_service.services import DatasetService

__all__ = ("DatasetSearch",)


# This const is kept to prevent creating huge documents and paylods for datasets
# with a large number of resources
MAX_NUMBER_OF_RESOURCES_TO_INDEX = 500


@register
class DatasetSearch(ModelSearchAdapter):
    model = Dataset
    service_class = DatasetService
    consumer_class = DatasetConsumer

    # Read in two places, and the difference matters when editing this. The **keys**
    # become the accepted `sort` values — `as_request_parser` builds the choices from
    # them, so renaming one changes the public API and its 400s. The **values** are only
    # ever used by `parse_sort`, called from `mongo_search` below, which is the path
    # that answers while no Elasticsearch service is configured — the case today. The
    # Elasticsearch branch forwards the parameter name as given and renames only
    # `created`, so it never reads these values at all.
    #
    # `last_update` now names the same date on both sides: Mongo orders the field of
    # that name, and Elasticsearch would order the index's `last_update`, which
    # `serialize()` below feeds from the same value. Same for `last_update_range` — the
    # Mongo filter and the service both range over `last_update`.
    #
    # `created` does **not** agree, and cannot be fixed the same way. `Dataset.created_at`
    # is a property (harvest issued date, else harvest created date, else the stored
    # field), so Mongo has nothing to order on and the mapping must point at the stored
    # `created_at_internal`. But `serialize()` feeds the index from the property, so for
    # a harvested dataset the two paths would order `created` by different dates. Left
    # as is deliberately; it needs the property materialised into a field first.
    #
    # Ties are the remaining divergence on `last_update`: the service adds relevance as
    # a second sort key and Mongo adds none, so datasets sharing a date may come back in
    # different orders. Measured on 19874 visible datasets, 2.6% share their
    # `last_update` with another — against 5.1% for the field this used to name.
    sorts = {
        "created": "created_at_internal",
        "last_update": "last_update",
        "reuses": "metrics.reuses",
        "followers": "metrics.followers",
        "views": "metrics.views",
    }

    # Uses __badges__ (not available_badges) so that users can still filter
    # by any existing badge, even hidden ones.
    filters = {
        "tag": ListFilter(),
        "badge": Filter(choices=list(Dataset.__badges__)),
        "organization": ModelTermsFilter(model=Organization),
        "organization_badge": Filter(choices=list(Organization.__badges__)),
        "organization_name": Filter(),
        "owner": ModelTermsFilter(model=User),
        "license": ModelTermsFilter(model=License),
        "geozone": ModelTermsFilter(model=GeoZone),
        "granularity": ListFilter(),
        "format": ListFilter(),
        "schema": ListFilter(),
        "temporal_coverage": TemporalCoverageFilter(),
        "featured": BoolFilter(),
        "topic": ModelTermsFilter(model=Topic),
        "access_type": Filter(),
        "format_family": Filter(choices=list(FormatFamily)),
        "producer_type": Filter(choices=list(PRODUCER_TYPES)),
        "last_update_range": Filter(choices=list(LAST_UPDATE_RANGES)),
    }

    @classmethod
    def is_indexable(cls, dataset: Dataset):
        return dataset.is_visible

    @classmethod
    def _compute_format_family(cls, dataset: Dataset) -> list[str]:
        """
        Compute the format families present in the dataset's resources.

        Returns a list of unique format family values based on the formats
        of all resources in the dataset.
        """
        families = set()
        for resource in dataset.resources:
            if resource.format:
                family = get_format_family(resource.format)
                families.add(family.value)
        return list(families) if families else [FormatFamily.OTHER.value]

    @classmethod
    def mongo_search(cls, args):
        datasets = Dataset.objects.visible()
        datasets = DatasetApiParser.parse_filters(datasets, args)

        sort = (
            cls.parse_sort(args["sort"])
            or ("$text_score" if args["q"] else None)
            or DEFAULT_SORTING
        )
        return datasets.order_by(sort).paginate(args["page"], args["page_size"])

    @classmethod
    def serialize(cls, dataset):
        organization = None

        topic_ids = list(
            set(te.topic.id for te in TopicElement.objects(element=dataset) if te.topic)
        )

        if dataset.organization:
            organization = {
                "id": str(dataset.organization.id),
                "name": dataset.organization.name,
                "public_service": 1 if dataset.organization.public_service else 0,
                "followers": dataset.organization.metrics.get("followers", 0),
                "badges": [badge.kind for badge in dataset.organization.badges],
            }

        document = {
            "id": str(dataset.id),
            "title": dataset.title,
            "description": dataset.description,
            "acronym": dataset.acronym or None,
            "url": dataset.url_for(),
            "tags": dataset.tags,
            "license": getattr(dataset.license, "id", None),
            "badges": [badge.kind for badge in dataset.badges],
            "frequency": dataset.frequency,
            "created_at": to_iso_datetime(dataset.created_at),
            "last_update": to_iso_datetime(dataset.last_update),
            "views": dataset.metrics.get("views", 0),
            "followers": dataset.metrics.get("followers", 0),
            "reuses": dataset.metrics.get("reuses", 0),
            "featured": 1 if dataset.featured else 0,
            "resources_count": len(dataset.resources),
            "resources": [
                {"id": str(res.id), "title": res.title}
                for res in dataset.resources[:MAX_NUMBER_OF_RESOURCES_TO_INDEX]
            ],
            "organization": organization,
            "organization_name": dataset.organization.name if dataset.organization else None,
            "owner": str(dataset.owner.id) if dataset.owner else None,
            "format": [r.format.lower() for r in dataset.resources if r.format],
            "schema": [r.schema.name for r in dataset.resources if r.schema],
            "topics": [str(tid) for tid in topic_ids],
            "access_type": dataset.access_type,
            "format_family": cls._compute_format_family(dataset),
            "producer_type": get_producer_type(dataset),
        }
        extras = {}
        for key, value in dataset.extras.items():
            extras[key] = to_iso_datetime(value) if isinstance(value, datetime.datetime) else value
        document.update({"extras": extras})
        if dataset.harvest:
            harvest = {}
            for key, value in dataset.harvest._data.items():
                harvest[key] = (
                    to_iso_datetime(value) if isinstance(value, datetime.datetime) else value
                )
            document.update({"harvest": harvest})

        if (
            dataset.temporal_coverage is not None
            and dataset.temporal_coverage.start
            and dataset.temporal_coverage.end
        ):
            start = to_iso_datetime(dataset.temporal_coverage.start)
            end = to_iso_datetime(dataset.temporal_coverage.end)
            document.update(
                {
                    "temporal_coverage_start": start,
                    "temporal_coverage_end": end,
                }
            )

        if dataset.spatial is not None:
            # Index precise zone labels to allow fast filtering.
            zone_ids = [z.id for z in dataset.spatial.zones]
            zones = GeoZone.objects(id__in=zone_ids)
            geozones = []
            coverage_level = ADMIN_LEVEL_MAX
            for zone in zones:
                geozones.append(
                    {
                        "id": zone.id,
                        "name": zone.name,
                    }
                )
                coverage_level = min(coverage_level, admin_levels[zone.level])
            document.update(
                {
                    "geozones": geozones,
                    "granularity": dataset.spatial.granularity,
                }
            )
        return document
