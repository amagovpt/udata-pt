import logging
import mimetypes
import re
from urllib.parse import urlparse

from dateutil.parser import parse as parse_date

from udata.core.dataset.constants import UpdateFrequency
from udata.core.dataset.models import HarvestDatasetMetadata
from udata.core.utils.sanitization import sanitize_strict
from udata.frontend.markdown import parse_html
from udata.harvest.backends.base import BaseBackend, HarvestFeature, HarvestFilter
from udata.harvest.exceptions import HarvestSkipException
from udata.harvest.models import HarvestItem
from udata.harvest.url_filter import redact_url_credentials_in_url
from udata.i18n import gettext as _
from udata.models import License, Resource
from udata.utils import get_by, safe_harvest_datetime

from .tools.harvester_utils import (
    bbox_to_spatial_coverage,
    guess_format_from_mime,
    map_ine_periodicity,
    normalize_url_slashes,
    reset_ine_periodicity_warnings,
    resolve_publisher_organization,
)

log = logging.getLogger(__name__)

# A qualifier the SNS source appends to a periodicity, as in
# "Diário (novembro a março)" or "Diária (dias úteis)".
#
# `[^()]*` rather than `.*?`: the text is remote, and a lazy dot in front of a closing
# parenthesis that never comes rescans the rest of the line from every `(`, which is
# quadratic -- reachable from the harvest preview, which runs on an HTTP worker.
PERIODICITY_QUALIFIER_RE = re.compile(r"\s*\([^()]*\)\s*")

# Longer than any periodicity the source publishes (the longest seen is 25 characters).
MAX_PERIODICITY_LENGTH = 256


def guess_mimetype(mimetype, url=None):
    """
    Guess a MIME type given a string or and URL
    """
    # TODO: factorize in udata
    if mimetype in mimetypes.types_map.values():
        return mimetype
    elif url:
        mime, encoding = mimetypes.guess_type(url)
        return mime


class OdsBackendPT(BaseBackend):
    name = "odspt"
    display_name = "OpenDataSoft PT"
    # verify_ssl inherits True from BaseBackend: the configured source
    # (transparencia.sns.gov.pt) presents a valid certificate (checked 2026-07).
    filters = (
        HarvestFilter(_("Tag"), "tags", str, _("A tag name")),
        HarvestFilter(_("Publisher"), "publisher", str, _("A publisher name")),
    )
    features = (
        HarvestFeature(
            "inspire",
            _("Harvest Inspire datasets"),
            _("Whether this harvester should import datasets coming from Inspire"),
        ),
    )

    # Map filters key to ODS facets
    FILTERS = {
        "tags": "keyword",
        "publisher": "publisher",
    }

    # above this records count limit, shapefile export will be disabled
    # since it would be a partial export
    SHAPEFILE_RECORDS_LIMIT = 50000

    FORMATS = {
        "csv": ("CSV", "csv", "text/csv"),
        "geojson": ("GeoJSON", "json", "application/vnd.geo+json"),
        "json": ("JSON", "json", "application/json"),
        "shp": ("Shapefile", "shp", None),
    }

    @property
    def source_url(self):
        """The source URL as configured, credentials included.

        `URLS_ALLOW_CREDENTIALS` is true, so this may be
        `https://user:password@host/path`. Only `api_url` may be built on it:
        that is the single request this backend makes, and it is the only place
        that needs the credentials back. Everything else this backend derives
        from the source URL is published, and must go through
        `public_source_url` instead. See LEDG-2500.
        """
        return self.source.url.rstrip("/")

    @property
    def public_source_url(self):
        """`source_url` with any userinfo replaced by `***`.

        The URLs built on this one end up in `Dataset.resources[].url` and in
        `extras["ods:url"]`, both served to callers without a session. A
        credentialed source would otherwise hand its password to every reader
        of the dataset -- and `/r/<id>` would fetch the file with it on their
        behalf.

        A redacted URL no longer downloads, which is the point: an anonymous
        reader is not supposed to hold the credentials. `udata.uris.validate`
        still accepts it, because `***@` matches the userinfo group of
        `URL_REGEX`; were `URLS_ALLOW_CREDENTIALS` ever turned off, these
        resources would stop validating and this is where to look.
        """
        return redact_url_credentials_in_url(self.source_url)

    @property
    def api_url(self):
        return "{0}/api/datasets/1.0/search/".format(self.source_url)

    def explore_url(self, dataset_id):
        return "{0}/explore/dataset/{1}/".format(self.public_source_url, dataset_id)

    def extra_file_url(self, dataset_id, file_id, plural_type):
        return "{0}/api/datasets/1.0/{1}/{2}/{3}".format(
            self.public_source_url, dataset_id, plural_type, file_id
        )

    def download_url(self, dataset_id, format):
        return ("{0}download?format={1}&timezone=Europe/Berlin&use_labels_for_header=true").format(
            self.explore_url(dataset_id), format
        )

    def export_url(self, dataset_id):
        return "{0}?tab=export".format(self.explore_url(dataset_id))

    @staticmethod
    def _frequency(text) -> UpdateFrequency:
        """The dataset's frequency, from `interop_metas.dcat.accrualperiodicity`.

        The SNS source writes a single periodicity for most datasets, but 11 of the 144
        enumerated on 2026-09-23 combine several (`Anual | Mensal`) and a few qualify
        theirs in parentheses. Each part is mapped by the shared periodicity map, and a
        combination resolves to the most frequent of its parts: the data is updated at
        least that often. Parts with no period of their own (`OTHER`, `IRREGULAR`) only
        count when nothing else does.

        "Most frequent" is the order `UpdateFrequency` declares its members in, from
        `CONTINUOUS` down to `DECENNIAL`, not their `delta`: the deltas tie (ANNUAL,
        SEMIANNUAL and THREE_TIMES_A_YEAR are all 365 days), which would let the order the
        source lists the parts in decide.
        """
        if not isinstance(text, str):
            return UpdateFrequency.UNKNOWN

        parts = [
            map_ine_periodicity(PERIODICITY_QUALIFIER_RE.sub(" ", part).strip())
            for part in text[:MAX_PERIODICITY_LENGTH].split("|")
        ]
        known = [part for part in parts if part != UpdateFrequency.UNKNOWN]
        periodic = [part for part in known if part.delta or part == UpdateFrequency.CONTINUOUS]
        if periodic:
            ranking = list(UpdateFrequency)
            return min(periodic, key=ranking.index)
        return known[0] if known else UpdateFrequency.UNKNOWN

    @staticmethod
    def _bbox_boxes(bbox) -> list[tuple[float, float, float, float]]:
        """`metas.bbox` as `(minx, miny, maxx, maxy)` tuples, one per polygon.

        ODS computes it from the records and publishes it as a GeoJSON `Polygon` --
        on 49 of the 144 SNS datasets on 2026-09-23 -- so its envelope is the box.
        A `MultiPolygon` is tolerated; any other shape is skipped rather than
        guessed at, and the shared helper drops what is not geographic.
        """
        if not isinstance(bbox, dict):
            return []
        coordinates = bbox.get("coordinates")
        if bbox.get("type") == "Polygon":
            polygons = [coordinates]
        elif bbox.get("type") == "MultiPolygon" and isinstance(coordinates, list):
            polygons = coordinates
        else:
            return []

        boxes = []
        for polygon in polygons:
            try:
                points = [(float(x), float(y)) for ring in polygon for x, y in ring]
            except (TypeError, ValueError):
                continue
            if points:
                xs, ys = zip(*points)
                boxes.append((min(xs), min(ys), max(xs), max(ys)))
        return boxes

    def inner_harvest(self):
        # An unmapped periodicity is warned about once per harvest, not once per
        # dataset, and reported again on the next run.
        reset_ine_periodicity_warnings()

        count = 0
        nhits = None

        def should_fetch():
            if nhits is None:
                return True
            max_value = min(nhits, self.max_items) if self.max_items else nhits
            return count < max_value

        while should_fetch():
            params = {
                "start": count,
                "rows": 50,
                "interopmetas": "true",
            }
            for f in self.get_filters():
                ods_key = self.FILTERS.get(f["key"], f["key"])
                op = "exclude" if f.get("type") == "exclude" else "refine"
                key = ".".join((op, ods_key))
                param = params.get(key, set())
                param.add(f["value"])
                params[key] = param
            response = self.get(self.api_url, params=params)
            response.raise_for_status()
            data = response.json()
            nhits = data["nhits"]
            for dataset in data["datasets"]:
                count += 1
                # self.add_item(dataset['datasetid'], dataset=dataset)
                self.process_dataset(dataset["datasetid"], dataset=dataset)

    def inner_process_dataset(self, item: HarvestItem, **kwargs):
        ods_dataset = kwargs.get("dataset")
        dataset_id = ods_dataset["datasetid"]
        ods_metadata = ods_dataset["metas"]
        ods_interopmetas = ods_dataset.get("interop_metas", {})

        if not ods_dataset.get("has_records"):
            msg = "Dataset {datasetid} has no record".format(**ods_dataset)
            raise HarvestSkipException(msg)

        if "inspire" in ods_interopmetas and not self.has_feature("inspire"):
            msg = "Dataset {datasetid} has INSPIRE metadata"
            raise HarvestSkipException(msg.format(**ods_dataset))

        dataset = self.get_dataset(item.remote_id)

        dataset.title = ods_metadata["title"]
        dcat = ods_interopmetas.get("dcat")
        if not isinstance(dcat, dict):
            dcat = {}
        dataset.frequency = self._frequency(dcat.get("accrualperiodicity"))

        # `created` on 141 and `issued` on 120 of the 144 SNS datasets (2026-09-23).
        # Written only when they parse, so a re-harvest of a record that stops
        # publishing one keeps the last date read, as in `dgt`.
        # Text only: `safe_harvest_datetime` hands a number or a list back untouched,
        # and its future-date comparison would then raise and fail the item.
        created, issued = (
            safe_harvest_datetime(value, f"ODS dcat.{field}", refuse_future=True)
            if isinstance(value, str)
            else None
            for field, value in (("created", dcat.get("created")), ("issued", dcat.get("issued")))
        )
        if created or issued:
            if not dataset.harvest:
                dataset.harvest = HarvestDatasetMetadata()
            if created:
                dataset.harvest.created_at = created
            if issued:
                dataset.harvest.issued_at = issued
            # The public listing sorts on `created_at_internal` (`DEFAULT_SORTING`),
            # while the dataset shows `Dataset.created_at`, which reads
            # `harvest.issued_at or harvest.created_at`. Same precedence here, so the
            # order of the listing agrees with the date on each card.
            dataset.created_at_internal = dataset.harvest.issued_at or dataset.harvest.created_at
        description = ods_metadata.get("description", "").strip()
        dataset.description = parse_html(description)
        dataset.private = False

        # Detect Organization
        try:
            organization_acronym = ods_metadata["publisher"]
        except KeyError:
            pass
        else:
            # The ODS feed carries no publisher title or description, so the
            # helper falls back to the acronym for both, as this backend did.
            organization = resolve_publisher_organization(self, organization_acronym)
            if organization:
                dataset.organization = organization

        tags = set()
        if "keyword" in ods_metadata:
            if isinstance(ods_metadata["keyword"], list):
                tags |= set(ods_metadata["keyword"])
            else:
                tags.add(ods_metadata["keyword"])

        if "theme" in ods_metadata:
            if isinstance(ods_metadata["theme"], list):
                for theme in ods_metadata["theme"]:
                    tags.update([t.strip().lower() for t in theme.split(",")])
            else:
                themes = ods_metadata["theme"].split(",")
                tags.update([t.strip().lower() for t in themes])

        dataset.tags = list(tags)
        dataset.tags.append(urlparse(self.source.url).hostname)

        # Detect license. The map of labels this used to go through came from the
        # French upstream (Licence Ouverte, Etalab) and the SNS source never uses it:
        # `metas.license` is empty on all 144 of its datasets (2026-09-23), so the
        # licence already set, or the portal default, is what stands.
        default_license = dataset.license or License.default()
        dataset.license = License.guess(ods_metadata.get("license"), default=default_license)

        self.process_resources(dataset, ods_dataset, ("csv", "json"))

        if "geo" in ods_dataset["features"]:
            exports = ["geojson"]
            if ods_metadata["records_count"] <= self.SHAPEFILE_RECORDS_LIMIT:
                exports.append("shp")
            self.process_resources(dataset, ods_dataset, exports)

        self.process_extra_files(dataset, ods_dataset, "alternative_export")
        self.process_extra_files(dataset, ods_dataset, "attachment")

        dataset.extras["ods:url"] = self.explore_url(dataset_id)
        dataset.extras["harvest:name"] = self.source.name

        if "references" in ods_metadata:
            dataset.extras["ods:references"] = ods_metadata["references"]
        dataset.extras["ods:has_records"] = ods_dataset["has_records"]

        # Free text, kept as published. Sanitized because extras are marshalled raw by
        # the API, as in `dgt` and `inehvd`; removed when the source stops publishing
        # them, so an extra never outlives its source. `dcat.temporal` is left out on
        # purpose: it is prose ("janeiro 2020 a agosto 2026"), not a date range.
        for field in ("creator", "contributor", "spatial"):
            value = dcat.get(field)
            value = sanitize_strict(value).strip() if isinstance(value, str) else ""
            if value:
                dataset.extras[f"ods:{field}"] = value
            else:
                dataset.extras.pop(f"ods:{field}", None)

        # Replaces the whole coverage when the source publishes a box, and leaves it
        # alone otherwise: `SpatialCoverage.clean` refuses `zones` and `geom` together.
        coverage = bbox_to_spatial_coverage(self._bbox_boxes(ods_metadata.get("bbox")))
        if coverage:
            dataset.spatial = coverage
        dataset.extras["ods:geo"] = "geo" in ods_dataset["features"]

        return dataset

    def process_extra_files(self, dataset, data, data_type):
        dataset_id = data["datasetid"]
        modified_at = self.parse_date(data["metas"]["modified"])
        plural_type = "{0}s".format(data_type)
        for export in data.get(plural_type, []):
            url = self.extra_file_url(dataset_id, export["id"], plural_type)
            created, resource = self.get_resource(dataset, url)
            resource.title = export.get("title", "No title")
            resource.description = export.get("description")
            resource.format = guess_format_from_mime(export.get("mimetype"), export["url"])
            resource.mime = guess_mimetype(export.get("mimetype"), export["url"])
            resource.modified = modified_at
            resource.extras["ods:type"] = data_type
            if created:
                dataset.resources.append(resource)

    def get_resource(self, dataset, url):
        url = normalize_url_slashes(url)
        resource = get_by(dataset.resources, "url", url)
        if not resource:
            return True, Resource(url=url)
        return False, resource

    def process_resources(self, dataset, data, formats):
        dataset_id = data["datasetid"]
        ods_metadata = data["metas"]
        modified_at = self.parse_date(ods_metadata["modified"])
        description = self.description_from_fields(data["fields"])
        for _format in formats:
            label, udata_format, mime = self.FORMATS[_format]
            url = self.download_url(dataset_id, _format)
            created, resource = self.get_resource(dataset, url)
            resource.title = _("Export to {format}").format(format=label)
            resource.description = description
            resource.filetype = "remote"
            resource.format = udata_format
            resource.mime = mime
            resource.modified = modified_at
            resource.extras["ods:type"] = "api"
            if created:
                dataset.resources.append(resource)

    def description_from_fields(self, fields):
        """Build a resource description/schema from ODS API fields"""
        if not fields:
            return

        out = ""
        for field in fields:
            out += "- *{label}*: {name}[{type}]".format(**field)
            if field.get("description"):
                out += " {description}".format(**field)
            out += "\n"
        return out

    def parse_date(self, date_str):
        try:
            return parse_date(date_str)
        except ValueError:
            pass
