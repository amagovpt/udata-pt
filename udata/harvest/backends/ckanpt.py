"""CKAN PT harvester: the upstream CKAN backend plus the Portuguese specifics.

Historically a copy-paste fork of `udata.harvest.backends.ckan.harvesters`, which
left it frozen on the state of that file at the time of the copy. It is now a
subclass, so upstream fixes reach this backend on their own instead of having to
be reapplied by hand on every sync.
"""

import json
import logging
from urllib.parse import urlparse
from uuid import UUID

from udata.harvest.models import HarvestItem
from udata.models import Organization, SpatialCoverage
from udata.utils import safe_unicode

from .ckan.harvesters import ALLOWED_RESOURCE_TYPES, CkanBackend
from .tools.harvester_utils import normalize_url_slashes

log = logging.getLogger(__name__)


class CkanPTBackend(CkanBackend):
    name = "ckanpt"
    display_name = "CKAN PT"
    # What `CkanBackend.inner_process_dataset` can map; anything else makes it raise.
    SPATIAL_GEOMETRY_TYPES = ("Polygon", "MultiPolygon")

    def __init__(self, source_or_job, dryrun=False, max_items=None):
        super().__init__(source_or_job, dryrun=dryrun, max_items=max_items)
        self._warn_if_description_holds_config()

    def source_label(self) -> str:
        """How to name the source in logs.

        `preview_from_config` previews an unsaved source, so there is no id yet -
        and that is exactly the path this backend's previews come from. Which means
        the fallback is the source *name*, free text from whoever asked for the
        preview: `repr` so it cannot forge a log line, since these warnings are
        captured into `HarvestLog` and rendered in the admin job detail.
        """
        if self.source.id:
            return str(self.source.id)
        return repr(self.source.name or self.source.url)[:200]

    def _warn_if_description_holds_config(self) -> None:
        """Transitional: the description used to double as a config blob.

        The description is what the form has always called it - free text. A
        description that is still a JSON object carrying `license` or `geozones`
        was written as config back when this backend read it from there, and it
        applies nowhere now: say so once per job instead of letting it look like
        it still works.
        """
        # Decode once: the description is a StringField, but nothing stops a CLI or a
        # migration from putting bytes or another type in there.
        text = safe_unicode(self.source.description) or ""
        try:
            legacy = json.loads(text)
        except (ValueError, TypeError, RecursionError):
            # Prose is the normal case and must stay silent, otherwise every run of
            # every CKAN PT harvester logs a warning. Config that never parsed never
            # applied anything either, so nothing changed for it.
            return

        if not isinstance(legacy, dict) or not any(
            key in legacy for key in ("license", "geozones")
        ):
            return

        log.warning(
            "Description of harvest source %s still holds JSON config; it is free "
            "text and neither the license nor the geozones in it are read",
            self.source_label(),
        )

    def validate(self, data, schema):
        """Keep the validated payload around: the PT deltas below need it.

        `CkanBackend.inner_process_dataset` reads the remote payload into a local
        variable and returns only the dataset, so an override running after it has
        no way to see the organization or the resource list the source published.
        Stashing it here is the one seam that keeps the upstream file untouched.
        """
        self._remote_data = self.drop_unsupported_spatial(super().validate(data, schema))
        return self._remote_data

    def drop_unsupported_spatial(self, data: dict) -> dict:
        """Keep a dataset whose remote publishes a geometry upstream cannot map.

        Upstream raises `HarvestException` for any geometry that is not a `Polygon`
        or a `MultiPolygon`, which fails the whole item - its title, its resources
        and the zones this source configures, not just its spatial coverage. The
        fork parsed that value and threw it away, so these datasets have always
        harvested here; dropping only the extra keeps them harvesting and loses
        nothing that was ever mapped.

        A value that is not JSON at all is left alone: upstream raises on it and so
        did the fork, so that is not a behaviour this convergence changes.
        """
        extras = data.get("extras")
        if not extras:
            return data

        kept = []
        for extra in extras:
            if extra.get("key") != "spatial":
                kept.append(extra)
                continue

            value = extra.get("value")
            try:
                geometry = value if isinstance(value, dict) else json.loads(value)
            except (ValueError, TypeError, RecursionError):
                kept.append(extra)
                continue

            if isinstance(geometry, dict) and geometry.get("type") in self.SPATIAL_GEOMETRY_TYPES:
                kept.append(extra)
            else:
                log.warning(
                    "Harvest source %s published an unsupported spatial geometry %s; ignoring it",
                    self.source_label(),
                    repr(geometry.get("type") if isinstance(geometry, dict) else geometry)[:100],
                )

        data["extras"] = kept
        return data

    def get_dataset(self, remote_id):
        """The last point where the stored resources and spatial coverage are intact.

        Upstream runs its resource loop after this, so this is where both are noted
        down for the deltas that run once `super()` has returned.
        """
        dataset = super().get_dataset(remote_id)
        self._uploaded_resource_ids = {
            resource.id for resource in dataset.resources if resource.filetype == "file"
        }
        self._stored_spatial_zones = list(dataset.spatial.zones) if dataset.spatial else []
        self.disown_uploaded_resources()
        return dataset

    def disown_uploaded_resources(self) -> None:
        """Hide from upstream any remote entry claiming an uploaded resource's id.

        Upstream matches remote entries to stored resources by id and sets
        `filetype = "remote"`, the url, the title and the format on every match.
        Resource ids are public - they are the `/api/1/datasets/r/<id>` permalinks
        people copy - so a remote publishing one of them would take over a file
        uploaded on the portal: the permalink would start serving remote content, and
        once the entry is no longer published the resource is prunable like any other.

        Guarding this after `super()` is too late, because by then the takeover has
        happened and the next run cannot tell the resource apart from a harvested
        one. So the entry is dropped from the payload before upstream reads it.
        """
        entries = self._remote_data.get("resources") or []
        kept = []
        for entry in entries:
            try:
                claimed = UUID(entry["id"]) in self._uploaded_resource_ids
            except (KeyError, TypeError, ValueError):
                claimed = False
            if claimed:
                log.warning(
                    "Harvest source %s published a resource claiming the id of a file "
                    "uploaded on the portal; ignoring the remote entry",
                    self.source_label(),
                )
            else:
                kept.append(entry)

        self._remote_data["resources"] = kept

    def inner_process_dataset(self, item: HarvestItem):
        """The upstream CKAN mapping, plus what is specific to this portal.

        Everything the two backends agree on - core attributes, license guessing,
        update frequency, spatial and temporal extras, remote URL, harvest metadata,
        resource fields - comes from `super()`. What is left below is the PT delta.
        """
        dataset = super().inner_process_dataset(item)
        data = self._remote_data

        # Upstream never touches `dataset.organization`. This portal maps the remote
        # CKAN organization onto a local one by acronym, creating it when it is new.
        acronym = data["organization"]["name"]
        organization = Organization.objects(acronym=acronym).first()
        if organization:
            dataset.organization = organization
        elif not self.dryrun:
            organization = Organization(
                acronym=acronym,
                name=data["organization"]["title"],
                description=data["organization"]["description"],
            )
            organization.save()
            dataset.organization = organization
        else:
            # A preview creates nothing, so an organization that does not exist yet
            # cannot be shown on the item: `organization` is a `ReferenceField` and
            # mongoengine refuses to reference an unsaved document, which would fail
            # the whole item on the `validate()` a dryrun runs instead of `save()`.
            # Same reasoning as upstream for contact points
            # (`contact_points_from_rdf`).
            #
            # The field is left untouched rather than set to `None`, which means it
            # keeps whatever `get_dataset` seeded from the source - so the item shows
            # the source's organization while a real run would file the dataset under
            # a new one. That is exactly the question a preview is used to answer, so
            # it is said out loud: `process_dataset` collects these onto `item.logs`,
            # which the preview API returns.
            #
            # `warning`, not `info`: `init_logging` puts the app logger at WARNING
            # outside debug, and the collector hangs off that logger - an `info`
            # would be dropped before it ever became a record. Warning is also the
            # honest level here, and this branch only runs on a preview, so it
            # cannot become noise on a scheduled harvest.
            log.warning(
                "Organization %s does not exist yet; a real harvest would create it, "
                "the preview does not",
                # `repr` and bounded, like the other warnings here: the value is
                # remote and these records are returned in the preview response.
                repr(acronym)[:200],
            )

        # Which source a dataset came from, as a tag. `super()` rebuilds the tag list
        # from the remote ones, so this has to come after it.
        dataset.tags.append(urlparse(self.source.url).hostname)

        # Upstream records the remote dates only on `harvest.created_at`, but the
        # public listing sorts on `created_at_internal` (`DEFAULT_SORTING` in
        # `core/dataset/api.py`) and `Dataset.last_modified` falls back to
        # `last_modified_internal`. Dropping these would make every newly harvested
        # dataset look like it was published today.
        dataset.created_at_internal = data["metadata_created"]
        dataset.last_modified_internal = data["metadata_modified"]

        stored_zones = getattr(self, "_stored_spatial_zones", [])
        if stored_zones and not (dataset.spatial and dataset.spatial.zones):
            # Keep the zones the dataset already had instead of letting the remote
            # drop them. On this portal the zones never came from the remote, so a
            # remote publishing a geometry would otherwise wipe the zones of every
            # one of its datasets, with no way back.
            #
            # The zones replace the coverage rather than joining it: `SpatialCoverage`
            # refuses to hold a geozone and a geometry at once, so merging the two
            # would fail the whole item on save.
            dataset.spatial = SpatialCoverage(zones=stored_zones)

        self.reconcile_resources(dataset, data["resources"])

        return dataset

    def reconcile_resources(self, dataset, entries: list[dict]) -> None:
        """The two resource rules upstream does not have.

        Upstream stores whatever path the source publishes and keeps every resource
        it has ever harvested. Here the URL goes through `normalize_url_slashes`
        first, and a resource the source stopped publishing is removed - except an
        uploaded one, which never belonged to the harvester (the exception
        `sync_resources` documents).

        Which resources were uploaded is read from the snapshot `get_dataset` takes
        before upstream runs, not from `filetype` as it stands now: upstream will
        have set `filetype = "remote"` on anything the remote claimed by id.

        A preview shows what the source has, it does not act on what it no longer
        has, so pruning is skipped on a dry run.
        """
        published = set()
        for entry in entries:
            if entry["resource_type"] not in ALLOWED_RESOURCE_TYPES:
                continue
            try:
                published.add(UUID(entry["id"]))
            except (TypeError, ValueError):
                # Already logged by `super()`, which could not store it either.
                continue

        uploaded = getattr(self, "_uploaded_resource_ids", frozenset())

        kept = []
        for resource in dataset.resources:
            if resource.id in uploaded or resource.filetype == "file":
                # Uploaded on the portal: not the harvester's to remove.
                kept.append(resource)
                continue
            if resource.id in published:
                resource.url = normalize_url_slashes(resource.url)
            elif not self.dryrun:
                continue
            kept.append(resource)

        dataset.resources = kept
