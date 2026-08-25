"""CKAN PT harvester: the upstream CKAN backend plus the Portuguese specifics.

Historically a copy-paste fork of `udata.harvest.backends.ckan.harvesters`, which
left it frozen on the state of that file at the time of the copy. It is now a
subclass, so upstream fixes reach this backend on their own instead of having to
be reapplied by hand on every sync.
"""

import json
import logging
from functools import cached_property
from urllib.parse import urlparse
from uuid import UUID

from udata.harvest.backends.base import HarvestExtraConfig
from udata.harvest.models import HarvestItem
from udata.i18n import lazy_gettext as _
from udata.models import GeoZone, License, Organization, SpatialCoverage
from udata.utils import safe_unicode

from .ckan.harvesters import ALLOWED_RESOURCE_TYPES, CkanBackend
from .tools.harvester_utils import normalize_url_slashes

log = logging.getLogger(__name__)


class CkanPTBackend(CkanBackend):
    name = "ckanpt"
    display_name = "CKAN PT"
    # No real source configures more than one zone; the cap is there because the
    # value is only type-checked, and a preview needs nothing but a login.
    MAX_GEOZONES = 50
    # What `CkanBackend.inner_process_dataset` can map; anything else makes it raise.
    SPATIAL_GEOMETRY_TYPES = ("Polygon", "MultiPolygon")
    extra_configs = (
        HarvestExtraConfig(
            _("License"),
            "license",
            str,
            _("Identifier of the license to fall back on, e.g. cc-by"),
        ),
        HarvestExtraConfig(
            _("Geozones"),
            "geozones",
            str,
            _("Comma-separated GeoZone identifiers, e.g. pt:concelho:1106"),
        ),
    )

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

        `license` and `geozones` are extra configs now, and the description is back
        to being what the form has always called it - free text. A description that
        is still a JSON object carrying those keys was written as config, and that
        config no longer applies: say so once per job instead of letting it look
        like it still works.
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
            "Description of harvest source %s still holds JSON config; license and "
            "geozones are extra configs now and the description is no longer read",
            self.source_label(),
        )

    @cached_property
    def default_license(self) -> License | None:
        """The license to fall back on when the remote one cannot be guessed.

        The extra config stores the license as its identifier, but `Dataset.license`
        is a reference: handing the raw string to `License.guess` as its default made
        every item fail validation whenever the remote license was not resolvable.

        Cached: the config cannot change during a run, and this is called once per
        dataset - an unknown identifier would otherwise re-query and re-log for
        every single item of the job.

        Returns `None` when the license list has never been seeded, since
        `License.default()` does; `Dataset.license` is not required.
        """
        configured = self.get_extra_config_value("license")
        if not configured:
            return License.default()

        # Identifiers are stored lower case and typed by hand, so match the way
        # `License.guess_one` does. Anything that is not a string is not an
        # identifier - and must never reach the query, where a dict would be read
        # as Mongo operators.
        license = (
            License.objects(id__iexact=configured.strip()).first()
            if isinstance(configured, str)
            else None
        )
        if license:
            return license

        log.warning(
            "Unknown license %s configured on harvest source %s; using the default one",
            # `repr` so a crafted identifier cannot forge log lines with newlines.
            repr(configured)[:200],
            self.source_label(),
        )
        return License.default()

    @cached_property
    def configured_geozones(self) -> list[GeoZone]:
        """The geozones configured on the source, resolved to documents.

        Stored comma-separated because `HarvestExtraConfig` only admits the scalar
        types of `HarvestFilter.TYPES`, and a zone identifier (`pt:concelho:1106`)
        never contains a comma.

        An identifier matching no zone is dropped with a warning rather than failing
        the item: this used to go through `GeoZone.objects.get()`, so a single typo
        in the config failed every dataset of the source.

        Bounded on purpose. `HarvestSourceForm` only checks that the value is a
        string, and `POST /harvest/source/preview/` needs nothing but a login, so
        the list is attacker-sized: it is deduplicated, cut at `MAX_GEOZONES`,
        resolved in a single query, and reports the unknown identifiers in one
        warning. One query and one log record whatever the input, otherwise a
        20k-entry value buys minutes of server time and a `HarvestJob` big enough
        to stop saving.

        Cached for the same reason as `default_license`: once per dataset otherwise.
        """
        configured = self.get_extra_config_value("geozones")
        if not isinstance(configured, str):
            return []

        identifiers = list(
            dict.fromkeys(part.strip() for part in configured.split(",") if part.strip())
        )
        if len(identifiers) > self.MAX_GEOZONES:
            log.warning(
                "Harvest source %s configures %d geozones; keeping the first %d",
                self.source_label(),
                len(identifiers),
                self.MAX_GEOZONES,
            )
            identifiers = identifiers[: self.MAX_GEOZONES]

        found = {zone.id: zone for zone in GeoZone.objects(id__in=identifiers)}
        unknown = [identifier for identifier in identifiers if identifier not in found]
        if unknown:
            log.warning(
                "Unknown geozones %s configured on harvest source %s; ignoring them",
                # `repr` so a crafted identifier cannot forge log lines.
                repr(unknown)[:500],
                self.source_label(),
            )

        return [found[identifier] for identifier in identifiers if identifier in found]

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
        """Seed a new dataset with the configured license, before upstream reads it.

        Upstream computes its fallback as `dataset.license or License.default()`, so
        putting the configured license on the dataset before it gets there turns the
        config into a default without touching the upstream file - and keeps
        upstream's rule that a license already stored wins on a re-harvest.

        Also the last point where the stored resources and spatial coverage are still
        untouched - upstream runs its resource loop after this - so it is where both
        are noted down for the deltas that run once `super()` has returned.
        """
        dataset = super().get_dataset(remote_id)
        self._uploaded_resource_ids = {
            resource.id for resource in dataset.resources if resource.filetype == "file"
        }
        self._stored_spatial_zones = list(dataset.spatial.zones) if dataset.spatial else []
        self.disown_uploaded_resources()
        if not dataset.license:
            dataset.license = self.default_license
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
        if not organization:
            organization = Organization(
                acronym=acronym,
                name=data["organization"]["title"],
                description=data["organization"]["description"],
            )
            # LEDG-2320: this runs on a preview too, where nothing should be saved.
            organization.save()
        dataset.organization = organization

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
        if self.configured_geozones:
            # Zones configured on the source own the spatial coverage.
            dataset.spatial = SpatialCoverage(zones=self.configured_geozones)
        elif stored_zones and not (dataset.spatial and dataset.spatial.zones):
            # Nothing configured: keep the zones the dataset already had instead of
            # letting the remote drop them. On this portal the zones never came from
            # the remote, they came from the source config - and between deploying
            # this code and running the migration, `configured_geozones` is empty for
            # a source whose config is still sitting in its description. A remote
            # publishing a geometry would otherwise wipe the zones of every one of
            # its datasets in that window, with no way back.
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
