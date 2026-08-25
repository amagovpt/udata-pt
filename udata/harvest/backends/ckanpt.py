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
        and that is exactly the path this backend's previews come from.
        """
        return self.source.id or self.source.name or self.source.url

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

        Cached for the same reason as `default_license`: once per dataset otherwise.
        """
        configured = self.get_extra_config_value("geozones")
        if not isinstance(configured, str):
            return []

        zones = []
        for identifier in (part.strip() for part in configured.split(",")):
            if not identifier:
                continue
            zone = GeoZone.objects(id=identifier).first()
            if zone:
                zones.append(zone)
            else:
                log.warning(
                    "Unknown geozone %s configured on harvest source %s; ignoring it",
                    # `repr` so a crafted identifier cannot forge log lines.
                    repr(identifier)[:200],
                    self.source_label(),
                )
        return zones

    def validate(self, data, schema):
        """Keep the validated payload around: the PT deltas below need it.

        `CkanBackend.inner_process_dataset` reads the remote payload into a local
        variable and returns only the dataset, so an override running after it has
        no way to see the organization or the resource list the source published.
        Stashing it here is the one seam that keeps the upstream file untouched.
        """
        self._remote_data = super().validate(data, schema)
        return self._remote_data

    def get_dataset(self, remote_id):
        """Seed a new dataset with the configured license.

        Upstream computes its fallback as `dataset.license or License.default()`, so
        putting the configured license on the dataset before it gets there turns the
        config into a default without touching the upstream file - and keeps
        upstream's rule that a license already stored wins on a re-harvest.
        """
        dataset = super().get_dataset(remote_id)
        if not dataset.license:
            dataset.license = self.default_license
        return dataset

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

        # Zones configured on the source win over whatever the remote declares.
        if self.configured_geozones:
            dataset.spatial = SpatialCoverage(zones=self.configured_geozones)

        self.reconcile_resources(dataset, data["resources"])

        return dataset

    def reconcile_resources(self, dataset, entries: list[dict]) -> None:
        """The two resource rules upstream does not have.

        Upstream stores whatever path the source publishes and keeps every resource
        it has ever harvested. Here the URL goes through `normalize_url_slashes`
        first, and a resource the source stopped publishing is removed - except an
        uploaded one, which never belonged to the harvester (the exception
        `sync_resources` documents).

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

        kept = []
        for resource in dataset.resources:
            if resource.filetype == "file":
                # Uploaded on the portal: not the harvester's to remove.
                kept.append(resource)
                continue
            if resource.id in published:
                resource.url = normalize_url_slashes(resource.url)
            elif not self.dryrun:
                continue
            kept.append(resource)

        dataset.resources = kept
