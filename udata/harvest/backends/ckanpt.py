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

from udata import uris
from udata.frontend.markdown import parse_html
from udata.harvest.backends.base import HarvestExtraConfig
from udata.harvest.exceptions import HarvestSkipException
from udata.harvest.models import HarvestItem
from udata.i18n import lazy_gettext as _
from udata.models import GeoZone, License, Organization, Resource, SpatialCoverage, db
from udata.utils import daterange_end, daterange_start, get_by, safe_unicode

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

    def inner_process_dataset(self, item: HarvestItem):
        response = self.get_action("package_show", id=item.remote_id)
        data = self.validate(response["result"], self.schema)

        if isinstance(data, list):
            data = data[0]

        # Fix the remote_id: use real ID instead of not stable name
        item.remote_id = data["id"]

        # Skip if no resource
        if not len(data.get("resources", [])):
            msg = "Dataset {0} has no record".format(item.remote_id)
            raise HarvestSkipException(msg)

        dataset = self.get_dataset(item.remote_id)

        # Core attributes
        if not dataset.slug:
            dataset.slug = data["name"]
        dataset.title = data["title"]
        dataset.description = parse_html(data["notes"])

        # Detect Org
        organization_acronym = data["organization"]["name"]
        orgObj = Organization.objects(acronym=organization_acronym).first()
        if orgObj:
            # print 'Found %s' % orgObj.acronym
            dataset.organization = orgObj
        else:
            orgObj = Organization()
            orgObj.acronym = organization_acronym
            orgObj.name = data["organization"]["title"]
            orgObj.description = data["organization"]["description"]
            orgObj.save()
            # print 'Created %s' % orgObj.acronym

            dataset.organization = orgObj

        # Detect license
        dataset.license = License.guess(
            data["license_id"], data["license_title"], default=self.default_license
        )

        dataset.tags = [t["name"] for t in data["tags"] if t["name"]]

        dataset.tags.append(urlparse(self.source.url).hostname)

        dataset.created_at_internal = data["metadata_created"]
        dataset.last_modified_internal = data["metadata_modified"]

        dataset.frequency = "unknown"
        dataset.extras["ckan:name"] = data["name"]

        temporal_start, temporal_end = None, None

        for extra in data["extras"]:
            # GeoJSON representation (Polygon or Point)
            if extra["key"] == "spatial":
                # Parsed for validation only; the spatial mapping below is disabled
                json.loads(extra["value"])
            #  Textual representation of the extent / location
            elif extra["key"] == "spatial-text":
                log.debug("spatial-text value not handled")
            # Linked Data URI representing the place name
            elif extra["key"] == "spatial-uri":
                log.debug("spatial-uri value not handled")
            # Update frequency
            elif extra["key"] == "frequency":
                log.debug("frequency %s", extra["value"])
            # Temporal coverage start
            elif extra["key"] == "temporal_start":
                temporal_start = daterange_start(extra["value"])
                continue
            # Temporal coverage end
            elif extra["key"] == "temporal_end":
                temporal_end = daterange_end(extra["value"])
                continue
            dataset.extras[extra["key"]] = extra["value"]

        # Zones configured on the source win over whatever the remote declares.
        if self.configured_geozones:
            dataset.spatial = SpatialCoverage(zones=self.configured_geozones)
        #
        # if spatial_geom:
        #     dataset.spatial = SpatialCoverage()
        #     if spatial_geom['type'] == 'Polygon':
        #         coordinates = [spatial_geom['coordinates']]
        #     elif spatial_geom['type'] == 'MultiPolygon':
        #         coordinates = spatial_geom['coordinates']
        #     else:
        #         HarvestException('Unsupported spatial geometry')
        #     dataset.spatial.geom = {
        #         'type': 'MultiPolygon',
        #         'coordinates': coordinates
        #     }

        if temporal_start and temporal_end:
            dataset.temporal_coverage = db.DateRange(
                start=temporal_start,
                end=temporal_end,
            )

        # Remote URL
        if data.get("url"):
            try:
                url = uris.validate(data["url"])
            except uris.ValidationError:
                dataset.extras["remote_url"] = self.dataset_url(data["name"])
                dataset.extras["ckan:source"] = data["url"]
            else:
                dataset.extras["remote_url"] = url

        dataset.extras["harvest:name"] = self.source.name

        current_resources = [str(resource.id) for resource in dataset.resources]
        fetched_resources = []

        # Resources
        for res in data["resources"]:
            if res["resource_type"] not in ALLOWED_RESOURCE_TYPES:
                continue

            # Ignore invalid Resources
            try:
                url = uris.validate(res["url"])
            except uris.ValidationError:
                continue

            try:
                resource = get_by(dataset.resources, "id", UUID(res["id"]))
            except Exception:
                log.error("Unable to parse resource ID %s", res["id"])
                continue

            fetched_resources.append(str(res["id"]))
            if not resource:
                resource = Resource(id=res["id"])
                dataset.resources.append(resource)
            resource.title = res.get("name", "") or ""
            resource.description = parse_html(res.get("description"))
            resource.url = normalize_url_slashes(res["url"])
            resource.filetype = "remote"
            resource.format = res.get("format")
            resource.mime = res.get("mimetype")
            resource.hash = res.get("hash")
            resource.created = res["created"]
            resource.modified = res["last_modified"]
            # resource.published = resource.published or resource.created
            resource.published = resource.created

        # Clean up old resources removed from source
        for resource_id in current_resources:
            if resource_id not in fetched_resources:
                try:
                    resource = get_by(dataset.resources, "id", UUID(resource_id))
                except Exception:
                    log.error("Unable to parse resource ID %s", resource_id)
                    continue
                else:
                    if resource and not self.dryrun:
                        dataset.resources.remove(resource)

        return dataset
