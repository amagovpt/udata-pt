"""
CSW (Catalogue Service for the Web) Harvester for udata.

This module defines a custom udata harvester backend for collecting datasets from CSW endpoints.
It fetches metadata records following the OGC CSW 2.0.2 standard, processes their metadata,
and maps them to udata datasets and resources.

Classes:
    CSWUdataBackend: Custom udata harvester backend for CSW endpoints.

Usage:
    This backend is intended to be used as a plugin in a udata instance. It will fetch datasets from the configured
    CSW endpoint, process their metadata, and create or update corresponding datasets and resources in udata.
"""

import logging

import requests
from owslib.csw import CatalogueServiceWeb

from udata.core.dataset.models import HarvestDatasetMetadata
from udata.harvest.backends.base import BaseBackend, HarvestExtraConfig
from udata.harvest.exceptions import HarvestException
from udata.harvest.filters import (
    normalize_string,
    normalize_tag,
)
from udata.harvest.models import HarvestItem
from udata.i18n import gettext as _
from udata.models import License, SpatialCoverage
from udata.utils import safe_harvest_datetime

from .tools.harvester_utils import (
    build_resource_url,
    guess_url_format,
    sync_resources,
    with_http_retry,
)

log = logging.getLogger(__name__)


def link_hint(res_data: dict) -> str:
    """What a catalogue says a link is, whichever field it says it in.

    GeoNetwork publishes `dc:URI` entries carrying a `protocol`; the Esri
    Geoportal publishes `dct:references` carrying a `scheme` instead. They mean
    the same thing, so both are read -- `protocol` first, since that is the path
    this backend already took.
    """
    return (res_data.get("protocol") or res_data.get("scheme") or "").lower()


# The Esri Geoportal announces the record's own metadata document as a link,
# alongside the data. It describes the dataset, so it belongs on `remote_url`;
# published as a resource it looks like something to download and is not.
METADATA_DOCUMENT_MARKER = "metadata:document"


def is_metadata_link(hint: str) -> bool:
    """Whether this link points at the record's metadata rather than its data."""
    return METADATA_DOCUMENT_MARKER in hint


def resource_format(hint: str, record_type: str | None, url: str) -> str:
    """The format of a resource, from what the catalogue declares about its link.

    The declared protocol or scheme is trusted first: an OGC endpoint carries no
    file extension at all. Only when it says nothing usable does the URL decide,
    through the shared helper -- the length heuristic this replaces published
    `meta_2030_0.xlsx` as a WMS service purely because "xlsx" is four characters
    (LEDG-2250).
    """
    if hint and ("wms" in hint or "wfs" in hint):
        return hint.split(":")[-1].lower() if ":" in hint else "wms"
    if record_type == "liveData":
        return "wms"
    # A MIME type, e.g. `image/jpeg`.
    if hint and "/" in hint:
        return hint.split("/")[-1].lower()
    return guess_url_format(url)


class CSWUdataBackend(BaseBackend):
    """
    Harvester backend for CSW (Catalogue Service for the Web) endpoints.

    This backend connects to CSW endpoints following the OGC CSW 2.0.2 standard,
    fetches dataset records, processes metadata including tags and resources,
    and maps them to udata datasets.
    """

    name = "cswudata"
    display_name = "CSW Harvester"

    extra_configs = (
        HarvestExtraConfig(
            _("Default tag"),
            "default_tag",
            str,
            _("A tag added to every dataset of this source, naming its producer."),
        ),
    )

    def _default_tag(self) -> str:
        """The producer tag for this source, from its config or its hostname.

        It used to be read straight off `self.config`, a key the source form has
        no way of writing: only declared extra configs are ever stored, so the
        configured value was unreachable and every source silently fell back to
        the literal "csw". The hostname replaces that fallback because the tag
        is there to name the producer, and "csw" names the protocol.
        """
        return self.get_extra_config_value("default_tag") or self.source.domain

    def inner_harvest(self):
        """
        Iterates over CSW records and adds them to the harvest job.
        """
        # base_url should be something like ".../srv/eng/csw"
        base_url = self.source.url

        # Discover the final URL to avoid POST -> GET conversion on redirects (common in GeoNetwork)
        try:
            # Guarded GET (SSRF check + retry/timeout) with stream=True to follow
            # redirects and find the actual endpoint without downloading the body.
            response = self.get(base_url, timeout=30, allow_redirects=True, stream=True)
            base_url = response.url
            response.close()
            log.debug(f"Resolved CSW endpoint URL: {base_url}")
        except requests.RequestException as e:
            # Fallback to source URL if anything goes wrong
            log.warning(f"Failed to resolve CSW endpoint URL, using original: {e}")
            pass

        page_size = 100
        # owslib issues its own HTTP requests, bypassing BaseBackend.get:
        # re-check the (possibly redirected) URL against the SSRF guard first.
        self._guard_url(base_url)
        # Set a generous timeout for the CSW client as government servers can be slow.
        # The constructor performs a GetCapabilities request, so retry it too.
        csw = with_http_retry(self, CatalogueServiceWeb, base_url, timeout=60)

        # Force all operations to use https if our base_url is https
        # This is needed because some servers (like GeoNetwork) advertise http URLs in GetCapabilities
        # even when accessed via https, which causes OWSLib to fail on POST requests due to redirects.
        if base_url.startswith("https://"):
            for op in getattr(csw, "operations", []):
                for method in op.methods:
                    if method.get("url", "").startswith("http://"):
                        method["url"] = method["url"].replace("http://", "https://", 1)

        # The server-advertised operation URLs are attacker-controllable input:
        # owslib will POST GetRecords to them, so re-check each against the
        # SSRF guard before any further request (LEDG-1729 / VULN-2084).
        for op in getattr(csw, "operations", []):
            for method in op.methods:
                if method.get("url"):
                    self._guard_url(method["url"])

        # First request to get matches and validate endpoint
        with_http_retry(self, csw.getrecords2, maxrecords=1, esn="full")
        matches = int(csw.results.get("matches", 0) or 0)
        log.info(f"Found {matches} records in CSW endpoint")

        startposition = 1  # CSW is 1-based
        while matches > 0 and startposition <= matches:
            with_http_retry(
                self, csw.getrecords2, maxrecords=page_size, startposition=startposition, esn="full"
            )
            nextrecord = int(csw.results.get("nextrecord", 0) or 0)
            log.debug(
                f"Processing records {startposition} to {startposition + len(csw.records) - 1}"
            )

            for rec_id, record in csw.records.items():
                resources = []

                # `dc:URI` (GeoNetwork) and `dct:references` (Esri Geoportal) are
                # both read, never one instead of the other: a record carrying a
                # single URI -- a thumbnail is enough -- used to drop every
                # reference, and with it the resource the dataset was published
                # with, whose id then died. `sync_resources` dedupes by URL, so
                # a link announced in both lists still yields one resource.
                for field in ("uris", "references"):
                    for entry in getattr(record, field, None) or []:
                        if isinstance(entry, dict) and entry.get("url"):
                            resources.append(entry)

                data = {
                    "id": record.identifier,
                    "title": getattr(record, "title", "") or "",
                    "description": getattr(record, "abstract", "") or "",
                    "tags": getattr(record, "subjects", []) or [],
                    "bbox": getattr(record, "bbox", None),
                    "resources": resources,
                    "type": getattr(record, "type", None),
                    "created": getattr(record, "created", None),
                    "modified": getattr(record, "modified", None),
                }

                self.process_dataset(data["id"], items=data)

                if self.has_reached_max_items():
                    log.info("Reached maximum items limit")
                    return

            if nextrecord == 0 or nextrecord <= startposition:
                break
            startposition = nextrecord

    def inner_process_dataset(self, item: HarvestItem, **kwargs):
        """
        Maps harvested metadata to a udata dataset.

        Args:
            item (HarvestItem): The harvested item containing the remote_id.
            **kwargs: Additional keyword arguments, expects 'items' with the metadata dict.

        Returns:
            Dataset: The updated or created udata dataset.
        """
        dataset = self.get_dataset(item.remote_id)

        data = kwargs.get("items")
        if not data:
            raise HarvestException("Missing data for dataset {0}".format(item.remote_id))

        # Set basic dataset fields
        dataset.title = normalize_string(data["title"])
        dataset.license = License.guess("cc-by")

        # Process tags - the producer tag from the source, then the record's own
        tags = [normalize_tag(self._default_tag())]
        for tag in data.get("tags", []):
            normalized = normalize_tag(tag)
            if normalized:
                tags.append(normalized)
        dataset.tags = list(set(tags))  # Remove duplicates

        dataset.description = normalize_string(data["description"])

        # `Dataset.created_at` is a read-only property -- it reads
        # `harvest.issued_at or harvest.created_at or created_at_internal` -- so
        # assigning it raised `AttributeError` for every record carrying a date,
        # and the `except` below it caught neither. The harvest metadata is what
        # the property reads, and what `rdf.py` writes.
        if not dataset.harvest:
            dataset.harvest = HarvestDatasetMetadata()

        created = safe_harvest_datetime(
            data.get("created"), "CSW creation date", refuse_future=True
        )
        if created:
            dataset.harvest.created_at = created

        modified = safe_harvest_datetime(
            data.get("modified"), "CSW modification date", refuse_future=True
        )
        if modified:
            # What `Dataset.last_modified` reads for a harvested dataset.
            dataset.harvest.modified_at = modified

        dataset.harvest.dct_identifier = data.get("id")
        dataset.harvest.uri = data.get("id")

        # The record's own page, when the catalogue announces one: a landing
        # page, or the metadata document itself.
        for res_data in data.get("resources", []):
            hint = link_hint(res_data)
            if "html" in hint or "link" in hint or is_metadata_link(hint):
                dataset.harvest.remote_url = res_data.get("url")
                break

        # Process spatial coverage
        self._process_spatial(dataset, data)

        # Reconcile the resources with the record instead of recreating them:
        # a fresh `Resource` gets a fresh id, and with it a fresh — therefore
        # broken — download permalink (LEDG-2251).
        resources = []

        for res_data in data.get("resources", []):
            url = res_data.get("url")
            if not url:
                continue

            hint = link_hint(res_data)
            if is_metadata_link(hint):
                # It describes the dataset; it is not one of its files.
                continue

            # Repair the separators and self-concatenated paths some catalogues
            # emit, before anything reads this URL: `sync_resources` matches
            # resources by URL, so repairing it afterwards would strand the id
            # of the resource already published (LEDG-2250, LEDG-2251).
            url = build_resource_url(url)
            name = res_data.get("name", "")

            resources.append(
                {
                    # Use the resource name if the catalogue gives one.
                    "title": name if name else dataset.title,
                    "url": url,
                    "filetype": "remote",
                    "format": resource_format(hint, data.get("type"), url),
                }
            )

        sync_resources(dataset, resources)

        log.debug(
            f"Processed dataset {item.remote_id}: {dataset.title} with {len(dataset.resources)} resources"
        )

        return dataset

    def _process_spatial(self, dataset, data):
        """
        Process spatial coverage from CSW bounding box.

        Args:
            dataset: The dataset object to update with spatial information.
            data: Dictionary containing the bbox information.
        """
        bbox = data.get("bbox")
        if not bbox:
            return

        try:
            # Extract coordinates ensuring float type
            minx = float(bbox.minx)
            miny = float(bbox.miny)
            maxx = float(bbox.maxx)
            maxy = float(bbox.maxy)

            # Ensure correct min/max order
            if minx > maxx:
                minx, maxx = maxx, minx
            if miny > maxy:
                miny, maxy = maxy, miny

            dataset.spatial = SpatialCoverage()

            if minx == maxx and miny == maxy:
                # It's a point – create a tiny polygon around it since
                # SpatialCoverage.geom is a MultiPolygonField and only
                # accepts "MultiPolygon" type geometries.
                epsilon = 0.0001  # ~11 meters at the equator
                minx -= epsilon
                miny -= epsilon
                maxx += epsilon
                maxy += epsilon
                polygon_coordinates = [
                    [
                        [minx, miny],
                        [maxx, miny],
                        [maxx, maxy],
                        [minx, maxy],
                        [minx, miny],
                    ]
                ]
                dataset.spatial.geom = {
                    "type": "MultiPolygon",
                    "coordinates": [polygon_coordinates],
                }
                log.debug(
                    f"Processed spatial coverage as MultiPolygon (from point): [{minx}, {miny}]"
                )
            else:
                # Construct GeoJSON Polygon (counter-clockwise)
                # [[minx, miny], [maxx, miny], [maxx, maxy], [minx, maxy], [minx, miny]]
                polygon_coordinates = [
                    # Ring Exterior
                    [
                        [minx, miny],
                        [maxx, miny],
                        [maxx, maxy],
                        [minx, maxy],
                        [minx, miny],
                    ]
                ]
                # MultiPolygon coordinates: [ [ [[x,y]...] ] ]
                coordinates = [polygon_coordinates]
                dataset.spatial.geom = {
                    "type": "MultiPolygon",
                    "coordinates": coordinates,
                }
                log.debug(
                    f"Processed spatial coverage as MultiPolygon: bbox=[{minx}, {miny}, {maxx}, {maxy}]"
                )
        except (ValueError, AttributeError, TypeError) as e:
            log.warning(f"Failed to process spatial coverage: {e}")
            pass
