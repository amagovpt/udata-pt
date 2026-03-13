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

from udata.harvest.backends.base import BaseBackend
from udata.models import Resource, Dataset, License, SpatialCoverage
from owslib.csw import CatalogueServiceWeb

from udata.harvest.models import HarvestItem
from udata.harvest.exceptions import HarvestException
from udata.harvest.filters import (
    to_date,
    normalize_tag,
    normalize_string,
)

log = logging.getLogger(__name__)


class CSWUdataBackend(BaseBackend):
    """
    Harvester backend for CSW (Catalogue Service for the Web) endpoints.

    This backend connects to CSW endpoints following the OGC CSW 2.0.2 standard,
    fetches dataset records, processes metadata including tags and resources,
    and maps them to udata datasets.
    """

    display_name = "CSW Harvester"

    def inner_harvest(self):
        """
        Iterates over CSW records and adds them to the harvest job.
        """
        # base_url should be something like ".../srv/eng/csw"
        base_url = self.source.url

        # Discover the final URL to avoid POST -> GET conversion on redirects (common in GeoNetwork)
        try:
            # We use a GET request with stream=True to follow redirects and find the actual endpoint
            # without downloading the whole body.
            response = requests.get(
                base_url, timeout=30, allow_redirects=True, stream=True
            )
            base_url = response.url
            response.close()
            log.debug(f"Resolved CSW endpoint URL: {base_url}")
        except requests.RequestException as e:
            # Fallback to source URL if anything goes wrong
            log.warning(f"Failed to resolve CSW endpoint URL, using original: {e}")
            pass

        page_size = 100
        # Set a generous timeout for the CSW client as government servers can be slow
        csw = CatalogueServiceWeb(base_url, timeout=60)

        # Force all operations to use https if our base_url is https
        # This is needed because some servers (like GeoNetwork) advertise http URLs in GetCapabilities
        # even when accessed via https, which causes OWSLib to fail on POST requests due to redirects.
        if base_url.startswith("https://"):
            for op in getattr(csw, "operations", []):
                for method in op.methods:
                    if method.get("url", "").startswith("http://"):
                        method["url"] = method["url"].replace("http://", "https://", 1)

        # First request to get matches and validate endpoint
        csw.getrecords2(maxrecords=1, esn="full")
        matches = int(csw.results.get("matches", 0) or 0)
        log.info(f"Found {matches} records in CSW endpoint")

        startposition = 1  # CSW is 1-based
        while matches > 0 and startposition <= matches:
            csw.getrecords2(
                maxrecords=page_size, startposition=startposition, esn="full"
            )
            nextrecord = int(csw.results.get("nextrecord", 0) or 0)
            log.debug(
                f"Processing records {startposition} to {startposition + len(csw.records) - 1}"
            )

            for rec_id, record in csw.records.items():
                resources = []

                # CSW records use 'uris' field for resources, not 'references'
                uris = getattr(record, "uris", None)
                if uris:
                    for uri in uris:
                        if isinstance(uri, dict) and uri.get("url"):
                            resources.append(uri)

                # Fallback to references if uris is not available
                if not resources:
                    refs = getattr(record, "references", None)
                    if refs:
                        for ref in refs:
                            if isinstance(ref, dict) and ref.get("url"):
                                resources.append(ref)

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
                    log.info(f"Reached maximum items limit")
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
            raise HarvestException(
                "Missing data for dataset {0}".format(item.remote_id)
            )

        # Set basic dataset fields
        dataset.title = normalize_string(data["title"])
        dataset.license = License.guess("cc-by")

        # Process tags - use config tag if available, otherwise use generic 'csw'
        default_tag = self.config.get("default_tag", "csw")
        tags = [normalize_tag(default_tag)]
        for tag in data.get("tags", []):
            normalized = normalize_tag(tag)
            if normalized:
                tags.append(normalized)
        dataset.tags = list(set(tags))  # Remove duplicates

        dataset.description = normalize_string(data["description"])

        # Process creation and modification dates
        if data.get("created"):
            dataset.extras["created_at"] = data.get("created")
            try:
                dataset.created_at = to_date(data["created"])
            except (ValueError, TypeError) as e:
                log.warning(f"Failed to parse created date for {item.remote_id}: {e}")

        if data.get("modified"):
            dataset.extras["modified_at"] = data.get("modified")
            try:
                dataset.last_modified_internal = to_date(data["modified"])
            except (ValueError, TypeError) as e:
                log.warning(f"Failed to parse modified date for {item.remote_id}: {e}")

        # Populate other extras
        dataset.extras["dct_identifier"] = data.get("id")
        dataset.extras["uri"] = data.get("id")

        # Try to find a remote_url
        for res_data in data.get("resources", []):
            protocol = res_data.get("protocol", "").lower()
            if "html" in protocol or "link" in protocol:
                dataset.extras["remote_url"] = res_data.get("url")
                break

        # Process spatial coverage
        self._process_spatial(dataset, data)

        # Force recreation of all resources
        dataset.resources = []

        for res_data in data.get("resources", []):
            url = res_data.get("url")
            if not url:
                continue

            # Determine resource format/type
            # CSW URIs use 'protocol' field for MIME types or service types
            protocol = res_data.get("protocol", "")
            name = res_data.get("name", "")

            # Check for WMS/WFS services
            if protocol and ("wms" in protocol.lower() or "wfs" in protocol.lower()):
                res_type = protocol.split(":")[-1].lower() if ":" in protocol else "wms"
            elif data.get("type") == "liveData":
                res_type = "wms"
            # Try to extract format from protocol (e.g., 'image/jpeg' -> 'jpeg')
            elif protocol and "/" in protocol:
                res_type = protocol.split("/")[-1].lower()
            else:
                # Fallback to URL extension
                res_type = url.split(".")[-1].lower() if "." in url else "remote"
                if len(res_type) > 5:
                    # Extension too long or invalid
                    res_type = "remote"

            # Use resource name if available, otherwise use dataset title
            resource_title = name if name else dataset.title

            # Create and append the resource
            new_resource = Resource(
                title=resource_title, url=url, filetype="remote", format=res_type
            )
            dataset.resources.append(new_resource)

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
