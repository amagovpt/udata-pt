"""
Harvester for the Portuguese Environment Portal (Portal do Ambiente).

This module defines a custom udata harvester backend for collecting datasets from a CSW (Catalogue Service for the Web)
endpoint provided by the Portuguese Environment Portal. It fetches metadata records, normalizes resource URLs,
and maps them to udata datasets and resources.

Classes:
    PortalAmbienteBackend: Custom udata harvester backend for the Environment Portal.

Functions:
    build_resource_url(raw_url: str) -> str: Turn a `dct:references` link into a resource URL.

Usage:
    This backend is intended to be used as a plugin in a udata instance. It will fetch datasets from the configured
    CSW endpoint, process their metadata, and create or update corresponding datasets and resources in udata.
"""

from owslib.csw import CatalogueServiceWeb

from udata.harvest.backends.base import BaseBackend
from udata.harvest.models import HarvestItem
from udata.models import License, Resource

from .tools.harvester_utils import (
    collapse_duplicated_path,
    guess_url_format,
    normalize_url_slashes,
    with_http_retry,
)

# backend = 'https://sniambgeoportal.apambiente.pt/geoportal/csw'


def build_resource_url(raw_url: str) -> str:
    """Turn a raw `dct:references` link into the URL published on the resource.

    The catalogue hands out Windows-style separators and, on at least one
    record, a path concatenated with itself — that doubled link 404s while the
    single one downloads (LEDG-2250). Both defects are repaired here so the
    resource URL matches what the origin actually serves.
    """
    return collapse_duplicated_path(normalize_url_slashes(raw_url))


class PortalAmbienteBackend(BaseBackend):
    """
    Harvester backend for the Portuguese Environment Portal (Portal do Ambiente).

    This backend connects to a CSW endpoint, fetches dataset records, normalizes resource URLs,
    and maps them to udata datasets and resources.
    """

    name = "apambiente"
    display_name = "Harvester Portal do Ambiente"

    def inner_harvest(self):
        """
        Main harvesting loop.

        Connects to the CSW endpoint, fetches records in batches, normalizes resource URLs,
        and processes each record into a udata dataset.

        Yields:
            None. Calls self.process_dataset for each harvested record.
        """
        startposition = 0
        # owslib issues its own HTTP requests, bypassing BaseBackend.get:
        # re-check the URL against the SSRF guard first (LEDG-1729 / VULN-2084).
        self._guard_url(self.source.url)
        # Generous timeout: government servers can be slow.
        # The constructor performs a GetCapabilities request, so retry it too.
        csw = with_http_retry(self, CatalogueServiceWeb, self.source.url, timeout=60)
        with_http_retry(self, csw.getrecords2, maxrecords=1)
        matches = csw.results.get("matches")

        while startposition <= matches:
            with_http_retry(self, csw.getrecords2, maxrecords=100, startposition=startposition)
            startposition = csw.results.get("nextrecord")
            for rec in csw.records:
                item = {}
                record = csw.records[rec]
                item["id"] = record.identifier
                item["title"] = record.title
                item["description"] = record.abstract
                # Repair the separators and self-concatenated paths the catalogue emits
                item["url"] = build_resource_url(record.references[0].get("url"))
                item["type"] = record.type
                # Process the dataset (create or update in udata)
                self.process_dataset(record.identifier, title=record.title, date=None, items=item)

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
        """
        Here you comes your implementation. You should :
        - fetch the remote dataset (if necessary)
        - validate the fetched payload
        - map its content to the dataset fields
        - store extra significant data in the `extra` attribute
        - map resources data
        """
        item = kwargs.get("items")

        # Set basic dataset fields
        dataset.title = item["title"]
        dataset.license = License.guess("cc-by")
        dataset.tags = ["apambiente.pt"]
        dataset.description = item["description"]

        if item.get("date"):
            dataset.created_at = item["date"]

        dataset.description = item.get("description")

        # Force recreation of all resources
        dataset.resources = []

        url = item.get("url")

        # Determine resource format/type. `liveData` records describe a map
        # service; everything else is a file, so the format comes from the URL
        # itself instead of being guessed from its length.
        if item.get("type") == "liveData":
            resource_format = "wms"
        else:
            resource_format = guess_url_format(url)

        # Create and append the resource
        new_resource = Resource(
            title=dataset.title, url=url, filetype="remote", format=resource_format
        )
        dataset.resources.append(new_resource)

        return dataset
