"""
Harvester for the Portuguese Environment Portal (Portal do Ambiente).

This module defines a custom udata harvester backend for collecting datasets from a CSW (Catalogue Service for the Web)
endpoint provided by the Portuguese Environment Portal. It fetches metadata records, normalizes resource URLs,
and maps them to udata datasets and resources.

Classes:
    PortalAmbienteBackend: Custom udata harvester backend for the Environment Portal.

Functions:
    normalize_url_slashes(url: str) -> str: Utility to normalize slashes in URLs (imported).

Usage:
    This backend is intended to be used as a plugin in a udata instance. It will fetch datasets from the configured
    CSW endpoint, process their metadata, and create or update corresponding datasets and resources in udata.
"""

from datetime import datetime
import requests
from urllib.parse import urlparse, urlencode

from udata.harvest.backends.base import BaseBackend
from udata.models import Resource, License
from owslib.csw import CatalogueServiceWeb

from udata.harvest.models import HarvestItem

from .tools.harvester_utils import normalize_url_slashes

# backend = 'https://sniambgeoportal.apambiente.pt/geoportal/csw'


class PortalAmbienteBackend(BaseBackend):
    """
    Harvester backend for the Portuguese Environment Portal (Portal do Ambiente).

    This backend connects to a CSW endpoint, fetches dataset records, normalizes resource URLs,
    and maps them to udata datasets and resources.
    """

    name = "apambiente"
    display_name = 'Harvester Portal do Ambiente'

    def inner_harvest(self):
        """
        Main harvesting loop.

        Connects to the CSW endpoint, fetches records in batches, normalizes resource URLs,
        and processes each record into a udata dataset.

        Yields:
            None. Calls self.process_dataset for each harvested record.
        """
        startposition = 0
        csw = CatalogueServiceWeb(self.source.url)
        csw.getrecords2(maxrecords=1)
        matches = csw.results.get("matches")

        while startposition <= matches:
            csw.getrecords2(maxrecords=100, startposition=startposition)
            startposition = csw.results.get('nextrecord')
            for rec in csw.records:
                item = {}
                record = csw.records[rec]
                item["id"] = record.identifier
                item["title"] = record.title
                item["description"] = record.abstract
                # Normalize URL slashes to ensure compatibility
                item["url"] = normalize_url_slashes(record.references[0].get('url'))
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
        item = kwargs.get('items')

        # Set basic dataset fields
        dataset.title = item['title']
        dataset.license = License.guess('cc-by')
        dataset.tags = ["apambiente.pt"]
        dataset.description = item['description']

        if item.get('date'):
            dataset.created_at = item['date']

        dataset.description = item.get('description')

        # Force recreation of all resources
        dataset.resources = []

        url = item.get('url')

        # Determine resource format/type
        if item.get('type') == "liveData":
            type = "wms"
        else:
            type = url.split('.')[-1].lower()
            if len(type) > 3:
                type = "wms"

        # Create and append the resource
        new_resource = Resource(
            title=dataset.title,
            url=url,
            filetype='remote',
            format=type
        )
        dataset.resources.append(new_resource)

        return dataset
