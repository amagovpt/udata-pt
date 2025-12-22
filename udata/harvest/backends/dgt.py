from udata.harvest.backends.base import BaseBackend
from udata.models import Resource, Dataset, License
import requests
# from urllib.parse import urlparse
import urllib.parse as urlparse
from datetime import datetime

from udata.harvest.models import HarvestItem
from .tools.harvester_utils import normalize_url_slashes

# backend = 'https://snig.dgterritorio.gov.pt/rndg/srv/por/q?_content_type=json&fast=index&from=1&resultType=details&sortBy=referenceDateOrd&type=dataset%2Bor%2Bseries&dataPolicy=Dados%20abertos&keyword=DGT'


class DGTBackend(BaseBackend):
    display_name = 'Harvester DGT'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        import logging
        self.logger = logging.getLogger(__name__)

    def inner_harvest(self):

        headers = {
            'content-type': 'application/json',
            'Accept-Charset': 'utf-8'
        }
        res = requests.get(self.source.url, headers=headers)
        
        res.encoding = 'utf-8'
        data = res.json()
        metadata = data.get("metadata")

        # Garante que metadata é sempre uma lista de dicts
        if isinstance(metadata, dict):
            metadata = [metadata]
        elif isinstance(metadata, str) and data.get("@to") == "1":
            # Se for string e @to == "1", não é possível processar como dict, então ignora ou loga erro
            msg = ('Error: metadata é uma string, não um dict: %r', metadata)
            self.logger.error(msg)
            raise Exception(msg)

        elif isinstance(metadata, str) and data.get("@to") == "0":
            msg = 'Erro: Metadados vazios. Nenhum dataset disponível.'
            self.logger.error(msg)
            raise Exception(msg)

        elif not isinstance(metadata, list):
            metadata = []

        if not metadata:
            msg = 'Erro: Metadados vazios. Nenhum dataset disponível.'
            self.logger.error(msg)
            raise Exception(msg)

        # Loop through the metadata and process each item
        for each in metadata:
            item = {
                "remote_id": each.get("geonet:info", {}).get("uuid"),
                "title": each.get("defaultTitle"),
                "description": each.get("defaultAbstract"),
                "resources": each.get("link"),
                "keywords": each.get("keyword")
            }
            # if each.get("publicationDate"):
            #    item["date"] = datetime.strptime(each.get("publicationDate"),
            #                                     "%Y-%m-%d")

            links = []
            resources = item.get("resources")

            # Checks if resources is a list or string and processes accordingly
            if isinstance(resources, list):
                for url in resources:
                    url_parts = url.split('|')
                    inner_link = {}
                    inner_link['url'] = url_parts[2]
                    inner_link['type'] = url_parts[3]
                    inner_link['format'] = url_parts[4]
                    links.append(inner_link)

            elif isinstance(resources, str):
                url_parts = resources.split('|')
                inner_link = {}
                inner_link['url'] = url_parts[2]
                inner_link['type'] = url_parts[3]
                inner_link['format'] = url_parts[4]
                links.append(inner_link)

            item['resources'] = links

            # self.add_item(item["remote_id"], item=item)
            self.process_dataset(item["remote_id"], items=item)

    
    def inner_process_dataset(self, item: HarvestItem, **kwargs):
        """Process harvested data into a dataset"""
        dataset = self.get_dataset(item.remote_id)
        # Here you comes your implementation. You should :
        # - fetch the remote dataset (if necessary)
        # - validate the fetched payload
        # - map its content to the dataset fields
        # - store extra significant data in the `extra` attribute
        # - map resources data
        item = kwargs.get('items')

        # Set basic dataset fields
        dataset.title = item['title']
        dataset.license = License.guess('cc-by')
        dataset.tags = ["snig.dgterritorio.gov.pt"]
        dataset.description = item['description']

        if item.get('date'):
            dataset.created_at = item['date']

        # Add keywords as tags
        for keyword in item.get('keywords'):
            dataset.tags.append(keyword)

        # Recreate all resources
        # Force recreation of all resources
        dataset.resources = []

        for resource in item.get("resources"):

            parsed = urlparse.urlparse(resource['url'])
            try:
                format = str(urlparse.parse_qs(parsed.query)['service'][0])
            except KeyError:
                format = resource['url'].split('.')[-1]

            new_resource = Resource(title=item['title'],
                                    url=normalize_url_slashes(resource['url']),
                                    filetype='remote',
                                    format=format)
            
            
            dataset.resources.append(new_resource)

        # Add extra metadata
        dataset.extras['harvest:name'] = self.source.name

        return dataset
