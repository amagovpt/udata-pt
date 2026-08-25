from urllib.parse import parse_qs, urlparse

from udata.harvest.backends.base import BaseBackend
from udata.harvest.models import HarvestItem
from udata.models import License

from .tools.harvester_utils import sync_resources


class DGTBackend(BaseBackend):
    name = "dgt"
    # verify_ssl inherits True from BaseBackend: the configured sources
    # (snig.dgterritorio.gov.pt) present a valid certificate (checked 2026-07).
    display_name = "Harvester DGT"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        import logging

        self.logger = logging.getLogger(__name__)

    def inner_harvest(self):
        headers = {"content-type": "application/json", "Accept-Charset": "utf-8"}
        # Guarded fetch (SSRF check + retry/timeout) via BaseBackend
        res = self.get(self.source.url, headers=headers)

        res.encoding = "utf-8"
        data = res.json()
        metadata = data.get("metadata")

        # Garante que metadata é sempre uma lista de dicts
        if isinstance(metadata, dict):
            metadata = [metadata]
        elif isinstance(metadata, str) and data.get("@to") == "1":
            # Se for string e @to == "1", não é possível processar como dict, então ignora ou loga erro
            msg = ("Error: metadata é uma string, não um dict: %r", metadata)
            self.logger.error(msg)
            raise Exception(msg)

        elif isinstance(metadata, str) and data.get("@to") == "0":
            msg = "Erro: Metadados vazios. Nenhum dataset disponível."
            self.logger.error(msg)
            raise Exception(msg)

        elif not isinstance(metadata, list):
            metadata = []

        if not metadata:
            msg = "Erro: Metadados vazios. Nenhum dataset disponível."
            self.logger.error(msg)
            raise Exception(msg)

        # Loop through the metadata and process each item
        for each in metadata:
            item = {
                "remote_id": each.get("geonet:info", {}).get("uuid"),
                "title": each.get("defaultTitle"),
                "description": each.get("defaultAbstract"),
                "resources": each.get("link"),
                "keywords": each.get("keyword"),
            }
            # if each.get("publicationDate"):
            #    item["date"] = datetime.strptime(each.get("publicationDate"),
            #                                     "%Y-%m-%d")

            links = []
            resources = item.get("resources")

            # Checks if resources is a list or string and processes accordingly
            if isinstance(resources, list):
                for url in resources:
                    url_parts = url.split("|")
                    inner_link = {}
                    inner_link["url"] = url_parts[2]
                    inner_link["type"] = url_parts[3]
                    inner_link["format"] = url_parts[4]
                    links.append(inner_link)

            elif isinstance(resources, str):
                url_parts = resources.split("|")
                inner_link = {}
                inner_link["url"] = url_parts[2]
                inner_link["type"] = url_parts[3]
                inner_link["format"] = url_parts[4]
                links.append(inner_link)

            item["resources"] = links

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
        data = kwargs.get("items")

        # Set basic dataset fields
        dataset.title = data["title"]
        dataset.license = License.guess("cc-by")
        dataset.tags = ["snig.dgterritorio.gov.pt"]
        dataset.description = data["description"]

        if data.get("date"):
            dataset.created_at = data["date"]

        # Add keywords as tags
        if data.get("keywords"):
            for keyword in data.get("keywords"):
                dataset.tags.append(keyword)

        # Reconcile the resources with the payload, keeping the id — and hence
        # the download permalink — of the ones already known (LEDG-2251).
        resources = []

        for resource in data.get("resources"):
            parsed = urlparse(resource["url"])
            try:
                format = str(parse_qs(parsed.query)["service"][0])
            except KeyError:
                format = resource["url"].split(".")[-1]

            resources.append(
                {
                    "title": data["title"],
                    "url": resource["url"],
                    "filetype": "remote",
                    "format": format,
                }
            )

        sync_resources(dataset, resources)

        # Add extra metadata
        dataset.extras["harvest:name"] = self.source.name

        return dataset
