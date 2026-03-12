from udata.harvest.backends.base import BaseBackend
from udata.models import Resource, Dataset, License
import logging
import json
import subprocess
import os
import unicodedata
import re

from .tools.harvester_utils import normalize_url_slashes
class DGTINEBackend(BaseBackend):
    display_name = 'INE Harvester'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.logger = logging.getLogger(__name__)

    def inner_harvest(self):
        # Caminho do ficheiro JSON baixado
        json_path = '/tmp/catalogo_hvd.json'

        # Faz o download do JSON via curl
        curl_cmd = [
            "curl", "-s", "https://www.ine.pt/ine/catalogo_hvd.jsp?opc=4&lang=PT",
            "-H", "Accept: application/json",
            "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "-H", "Accept-Encoding: gzip, deflate, br",
            "--compressed",
            "-o", json_path
        ]
        subprocess.run(curl_cmd, check=True)

        # Lê o conteúdo do ficheiro JSON baixado
        if not os.path.exists(json_path):
            self.logger.error(f'JSON file not found: {json_path}')
            return

        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            self.logger.error(f'Error parsing JSON from file: {e}')
            return

        indicators = data.get('catalog', {}).get('indicators', [])
        if not indicators:
            self.logger.error('No indicators found in INE JSON.')
            # Remove o ficheiro mesmo em caso de erro
            if os.path.exists(json_path):
                os.remove(json_path)
            return

        for ind in indicators:
            item = {
                'remote_id': ind.get('indicator_id'),
                'title': ind.get('title'),
                'description': ind.get('description'),
                'theme': ind.get('theme'),
                'sub_theme': ind.get('sub_theme'),
                'tags': ind.get('tags', []),
                'geo_lastlevel': ind.get('geo_lastlevel'),
                'date_published': ind.get('date_published'),
                'last_update': ind.get('last_update'),
                'periodicity': ind.get('periodicity'),
                'source': ind.get('source'),
                'resources': [
                    ind.get('bdd_url'),
                    ind.get('json_dataset'),
                    ind.get('json_metainfo')
                ],
                'meta_url': ind.get('meta_url'),
                'last_period_available': ind.get('last_period_available'),
                'activity_type': ind.get('activity_type'),
                'differenceInDays': ind.get('differenceInDays')
            }
            self.process_dataset(item['remote_id'], items=item)

        # Remove o ficheiro JSON após o processamento
        if os.path.exists(json_path):
            os.remove(json_path)

    @staticmethod
    def slugify(value):
        """
        Normaliza uma string para uso como tag (slug):
        - remove acentos e cedilhas
        - substitui espaços por hífens
        - converte para minúsculas
        - remove caracteres especiais
        """
        value = str(value)
        value = unicodedata.normalize('NFKD', value).encode('ascii', 'ignore').decode('ascii')
        value = re.sub(r'[^\w\s-]', '', value).strip().lower()
        return re.sub(r'[\s]+', '-', value)

    def inner_process_dataset(self, item: 'HarvestItem', **kwargs):
        dataset = self.get_dataset(item.remote_id)
        data = kwargs.get('items')

        dataset.title = data['title']
        dataset.description = (
            f"{data['description']}\n\n"
            f"Theme: {data['theme']} | Subtheme: {data['sub_theme']}\n"
            f"Geo: {data.get('geo_lastlevel', '')}\n"
            f"Source: {data['source']}\n"
            f"Periodicity: {data['periodicity']}\n"
            f"Published on: {data['date_published']} | Updated on: {data['last_update']}\n"
            f"Last period available: {data.get('last_period_available', '')}\n"
            f"Activity type: {data.get('activity_type', '')}\n"
            f"Days since last update: {data.get('differenceInDays', '')}\n"
            f"Metadata: {data['meta_url']}"
        )
        dataset.license = License.guess('cc-by')

        # Corrigir TAGS
        original_tags = data.get('tags', [])
        slug_tags = [self.slugify(tag) for tag in original_tags if isinstance(tag, str)]

        dataset.tags = ['ine.pt'] + slug_tags
        dataset.extras['original_tags'] = original_tags

        # Resources
        dataset.resources = []
        for url in data.get('resources', []):
            if url:
                dataset.resources.append(Resource(
                    title=data['title'],
                    url=normalize_url_slashes(url),
                    filetype='remote',
                    format=url.split('.')[-1] if '.' in url else 'file'
                ))
        dataset.extras['harvest:name'] = self.source.name
        return dataset
