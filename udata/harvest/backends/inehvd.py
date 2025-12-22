from udata.models import Resource, License
from udata.harvest.backends.base import BaseBackend
from datetime import datetime
from xml.dom import minidom, Node
import requests
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
import re

from udata.harvest.models import HarvestItem
from .tools.harvester_utils import normalize_url_slashes

class INEHvdBackend(BaseBackend):
    '''
    Harvester for INE HVD (High Value Datasets).

    Mapping of fields:
    Source (XML)                                | Local (uData Dataset)
    ------------------------------------------- | ---------------------
    indicator['id']                             | dataset.remote_id
    title                                       | dataset.title
    description                                 | dataset.description
    keywords, theme, subtheme                   | dataset.tags
    periodicity                                 | dataset.frequency
    dates > last_period_available               | dataset.extras['last_period_available']
    dates > last_update                         | dataset.extras['last_update_remote']
    geo_lastlevel                               | dataset.extras['geo_lastlevel']
    source                                      | dataset.extras['source_description']
    html > bdd_url                              | dataset.extras['bdd_url']
    json > json_dataset                         | dataset.resources (JSON Dataset)
    json > json_metainfo                        | dataset.resources (Metainfo JSON)
    '''
    name = "inehvd"
    display_name = 'Instituto nacional de estatística (HVD)'

    def inner_harvest(self):
        '''
        Changes the status of the harvesting process.
        Fetches the main source XML, parses the available indicators (datasets),
        and initiates the processing for each identified dataset ID.
        '''
        try:
            from ineDatasets import datasetIds
        except ImportError:
            datasetIds = set([])

        # Fetch the catalog
        req = requests.get(self.source.url)
        # Handle potential encoding issues if needed, usually requests detects it
        if req.encoding is None:
            req.encoding = 'utf-8'

        doc = minidom.parseString(req.content)
        properties = doc.getElementsByTagName('indicator')

        for propNode in properties:
            if propNode.hasAttribute('id'):
                currentId = propNode.getAttribute('id')
                datasetIds.add(currentId)

        for dsId in datasetIds:
            self.process_dataset(dsId)

    def inner_process_dataset(self, item: HarvestItem):
        '''
        Processing a specific item (dataset) from the harvest.
        Fetches the detailed XML for the specific dataset ID, extracts metadata
        (title, description, tags, etc.), maps them to the uData Dataset object,
        and defines the associated resources (JSON data and metadata).
        '''
        dataset = self.get_dataset(item.remote_id)

        # Build final URL preserving hostname/path if present in source.url
        base_url = self.source.url
        parsed = urlparse(base_url)
        qs = parse_qs(parsed.query)

        # ensure language is set (default PT)
        if 'lang' not in qs or not qs['lang']:
            qs['lang'] = ['PT']

        # add varcd (dataset id) param used by INE endpoints
        qs['varcd'] = [str(item.remote_id)]

        new_query = urlencode({k: v[0] for k, v in qs.items()})
        final_url = urlunparse(parsed._replace(query=new_query))

        req = requests.get(final_url, headers={'charset': 'utf8'})
        
        # Parse content
        doc = minidom.parseString(req.content)
        properties = doc.getElementsByTagName('indicator')
        
        target = None
        for propNode in properties:
            if propNode.hasAttribute('id') and str(propNode.getAttribute('id')) == str(item.remote_id):
                target = propNode
                break
        
        if not target:
            # Fallback (though ideally we should find the exact ID)
            target = properties[0] if properties else None

        if not target:
            return dataset

        # --- Extract Fields ---

        # Helper to get text content from elements
        def get_text(node_list):
            if not node_list:
                return ''
            node = node_list[0]
            # Join text nodes and CData sections
            return ''.join([n.nodeValue or '' for n in node.childNodes if n.nodeType in (n.TEXT_NODE, n.CDATA_SECTION_NODE)]).strip()

        # Title
        dataset.title = get_text(target.getElementsByTagName('title'))

        # Description
        dataset.description = get_text(target.getElementsByTagName('description'))

        # License (Guessing cc-by as in ine.py)
        dataset.license = License.guess('cc-by')

        # Tags (Keywords + Theme + Subtheme)
        keywordSet = set()
        
        # Keywords
        kw_text = get_text(target.getElementsByTagName('keywords'))
        if kw_text:
            # Split by common separators
            parts = re.split(r'[;,/]|\\s+\\-\\s+|\\s+\\|\\s+', kw_text)
            for p in parts:
                p = p.strip().strip(',')
                if p:
                    keywordSet.add(p.lower())

        # Theme & Subtheme
        for tagname in ('theme', 'subtheme'):
            val = get_text(target.getElementsByTagName(tagname))
            if val:
                keywordSet.add(val.lower())

        dataset.tags = sorted(list(keywordSet))
        if 'ine.pt' not in dataset.tags:
            dataset.tags.append('ine.pt')

        # Frequency / Periodicity
        periodicity = get_text(target.getElementsByTagName('periodicity'))
        dataset.frequency = self.map_frequency(periodicity)

        # Extras
        dataset.extras['geo_lastlevel'] = get_text(target.getElementsByTagName('geo_lastlevel'))
        dataset.extras['source_description'] = get_text(target.getElementsByTagName('source'))
        
        dates_node = target.getElementsByTagName('dates')
        if dates_node:
            dataset.extras['last_period_available'] = get_text(dates_node[0].getElementsByTagName('last_period_available'))
            dataset.extras['last_update_remote'] = get_text(dates_node[0].getElementsByTagName('last_update'))

        html_node = target.getElementsByTagName('html')
        if html_node:
            dataset.extras['bdd_url'] = get_text(html_node[0].getElementsByTagName('bdd_url'))

        # Resources
        dataset.resources = []
        
        json_node = target.getElementsByTagName('json')
        if json_node:
            # JSON Dataset Resource
            json_ds_url = get_text(json_node[0].getElementsByTagName('json_dataset'))
            if json_ds_url:
                dataset.resources.append(Resource(
                    title='Dados (JSON)',
                    url=json_ds_url,
                    filetype='remote',
                    mime='application/json'
                ))
            
            # JSON Metainfo Resource
            json_meta_url = get_text(json_node[0].getElementsByTagName('json_metainfo'))
            if json_meta_url:
                dataset.resources.append(Resource(
                    title='Metainfo (JSON)',
                    url=json_meta_url,
                    filetype='remote',
                    mime='application/json'
                ))

        return dataset

    def map_frequency(self, text):
        '''
        Maps the Portuguese frequency text (e.g., 'Mensal', 'Anual') to the
        internal uData controlled vocabulary (e.g., 'monthly', 'annual').
        Returns 'unknown' if no match is found.
        '''
        if not text:
            return 'unknown'
        t = text.lower()
        if 'mensal' in t:
            return 'monthly'
        if 'anual' in t:
            return 'annual'
        if 'trimestral' in t:
            return 'quarterly'
        if 'semanal' in t:
            return 'weekly'
        if 'diário' in t or 'diario' in t:
            return 'daily'
        return 'unknown'
