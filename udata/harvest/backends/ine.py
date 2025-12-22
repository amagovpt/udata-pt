from udata.models import db, Resource, License

from udata.harvest.backends.base import BaseBackend

from datetime import datetime
from xml.dom import minidom, Node
import requests
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
import re

from udata.harvest.models import HarvestItem
from .tools.harvester_utils import normalize_url_slashes

class INEBackend(BaseBackend):
    display_name = 'Instituto nacional de estatística'

    def inner_harvest(self):
        try:
            from ineDatasets import datasetIds
        except :
            datasetIds = set([])

        req = requests.get(self.source.url)
        doc = minidom.parseString(req.content)

        properties = doc.getElementsByTagName('indicator')

        for propNode in properties:
            currentId = propNode.attributes['id'].value
            datasetIds.add(currentId)

        for dsId in datasetIds:
            #self.add_item(dsId)
            self.process_dataset(dsId)

    def inner_process_dataset(self, item: HarvestItem):
        '''Return the INE datasets'''

        dataset = self.get_dataset(item.remote_id)

        # get remote data for dataset
        # The harvester can be configured with different backend URLs (e.g.
        # https://www.ine.pt/ine/xml_indic.jsp?opc=2 or
        # https://www.ine.pt/ine/xml_indic_hvd.jsp?opc=3). Prefer the full URL
        # if provided in source.url. Otherwise fall back to the default xml_indic.jsp
        # and allow overriding opc via source.options (if set in the Backend config).
        base_url = self.source.url 

        parsed = urlparse(base_url)
        qs = parse_qs(parsed.query)

        # ensure language is set (default PT)
        if 'lang' not in qs or not qs['lang']:
            qs['lang'] = ['PT']

        # add varcd (dataset id) param used by INE endpoints
        qs['varcd'] = [str(item.remote_id)]

        # build final URL preserving hostname/path if present in source.url
        new_query = urlencode({k: v[0] for k, v in qs.items()})
        final_url = urlunparse(parsed._replace(query=new_query))

        req = requests.get(final_url, headers={'charset': 'utf8'})

        returnedData = req.content
        print('Get metadata for %s' % (item.remote_id))

        keywordSet = set()
        dataset.license = License.guess('cc-by')
        dataset.resources = []
        doc = minidom.parseString(returnedData)
        properties = doc.getElementsByTagName('indicator')
        # procurar o indicator que corresponde ao item.remote_id
        target = None
        for propNode in properties:
            if propNode.hasAttribute('id') and str(propNode.getAttribute('id')) == str(item.remote_id):
                target = propNode
                break
        if not target:
            # fallback: use first indicator
            target = properties[0] if properties else None

        keywordSet = set()
        if target:
            # 1) extrair keywords a partir do nó <keywords>
            for kn in target.getElementsByTagName('keywords'):
                # juntar todos os nós de texto dentro de <keywords>
                text = ''.join([n.nodeValue or '' for n in kn.childNodes if n.nodeType in (n.TEXT_NODE, n.CDATA_SECTION_NODE)])
                if text:
                    # split por vírgula, ponto-e-vírgula, barra, ou outros separadores comuns
                    parts = re.split(r'[;,/]|\\s+\\-\\s+|\\s+\\|\\s+', text)
                    for p in parts:
                        p = p.strip().strip(',')  # remove espaços e vírgula sobrante
                        if p:
                            keywordSet.add(p.lower())

            # 2) opcional: adicionar theme e subtheme como tags
            for tagname in ('theme', 'subtheme'):
                for tn in target.getElementsByTagName(tagname):
                    if tn.firstChild and tn.firstChild.nodeValue:
                        val = tn.firstChild.nodeValue.strip()
                        if val:
                            keywordSet.add(val.lower())

        # definir tags no dataset
        dataset.tags = sorted(keywordSet)
        if 'ine.pt' not in dataset.tags:
            dataset.tags.append('ine.pt')
        dataset.frequency = 'unknown'

        return dataset
