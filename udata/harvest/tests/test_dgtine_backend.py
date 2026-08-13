"""Resource identity across DGT/INE harvests (LEDG-2251)."""

import pytest

from udata.tests.api import PytestOnlyDBTestCase

from ..backends.dgtIne import DGTINEBackend
from .factories import HarvestSourceFactory
from .id_stability import harvest, resource_ids, resource_urls

DGTINE_URL = "https://geo.ine.pt/catalog"
REMOTE_ID = "indicador-0001"
BDD_URL = "https://www.ine.pt/xurl/indx/0001/PT"
DATASET_URL = "https://www.ine.pt/js/0001.json"
METAINFO_URL = "https://www.ine.pt/js/0001_metainfo.json"


def _payload(urls, title="Indicador municipal"):
    return {
        "remote_id": REMOTE_ID,
        "title": title,
        "description": "Descrição do indicador",
        "theme": "População",
        "sub_theme": "Demografia",
        "geo_lastlevel": "Município",
        "source": "INE",
        "periodicity": "Anual",
        "date_published": "2024-01-01",
        "last_update": "2026-01-01",
        "last_period_available": "2025",
        "activity_type": "Estatística",
        "differenceInDays": "10",
        "meta_url": "https://www.ine.pt/meta/0001",
        "tags": ["Estatistica municipal"],
        "resources": urls,
    }


@pytest.mark.options(HARVESTER_BACKENDS=["dgtIne"])
class DgtIneResourceIdentityTest(PytestOnlyDBTestCase):
    def _source(self):
        return HarvestSourceFactory(backend="dgtIne", url=DGTINE_URL)

    def test_reharvest_keeps_the_resource_ids(self):
        source = self._source()
        urls = [BDD_URL, DATASET_URL, METAINFO_URL]
        harvest(DGTINEBackend, source, REMOTE_ID, items=_payload(urls))
        before = resource_ids(REMOTE_ID)
        assert len(before) == 3

        harvest(DGTINEBackend, source, REMOTE_ID, items=_payload(urls))

        assert resource_ids(REMOTE_ID) == before

    def test_empty_slots_are_skipped_and_removals_applied(self):
        source = self._source()
        harvest(DGTINEBackend, source, REMOTE_ID, items=_payload([BDD_URL, DATASET_URL]))
        bdd_id = resource_ids(REMOTE_ID)[0]

        harvest(DGTINEBackend, source, REMOTE_ID, items=_payload([BDD_URL, None]))

        assert resource_urls(REMOTE_ID) == [BDD_URL]
        assert resource_ids(REMOTE_ID) == [bdd_id]
