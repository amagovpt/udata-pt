"""Resource identity across DGT harvests (LEDG-2251)."""

import pytest

from udata.tests.api import PytestOnlyDBTestCase

from ..backends.dgt import DGTBackend
from .factories import HarvestSourceFactory
from .id_stability import harvest, harvested_dataset, resource_ids, resource_urls

DGT_URL = "https://snig.dgterritorio.gov.pt/rndg/srv/por/q?_content_type=json"
REMOTE_ID = "8c3d4f1a-0000-4000-8000-000000000001"
WMS_URL = "https://snig.dgterritorio.gov.pt/geoserver/wms?service=WMS&request=GetCapabilities"
ZIP_URL = "https://snig.dgterritorio.gov.pt/downloads/cartografia.zip"


def _payload(urls, title="Carta administrativa"):
    return {
        "remote_id": REMOTE_ID,
        "title": title,
        "description": "Limites administrativos oficiais",
        "keywords": ["geo"],
        "resources": [{"url": url, "type": "WWW:LINK", "format": "zip"} for url in urls],
    }


@pytest.mark.options(HARVESTER_BACKENDS=["dgt"])
class DGTResourceIdentityTest(PytestOnlyDBTestCase):
    def _source(self):
        return HarvestSourceFactory(backend="dgt", url=DGT_URL)

    def test_reharvest_keeps_the_resource_ids(self):
        source = self._source()
        harvest(DGTBackend, source, REMOTE_ID, items=_payload([WMS_URL, ZIP_URL]))
        before = resource_ids(REMOTE_ID)
        assert len(before) == 2

        harvest(DGTBackend, source, REMOTE_ID, items=_payload([WMS_URL, ZIP_URL]))

        assert resource_ids(REMOTE_ID) == before

    def test_metadata_changes_do_not_cost_the_id(self):
        source = self._source()
        harvest(DGTBackend, source, REMOTE_ID, items=_payload([ZIP_URL]))
        before = resource_ids(REMOTE_ID)

        harvest(DGTBackend, source, REMOTE_ID, items=_payload([ZIP_URL], title="Novo título"))

        assert resource_ids(REMOTE_ID) == before
        # DGT names its resources after the dataset, so the refresh is visible.
        assert [r.title for r in harvested_dataset(REMOTE_ID).resources] == ["Novo título"]

    def test_resource_dropped_upstream_disappears(self):
        source = self._source()
        harvest(DGTBackend, source, REMOTE_ID, items=_payload([WMS_URL, ZIP_URL]))
        wms_id = resource_ids(REMOTE_ID)[0]

        harvest(DGTBackend, source, REMOTE_ID, items=_payload([WMS_URL]))

        assert resource_urls(REMOTE_ID) == [WMS_URL]
        assert resource_ids(REMOTE_ID) == [wms_id]
