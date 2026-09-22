"""Resource identity for the APAmbiente CSW harvester (LEDG-2251).

The URL and format helpers this backend uses are generic and tested in
`test_harvester_utils.py`.
"""

import pytest

from udata.tests.api import PytestOnlyDBTestCase

from ..backends.apambiente import PortalAmbienteBackend
from .factories import HarvestSourceFactory
from .id_stability import harvest, harvested_dataset, resource_ids, resource_urls

GEODOCS = "https://sniambgeoviewer.apambiente.pt/GeoDocs/geoportaldocs"

EXPECTED_URL = f"{GEODOCS}/_Clima/PortalAcaoClimatica_Emissoes2030/meta_2030_0.xlsx"


CSW_URL = "https://sniambgeoportal.apambiente.pt/geoportal/csw"
REMOTE_ID = "{DCFDE102-CAE9-415B-9D70-43EC25677DC7}"
WMS_SERVICE_URL = (
    "https://inspire.apambiente.pt/getogc/services/INSPIRE/PF_CELE/MapServer/WMSServer"
)


def _payload(url, title="Metas de redução de emissões", record_type="dataset"):
    return {
        "remote_id": REMOTE_ID,
        "title": title,
        "description": "Descrição do registo",
        "url": url,
        "type": record_type,
    }


@pytest.mark.options(HARVESTER_BACKENDS=["apambiente"])
class ApambienteResourceIdentityTest(PytestOnlyDBTestCase):
    """The single resource of each record must keep its id across harvests.

    It used to be dropped and rebuilt on every run, so its download permalink
    changed every night (LEDG-2251).
    """

    def _source(self):
        return HarvestSourceFactory(backend="apambiente", url=CSW_URL)

    def test_reharvest_keeps_the_resource_id(self):
        source = self._source()
        harvest(PortalAmbienteBackend, source, REMOTE_ID, items=_payload(EXPECTED_URL))
        before = resource_ids(REMOTE_ID)
        assert len(before) == 1

        harvest(PortalAmbienteBackend, source, REMOTE_ID, items=_payload(EXPECTED_URL))

        assert resource_ids(REMOTE_ID) == before

    def test_title_change_keeps_the_resource_id(self):
        source = self._source()
        harvest(PortalAmbienteBackend, source, REMOTE_ID, items=_payload(EXPECTED_URL))
        before = resource_ids(REMOTE_ID)

        harvest(
            PortalAmbienteBackend,
            source,
            REMOTE_ID,
            items=_payload(EXPECTED_URL, title="Metas revistas"),
        )

        assert resource_ids(REMOTE_ID) == before
        assert [r.title for r in harvested_dataset(REMOTE_ID).resources] == ["Metas revistas"]

    def test_url_change_upstream_replaces_the_resource(self):
        # A different URL is a different resource: its id cannot be preserved,
        # and the stale one must not linger.
        source = self._source()
        harvest(PortalAmbienteBackend, source, REMOTE_ID, items=_payload(EXPECTED_URL))

        harvest(
            PortalAmbienteBackend,
            source,
            REMOTE_ID,
            items=_payload(WMS_SERVICE_URL, record_type="liveData"),
        )

        assert resource_urls(REMOTE_ID) == [WMS_SERVICE_URL]
        assert [r.format for r in harvested_dataset(REMOTE_ID).resources] == ["wms"]
