"""Resource identity across INE HVD harvests (LEDG-2251)."""

import pytest

from udata.tests.api import PytestOnlyDBTestCase

from ..backends.inehvd import INEHvdBackend
from .factories import HarvestSourceFactory
from .id_stability import harvest, harvested_dataset, resource_ids, resource_urls

INEHVD_URL = "https://www.ine.pt/ine/xml_indic_hvd.jsp?opc=3&lang=PT"
REMOTE_ID = "0001"
DATASET_URL = "https://www.ine.pt/js/0001.json"
METAINFO_URL = "https://www.ine.pt/js/0001_metainfo.json"


def _indicator_xml(urls, title="Indicador HVD"):
    slots = "".join(
        f"<{tag}><![CDATA[{url}]]></{tag}>" for tag, url in urls.items() if url is not None
    )
    return (
        "<?xml version='1.0' encoding='UTF-8'?>"
        "<indicators>"
        f"<indicator id='{REMOTE_ID}'>"
        f"<title><![CDATA[{title}]]></title>"
        "<description><![CDATA[Descricao do indicador]]></description>"
        "<keywords>INE,estatistica</keywords>"
        "<periodicity><![CDATA[Anual]]></periodicity>"
        f"<json>{slots}</json>"
        "</indicator>"
        "</indicators>"
    )


@pytest.mark.options(HARVESTER_BACKENDS=["inehvd"])
class INEHvdResourceIdentityTest(PytestOnlyDBTestCase):
    def _harvest(self, rmock, source, urls, title="Indicador HVD"):
        # The backend appends `varcd`/`lang` to the source URL; requests-mock
        # matches on the path, so one registration covers both requests.
        rmock.get("https://www.ine.pt/ine/xml_indic_hvd.jsp", text=_indicator_xml(urls, title))
        return harvest(INEHvdBackend, source, REMOTE_ID)

    def test_reharvest_keeps_the_resource_ids(self, rmock):
        source = HarvestSourceFactory(backend="inehvd", url=INEHVD_URL)
        urls = {"json_dataset": DATASET_URL, "json_metainfo": METAINFO_URL}
        self._harvest(rmock, source, urls)
        before = resource_ids(REMOTE_ID)
        assert len(before) == 2

        self._harvest(rmock, source, urls)

        assert resource_ids(REMOTE_ID) == before

    def test_title_change_upstream_keeps_the_resource_ids(self, rmock):
        source = HarvestSourceFactory(backend="inehvd", url=INEHVD_URL)
        urls = {"json_dataset": DATASET_URL, "json_metainfo": METAINFO_URL}
        self._harvest(rmock, source, urls)
        before = resource_ids(REMOTE_ID)

        self._harvest(rmock, source, urls, title="Indicador HVD revisto")

        assert harvested_dataset(REMOTE_ID).title == "Indicador HVD revisto"
        assert resource_ids(REMOTE_ID) == before

    def test_resource_dropped_upstream_disappears(self, rmock):
        source = HarvestSourceFactory(backend="inehvd", url=INEHVD_URL)
        self._harvest(rmock, source, {"json_dataset": DATASET_URL, "json_metainfo": METAINFO_URL})
        dataset_resource_id = resource_ids(REMOTE_ID)[0]

        self._harvest(rmock, source, {"json_dataset": DATASET_URL, "json_metainfo": None})

        assert resource_urls(REMOTE_ID) == [DATASET_URL]
        assert resource_ids(REMOTE_ID) == [dataset_resource_id]
