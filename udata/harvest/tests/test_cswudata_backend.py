"""Resource identity across generic CSW harvests (LEDG-2251)."""

import pytest

from udata.tests.api import PytestOnlyDBTestCase

from ..backends.cswudata import CSWUdataBackend
from .factories import HarvestSourceFactory
from .id_stability import harvest, harvested_dataset, resource_ids, resource_urls

CSW_URL = "https://geoportal.example.pt/geoportal/csw"
REMOTE_ID = "{ABCDEF01-0000-4000-8000-000000000001}"
WMS_URL = "https://geoportal.example.pt/services/INSPIRE/MapServer/WMSServer"
FILE_URL = "https://geoportal.example.pt/docs/relatorio.pdf"


def _payload(resources, title="Registo CSW"):
    return {
        "id": REMOTE_ID,
        "title": title,
        "description": "Descrição do registo",
        "tags": ["ambiente"],
        "type": "dataset",
        "resources": resources,
    }


def _wms(name="Serviço WMS"):
    return {"url": WMS_URL, "protocol": "OGC:WMS", "name": name}


def _file(name="Relatório"):
    return {"url": FILE_URL, "protocol": "WWW:DOWNLOAD-1.0-http--download", "name": name}


@pytest.mark.options(HARVESTER_BACKENDS=["cswudata"])
class CswUdataResourceIdentityTest(PytestOnlyDBTestCase):
    def _source(self):
        return HarvestSourceFactory(backend="cswudata", url=CSW_URL)

    def test_reharvest_keeps_the_resource_ids(self):
        source = self._source()
        harvest(CSWUdataBackend, source, REMOTE_ID, items=_payload([_wms(), _file()]))
        before = resource_ids(REMOTE_ID)
        assert len(before) == 2

        harvest(CSWUdataBackend, source, REMOTE_ID, items=_payload([_wms(), _file()]))

        assert resource_ids(REMOTE_ID) == before

    def test_renamed_resource_keeps_its_id(self):
        source = self._source()
        harvest(CSWUdataBackend, source, REMOTE_ID, items=_payload([_wms()]))
        before = resource_ids(REMOTE_ID)

        harvest(CSWUdataBackend, source, REMOTE_ID, items=_payload([_wms("Outro nome")]))

        assert resource_ids(REMOTE_ID) == before
        assert [r.title for r in harvested_dataset(REMOTE_ID).resources] == ["Outro nome"]

    def test_resource_dropped_upstream_disappears(self):
        source = self._source()
        harvest(CSWUdataBackend, source, REMOTE_ID, items=_payload([_wms(), _file()]))
        wms_id = resource_ids(REMOTE_ID)[0]

        harvest(CSWUdataBackend, source, REMOTE_ID, items=_payload([_wms()]))

        assert resource_urls(REMOTE_ID) == [WMS_URL]
        assert resource_ids(REMOTE_ID) == [wms_id]


@pytest.mark.options(HARVESTER_BACKENDS=["cswudata"])
class CswUdataDefaultTagTest(PytestOnlyDBTestCase):
    """Every dataset carries a tag naming its producer, plus the record's own.

    The producer tag used to be read from a `default_tag` key on the source
    config, which the source form has no way of writing -- only declared extra
    configs are stored -- so it was unreachable and every source fell back to
    the literal "csw" (LEDG-2492).
    """

    def _source(self, default_tag=None):
        config = {"extra_configs": [{"key": "default_tag", "value": default_tag}]}
        return HarvestSourceFactory(
            backend="cswudata", url=CSW_URL, config=config if default_tag else {}
        )

    def test_configured_default_tag_is_written(self):
        source = self._source(default_tag="apambiente.pt")

        harvest(CSWUdataBackend, source, REMOTE_ID, items=_payload([_file()]))

        # Stored slugified, as every tag is: the dotted form is what a human
        # types into the source form.
        assert "apambiente-pt" in harvested_dataset(REMOTE_ID).tags

    def test_hostname_is_the_fallback_tag(self):
        source = self._source()

        harvest(CSWUdataBackend, source, REMOTE_ID, items=_payload([_file()]))

        assert "geoportal-example-pt" in harvested_dataset(REMOTE_ID).tags

    def test_subjects_become_tags(self):
        source = self._source(default_tag="apambiente.pt")

        harvest(CSWUdataBackend, source, REMOTE_ID, items=_payload([_file()]))

        # `_payload` carries the record's own subjects; they join the producer tag
        # instead of replacing it.
        assert set(harvested_dataset(REMOTE_ID).tags) == {"apambiente-pt", "ambiente"}
