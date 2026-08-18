"""Resource identity across MAAF harvests (LEDG-2251)."""

import pytest

from udata.tests.api import PytestOnlyDBTestCase

from ..backends.maaf import MaafBackend
from .factories import HarvestSourceFactory
from .id_stability import harvest, harvested_dataset, resource_ids, resource_urls

MAAF_URL = "https://example.pt/maaf/"
DESCRIPTOR_URL = "https://example.pt/maaf/dataset.xml"
REMOTE_ID = "maaf-0001"
CSV_URL = "https://example.pt/maaf/data.csv"
PDF_URL = "https://example.pt/maaf/notice.pdf"
CLE_URL = "https://example.pt/maaf/data.csv.sha256"


def _resource(url, name, resource_format):
    return {"name": name, "description": "Une ressource", "format": resource_format, "url": url}


def _metadata(resources, title="Jeu de données"):
    return {
        "id": REMOTE_ID,
        "title": title,
        "notes": "Description du jeu de données",
        "frequency": "annuelle",
        "private": False,
        "tags": ["agriculture"],
        "extras": [],
        "resources": resources,
    }


@pytest.mark.options(HARVESTER_BACKENDS=["maaf"])
class MaafResourceIdentityTest(PytestOnlyDBTestCase):
    def _harvest(self, rmock, monkeypatch, source, metadata):
        rmock.get(DESCRIPTOR_URL, text="<not-parsed/>")
        rmock.get(CLE_URL, text="0" * 64)
        # The XSD/voluptuous parsing is not what this test is about: the point is
        # the mapping from the validated metadata onto the resources.
        monkeypatch.setattr(MaafBackend, "parse_xml", lambda self, xml: {"metadata": metadata})
        return harvest(MaafBackend, source, DESCRIPTOR_URL)

    def test_reharvest_keeps_the_resource_ids(self, rmock, monkeypatch):
        source = HarvestSourceFactory(backend="maaf", url=MAAF_URL)
        resources = [_resource(CSV_URL, "Données", "csv"), _resource(PDF_URL, "Notice", "pdf")]
        self._harvest(rmock, monkeypatch, source, _metadata(resources))
        before = resource_ids(REMOTE_ID)
        assert len(before) == 2

        self._harvest(rmock, monkeypatch, source, _metadata(resources))

        assert resource_ids(REMOTE_ID) == before

    def test_checksum_resource_is_still_skipped(self, rmock, monkeypatch):
        source = HarvestSourceFactory(backend="maaf", url=MAAF_URL)
        resources = [
            _resource(CSV_URL, "Données", "csv"),
            _resource(CLE_URL, "Clé", "cle"),
        ]
        self._harvest(rmock, monkeypatch, source, _metadata(resources))

        assert resource_urls(REMOTE_ID) == [CSV_URL]
        assert harvested_dataset(REMOTE_ID).resources[0].checksum.value == "0" * 64

    def test_resource_dropped_upstream_disappears(self, rmock, monkeypatch):
        source = HarvestSourceFactory(backend="maaf", url=MAAF_URL)
        resources = [_resource(CSV_URL, "Données", "csv"), _resource(PDF_URL, "Notice", "pdf")]
        self._harvest(rmock, monkeypatch, source, _metadata(resources))
        csv_id = resource_ids(REMOTE_ID)[0]

        self._harvest(rmock, monkeypatch, source, _metadata(resources[:1]))

        assert resource_urls(REMOTE_ID) == [CSV_URL]
        assert resource_ids(REMOTE_ID) == [csv_id]
