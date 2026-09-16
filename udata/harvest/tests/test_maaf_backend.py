"""Resource identity across MAAF harvests (LEDG-2251)."""

import pytest

from udata.tests.api import PytestOnlyDBTestCase

from ..backends.maaf import MaafBackend
from ..models import HarvestJob
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


CREDENTIALED_MAAF_URL = "https://harvestuser:sup3rs3cr3t@example.pt/maaf/"
CREDENTIALED_DESCRIPTOR_URL = "https://harvestuser:sup3rs3cr3t@example.pt/maaf/dataset.xml"
REDACTED_DESCRIPTOR_URL = "https://***@example.pt/maaf/dataset.xml"
# `inner_harvest` skips the first link as the parent directory.
INDEX_HTML = (
    "<ul><li><a href='../'>Parent</a></li><li><a href='dataset.xml'>dataset.xml</a></li></ul>"
)


@pytest.mark.options(HARVESTER_BACKENDS=["maaf"])
class MaafCredentialedSourceTest(PytestOnlyDBTestCase):
    """The descriptor URL is the item's `remote_id`, and `remote_id` is public.

    `URLS_ALLOW_CREDENTIALS` is true, so a MAAF source may carry
    `user:password@`; `urljoin` then puts it on every descriptor URL. The first
    `save_job()` persists that as the `remote_id` before the metadata supplies
    the real one, so a failed item keeps it -- and `item_fields` /
    `error_item_fields` serialize `remote_id` on routes with no session
    (LEDG-2500).

    These run the real `inner_harvest`, unlike the resource identity tests
    above, because the line under test is the one that builds the `remote_id`.
    """

    def _source(self):
        return HarvestSourceFactory(backend="maaf", url=CREDENTIALED_MAAF_URL)

    def test_failed_item_remote_id_carries_no_credentials(self, rmock):
        rmock.get(CREDENTIALED_MAAF_URL, text=INDEX_HTML)
        rmock.get(CREDENTIALED_DESCRIPTOR_URL, status_code=500)

        job = MaafBackend(self._source()).harvest()

        assert [item.status for item in job.items] == ["failed"]
        assert job.items[0].remote_id == REDACTED_DESCRIPTOR_URL
        assert "sup3rs3cr3t" not in job.items[0].remote_id
        # What the first `save_job()` wrote is what an anonymous caller reads,
        # so assert on the reloaded document and not just the in-memory item.
        stored = HarvestJob.objects.get(id=job.id)
        assert stored.items[0].remote_id == REDACTED_DESCRIPTOR_URL

    def test_fetch_still_uses_the_credentialed_url(self, rmock, monkeypatch):
        rmock.get(CREDENTIALED_MAAF_URL, text=INDEX_HTML)
        rmock.get(CREDENTIALED_DESCRIPTOR_URL, text="<not-parsed/>")
        monkeypatch.setattr(MaafBackend, "parse_xml", lambda self, xml: {"metadata": _metadata([])})

        job = MaafBackend(self._source()).harvest()

        assert [item.status for item in job.items] == ["done"], [
            error.message for item in job.items for error in item.errors
        ]
        # Redacting what is published must not cost the fetch its credentials.
        assert job.items[0].remote_id == REMOTE_ID
        assert any("harvestuser" in request.url for request in rmock.request_history)
