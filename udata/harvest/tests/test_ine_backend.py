import pytest

from udata.core.dataset.factories import DatasetFactory
from udata.core.dataset.models import HarvestDatasetMetadata
from udata.core.organization.factories import OrganizationFactory
from udata.models import Dataset
from udata.tests.api import PytestOnlyDBTestCase

from ..backends.ine import INEBackend, INEDownloadIncomplete
from .factories import HarvestSourceFactory

INE_URL = "https://www.ine.pt/ine/xml_indic.jsp?opc=2&lang=PT"
INE_HVD_URL = "https://www.ine.pt/ine/xml_indic_hvd.jsp?opc=3&lang=PT"

COMPLETE_XML = (
    "<?xml version='1.0' encoding='UTF-8'?>\n"
    "<catalog>\n"
    "<indicator id='0001'><title><![CDATA[Indicador A]]></title></indicator>\n"
    "</catalog>\n"
)

# Same payload but the connection dropped mid-stream: no closing </catalog>.
TRUNCATED_XML = (
    "<?xml version='1.0' encoding='UTF-8'?>\n"
    "<catalog>\n"
    "<indicator id='0001'><title><![CDATA[Indicador A]]></title></indicator>\n"
)


class INEIsCompleteXmlTest(PytestOnlyDBTestCase):
    def _backend(self):
        source = HarvestSourceFactory(backend="ine", url=INE_URL)
        return INEBackend(source)

    def test_complete_file_is_accepted(self, tmp_path):
        path = tmp_path / "ine.xml"
        path.write_text(COMPLETE_XML)
        assert self._backend()._is_complete_xml(str(path)) is True

    def test_truncated_file_is_rejected(self, tmp_path):
        path = tmp_path / "ine.xml"
        path.write_text(TRUNCATED_XML)
        assert self._backend()._is_complete_xml(str(path)) is False

    def test_empty_file_is_rejected(self, tmp_path):
        path = tmp_path / "ine.xml"
        path.write_text("")
        assert self._backend()._is_complete_xml(str(path)) is False

    def test_missing_file_is_rejected(self, tmp_path):
        assert self._backend()._is_complete_xml(str(tmp_path / "nope.xml")) is False


class INEDownloadToFileTest(PytestOnlyDBTestCase):
    def _backend(self, monkeypatch):
        # Avoid real backoff sleeps between retries.
        monkeypatch.setattr("udata.harvest.backends.ine.time.sleep", lambda *a, **k: None)
        source = HarvestSourceFactory(backend="ine", url=INE_URL)
        backend = INEBackend(source)
        backend.MAX_RETRIES = 3
        return backend

    def test_retries_truncated_download_then_succeeds(self, rmock, monkeypatch, tmp_path):
        # First transfer is truncated (connection dropped), second one is complete.
        rmock.get(INE_URL, [{"text": TRUNCATED_XML}, {"text": COMPLETE_XML}])
        dest = tmp_path / "ine.xml"

        self._backend(monkeypatch)._download_to_file(INE_URL, str(dest))

        assert dest.exists()
        content = dest.read_text()
        assert "</catalog>" in content
        assert "Indicador A" in content
        # No leftover .part file
        assert not (tmp_path / "ine.xml.part").exists()

    def test_falls_back_to_cached_valid_file_when_all_attempts_fail(
        self, rmock, monkeypatch, tmp_path
    ):
        rmock.get(INE_URL, text=TRUNCATED_XML)
        dest = tmp_path / "ine.xml"
        dest.write_text(COMPLETE_XML)  # previously cached valid download

        # Should not raise: the last valid file is reused.
        self._backend(monkeypatch)._download_to_file(INE_URL, str(dest))

        assert dest.read_text() == COMPLETE_XML

    def test_raises_when_truncated_and_no_cache(self, rmock, monkeypatch, tmp_path):
        rmock.get(INE_URL, text=TRUNCATED_XML)
        dest = tmp_path / "ine.xml"

        with pytest.raises(INEDownloadIncomplete):
            self._backend(monkeypatch)._download_to_file(INE_URL, str(dest))

        assert not dest.exists()
        assert not (tmp_path / "ine.xml.part").exists()


class INEPrefetchDatasetsTest(PytestOnlyDBTestCase):
    def test_prefetch_finds_existing_and_misses_absent(self):
        source = HarvestSourceFactory(backend="ine", url=INE_URL)
        existing = DatasetFactory(
            harvest=HarvestDatasetMetadata(
                remote_id="0001", source_id=str(source.id), domain=source.domain
            )
        )
        # Same remote_id but another source: must NOT match
        DatasetFactory(
            harvest=HarvestDatasetMetadata(
                remote_id="0002", source_id="other-source", domain="other.example.pt"
            )
        )
        backend = INEBackend(source)

        result = backend._prefetch_datasets(["0001", "0002", "0003"])

        assert set(result) == {"0001"}
        assert result["0001"].id == existing.id

    def test_new_dataset_inherits_source_organization(self):
        org = OrganizationFactory()
        source = HarvestSourceFactory(backend="ine", url=INE_URL, organization=org)
        backend = INEBackend(source)

        dataset = backend._new_dataset()

        assert dataset.id is None
        assert dataset.organization == org


def _catalog_xml(ids):
    indicators = "\n".join(
        f"""<indicator id='{i}'>
        <title><![CDATA[Indicador {i}]]></title>
        <description><![CDATA[Descrição {i}]]></description>
        <html><bdd_url><![CDATA[https://www.ine.pt/xurl/indx/{i}/PT]]></bdd_url></html>
        <json>
        <json_dataset><![CDATA[https://www.ine.pt/js/{i}.json]]></json_dataset>
        </json>
        <keywords>INE,<![CDATA[Estatística]]></keywords>
        </indicator>"""
        for i in ids
    )
    return f"<?xml version='1.0' encoding='UTF-8'?>\n<catalog>\n{indicators}\n</catalog>\n"


@pytest.mark.options(HARVESTER_BACKENDS=["ine"])
class INEInnerHarvestTest(PytestOnlyDBTestCase):
    def _harvest(self, rmock, tmp_path, source):
        rmock.get(INE_URL, text=_catalog_xml(["0001", "0002", "0003"]))
        rmock.get(INE_HVD_URL, text="<indicators/>")
        backend = INEBackend(source)
        backend.LOCAL_FILE_PATH = str(tmp_path / "ine.xml")
        return backend.harvest()

    def test_harvest_creates_datasets_with_job_item_references(self, rmock, tmp_path):
        org = OrganizationFactory()
        source = HarvestSourceFactory(backend="ine", url=INE_URL, organization=org)

        job = self._harvest(rmock, tmp_path, source)

        assert job.status == "done"
        assert len(job.items) == 3
        assert all(item.status == "done" for item in job.items)
        # The flush must happen before the created-ids lookup, otherwise
        # HarvestItems are left without a dataset reference.
        assert all(item.dataset is not None for item in job.items)

        datasets = Dataset.objects(__raw__={"harvest.source_id": str(source.id)})
        assert datasets.count() == 3
        one = datasets.filter(__raw__={"harvest.remote_id": "0001"}).first()
        assert one.title == "Indicador 0001"
        assert one.organization == org
        assert [r.url for r in one.resources] == ["https://www.ine.pt/js/0001.json"]

        # Job items must also be persisted (pushed), not only in memory
        job.reload()
        assert len(job.items) == 3

    def test_second_harvest_skips_unchanged_datasets(self, rmock, tmp_path):
        org = OrganizationFactory()
        source = HarvestSourceFactory(backend="ine", url=INE_URL, organization=org)
        self._harvest(rmock, tmp_path, source)

        job = self._harvest(rmock, tmp_path, source)

        assert job.status == "done"
        assert [item.status for item in job.items] == ["skipped"] * 3
        assert Dataset.objects(__raw__={"harvest.source_id": str(source.id)}).count() == 3
