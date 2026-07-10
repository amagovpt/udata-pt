import pytest

from udata.tests.api import PytestOnlyDBTestCase

from ..backends.ine import INEBackend, INEDownloadIncomplete
from .factories import HarvestSourceFactory

INE_URL = "https://www.ine.pt/ine/xml_indic.jsp?opc=2&lang=PT"

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
