"""Integration test: Dataservice.pre_save sanitizes title/acronym/description (LEDG-1715 / VULN-2075)."""

from udata.core.dataservices.models import Dataservice
from udata.tests.api import DBTestCase


class DataservicePreSaveSanitizationTest(DBTestCase):
    """Cover the AC of LEDG-1715."""

    def _run_pre_save(self, title="ok", acronym=None, description=""):
        doc = Dataservice(title=title, acronym=acronym, description=description)
        Dataservice.pre_save(sender=Dataservice, document=doc)
        return doc

    def test_description_strips_img_onerror(self):
        doc = self._run_pre_save(description='<img src=x onerror="alert(1)">payload')
        assert "onerror" not in doc.description

    def test_description_strips_script_tag(self):
        doc = self._run_pre_save(description="<script>alert(1)</script>safe")
        assert "<script" not in doc.description
        assert "</script" not in doc.description

    def test_title_strips_all_html(self):
        doc = self._run_pre_save(title="<img src=x onerror=alert(1)>title")
        assert "<img" not in doc.title
        assert "onerror" not in doc.title

    def test_acronym_strips_all_html(self):
        doc = self._run_pre_save(acronym="<b>API</b>")
        assert "<b>" not in doc.acronym
        assert doc.acronym == "API"

    def test_legitimate_markdown_intact(self):
        markdown_in = "**bold** _italic_ [link](https://example.com)"
        doc = self._run_pre_save(title="Plain title", description=markdown_in)
        assert doc.description == markdown_in
        assert doc.title == "Plain title"
