"""Integration test: Reuse.pre_save sanitizes title and description (LEDG-1690 / VULN-2076)."""

from udata.core.dataservices.factories import DataserviceFactory  # noqa: F401
from udata.core.dataset.factories import DatasetFactory  # noqa: F401
from udata.core.organization.factories import OrganizationFactory  # noqa: F401
from udata.core.reuse.factories import ReuseFactory  # noqa: F401
from udata.core.reuse.models import Reuse
from udata.core.user.factories import UserFactory  # noqa: F401
from udata.tests.api import DBTestCase


class ReusePreSaveSanitizationTest(DBTestCase):
    """Cover AC #1, #2, #3, #4 of LEDG-1690."""

    def _run_pre_save(self, title, description):
        doc = Reuse(title=title, description=description)
        Reuse.pre_save(sender=Reuse, document=doc)
        return doc

    def test_description_strips_img_onerror(self):
        doc = self._run_pre_save("ok", '<img src=x onerror="alert(1)">payload')
        assert "onerror" not in doc.description

    def test_description_strips_script_tag(self):
        doc = self._run_pre_save("ok", "<script>alert(1)</script>safe")
        assert "<script" not in doc.description
        assert "</script" not in doc.description

    def test_title_strips_all_html(self):
        doc = self._run_pre_save("<img src=x onerror=alert(1)>title", "ok")
        assert "<img" not in doc.title
        assert "onerror" not in doc.title

    def test_legitimate_markdown_intact(self):
        markdown_in = "**bold** _italic_ [link](https://example.com)"
        doc = self._run_pre_save("Plain title", markdown_in)
        assert doc.description == markdown_in
        assert doc.title == "Plain title"
