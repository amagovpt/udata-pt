"""Integration test: CommunityResource.pre_save sanitizes title/description (LEDG-1716 / VULN-2075).

Covers the AC of LEDG-1716, in particular AC4 (direct ORM save bypasses the
form, but pre_save still sanitizes).
"""

from udata.core.dataset.factories import CommunityResourceFactory, DatasetFactory
from udata.core.dataset.models import CommunityResource
from udata.tests.api import DBTestCase


class CommunityResourcePreSaveSanitizationTest(DBTestCase):
    def _run_pre_save(self, title="ok", description=""):
        doc = CommunityResource(title=title, description=description)
        CommunityResource.pre_save(sender=CommunityResource, document=doc)
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

    def test_legitimate_markdown_intact(self):
        markdown_in = "**bold** _italic_ [link](https://example.com)"
        doc = self._run_pre_save(title="Plain title", description=markdown_in)
        assert doc.description == markdown_in
        assert doc.title == "Plain title"

    def test_orm_save_persists_sanitized_payload(self):
        """AC4: write goes via ORM (no form), pre_save still fires."""
        dataset = DatasetFactory()
        cr = CommunityResourceFactory(
            dataset=dataset,
            title="<script>alert(1)</script>Clean title",
            description='<img src=x onerror="alert(1)">payload',
        )
        cr.save()

        reloaded = CommunityResource.objects.get(id=cr.id)
        assert "<script" not in reloaded.title
        assert "onerror" not in reloaded.description
        assert reloaded.title.endswith("Clean title")
