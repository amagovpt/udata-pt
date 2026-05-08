"""Tests for udata.core.utils.sanitization (VULN-2075, VULN-2076)."""

from udata.core.utils.sanitization import sanitize_markdown_html, sanitize_strict
from udata.tests.api import PytestOnlyAPITestCase


class SanitizeStrictTest(PytestOnlyAPITestCase):
    def test_returns_falsy_unchanged(self):
        assert sanitize_strict(None) is None
        assert sanitize_strict("") == ""

    def test_strips_all_tags(self):
        assert sanitize_strict("<b>hello</b>") == "hello"

    def test_strips_script_tag_keeps_text(self):
        # The <script> markup is removed; inner text is harmless plain text.
        cleaned = sanitize_strict("<script>alert(1)</script>safe")
        assert "<script" not in cleaned
        assert "</script" not in cleaned
        assert cleaned.endswith("safe")

    def test_strips_event_handler_payload(self):
        assert sanitize_strict('<img src=x onerror="alert(1)">title') == "title"


class SanitizeMarkdownHtmlTest(PytestOnlyAPITestCase):
    def test_returns_falsy_unchanged(self, app):
        with app.app_context():
            assert sanitize_markdown_html(None) is None
            assert sanitize_markdown_html("") == ""

    def test_strips_script_tag(self, app):
        with app.app_context():
            cleaned = sanitize_markdown_html("a<script>alert(1)</script>b")
            # <script> is not in MD_ALLOWED_TAGS so the markup is stripped.
            # The text inside survives but is no longer executable.
            assert "<script" not in cleaned
            assert "</script" not in cleaned

    def test_strips_event_handlers(self, app):
        with app.app_context():
            cleaned = sanitize_markdown_html('<img src="x" onerror="alert(1)">')
            assert "onerror" not in cleaned

    def test_strips_javascript_uri(self, app):
        with app.app_context():
            cleaned = sanitize_markdown_html('<a href="javascript:alert(1)">x</a>')
            assert "javascript:" not in cleaned

    def test_preserves_safe_anchor(self, app):
        with app.app_context():
            cleaned = sanitize_markdown_html('<a href="https://example.com">x</a>')
            assert 'href="https://example.com"' in cleaned

    def test_preserves_safe_img(self, app):
        with app.app_context():
            cleaned = sanitize_markdown_html('<img src="https://example.com/i.png" alt="i">')
            assert "<img" in cleaned
            assert "src=" in cleaned

    def test_passes_plain_markdown_through(self, app):
        with app.app_context():
            text = "**bold** _italic_ [link](https://example.com)"
            assert sanitize_markdown_html(text) == text
