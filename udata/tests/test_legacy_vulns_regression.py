"""Regression suite for KITS24 legacy vulnerabilities that were closed on
the legacy infrastructure (deploys 2024-06-04, 2024-06-18, 2024-07-23, …)
and currently have NO dedicated test coverage on the migrated udata-pt
backend.

Source of truth: ``Vulnerabilidades_mapa_geral.xlsx`` rows with
``Mitigado (Y/N) = YES``, cross-referenced with the per-VULN PDF reports.

Each test class names the originating VULN(s). Tests for VULNs whose
mitigation surface is HTTP-layer-only (clickjacking, cache-control,
internal-IP leakage, reflected XSS via query string) live in the frontend
Playwright suite ``frontend/tests/e2e/frontend-vulnerabilities/
06-legacy-vulns-regression.spec.ts`` instead.

Covered here:

* **VULN-1376** — Weak password policy. Verifies
  :class:`udata.auth.password_validation.UdataPasswordUtil` rejects every
  weak shape called out in the audit (numeric-only, too short, missing
  case classes) and accepts a strong shape.
* **VULN-1379 / VULN-1593** — XSS via SVG uploaded to
  ``/api/1/datasets/<id>/upload/community/``. Verifies the centralised
  HTML sanitizer strips ``<script>`` / event handlers / ``javascript:``
  URIs out of SVG-shaped Markdown/HTML before render.
* **VULN-1496** — HTML5 CORS misconfiguration. Verifies the origin
  allowlist in :mod:`udata.cors` only authorises configured origins
  (no ``*`` echo, no arbitrary origin reflection).
"""

import pytest

from udata.auth.password_validation import UdataPasswordUtil
from udata.core.utils.sanitization import sanitize_markdown_html, sanitize_strict
from udata.cors import _is_origin_allowed
from udata.tests.api import PytestOnlyAPITestCase


# ---------------------------------------------------------------------------
# VULN-1376 — Weak password policy (Severity MEDIUM, asset dados.gov.pt)
# ---------------------------------------------------------------------------
@pytest.mark.usefixtures("app")
class PasswordPolicyRegressionTest(PytestOnlyAPITestCase):
    """VULN-1376: the legacy app accepted ``123456`` / ``111111`` and other
    6-character numeric-only passwords. The audit recommended a min length of
    10 with mixed case + digit + symbol. The current Flask-Security policy
    (configured in :mod:`udata.settings`) enforces min length 8 +
    lower/upper/digit. These tests pin that floor so future settings drift
    that re-introduces the original weakness is caught.

    .. note::
       ``UdataPasswordUtil.validate`` returns ``(error_list, normalised)``.
       Any non-empty error list means rejected.
    """

    @pytest.fixture
    def util(self, app):
        return UdataPasswordUtil(app)

    def _validate(self, util, password):
        with self.app.app_context():
            errors, _ = util.validate(password, is_register=True)
        return errors

    def test_rejects_numeric_only_short_password(self, util):
        # The original PoC payload from the audit (registered users had
        # passwords like ``123456`` / ``111111``).
        errors = self._validate(util, "123456")
        assert errors, "weak numeric-only password 123456 must be rejected"

    def test_rejects_short_password(self, util):
        # Anything below the configured minimum length must fail. Assertion
        # is locale-tolerant: we only require *some* error to be raised
        # because the message itself is translated.
        errors = self._validate(util, "Aa1")
        assert errors, "short password 'Aa1' must be rejected"

    def test_rejects_password_missing_uppercase(self, util):
        errors = self._validate(util, "lowercaseonly1")
        assert errors, "lowercase-only password must be rejected"

    def test_rejects_password_missing_lowercase(self, util):
        errors = self._validate(util, "UPPERCASEONLY1")
        assert errors, "uppercase-only password must be rejected"

    def test_rejects_password_missing_digit(self, util):
        errors = self._validate(util, "NoDigitsHereXYZ")
        assert errors, "password without digits must be rejected"

    def test_accepts_strong_password(self, util):
        # Strong password matching the audit recommendation: length >= 13,
        # mixed case, digit, symbol — passes every configured requirement
        # in both production (``SECURITY_PASSWORD_LENGTH_MIN`` = 8, no
        # symbols required) and test (``= 13`` + symbols required) profiles.
        errors = self._validate(util, "StrongPass1!@#")
        assert errors == [], (
            f"strong password should be accepted, got errors: {errors}"
        )


# ---------------------------------------------------------------------------
# VULN-1379 + VULN-1593 — XSS via SVG uploaded to
# /api/1/datasets/<id>/upload/community/
# ---------------------------------------------------------------------------
class SvgXssSanitizationRegressionTest(PytestOnlyAPITestCase):
    """The audit PoC uploaded an SVG with an inline ``<script>alert('XSS')
    </script>`` block; the file was then served back unsanitised and the
    payload executed on view. The current backend pipeline runs every
    user-supplied HTML/markdown string through :func:`sanitize_markdown_html`
    /``sanitize_strict`` before storage. These tests pin that contract for
    the exact SVG-shaped payload from the report.
    """

    SVG_WITH_SCRIPT = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="-52 -53 100 100">'
        '<g fill="none"><ellipse stroke="#66899a" rx="6" ry="44"/></g>'
        '<script type="text/javascript">alert(\'XSS\')</script>'
        "</svg>"
    )

    SVG_WITH_ONLOAD = (
        '<svg xmlns="http://www.w3.org/2000/svg" '
        'onload="window.__vuln1593=1">'
        '<rect width="10" height="10" /></svg>'
    )

    def test_strict_sanitizer_strips_script_block_from_svg(self):
        cleaned = sanitize_strict(self.SVG_WITH_SCRIPT)
        assert "<script" not in cleaned
        assert "alert('XSS')" not in cleaned or "<script" not in cleaned, (
            "alert text alone is harmless plain text, but the <script> "
            "wrapper must be gone"
        )

    def test_strict_sanitizer_strips_event_handler_from_svg(self):
        cleaned = sanitize_strict(self.SVG_WITH_ONLOAD)
        # sanitize_strict drops every tag and every attribute on it.
        assert "<svg" not in cleaned
        assert "onload" not in cleaned

    def test_markdown_sanitizer_strips_script_block_from_svg(self, app):
        with app.app_context():
            cleaned = sanitize_markdown_html(self.SVG_WITH_SCRIPT)
        assert "<script" not in cleaned
        assert "</script" not in cleaned

    def test_markdown_sanitizer_strips_onload_from_svg(self, app):
        with app.app_context():
            cleaned = sanitize_markdown_html(self.SVG_WITH_ONLOAD)
        assert "onload" not in cleaned

    def test_markdown_sanitizer_strips_javascript_uri_from_svg_link(self, app):
        payload = (
            '<svg xmlns="http://www.w3.org/2000/svg">'
            '<a href="javascript:alert(1)">click</a>'
            "</svg>"
        )
        with app.app_context():
            cleaned = sanitize_markdown_html(payload)
        assert "javascript:" not in cleaned


# ---------------------------------------------------------------------------
# VULN-1496 — HTML5 CORS misconfiguration
# ---------------------------------------------------------------------------
class CorsAllowlistRegressionTest(PytestOnlyAPITestCase):
    """The legacy server responded with
    ``Access-Control-Allow-Origin: *`` even on credential-sensitive routes.
    The current :func:`udata.cors._is_origin_allowed` reads from a configured
    allowlist (``CORS_ALLOWED_ORIGINS``) and only echoes a matching origin.
    These tests pin that contract.
    """

    @pytest.mark.options(
        CORS_ALLOWED_ORIGINS=["https://dados.gov.pt", "https://preprod.dados.gov.pt"]
    )
    def test_arbitrary_attacker_origin_is_rejected(self, app):
        with app.app_context():
            assert _is_origin_allowed("https://evil.example.com") is False

    @pytest.mark.options(
        CORS_ALLOWED_ORIGINS=["https://dados.gov.pt", "https://preprod.dados.gov.pt"]
    )
    def test_wildcard_origin_is_not_accepted(self, app):
        # The function does a literal membership check — ``*`` is not a
        # legitimate allowlist entry and must not be matched.
        with app.app_context():
            assert _is_origin_allowed("*") is False

    @pytest.mark.options(
        CORS_ALLOWED_ORIGINS=["https://dados.gov.pt", "https://preprod.dados.gov.pt"]
    )
    def test_configured_origin_is_accepted(self, app):
        with app.app_context():
            assert _is_origin_allowed("https://dados.gov.pt") is True
            assert _is_origin_allowed("https://preprod.dados.gov.pt") is True

    @pytest.mark.options(CORS_ALLOWED_ORIGINS=[])
    def test_empty_allowlist_rejects_everything(self, app):
        with app.app_context():
            assert _is_origin_allowed("https://dados.gov.pt") is False
            assert _is_origin_allowed("https://evil.example.com") is False
