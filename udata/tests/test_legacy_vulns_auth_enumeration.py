"""Regression suite for legacy KITS24 auth-enumeration + mass-submission
vulnerabilities not covered by ``test_legacy_vulns_regression.py``.

The audit reports cited four separate user-enumeration vectors on the
legacy Vue.js frontend (all variants of CWE-203 — Information Exposure
Through Discrepancy) plus a related mass-submission gap:

* **VULN-1377 / VULN-1532** — ``/pt/login`` returned a distinguishable
  error message for valid email + wrong password ("Your username and
  password do not match") vs. invalid email ("Invalid credentials").
* **VULN-1533** — ``/pt/register`` leaked
  "<email> is already associated with an account" for known emails.
* **VULN-1534** — ``/pt/reset`` returned
  "Instructions to reset your password have been sent" for known emails
  and "Invalid credentials" for unknown ones.
* **VULN-1688** — ``/pt/confirm`` (resend confirmation) returned
  "O seu email já foi confirmado" for known confirmed emails and
  "Utilizador não existe" for unknown emails.
* **VULN-1498** — ``/pt/confirm`` accepted unbounded automated
  submissions (mass form abuse).

The migrated backend wires Flask-Security with
``SECURITY_RETURN_GENERIC_RESPONSES = True`` (see
``udata/settings.py:160``), which is the official Flask-Security
mitigation for CWE-203 — the same generic response is rendered whether
the email is known or not. ``auth_rate_limit = 5/min`` (see
``udata/auth/views.py:39``) wraps ``login``, ``register``,
``forgot_password``, and ``reset_password``, but **not** the
``send_confirmation`` view (``udata/auth/views.py:205-209``). The
``RateLimitRegressionTest`` below is intentionally fail-by-design until
that gap is closed — its failure is the trigger to apply the rate-limit
wrapper to ``send_confirmation``.
"""

from datetime import datetime

import pytest
from flask import url_for

from udata.app import limiter
from udata.commands.fixtures import UserFactory
from udata.tests.api import PytestOnlyAPITestCase


@pytest.fixture(autouse=True)
def _reset_auth_limiter():
    """Clear the shared ``auth`` rate-limit window before every test.

    Without this, requests made by earlier tests in the same suite consume
    slots in the ``5 per minute`` shared scope (``udata/auth/views.py:39``)
    and leak a 429 onto the second request of the next test — producing a
    false ``CWE-203`` signal that has nothing to do with enumeration. The
    same pattern is used in ``udata/tests/api/test_vuln_2078_audit_simulation.py:53``.
    """
    limiter.reset()
    yield
    limiter.reset()


# ---------------------------------------------------------------------------
# Helper: are these two responses indistinguishable from an attacker's POV?
# ---------------------------------------------------------------------------
def _bodies_indistinguishable(r1, r2, *, length_tolerance: int = 4) -> bool:
    """Return ``True`` iff ``r1`` and ``r2`` carry no enumeration signal.

    The check is intentionally strict but pragmatic:

    * ``status_code`` MUST match exactly.
    * If both responses are JSON, the top-level key SETS MUST match (the
      values may legitimately differ — e.g. opaque tokens — but the shape
      cannot betray which email branch was taken).
    * Otherwise (HTML) the body length MUST agree within ``length_tolerance``
      bytes; small differences are tolerated to absorb CSRF token noise
      and locale-dependent message lengths that do not encode user state.

    The audit PoCs in the KITS24 reports always hinged on either (a) a
    different message length, or (b) a different error string between the
    valid- and invalid-email branches — both shapes are caught here.
    """
    if r1.status_code != r2.status_code:
        return False
    j1 = r1.get_json(silent=True)
    j2 = r2.get_json(silent=True)
    if j1 is not None and j2 is not None:
        return set(j1.keys()) == set(j2.keys())
    if j1 is None and j2 is None:
        return abs(len(r1.data) - len(r2.data)) <= length_tolerance
    # One JSON, one HTML — definitionally distinguishable.
    return False


def _diff_message(scenario, known, unknown) -> str:
    """Build a helpful error message for the diagnostic assertion."""
    return (
        f"[{scenario}] response distinguishes known vs unknown email "
        f"(CWE-203). known: status={known.status_code} len={len(known.data)} "
        f"body={known.get_data(as_text=True)[:200]!r} | "
        f"unknown: status={unknown.status_code} len={len(unknown.data)} "
        f"body={unknown.get_data(as_text=True)[:200]!r}"
    )


# ---------------------------------------------------------------------------
# VULN-1377 + VULN-1532 — Enumeration on /login/
# ---------------------------------------------------------------------------
class LoginEnumerationRegressionTest(PytestOnlyAPITestCase):
    """The legacy app returned different login error messages depending on
    whether the email was registered or not. The current Flask-Security
    setup with ``SECURITY_RETURN_GENERIC_RESPONSES`` should erase that
    distinction.
    """

    @pytest.mark.options(
        CAPTCHETAT_BASE_URL=None,
        SECURITY_RETURN_GENERIC_RESPONSES=True,
        RATELIMIT_ENABLED=False,
    )
    def test_login_does_not_leak_email_existence(self):
        UserFactory(
            email="known@example.org",
            password="Strong-Pass1!",
            confirmed_at=datetime.now(),
        )
        known = self.post(
            url_for("security.login"),
            {"email": "known@example.org", "password": "Wrong-Pass1!"},
        )
        unknown = self.post(
            url_for("security.login"),
            {"email": "unknown@example.org", "password": "Wrong-Pass1!"},
        )
        assert _bodies_indistinguishable(known, unknown), _diff_message(
            "VULN-1377/1532 login", known, unknown
        )


# ---------------------------------------------------------------------------
# VULN-1533 — Enumeration on /register/
# ---------------------------------------------------------------------------
class RegisterEnumerationRegressionTest(PytestOnlyAPITestCase):
    """The legacy app told the attacker '<email> is already associated with
    an account' for known emails. The current backend should return a
    generic response either way.
    """

    @pytest.mark.options(
        CAPTCHETAT_BASE_URL=None,
        SECURITY_RETURN_GENERIC_RESPONSES=True,
        RATELIMIT_ENABLED=False,
    )
    def test_register_does_not_leak_email_existence(self):
        UserFactory(email="taken@example.org", confirmed_at=datetime.now())
        existing = self.post(
            url_for("security.register"),
            {
                "first_name": "Jane",
                "last_name": "Doe",
                "accept_conditions": True,
                "email": "taken@example.org",
                "password": "Strong-Pass1!",
                "password_confirm": "Strong-Pass1!",
                "submit": True,
            },
        )
        new = self.post(
            url_for("security.register"),
            {
                "first_name": "Jane",
                "last_name": "Doe",
                "accept_conditions": True,
                "email": "fresh@example.org",
                "password": "Strong-Pass1!",
                "password_confirm": "Strong-Pass1!",
                "submit": True,
            },
        )
        assert _bodies_indistinguishable(existing, new), _diff_message(
            "VULN-1533 register", existing, new
        )


# ---------------------------------------------------------------------------
# VULN-1534 — Enumeration on /reset/ (forgot-password request)
# ---------------------------------------------------------------------------
class ForgotPasswordEnumerationRegressionTest(PytestOnlyAPITestCase):
    """The legacy app returned 'Instructions to reset your password have
    been sent' only for known emails. The mitigation is to always render
    that message — Flask-Security's generic responses do exactly that.
    """

    @pytest.mark.options(
        CAPTCHETAT_BASE_URL=None,
        SECURITY_RETURN_GENERIC_RESPONSES=True,
        RATELIMIT_ENABLED=False,
    )
    def test_forgot_password_does_not_leak_email_existence(self):
        UserFactory(email="known@example.org", confirmed_at=datetime.now())
        known = self.post(
            url_for("security.forgot_password"),
            {"email": "known@example.org", "submit": True},
        )
        unknown = self.post(
            url_for("security.forgot_password"),
            {"email": "unknown@example.org", "submit": True},
        )
        assert _bodies_indistinguishable(known, unknown), _diff_message(
            "VULN-1534 forgot_password", known, unknown
        )


# ---------------------------------------------------------------------------
# VULN-1688 — Enumeration on /confirm/ (resend confirmation)
# ---------------------------------------------------------------------------
class SendConfirmationEnumerationRegressionTest(PytestOnlyAPITestCase):
    """The legacy app told the attacker 'O seu email já foi confirmado'
    for known confirmed emails and 'Utilizador não existe' for unknown
    emails. The current backend should erase that distinction via
    ``SECURITY_RETURN_GENERIC_RESPONSES``.
    """

    @pytest.mark.options(
        CAPTCHETAT_BASE_URL=None,
        SECURITY_RETURN_GENERIC_RESPONSES=True,
        RATELIMIT_ENABLED=False,
    )
    def test_send_confirmation_does_not_leak_email_existence(self):
        UserFactory(email="confirmed@example.org", confirmed_at=datetime.now())
        known = self.post(
            url_for("security.send_confirmation"),
            {"email": "confirmed@example.org", "submit": True},
        )
        unknown = self.post(
            url_for("security.send_confirmation"),
            {"email": "unknown@example.org", "submit": True},
        )
        assert _bodies_indistinguishable(known, unknown), _diff_message(
            "VULN-1688 send_confirmation", known, unknown
        )


# ---------------------------------------------------------------------------
# VULN-1498 — Mass-submission abuse on /confirm/
# ---------------------------------------------------------------------------
class SendConfirmationRateLimitRegressionTest(PytestOnlyAPITestCase):
    """The audit demonstrated that ``/pt/confirm`` accepted hundreds of
    rapid submissions, enabling email-flood / phishing-list validation
    abuse.

    ``udata.auth.views`` wraps ``login``, ``register``, ``forgot_password``
    and ``reset_password`` in ``auth_rate_limit`` (5 requests/minute) but
    leaves ``send_confirmation`` (lines 205-209) wired bare. This test is
    intentionally **fail-by-design** until the wrapper is applied — the
    failure is the diagnostic signal to apply the matching fix:

        bp.route(app.config["SECURITY_CONFIRM_URL"], methods=[...],
                 endpoint="send_confirmation")(
            auth_rate_limit(send_confirmation)
        )

    Once the fix lands, this assertion flips to passing and the same test
    file documents the regression boundary going forward.
    """

    @pytest.mark.xfail(
        strict=True,
        reason=(
            "VULN-1498 fix pending — send_confirmation (udata/auth/views.py:"
            "205-209) is not wrapped in auth_rate_limit. When the wrapper "
            "is added, this test starts passing and strict=True flips the "
            "result to red, forcing removal of the xfail marker."
        ),
    )
    @pytest.mark.options(
        CAPTCHETAT_BASE_URL=None,
        SECURITY_RETURN_GENERIC_RESPONSES=True,
        RATELIMIT_ENABLED=True,
    )
    def test_send_confirmation_endpoint_rate_limits_rapid_submissions(self):
        statuses = []
        for _ in range(10):
            response = self.post(
                url_for("security.send_confirmation"),
                {"email": "anyone@example.org", "submit": True},
            )
            statuses.append(response.status_code)
        assert 429 in statuses, (
            "VULN-1498 regression: /confirm/ accepted 10 rapid POSTs "
            "without producing a single 429 response. The Flask-Security "
            "send_confirmation view at udata/auth/views.py:205-209 is "
            f"not wrapped in auth_rate_limit. observed statuses: {statuses}"
        )
