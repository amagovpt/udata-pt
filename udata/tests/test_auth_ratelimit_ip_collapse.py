"""Regression suite for the two-tier auth rate limit.

Behind the PRD F5/proxy chain every client can reach the backend with the
same origin IP (docs/infra-adc-waf-impact-ppr-prd.md §4.2, §6.4). The
original ``auth_rate_limit`` keyed its ``5 per minute`` budget on the IP
alone, so legitimate users behind a collapsed egress shared 5 login
attempts per minute for the whole portal — the same failure mode that
produced the random-logout incident on ``/api/1/me/``.

``udata/auth/views.py`` now applies two stacked shared limits:

* ``5/min`` keyed on ``(IP, sha256(email))`` — unchanged anti-brute-force
  pressure on any single account (VULN-1377/1532/1533/1534);
* ``30/min`` keyed on the IP — ceiling against cross-email enumeration or
  credential stuffing from a single source.

Requests without an ``email`` form field (GETs, token reset POSTs) fall
back to the plain IP key, preserving the historical behaviour.
"""

from datetime import datetime

import pytest
from flask import url_for

from udata.app import limiter
from udata.commands.fixtures import UserFactory
from udata.tests.api import PytestOnlyAPITestCase

RATELIMIT_OPTIONS = dict(
    CAPTCHETAT_BASE_URL=None,
    SECURITY_RETURN_GENERIC_RESPONSES=True,
    RATELIMIT_ENABLED=True,
)


@pytest.fixture(autouse=True)
def _reset_auth_limiter():
    """Clear the shared rate-limit windows before/after every test.

    Same pattern as ``test_legacy_vulns_auth_enumeration.py``: without it,
    earlier tests in the suite consume slots in the shared scopes and leak
    spurious 429s into the next test.
    """
    limiter.reset()
    yield
    limiter.reset()


class DistinctCredentialsNotCollapsedTest(PytestOnlyAPITestCase):
    """Different users behind one IP must not consume each other's budget."""

    @pytest.mark.options(**RATELIMIT_OPTIONS)
    def test_distinct_emails_from_one_ip_are_not_blocked(self):
        UserFactory(
            email="user00@example.org",
            password="Strong-Pass1!",
            confirmed_at=datetime.now(),
        )
        statuses = []
        for i in range(10):  # > old 5/min IP budget, < 30/min IP ceiling
            response = self.post(
                url_for("security.login"),
                {"email": f"user{i:02d}@example.org", "password": "Wrong-Pass1!"},
            )
            statuses.append(response.status_code)
        assert 429 not in statuses, (
            "IP-collapse regression: 10 login attempts with 10 distinct "
            "emails from one IP hit a 429 — distinct credentials are "
            f"sharing a rate-limit bucket again. observed: {statuses}"
        )


class SingleCredentialStillLimitedTest(PytestOnlyAPITestCase):
    """Brute-forcing one account keeps the original 5/min pressure."""

    @pytest.mark.options(**RATELIMIT_OPTIONS)
    def test_single_email_brute_force_still_hits_429(self):
        UserFactory(
            email="target@example.org",
            password="Strong-Pass1!",
            confirmed_at=datetime.now(),
        )
        statuses = [
            self.post(
                url_for("security.login"),
                {"email": "target@example.org", "password": f"Wrong-Pass{i}!"},
            ).status_code
            for i in range(8)
        ]
        assert 429 not in statuses[:5], f"per-credential budget tighter than 5/min: {statuses}"
        assert 429 in statuses[5:], (
            "VULN-1377/1532 regression: 8 rapid login attempts against one "
            f"account never produced a 429. observed: {statuses}"
        )


class IpCeilingCapsCrossEmailBurstsTest(PytestOnlyAPITestCase):
    """Rotating emails from one source is bounded by the 30/min IP ceiling."""

    @pytest.mark.options(**RATELIMIT_OPTIONS)
    def test_cross_email_enumeration_burst_hits_ip_ceiling(self):
        statuses = [
            self.post(
                url_for("security.login"),
                {"email": f"probe{i:03d}@example.org", "password": "Wrong-Pass1!"},
            ).status_code
            for i in range(35)
        ]
        assert 429 not in statuses[:30], f"IP ceiling tighter than 30/min: {statuses}"
        assert 429 in statuses[30:], (
            "enumeration regression: 35 cross-email login attempts from one "
            f"IP never hit the 30/min ceiling. observed: {statuses}"
        )


class NoEmailFallsBackToIpKeyTest(PytestOnlyAPITestCase):
    """Requests without an email field keep the historical plain-IP 5/min."""

    @pytest.mark.options(**RATELIMIT_OPTIONS)
    def test_login_page_views_keep_ip_keyed_budget(self):
        statuses = [self.get(url_for("security.login")).status_code for _ in range(7)]
        assert 429 not in statuses[:5], f"no-email fallback tighter than 5/min: {statuses}"
        assert 429 in statuses[5:], (
            "no-email fallback regression: 7 rapid GETs to the login page "
            f"never produced a 429. observed: {statuses}"
        )
