"""Regression suite for the harvest source *creation* rate limit (VULN-1879).

The audit reported mass form submission against four endpoints. Three of them --
``POST /api/1/datasets/``, ``POST /api/1/reuses/`` and ``POST /api/1/organizations/``
-- were given per-endpoint limits and are covered by
``udata/tests/api/test_vuln_2078_audit_simulation.py``. ``POST /api/1/harvest/sources/``
was not: replaying the audit's run against it produced 201 a hundred times out of a
hundred, and 200 sources were created before the IP-keyed ``RATELIMIT_DEFAULT``
("200 per hour") finally answered 429.

That default is the wrong ceiling twice over. Behind the F5/WAF every client reaches
the backend from one origin IP (docs/infra-adc-waf-impact-ppr-prd.md §4.2), so it is a
SHARED site-wide bucket an attacker can spend on everyone's behalf; and creating a
harvest source is the heaviest of the four operations, because it schedules recurring
crawls against a host the caller supplies.

The endpoint now carries HEAVY_CREATE_LIMIT (2/min, 5/h, 10/day) on POST, keyed by
``user_or_ip`` -- the same profile organization creation carries -- and
PUBLIC_SEARCH_LIMIT on GET so the backoffice listing keeps its own bucket.

This file follows the shape of ``test_harvest_preview_ratelimit.py`` (the newer
PytestOnlyAPITestCase style, where the harvest rate-limit tests live) and the content
of ``test_vuln_2078_audit_simulation.py`` (the audit replay for the sibling endpoints).

Run:
    uv run pytest udata/tests/api/test_harvest_sources_ratelimit.py -v
"""

import pytest
from flask import url_for

from udata.app import limiter
from udata.harvest.tests.factories import MockBackendsMixin
from udata.tests.api import PytestOnlyAPITestCase
from udata.utils import faker

# NOTE: there is deliberately no `@pytest.mark.options(RATELIMIT_ENABLED=True)` here, even
# though neighbouring rate-limit suites carry it. The marker cannot do anything: `limiter`
# is a process-wide singleton that captures `enabled` inside `init_app`, and pytest-flask
# patches `app.config` only after the app fixture has already built the app. The limiter is
# live by default under `settings.Testing`; the fixture below asserts that rather than
# decorating the tests with a flag that does nothing.

# Mirrored from udata/api/limits.py.
HEAVY_CREATE_PER_MIN = 2  # HEAVY_CREATE_LIMIT = "2 per minute; ..."
PUBLIC_SEARCH_PER_MIN = 300  # PUBLIC_SEARCH_LIMIT = "300 per minute; ..."
# What the route fell under before it carried a limit of its own:
# RATELIMIT_DEFAULT = "1000 per day;200 per hour" (udata/settings.py), keyed on the
# remote address rather than the user.
IP_DEFAULT_PER_HOUR = 200

# The audit's own run length.
AUDIT_REPLAY = 100

BLOCK_STATUSES = (429, 403)


def _statuses(responses):
    return [r.status_code for r in responses]


def _source_payload():
    """A payload the form accepts, so a 201 means the limiter let it through.

    `backend="factory"` is only a valid choice under MockBackendsMixin; without the
    mixin every POST answers 400 and the run proves nothing about the limit.
    """
    return {"name": faker.word(), "url": faker.url(), "backend": "factory"}


@pytest.fixture(autouse=True)
def _reset_limiter():
    """Clear the shared rate-limit windows around every test so counters from one
    test never leak spurious 429s into the next, and refuse to run at all if the
    limiter is disabled -- every assertion below would pass vacuously."""
    assert limiter.enabled, "the limiter is disabled, so these tests would prove nothing"
    limiter.reset()
    yield
    limiter.reset()


def _assert_throttled_at(statuses, threshold, endpoint):
    """Assert the per-endpoint limit engaged at ``threshold`` (and not earlier),
    proving the endpoint carries its own limit rather than the 200/h default."""
    blocked_before = [s for s in statuses[:threshold] if s in BLOCK_STATUSES]
    blocked_after = [s for s in statuses[threshold:] if s in BLOCK_STATUSES]
    assert not blocked_before, (
        f"{endpoint}: blocked within the first {threshold} requests "
        f"(limit tighter than expected, or a leaked window). statuses={statuses}"
    )
    assert blocked_after, (
        f"{endpoint}: {len(statuses)} rapid creations never produced a 429 past "
        f"request #{threshold}. The endpoint is either unlimited or back under the "
        f"collapsing 200/h IP default. statuses={statuses}"
    )


class HarvestSourceCreateRateLimitTest(MockBackendsMixin, PytestOnlyAPITestCase):
    """POST /api/1/harvest/sources/ must carry HEAVY_CREATE_LIMIT."""

    def test_audit_replay_is_blocked(self):
        """The audit's run, replayed against the patched code.

        Counts the sources that actually reached the database, not just the status
        codes: a limiter that answered 429 after the document was written would
        still leave the portal flooded.
        """
        from udata.harvest.models import HarvestSource

        self.login()
        url = url_for("api.harvest_sources")
        statuses = _statuses(self.post(url, _source_payload()) for _ in range(AUDIT_REPLAY))

        created = statuses.count(201)
        assert created <= HEAVY_CREATE_PER_MIN, (
            f"{created} sources accepted out of {AUDIT_REPLAY}; the per-minute "
            f"ceiling is {HEAVY_CREATE_PER_MIN}. statuses={statuses}"
        )
        assert statuses.count(429) >= AUDIT_REPLAY - HEAVY_CREATE_PER_MIN - 1, (
            f"the flood was not mostly refused. statuses={statuses}"
        )
        # Filtered on purpose: an unfiltered count is routed to mongoengine's
        # estimated_document_count, which can report zero while the rows are there.
        created_rows = HarvestSource.objects(backend="factory").count()
        assert created_rows <= HEAVY_CREATE_PER_MIN, (
            f"{created_rows} sources reached the database past the ceiling"
        )

    def test_create_throttles_exactly_at_heavy_create_limit(self):
        """Blocked at 2, not at the 200/h default it used to fall under."""
        self.login()
        url = url_for("api.harvest_sources")
        statuses = _statuses(
            self.post(url, _source_payload()) for _ in range(HEAVY_CREATE_PER_MIN + 3)
        )
        _assert_throttled_at(statuses, HEAVY_CREATE_PER_MIN, "harvest_sources")

        # `_assert_throttled_at` alone would also pass under a 3/min limit: it only says
        # "nothing blocked before N, something blocked after". Pin the cut exactly.
        assert statuses[HEAVY_CREATE_PER_MIN] in BLOCK_STATUSES, (
            f"request #{HEAVY_CREATE_PER_MIN + 1} was not the one refused, so the ceiling "
            f"is not {HEAVY_CREATE_PER_MIN}/min. statuses={statuses}"
        )

    def test_ip_rotation_does_not_bypass_the_user_keyed_limit(self):
        """A rotating proxy pool buys nothing: the key is the user, not the address.

        ProxyFix is mounted, so X-Forwarded-For really does change what an anonymous
        caller would be keyed on -- which is exactly why the authenticated key must
        not be derived from it.
        """
        self.login()
        url = url_for("api.harvest_sources")
        statuses = _statuses(
            self.post(
                url,
                _source_payload(),
                headers={"X-Forwarded-For": f"203.0.113.{i + 1}"},
            )
            for i in range(20)
        )

        assert statuses.count(201) <= HEAVY_CREATE_PER_MIN, (
            f"rotating the forwarded address bought extra creations. statuses={statuses}"
        )
        assert statuses.count(429) > 0, (
            f"nothing was refused, so this run never reached the ceiling and proves "
            f"nothing about the key. statuses={statuses}"
        )

    def test_anonymous_attempts_are_counted_before_auth(self):
        """The limit must sit outside the authorization check.

        Unauthenticated callers never reach the view, so a limit declared on the
        method (under ``@api.secure``) would let them retry without ever being
        counted. These answer 401 up to the ceiling and 429 after, which can only
        happen if the limiter ran first.
        """
        url = url_for("api.harvest_sources")
        statuses = _statuses(
            self.post(url, _source_payload()) for _ in range(HEAVY_CREATE_PER_MIN + 1)
        )

        assert statuses[:HEAVY_CREATE_PER_MIN] == [401] * HEAVY_CREATE_PER_MIN, (
            f"expected the anonymous attempts to be refused as unauthenticated "
            f"before the ceiling. statuses={statuses}"
        )
        assert statuses[-1] == 429, (
            f"the attempt past the ceiling was not rate-limited. statuses={statuses}"
        )


class HarvestSourceListNotThrottledByCreateLimitTest(MockBackendsMixin, PytestOnlyAPITestCase):
    """The listing keeps its own bucket, so creation never starves the backoffice."""

    def test_get_is_unaffected_by_an_exhausted_create_limit(self):
        url = url_for("api.harvest_sources")

        post_statuses = _statuses(
            self.post(url, _source_payload()) for _ in range(HEAVY_CREATE_PER_MIN + 1)
        )
        assert post_statuses[-1] == 429, (
            f"the create ceiling was not reached, so the GET below proves nothing. "
            f"statuses={post_statuses}"
        )

        # The read run must be long enough to tell the GET's own limit apart from NO
        # limit: without one, a GET falls back to the IP-keyed RATELIMIT_DEFAULT
        # (200/hour), so a short run of 10 would answer 200 either way and this test
        # would pass with the GET limit deleted. Over that default but under
        # PUBLIC_SEARCH_LIMIT, only the real limit can keep every read at 200.
        reads = IP_DEFAULT_PER_HOUR + 50
        assert IP_DEFAULT_PER_HOUR < reads < PUBLIC_SEARCH_PER_MIN, (
            "the read run must sit above the default it would fall back to and below "
            "the GET's own per-minute ceiling, or it discriminates between nothing"
        )
        get_statuses = _statuses(self.get(url) for _ in range(reads))

        assert get_statuses == [200] * reads, (
            f"the listing was throttled. Either the creation limit is leaking into the "
            f"GET bucket, or the GET carries no limit of its own and fell back to the "
            f"shared IP-keyed default. distribution="
            f"{ {s: get_statuses.count(s) for s in set(get_statuses)} }"
        )
