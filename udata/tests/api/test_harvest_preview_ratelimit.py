"""Regression suite for the harvest config-preview rate limit.

``POST /api/1/harvest/source/preview/`` carried no per-endpoint limit, so it fell
under the IP-keyed ``RATELIMIT_DEFAULT`` ("200 per hour"). That is the wrong
ceiling twice over. Behind the F5/WAF every client reaches the backend from one
origin IP (docs/infra-adc-waf-impact-ppr-prd.md §4.2), so the default is a
SHARED site-wide bucket; and 200 an hour is far too generous for this particular
route, which is the only one that makes the server run a whole harvest backend
against a URL the caller supplies. Each request walks a remote catalogue and
produces outbound traffic in the portal's name, so the cost lands on the portal
regardless of the authorization now required alongside it.

The endpoint carries HARVEST_PREVIEW_LIMIT (5/min, 30/h, 100/day), keyed by
``user_or_ip``. Because the route is ``@api.secure`` the key resolves to
``user:{id}`` for real traffic — a per-publisher bucket that never collapses
with, or starves, anyone else.

Method: fire requests ANONYMOUSLY. The limit is declared in the resource's
``decorators``, which wrap the view OUTSIDE ``@api.secure``, so each anonymous
POST consumes a limiter slot (keyed by IP through the ``user_or_ip`` fallback)
and returns 401 until the ceiling is crossed, then 429. That placement is the
point of the test: a limit applied under ``@api.secure`` would only ever count
requests that already authenticated, and a flood of unauthorized attempts would
pass unmetered.

Run:
    uv run pytest udata/tests/api/test_harvest_preview_ratelimit.py -v
"""

import pytest
from flask import url_for

from udata.app import limiter
from udata.tests.api import PytestOnlyAPITestCase

RATELIMIT_OPTIONS = dict(RATELIMIT_ENABLED=True)

# Mirrored from udata/api/limits.py.
HARVEST_PREVIEW_PER_MIN = 5  # HARVEST_PREVIEW_LIMIT = "5 per minute; ..."

BLOCK_STATUSES = (429, 403)


def _statuses(responses):
    return [r.status_code for r in responses]


@pytest.fixture(autouse=True)
def _reset_limiter():
    """Clear the shared rate-limit windows around every test so counters from
    one test never leak spurious 429s into the next."""
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
        f"{endpoint}: {len(statuses)} rapid previews from one IP never produced a "
        f"429 past request #{threshold}. The endpoint is either unlimited or back "
        f"under the collapsing 200/h IP default. statuses={statuses}"
    )


class HarvestConfigPreviewLiftedAboveIpDefaultTest(PytestOnlyAPITestCase):
    """The config-preview route must carry HARVEST_PREVIEW_LIMIT (5/min), not the
    IP-keyed 200/h default that collapses site-wide behind the F5/WAF."""

    @pytest.mark.options(**RATELIMIT_OPTIONS)
    def test_config_preview_throttles_at_harvest_preview_limit(self):
        url = url_for("api.preview_harvest_source_config")
        statuses = _statuses(self.post(url) for _ in range(HARVEST_PREVIEW_PER_MIN + 3))
        _assert_throttled_at(statuses, HARVEST_PREVIEW_PER_MIN, "preview_harvest_source_config")

    @pytest.mark.options(**RATELIMIT_OPTIONS)
    def test_config_preview_counts_unauthorized_attempts(self):
        """The limit must sit outside the authorization check.

        Unauthenticated callers never reach the view, so a limit declared on the
        method (under ``@api.secure``) would let them retry without ever being
        counted. Every one of these answers 401 up to the ceiling and 429 after,
        which can only happen if the limiter ran first.
        """
        url = url_for("api.preview_harvest_source_config")
        statuses = _statuses(self.post(url) for _ in range(HARVEST_PREVIEW_PER_MIN + 1))

        assert statuses[:HARVEST_PREVIEW_PER_MIN] == [401] * HARVEST_PREVIEW_PER_MIN, (
            f"expected the anonymous attempts to be refused as unauthenticated "
            f"before the ceiling. statuses={statuses}"
        )
        assert statuses[-1] == 429, (
            f"the attempt past the ceiling was not rate-limited. statuses={statuses}"
        )
