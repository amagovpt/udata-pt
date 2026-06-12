"""Regression suite for the public download/export/feed rate limits.

Companion to the public-search fix (PR #89). The interactive listing/search
endpoints were lifted out of the IP-keyed ``RATELIMIT_DEFAULT`` ("200 per
hour") so they would not collapse into a single site-wide bucket behind the
F5/WAF (docs/infra-adc-waf-impact-ppr-prd.md §4.2). The endpoints that *serve
downloads* were left under that same default and shared the identical failure
mode:

* the resource "latest" download (``GET /api/1/datasets/r/<id>``) and the SSRF
  download proxy — the single most frequent public action, and NOT cacheable;
* catalog exports — the ``/site/*.csv`` and ``/organizations/<org>/*.csv``
  dumps and the RDF catalogs;
* the ``*/recent.atom`` syndication feeds.

Behind the F5 every anonymous visitor reaches the backend from one origin IP,
so the IP-keyed 200/hour ceiling became a shared cap that returned 429 to
everyone after 200 aggregated downloads/hour. The fix applies explicit
``user_or_ip``-keyed limits sized per workload:

* ``RESOURCE_DOWNLOAD_LIMIT`` = 300/min; 6000/h (generous, no daily cap);
* ``EXPORT_LIMIT``            = 60/min; 1200/h (heavy to generate);
* ``FEED_LIMIT``              = 120/min; 2400/h (polled, cacheable).

Run:
    uv run pytest udata/tests/api/test_download_ratelimit_ip_collapse.py -v
"""

from uuid import uuid4

import pytest
from flask import url_for

from udata.app import limiter
from udata.tests.api import PytestOnlyAPITestCase

RATELIMIT_OPTIONS = dict(RATELIMIT_ENABLED=True)


def _statuses(responses):
    return [r.status_code for r in responses]


@pytest.fixture(autouse=True)
def _reset_limiter():
    """Clear the shared rate-limit windows around every test so memory-storage
    counters from one test never leak spurious 429s into the next."""
    limiter.reset()
    yield
    limiter.reset()


class ResourceDownloadLiftedAboveIpDefaultTest(PytestOnlyAPITestCase):
    """The resource download must no longer sit under the IP-keyed 200/hour
    default that collapses site-wide behind the F5/WAF."""

    @pytest.mark.options(**RATELIMIT_OPTIONS)
    def test_resource_download_survives_past_the_old_200_per_hour_ceiling(self):
        # A missing resource still consumes a limiter slot (the limit runs
        # before the 404), so a random UUID is enough to exercise the limit
        # without seeding storage. 210 > the old IP-keyed 200/hour default and
        # < RESOURCE_DOWNLOAD_LIMIT's 300/min, so the only way a 429 appears
        # here is the regression: the endpoint is back under the shared default.
        statuses = _statuses(
            self.get(url_for("api.resource_redirect", id=uuid4())) for _ in range(210)
        )
        assert 429 not in statuses, (
            "IP-collapse regression: 210 anonymous resource downloads from one "
            "IP hit a 429 — the download endpoint is back under the shared "
            f"200/hour IP default. status distribution: {set(statuses)}"
        )


class ExportLimitKeyedAndGenerousTest(PytestOnlyAPITestCase):
    """CSV exports carry the explicit per-endpoint EXPORT_LIMIT (60/min),
    six times the old 200/hour hourly ceiling, and engage when exceeded."""

    @pytest.mark.options(**RATELIMIT_OPTIONS)
    def test_csv_export_allows_60_per_minute_then_throttles(self):
        statuses = _statuses(self.get(url_for("api.site_datasets_csv")) for _ in range(65))
        assert 429 not in statuses[:60], f"EXPORT_LIMIT tighter than 60/min: {statuses}"
        assert 429 in statuses[60:], (
            "EXPORT_LIMIT not wired: 65 rapid CSV exports from one IP never "
            f"produced a 429. observed: {statuses}"
        )


class FeedLimitKeyedAndGenerousTest(PytestOnlyAPITestCase):
    """Atom feeds carry the explicit FEED_LIMIT (120/min) instead of the
    IP-keyed default, and engage when exceeded."""

    @pytest.mark.options(**RATELIMIT_OPTIONS)
    def test_atom_feed_allows_120_per_minute_then_throttles(self):
        statuses = _statuses(self.get(url_for("api.recent_datasets_atom_feed")) for _ in range(125))
        assert 429 not in statuses[:120], f"FEED_LIMIT tighter than 120/min: {statuses}"
        assert 429 in statuses[120:], (
            "FEED_LIMIT not wired: 125 rapid feed polls from one IP never "
            f"produced a 429. observed: {statuses}"
        )
