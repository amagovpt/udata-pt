"""Regression suite for the public READ rate limits (suggest / detail / reference).

Fourth companion to the public-search (PR #89), download/export/feed (PR #90)
and upload (PR #91) IP-collapse fixes. A large set of anonymous GET endpoints
that the SSR/public pages hit live (not ISR cached) carried NO explicit limit,
so they fell under the IP-keyed ``RATELIMIT_DEFAULT`` ("200 per hour"). Behind
the F5/WAF every visitor reaches the backend from one origin IP
(docs/infra-adc-waf-impact-ppr-prd.md §4.2), so that 200/hour became a shared
site-wide ceiling: once aggregate read volume crosses it every anonymous
visitor gets 429 and the public pages stop rendering. The worst offenders are
the ``*/suggest/`` typeahead endpoints (fired per keystroke).

The fix gives these endpoints explicit ``user_or_ip``-keyed, method-scoped
limits (no per-day cap):

* ``*/suggest/`` typeahead -> ``PUBLIC_SEARCH_LIMIT`` (300/min; search-backed);
* entity detail reads + public sub-listings + reference-data lists
  -> ``PUBLIC_READ_LIMIT`` (300/min).

Method: fire anonymous GETs. A missing/invalid object still consumes a limiter
slot (the limit wraps the view, ahead of the handler). 210 > the old 200/hour
default and < the new 300/min ceiling, so the ONLY way a 429 appears in the
survival tests is the regression: the endpoint is back under the shared
200/hour IP default. The engagement test then drives one endpoint past 300/min
to prove the limiter is genuinely active (not merely disabled).

Run:
    uv run pytest udata/tests/api/test_public_read_ratelimit_ip_collapse.py -v
"""

import pytest
from flask import url_for

from udata.app import limiter
from udata.core.dataservices.factories import DataserviceFactory
from udata.core.dataset.factories import DatasetFactory
from udata.core.organization.factories import OrganizationFactory
from udata.core.reuse.factories import ReuseFactory
from udata.tests.api import PytestOnlyAPITestCase

RATELIMIT_OPTIONS = dict(RATELIMIT_ENABLED=True)

# Mirrored from udata/api/limits.py: both PUBLIC_SEARCH_LIMIT and
# PUBLIC_READ_LIMIT are "300 per minute; 6000 per hour".
PUBLIC_READ_PER_MIN = 300
OLD_IP_DEFAULT_PER_HOUR = 200


def _statuses(responses):
    return [r.status_code for r in responses]


@pytest.fixture(autouse=True)
def _reset_limiter():
    limiter.reset()
    yield
    limiter.reset()


class PublicReadLiftedAboveIpDefaultTest(PytestOnlyAPITestCase):
    """Every newly-covered anonymous GET must survive past the old 200/hour
    IP-keyed ceiling that collapses site-wide behind the F5/WAF. A 429 below the
    new 300/min limit means the endpoint regressed back under the default."""

    def _assert_survives(self, url):
        # 210 anonymous reads from one IP: > old 200/h default, < new 300/min.
        statuses = _statuses(self.get(url) for _ in range(OLD_IP_DEFAULT_PER_HOUR + 10))
        assert 429 not in statuses, (
            f"IP-collapse regression on {url}: a 429 appeared below the 300/min "
            f"ceiling, so the endpoint is back under the shared 200/h IP default. "
            f"status set: {set(statuses)}"
        )

    @pytest.mark.options(**RATELIMIT_OPTIONS)
    def test_dataset_suggest_lifted(self):
        self._assert_survives(url_for("api.suggest_datasets", q="data"))

    @pytest.mark.options(**RATELIMIT_OPTIONS)
    def test_tags_suggest_lifted(self):
        self._assert_survives(url_for("api.suggest_tags", q="env"))

    @pytest.mark.options(**RATELIMIT_OPTIONS)
    def test_dataset_detail_lifted(self):
        dataset = DatasetFactory()
        self._assert_survives(url_for("api.dataset", dataset=dataset))

    @pytest.mark.options(**RATELIMIT_OPTIONS)
    def test_organization_detail_lifted(self):
        org = OrganizationFactory()
        self._assert_survives(url_for("api.organization", org=org))

    @pytest.mark.options(**RATELIMIT_OPTIONS)
    def test_reuse_detail_lifted(self):
        reuse = ReuseFactory()
        self._assert_survives(url_for("api.reuse", reuse=reuse))

    @pytest.mark.options(**RATELIMIT_OPTIONS)
    def test_dataservice_detail_lifted(self):
        dataservice = DataserviceFactory()
        self._assert_survives(url_for("api.dataservice", dataservice=dataservice))

    @pytest.mark.options(**RATELIMIT_OPTIONS)
    def test_reference_lists_lifted(self):
        for endpoint in ("api.licenses", "api.dataset_frequencies", "api.reuse_types"):
            self._assert_survives(url_for(endpoint))


class PublicReadLimiterActuallyEngagesTest(PytestOnlyAPITestCase):
    """The lift must not silently disable the limiter: driving one endpoint past
    its 300/min ceiling must still 429, proving the limit is live and keyed."""

    @pytest.mark.options(**RATELIMIT_OPTIONS)
    def test_public_read_throttles_past_300_per_minute(self):
        url = url_for("api.licenses")
        statuses = _statuses(self.get(url) for _ in range(PUBLIC_READ_PER_MIN + 5))
        assert 429 not in statuses[:PUBLIC_READ_PER_MIN], (
            f"PUBLIC_READ_LIMIT tighter than {PUBLIC_READ_PER_MIN}/min: {set(statuses)}"
        )
        assert 429 in statuses[PUBLIC_READ_PER_MIN:], (
            "PUBLIC_READ_LIMIT not wired: 305 rapid reads from one IP never "
            f"produced a 429. observed set: {set(statuses)}"
        )
