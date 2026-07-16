"""Regression suite for the Hydra metadata-writeback rate limits.

The `hydra-pt` crawler writes check/analysis results back to udata after every
resource check via authenticated callbacks (udata_hydra/utils/http.py `send()`):

* ``PUT/DELETE /api/2/datasets/<d>/resources/<rid>/extras/`` (primary target);
* ``PUT/DELETE /api/2/datasets/<d>/extras/`` (dataset-level writeback).

These carried NO explicit per-endpoint limit, so they fell under the IP-keyed
``RATELIMIT_DEFAULT`` ("200 per hour"). The crawler runs from a single origin IP
(and behind the F5/WAF everything collapses to one IP anyway,
docs/infra-adc-waf-impact-ppr-prd.md §4.2), so a full-catalog crawl exhausted
that 200/hour ceiling almost immediately and every subsequent callback returned
429 — the bot then dropped its analysis results.

Unlike the upload endpoints (which got TIGHTER limits than the default), the
writeback fix LIFTS these endpoints to a much HIGHER per-bot ceiling
(CRAWLER_WRITE_LIMIT = "1200 per minute; 60000 per hour"), keyed by
``user_or_ip`` so the authenticated bot gets its own bucket. So the regression
signature is the inverse of the upload suite: firing well PAST the old 200/hour
IP default must NOT produce a 429 — proving the endpoint escaped the collapsing
default rather than throttling at 200.

Method: fire requests ANONYMOUSLY. The limiter decorator wraps the view and runs
BEFORE ``@apiv2.secure``, so each anonymous PUT consumes a limiter slot (keyed by
IP via the user_or_ip fallback) and returns 401 — until a ceiling is crossed,
then 429. Under the old collapsing default the 201st request would be a 429;
under the fix it stays 401 far beyond that.

Run:
    uv run pytest udata/tests/api/test_extras_writeback_ratelimit_ip_collapse.py -v
"""

from uuid import uuid4

import pytest
from flask import url_for

from udata.app import limiter
from udata.core.dataset.factories import DatasetFactory
from udata.tests.api import PytestOnlyAPITestCase

RATELIMIT_OPTIONS = dict(RATELIMIT_ENABLED=True)

# The IP-keyed ``RATELIMIT_DEFAULT`` these endpoints used to fall under
# ("1000 per day;200 per hour"). Firing past the hourly figure is what used to
# 429 the crawler; the fix must let it through.
OLD_IP_DEFAULT_PER_HOUR = 200
# Comfortably past the old default but well under CRAWLER_WRITE_LIMIT's 1200/min,
# so a correct fix returns 401 (unauthenticated) for every request, never 429.
PROBE_COUNT = OLD_IP_DEFAULT_PER_HOUR + 10

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


def _assert_not_throttled_past_default(statuses, endpoint):
    """Assert no request was blocked, proving the endpoint no longer sits under
    the collapsing 200/hour IP default (it would 429 at request #201)."""
    blocked = [(i, s) for i, s in enumerate(statuses) if s in BLOCK_STATUSES]
    assert not blocked, (
        f"{endpoint}: {len(statuses)} anonymous writebacks from one IP hit a "
        f"block (429/403) at request(s) {blocked} — the endpoint is still under "
        f"the collapsing 200/h IP default instead of CRAWLER_WRITE_LIMIT. "
        f"statuses={statuses}"
    )


class ResourceExtrasWritebackLiftedAboveIpDefaultTest(PytestOnlyAPITestCase):
    """The primary Hydra target — ``PUT .../resources/<rid>/extras/`` — must
    carry CRAWLER_WRITE_LIMIT (1200/min, per-bot) rather than the IP-keyed
    200/hour default that 429s the crawler mid-catalog behind the F5/WAF."""

    @pytest.mark.options(**RATELIMIT_OPTIONS)
    def test_resource_extras_writeback_not_throttled_past_default(self):
        dataset = DatasetFactory()
        url = url_for("apiv2.resource_extras", dataset=dataset, rid=uuid4())
        statuses = _statuses(self.put(url, {"check:status": 200}) for _ in range(PROBE_COUNT))
        _assert_not_throttled_past_default(statuses, "apiv2.resource_extras")


class DatasetExtrasWritebackLiftedAboveIpDefaultTest(PytestOnlyAPITestCase):
    """Dataset-level writeback — ``PUT .../<d>/extras/`` — must carry the same
    per-bot CRAWLER_WRITE_LIMIT, not the collapsing 200/hour IP default."""

    @pytest.mark.options(**RATELIMIT_OPTIONS)
    def test_dataset_extras_writeback_not_throttled_past_default(self):
        dataset = DatasetFactory()
        url = url_for("apiv2.dataset_extras", dataset=dataset)
        statuses = _statuses(self.put(url, {"hydra:crawled": True}) for _ in range(PROBE_COUNT))
        _assert_not_throttled_past_default(statuses, "apiv2.dataset_extras")
