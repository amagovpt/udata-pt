"""Regression test for the PRD random-logout bug.

`GET /api/1/me/` is polled by the frontend on every page load through a
server-side proxy (``frontend/src/app/me/route.ts``). Before the fix the
endpoint had no per-endpoint limit, so it fell under the IP-keyed global
default (``RATELIMIT_DEFAULT``). Behind the proxy every user reaches the
backend from the same source IP, so the shared ceiling was exhausted by
aggregated traffic and the backend started returning 429 — which the
frontend reads as "logged out", forcing a re-login that only succeeded once
the rate-limit window expired.

Fix: ``MeAPI`` GET is now rate-limited per authenticated user
(``user_or_ip``) with a generous ``IDENTITY_READ_LIMIT``. One user's polling
can no longer evict another, and a single source IP (the proxy) no longer
collapses everyone into one bucket.

Run:
    uv run pytest udata/tests/api/test_me_ratelimit_regression.py -v
"""

from flask import url_for

from udata.app import limiter
from udata.tests.api import APITestCase


def _status_distribution(responses):
    """Return a {status_code: count} dict for a list of responses."""
    counts = {}
    for r in responses:
        counts[r.status_code] = counts.get(r.status_code, 0) + 1
    return dict(sorted(counts.items()))


class MeRateLimitRegressionTest(APITestCase):
    def setUp(self):
        super().setUp() if hasattr(super(), "setUp") else None
        # Clean window per test so memory-storage counters don't leak.
        limiter.reset()

    def test_one_user_polling_does_not_lock_out_another_on_same_ip(self):
        """The core regression: two users behind one proxy IP must not share
        a bucket.

        Pre-fix the limit was IP-keyed, so heavy polling by user A would
        exhaust the shared per-IP ceiling and start returning 429 to user B —
        i.e. B is randomly "logged out" by A's traffic. Post-fix the key is
        ``user_or_ip``, so each authenticated user has an independent bucket.
        """
        proxy_ip = "10.0.0.1"

        # User A hammers /me past the per-minute ceiling from the proxy IP.
        self.login()
        a_responses = [
            self.get(url_for("api.me"), headers={"X-Forwarded-For": proxy_ip}) for _ in range(70)
        ]
        a_dist = _status_distribution(a_responses)
        print(f"\n[me rate-limit — user A] status distribution: {a_dist}")

        # A exceeded its own 60/min bucket, so it must see throttling — this
        # proves the limit is actually applied to GET /me.
        self.assertGreater(a_dist.get(429, 0), 0, f"GET /me was not rate-limited at all: {a_dist}")

        # User B logs in from the SAME proxy IP. Its bucket is independent, so
        # the very first poll must succeed — B is NOT collapsed into A's IP.
        self.login()
        b_response = self.get(url_for("api.me"), headers={"X-Forwarded-For": proxy_ip})
        self.assertEqual(
            b_response.status_code,
            200,
            "second user was locked out by the first user's polling — the /me "
            "limit is still IP-keyed (the random-logout bug)",
        )

    def test_normal_navigation_volume_is_never_throttled(self):
        """A realistic per-user poll volume stays well under the ceiling, so a
        legitimate session is never thrown a 429 (the symptom users reported).
        """
        self.login()
        responses = [self.get(url_for("api.me")) for _ in range(30)]
        dist = _status_distribution(responses)
        print(f"\n[me rate-limit — normal volume] status distribution: {dist}")
        self.assertEqual(dist.get(200, 0), 30, f"normal navigation volume was throttled: {dist}")
