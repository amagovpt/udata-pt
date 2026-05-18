"""End-to-end simulation of the VULN-2083 audit attack pattern.

Reproduces the KITS24 audit's Burp Intruder run against the discussions
endpoint — the screenshot shows ~99 discussions flooding a single dataset
(titles ``a1``..``a99``, comment ``aa``, same author, same subject) all
with timestamps within a few seconds of each other.

The replay mirrors the Burp run exactly so a failure surfaces the same
status-code distribution the auditor would see.

Run with:

    uv run pytest udata/tests/api/test_vuln_2083_discussion_audit_simulation.py -v

Companion suite to ``test_vuln_2078_audit_simulation.py``; same scaffolding,
different attack vector.
"""

from flask import url_for

from udata.app import limiter
from udata.core.dataset.factories import DatasetFactory
from udata.core.discussions.models import Discussion
from udata.tests.api import APITestCase


def _status_distribution(responses):
    """Return a {status_code: count} dict for a list of responses."""
    counts = {}
    for r in responses:
        counts[r.status_code] = counts.get(r.status_code, 0) + 1
    return dict(sorted(counts.items()))


class VULN2083DiscussionAuditSimulationTest(APITestCase):
    """Replays the Burp Intruder discussion-flood run against the patched code."""

    def setUp(self):
        super().setUp() if hasattr(super(), "setUp") else None
        # Reset the limiter so each test starts with a clean window. Without
        # this, consecutive tests would see leaking state and produce false
        # positives/negatives.
        limiter.reset()

    # ------------------------------------------------------------------
    # Vector 1 — exact Burp Intruder replay (titles a1..a99, comment aa)
    # ------------------------------------------------------------------

    def test_burp_intruder_replay_is_blocked(self):
        """Audit replay: 100 rapid POSTs creating discussions on one dataset.

        Pre-fix: all 100 returned 201, producing the "99 DISCUSSÕES" flood
        seen in the audit screenshot.
        Post-fix: at most 3 succeed inside the per-minute DISCUSSION_CREATE_LIMIT;
        the rest are throttled (429).
        """
        self.login()
        dataset = DatasetFactory()
        before = Discussion.objects.count()

        responses = []
        for i in range(100):
            payload = {
                # Same payload shape as the Burp Intruder run captured in the
                # VULN-2083 screenshot: title varies (a1..a100), comment is
                # constant, subject is the same dataset.
                "title": f"a{i + 1}",
                "comment": "aa",
                "subject": {"id": str(dataset.id), "class": "Dataset"},
            }
            responses.append(self.post(url_for("api.discussions"), payload))

        dist = _status_distribution(responses)
        print(f"\n[VULN-2083 vector 1 — discussions Burp replay] status distribution: {dist}")

        success = dist.get(201, 0)
        throttled = dist.get(429, 0)

        # Pre-fix the audit got 100 × 201. Post-fix DISCUSSION_CREATE_LIMIT
        # caps at 3/min — only the first 3 should pass.
        self.assertLessEqual(
            success, 3, f"too many discussions succeeded ({success}); rate-limit not effective"
        )
        self.assertGreaterEqual(throttled, 90, f"only {throttled} requests were throttled")

        # Database state — the audit produced 99 rows; we should see at most 3.
        persisted = Discussion.objects.count() - before
        self.assertLessEqual(persisted, 3, f"persisted {persisted} discussions (audit produced 99)")

    # ------------------------------------------------------------------
    # Vector 2 — dedup of identical (subject, user, title)
    # ------------------------------------------------------------------

    def test_dedup_blocks_identical_resubmission(self):
        """Re-posting the exact same (subject, user, title) triple within the
        dedupe window must yield 409 starting from the second attempt.

        Rate-limit is far from saturated at 2 requests (3/min), so any non-
        201 here is the dedup logic firing.
        """
        self.login()
        dataset = DatasetFactory()

        payload = {
            "title": "identical-title",
            "comment": "first body",
            "subject": {"id": str(dataset.id), "class": "Dataset"},
        }

        first = self.post(url_for("api.discussions"), payload)
        self.assert201(first)

        # Re-submit the same triple — must be 409, not a silent duplicate.
        second = self.post(url_for("api.discussions"), payload)
        self.assertEqual(
            second.status_code, 409, f"2nd identical submission returned {second.status_code}"
        )

        # Different title on same subject must still be accepted (proves the
        # dedup is title-aware, not a blanket per-subject lock).
        payload_other = dict(payload, title="other-title")
        third = self.post(url_for("api.discussions"), payload_other)
        self.assert201(third)

        self.assertEqual(Discussion.objects(subject=dataset).count(), 2)

    # ------------------------------------------------------------------
    # Vector 3 — per-user keying (rotating-IP bypass attempt)
    # ------------------------------------------------------------------

    def test_rotating_ip_does_not_bypass_per_user_limit(self):
        """Pre-fix the limiter was IP-keyed, so a rotating-proxy attacker
        could bypass it. Post-fix the key is `user_or_ip`, so spoofing
        X-Forwarded-For doesn't help once authenticated.
        """
        self.login()
        dataset = DatasetFactory()

        responses = []
        for i in range(20):
            payload = {
                "title": f"rotating-{i}",
                "comment": "audit",
                "subject": {"id": str(dataset.id), "class": "Dataset"},
            }
            responses.append(
                self.post(
                    url_for("api.discussions"),
                    payload,
                    headers={"X-Forwarded-For": f"203.0.113.{i % 250 + 1}"},
                )
            )

        dist = _status_distribution(responses)
        print(f"\n[VULN-2083 vector 3 — rotating IP] status distribution: {dist}")

        # Per-user limit must hold even with rotating source IPs.
        success = dist.get(201, 0)
        self.assertLessEqual(
            success, 3, f"per-user limit was bypassed ({success} successes via IP rotation)"
        )

    # ------------------------------------------------------------------
    # Vector 4 — listing GET is unaffected (regression check)
    # ------------------------------------------------------------------

    def test_list_get_is_not_throttled(self):
        """The rate-limit decorator is method-scoped (POST only). A flood of
        GETs must NOT be throttled at the per-endpoint layer.
        """
        responses = [self.get(url_for("api.discussions")) for _ in range(50)]
        dist = _status_distribution(responses)
        print(f"\n[VULN-2083 vector 4 — list GET] status distribution: {dist}")

        self.assertEqual(dist.get(200, 0), 50, f"GET listing was throttled: {dist}")
