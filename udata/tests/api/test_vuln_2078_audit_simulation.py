"""End-to-end simulation of the VULN-2078 audit attack pattern.

Reproduces the KITS24 audit's Burp Intruder run (100+ rapid POSTs to
`/api/1/datasets/community_resources/`) against the patched code, plus the
adjacent attack vectors that the same class of bug exposes:

- Mass-creation on every other content-creation endpoint protected by the
  fix (datasets, reuses, organizations, discussions, /me/avatar).
- Per-user keying — verifies that a single attacker still hits the limit
  even from rotating "IPs" (simulated by varying `X-Forwarded-For`).
- Deduplication — verifies identical resubmissions return 409.

Run with:

    uv run pytest udata/tests/api/test_vuln_2078_audit_simulation.py -v

This is a *validation* / *security-regression* suite. It is intentionally
loud about counters so failures show the same kind of evidence the audit
produced (status-code distribution).
"""

from flask import url_for

from udata.app import limiter
from udata.core.dataset.factories import (
    CommunityResourceFactory,
    DatasetFactory,
    ResourceFactory,
)
from udata.core.dataset.models import CommunityResource, Dataset
from udata.core.discussions.models import Discussion
from udata.core.organization.models import Organization
from udata.core.reuse.models import Reuse
from udata.tests.api import APITestCase


def _status_distribution(responses):
    """Return a {status_code: count} dict for a list of responses."""
    counts = {}
    for r in responses:
        counts[r.status_code] = counts.get(r.status_code, 0) + 1
    return dict(sorted(counts.items()))


class VULN2078AuditSimulationTest(APITestCase):
    """Reproduces the audit's Burp Intruder run against the patched code."""

    def setUp(self):
        super().setUp() if hasattr(super(), "setUp") else None
        # Reset the limiter so each test starts with a clean window. Without
        # this, consecutive tests would see leaking state and produce false
        # positives/negatives.
        limiter.reset()

    # ------------------------------------------------------------------
    # Vector 1 — community_resources mass-submission (the original PoC)
    # ------------------------------------------------------------------

    def test_vector_1_burp_intruder_replay_is_blocked(self):
        """Audit replay: 100 rapid POSTs to community_resources/.

        Pre-fix: all 100 returned 201, producing the "106 RECURSOS COMUNITÁRIOS"
        flood seen in the audit screenshot.
        Post-fix: only the first ~5 succeed inside the per-minute window;
        subsequent attempts are throttled (429) or rejected as duplicates (409).
        """
        self.login()
        dataset = DatasetFactory()

        responses = []
        for i in range(100):
            attrs = CommunityResourceFactory.as_dict()
            attrs["filetype"] = "remote"
            attrs["dataset"] = str(dataset.id)
            # Vary URL so the dedup logic isn't the only thing throwing 409s —
            # we want to see the rate-limit kick in too.
            attrs["url"] = f"https://example.com/audit-replay-{i}.csv"
            responses.append(self.post(url_for("api.community_resources"), attrs))

        dist = _status_distribution(responses)
        print(f"\n[VULN-2078 vector 1 — community_resources] status distribution: {dist}")

        # Successful creations capped — the rest blocked.
        success = dist.get(201, 0)
        throttled = dist.get(429, 0)

        # Pre-fix the audit got 100 × 201. Post-fix we expect at most a handful
        # succeed and the bulk are rejected with 429.
        self.assertLessEqual(
            success, 5, f"too many succeeded ({success}); rate-limit not effective"
        )
        self.assertGreaterEqual(throttled, 90, f"only {throttled} requests were throttled")

        # Database state — the audit produced 106 rows; we should see at most 5.
        persisted = CommunityResource.objects(dataset=dataset).count()
        self.assertLessEqual(persisted, 5, f"persisted {persisted} community resources")

    def test_vector_1_dedup_blocks_identical_url_resubmission(self):
        """Re-posting the exact same (dataset, owner, url) triple within the
        dedup window must yield 409 starting from the second attempt.
        """
        self.login()
        dataset = DatasetFactory()

        attrs = CommunityResourceFactory.as_dict()
        attrs["filetype"] = "remote"
        attrs["dataset"] = str(dataset.id)
        attrs["url"] = "https://example.com/identical.csv"

        first = self.post(url_for("api.community_resources"), attrs)
        self.assert201(first)

        second = self.post(url_for("api.community_resources"), attrs)
        third = self.post(url_for("api.community_resources"), attrs)

        # Both follow-ups must be 409 (deduplication). Rate-limit (429) would
        # also be acceptable, but on the 2nd attempt we have not exceeded 5/min.
        self.assertEqual(
            second.status_code, 409, f"2nd identical submission returned {second.status_code}"
        )
        self.assertEqual(
            third.status_code, 409, f"3rd identical submission returned {third.status_code}"
        )
        self.assertEqual(CommunityResource.objects(dataset=dataset).count(), 1)

    # ------------------------------------------------------------------
    # Vector 2 — same class of bug on adjacent endpoints
    # ------------------------------------------------------------------

    def test_vector_2_dataset_mass_creation_is_blocked(self):
        """POST /api/1/datasets/ replayed 100×."""
        self.login()
        before = Dataset.objects.count()

        responses = []
        for i in range(100):
            payload = {
                "title": f"Audit dataset {i}",
                "description": "audit",
            }
            responses.append(self.post(url_for("api.datasets"), payload))

        dist = _status_distribution(responses)
        print(f"\n[VULN-2078 vector 2 — datasets] status distribution: {dist}")

        success = dist.get(201, 0)
        self.assertLessEqual(success, 5, f"too many datasets created ({success})")
        self.assertGreaterEqual(dist.get(429, 0), 90)
        self.assertLessEqual(Dataset.objects.count() - before, 5)

    def test_vector_2_reuse_mass_creation_is_blocked(self):
        """POST /api/1/reuses/ replayed 100×."""
        self.login()
        dataset = DatasetFactory()
        before = Reuse.objects.count()

        responses = []
        for i in range(100):
            payload = {
                "title": f"Audit reuse {i}",
                "type": "api",
                "url": f"https://example.com/audit-reuse-{i}",
                "description": "audit",
                "datasets": [{"id": str(dataset.id), "class": "Dataset"}],
            }
            responses.append(self.post(url_for("api.reuses"), payload))

        dist = _status_distribution(responses)
        print(f"\n[VULN-2078 vector 2 — reuses] status distribution: {dist}")

        success = dist.get(201, 0)
        self.assertLessEqual(success, 5, f"too many reuses created ({success})")
        self.assertGreaterEqual(dist.get(429, 0), 90)
        self.assertLessEqual(Reuse.objects.count() - before, 5)

    def test_vector_2_organization_mass_creation_is_blocked(self):
        """POST /api/1/organizations/ replayed 100×.

        Heavier limit profile (HEAVY_CREATE_LIMIT = 2/min, 5/h, 10/day) — only
        the first 2 should succeed inside the per-minute window.
        """
        self.login()
        before = Organization.objects.count()

        responses = []
        for i in range(100):
            payload = {
                "name": f"Audit org {i}",
                "description": "audit",
            }
            responses.append(self.post(url_for("api.organizations"), payload))

        dist = _status_distribution(responses)
        print(f"\n[VULN-2078 vector 2 — organizations] status distribution: {dist}")

        success = dist.get(201, 0)
        # HEAVY_CREATE_LIMIT is 2/min — only 2 should pass.
        self.assertLessEqual(success, 2, f"too many organizations created ({success})")
        self.assertGreaterEqual(dist.get(429, 0), 95)
        self.assertLessEqual(Organization.objects.count() - before, 2)

    def test_vector_2_discussion_mass_creation_is_blocked(self):
        """POST /api/1/discussions/ replayed 100×."""
        self.login()
        dataset = DatasetFactory()
        before = Discussion.objects.count()

        responses = []
        for i in range(100):
            payload = {
                "title": f"Audit discussion {i}",
                "comment": "audit",
                "subject": {"id": str(dataset.id), "class": "Dataset"},
            }
            responses.append(self.post(url_for("api.discussions"), payload))

        dist = _status_distribution(responses)
        print(f"\n[VULN-2078 vector 2 — discussions] status distribution: {dist}")

        success = dist.get(201, 0)
        self.assertLessEqual(success, 5, f"too many discussions created ({success})")
        self.assertGreaterEqual(dist.get(429, 0), 90)
        self.assertLessEqual(Discussion.objects.count() - before, 5)

    # ------------------------------------------------------------------
    # Vector 3 — per-user keying (rotating-IP bypass attempt)
    # ------------------------------------------------------------------

    def test_vector_3_rotating_ip_does_not_bypass_per_user_limit(self):
        """Pre-fix: the limiter was IP-keyed, so an attacker behind a rotating
        proxy / VPN could send unlimited requests by changing source IPs.

        Post-fix: the per-endpoint key is `user_or_ip`, which prefers the
        authenticated user id. Even if every request appears to come from a
        different IP (X-Forwarded-For varied), the user-keyed limit still
        applies.
        """
        self.login()
        dataset = DatasetFactory()

        responses = []
        for i in range(50):
            attrs = CommunityResourceFactory.as_dict()
            attrs["filetype"] = "remote"
            attrs["dataset"] = str(dataset.id)
            attrs["url"] = f"https://example.com/rotating-ip-{i}.csv"
            # Spoof a different source IP for every request.
            responses.append(
                self.post(
                    url_for("api.community_resources"),
                    attrs,
                    headers={"X-Forwarded-For": f"203.0.113.{i % 250 + 1}"},
                )
            )

        dist = _status_distribution(responses)
        print(f"\n[VULN-2078 vector 3 — rotating IP] status distribution: {dist}")

        # The user-keyed limit must still apply.
        success = dist.get(201, 0)
        self.assertLessEqual(
            success, 5, f"per-user limit was bypassed ({success} successes via IP rotation)"
        )

    # ------------------------------------------------------------------
    # Vector 4 — listing GETs are unaffected (regression check)
    # ------------------------------------------------------------------

    def test_vector_4_list_get_is_not_throttled(self):
        """The rate-limit decorators are method-scoped (POST only). A flood of
        GETs to the same endpoint must NOT be throttled at the per-endpoint
        layer (only by the global ceiling, far higher).
        """
        # Pre-seed a couple of resources so the GET has something to list.
        for _ in range(3):
            ResourceFactory()

        responses = [self.get(url_for("api.community_resources")) for _ in range(50)]
        dist = _status_distribution(responses)
        print(f"\n[VULN-2078 vector 4 — list GET] status distribution: {dist}")

        # All 50 should be 200; if any are 429 the per-endpoint decorator is
        # leaking onto GET, which would be a regression.
        self.assertEqual(dist.get(200, 0), 50, f"GET listing was throttled: {dist}")

    # ------------------------------------------------------------------
    # Vector 5 — production wiring: RATELIMIT_STORAGE_URI must be honored
    # ------------------------------------------------------------------

    def test_vector_5_storage_uri_from_config_is_honored(self):
        """Regression test: the Limiter() must read its storage backend from
        `RATELIMIT_STORAGE_URI` in app config, not from a hardcoded value in
        the constructor.

        Pre-fix the Limiter was instantiated with `storage_uri="memory://"`,
        which silently overrides the config. Production deploys configured
        Redis but were actually running on per-process memory storage,
        rendering the rate-limit useless across multiple gunicorn workers.

        We swap the config to a Redis URI and verify the limiter actually
        switches storage class. If the constructor fallback regresses, the
        storage will stay `MemoryStorage` regardless of config.
        """
        from udata.app import limiter

        # The local docker-compose stack always has Redis available on 6379;
        # if it isn't, this test is a no-op (skipped) rather than a false fail.
        try:
            import redis

            redis.Redis(host="localhost", port=6379).ping()
        except Exception:
            self.skipTest("local Redis not reachable on localhost:6379")

        original_uri = self.app.config.get("RATELIMIT_STORAGE_URI")
        try:
            self.app.config["RATELIMIT_STORAGE_URI"] = "redis://localhost:6379/3"
            limiter.init_app(self.app)
            storage_class = type(limiter.storage).__name__
            self.assertEqual(
                storage_class,
                "RedisStorage",
                f"limiter is using {storage_class} despite Redis config — "
                "the constructor likely shadows RATELIMIT_STORAGE_URI again",
            )
        finally:
            self.app.config["RATELIMIT_STORAGE_URI"] = original_uri or "memory://"
            limiter.init_app(self.app)
