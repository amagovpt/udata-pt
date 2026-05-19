"""End-to-end simulation of the VULN-2084 SSRF attack pattern.

Reproduces the KITS24 audit's Burp probe against the harvest preview
endpoint — the auditor submitted ``http://ama.http.interaction.s.inty.io``
as the ``url`` of a `POST /api/1/harvest/source/preview/` and the server
issued an out-of-band DNS lookup that landed on the auditor's collaborator
server.

The replay checks both layers of the fix (LEDG-1729):

1. The form-level denylist (`HarvestURLField` → `check_harvest_url`) MUST
   reject the URL **before** any DNS resolution happens.
2. The fetch-level guard in `BaseBackend.get/post/head` MUST reject the
   same URL even if a caller bypasses the form (e.g. a programmatic source
   creation, a fixture, or a DNS-rebinding attempt).

Run with:

    uv run pytest udata/tests/api/test_vuln_2084_harvest_ssrf_simulation.py -v
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from flask import url_for

from udata.harvest.exceptions import HarvestException
from udata.harvest.models import HarvestSource
from udata.harvest.tests.factories import FactoryBackend, MockBackendsMixin
from udata.tests.api import APITestCase
from udata.tests.helpers import assert200, assert400

# Public pentest canary services — same shape as `HARVEST_URL_HOST_DENYLIST`.
# Listed here so the test reads as a literal replay of the audit payloads.
PENTEST_CANARY_URLS = [
    "http://ama.http.interaction.s.inty.io",  # exact audit payload
    "http://example.interact.sh/x",
    "https://collaborator.burpcollaborator.net/x",
    "http://abc.oast.fun",
    "https://leak.oast.online/",
    "http://webhook.site/abc-123",
    "http://requestbin.com/r/abcdef",
]


class VULN2084HarvestSSRFSimulationTest(MockBackendsMixin, APITestCase):
    """Replays the audit's harvest-preview SSRF probe against the patched code."""

    # ------------------------------------------------------------------
    # Layer 1 — form-level denylist gate, runs BEFORE DNS resolution
    # ------------------------------------------------------------------

    def test_audit_replay_inty_io_is_blocked_without_dns_leak(self):
        """Exact audit payload: ``http://ama.http.interaction.s.inty.io``.

        Pre-fix: the form ran `URLField.pre_validate` → `uris.validate` →
        `udata.uris.resolve_hostname("ama.http.interaction.s.inty.io")`,
        leaking the DNS request to the auditor's collaborator.

        Post-fix: the deny pattern ``*.s.inty.io`` matches the hostname
        BEFORE the DNS resolution; `resolve_hostname` must not be invoked.
        """
        self.login()
        payload = {
            "name": "audit-replay",
            "url": "http://ama.http.interaction.s.inty.io",
            "backend": "factory",
        }

        # Only patch the *udata-side* resolver. Mocking socket.getaddrinfo
        # globally breaks MongoDB/Redis/Sentry probes inside the test
        # client setup — and is not necessary: the denylist gate runs
        # strictly before `uris.resolve_hostname`, which is the only path
        # the harvest URL validation could take to leak DNS.
        with patch(
            "udata.uris.resolve_hostname",
            side_effect=AssertionError("DNS leak: resolve_hostname called for blocked host"),
        ):
            response = self.post(url_for("api.preview_harvest_source_config"), payload)

        assert400(response)
        assert "s.inty.io" in str(response.json) or "blocked" in str(response.json).lower()

    def test_known_pentest_canaries_are_blocked(self):
        """All canary domains shipped in the default denylist must yield 400."""
        self.login()
        for u in PENTEST_CANARY_URLS:
            response = self.post(
                url_for("api.preview_harvest_source_config"),
                {"name": "x", "url": u, "backend": "factory"},
            )
            assert response.status_code == 400, (
                f"canary URL {u!r} returned {response.status_code}, expected 400"
            )

    def test_legitimate_public_url_still_passes_the_filter(self):
        """A normal harvest source URL (not in the denylist, allowlist=None)
        must still go through validation and reach the backend's harvest
        call — i.e. the guard is targeted, not a blanket block.
        """
        self.login()
        response = self.post(
            url_for("api.preview_harvest_source_config"),
            {"name": "ok", "url": "https://example.com/dcat", "backend": "factory"},
        )
        assert200(response)

    # ------------------------------------------------------------------
    # Layer 2 — backend fetch guard (defense in depth)
    # ------------------------------------------------------------------

    def test_backend_get_blocks_denied_host_even_if_form_was_bypassed(self):
        """A `HarvestSource` created programmatically (bypassing the form
        validator) MUST still be blocked at fetch time by `_guard_url`.

        Mirrors the DNS-rebinding scenario: hostname passed the form but
        resolves to a forbidden target later, or — as here — was never
        validated in the first place.
        """
        source = HarvestSource(name="rogue", url="http://example.com", backend="factory")
        backend = FactoryBackend(source, dryrun=True, max_items=1)

        with pytest.raises(HarvestException) as exc_info:
            backend.get("http://example.interact.sh/leak")

        assert (
            "interact.sh" in str(exc_info.value).lower() or "blocked" in str(exc_info.value).lower()
        )

    def test_backend_post_and_head_also_blocked(self):
        """The same `_guard_url` must fire on POST and HEAD, not just GET —
        protects against backends that use other verbs (e.g. CSW).
        """
        source = HarvestSource(name="rogue", url="http://example.com", backend="factory")
        backend = FactoryBackend(source, dryrun=True, max_items=1)

        with pytest.raises(HarvestException):
            backend.post("http://x.oast.fun/leak", data={})

        with pytest.raises(HarvestException):
            backend.head("http://x.burpcollaborator.net/leak")

    # ------------------------------------------------------------------
    # Layer 3 — allowlist tightening (opt-in, default off)
    # ------------------------------------------------------------------

    @pytest.mark.options(HARVEST_URL_HOST_ALLOWLIST=("*.gov.pt",))
    def test_allowlist_rejects_non_matching_hosts(self):
        """When `HARVEST_URL_HOST_ALLOWLIST` is set, hostnames outside the
        allowlist are rejected — proves the opt-in tightening works for
        operators that want a stricter posture (e.g. prod limited to gov.pt).
        """
        self.login()
        response = self.post(
            url_for("api.preview_harvest_source_config"),
            {"name": "x", "url": "https://example.com/dcat", "backend": "factory"},
        )
        assert400(response)

    @pytest.mark.options(HARVEST_URL_HOST_ALLOWLIST=("*.gov.pt",))
    def test_allowlist_accepts_matching_hosts(self):
        """Allowlist must accept hosts matching one of its glob patterns."""
        self.login()
        response = self.post(
            url_for("api.preview_harvest_source_config"),
            {
                "name": "x",
                "url": "https://dados.gov.pt/dcat",
                "backend": "factory",
            },
        )
        assert200(response)
