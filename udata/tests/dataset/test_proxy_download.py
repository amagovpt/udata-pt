"""Tests for the resource download proxy — LEDG-1214.

Covers:
- `derive_filename` purity and sanitization.
- SSRF guard reuse (canary denylist + private/loopback IPs).
- `iter_capped` truncation at `DOWNLOAD_PROXY_MAX_BYTES`.
- Timeout resolution and its in-code fallbacks (LEDG-2249).
- Endpoint contract: status codes, Content-Disposition, Content-Type,
  Cache-Control, and `allow_redirects=False` on the outbound call.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests
from flask import url_for

from udata.core.dataset.download_proxy import (
    DEFAULT_CONNECT_TIMEOUT_S,
    DEFAULT_MAX_BYTES,
    DEFAULT_READ_TIMEOUT_S,
    ProxyDownloadForbidden,
    ProxyDownloadTooLarge,
    check_external_url,
    derive_filename,
    iter_capped,
    open_upstream,
)
from udata.settings import Defaults
from udata.tests.api import APITestCase


def _build_mock_response(body=b"hello", content_type="text/plain"):
    """Return a `requests.Response`-shaped mock yielding `body` once."""
    m = MagicMock()
    m.headers = {"Content-Type": content_type}
    m.status_code = 200
    m.iter_content = MagicMock(return_value=iter([body]))
    m.raise_for_status = MagicMock()
    return m


# ----------------------------------------------------------------------
# Pure helpers — no I/O, no Flask
# ----------------------------------------------------------------------


class TestDeriveFilename:
    def test_uses_fallback_when_provided(self):
        assert derive_filename("https://x.gov.pt/any", "export.csv") == "export.csv"

    def test_falls_back_to_url_last_segment(self):
        assert derive_filename("https://x.gov.pt/path/to/file.pdf") == "file.pdf"

    def test_returns_default_when_path_empty(self):
        assert derive_filename("https://x.gov.pt/") == "download"
        assert derive_filename("https://x.gov.pt") == "download"

    def test_strips_path_traversal_and_quotes(self):
        out = derive_filename("https://x.gov.pt/", 'bad/name"file<x>:|*?')
        assert "/" not in out
        assert '"' not in out
        assert "<" not in out
        assert "|" not in out

    def test_strips_control_characters(self):
        out = derive_filename("https://x.gov.pt/", "a\x00b\x01c.csv")
        assert "\x00" not in out and "\x01" not in out

    def test_url_decodes_path_segment(self):
        assert derive_filename("https://x.gov.pt/some%20file.pdf") == "some file.pdf"


# ----------------------------------------------------------------------
# SSRF guard and streaming cap — need Flask app config
# ----------------------------------------------------------------------


class ProxyDownloadHelpersTest(APITestCase):
    def test_check_rejects_canary_host(self):
        """`*.s.inty.io` is in the default denylist (shared with harvest)."""
        with pytest.raises(ProxyDownloadForbidden):
            check_external_url("http://x.s.inty.io/probe")

    def test_check_rejects_loopback_ip(self):
        with pytest.raises(ProxyDownloadForbidden):
            check_external_url("http://127.0.0.1/anything")

    def test_check_rejects_private_ip(self):
        with pytest.raises(ProxyDownloadForbidden):
            check_external_url("http://10.0.0.5/anything")

    @pytest.mark.options(DOWNLOAD_PROXY_MAX_BYTES=10)
    def test_iter_capped_truncates_when_over_limit(self):
        """Two 8-byte chunks with a 10-byte cap: first passes, second trips."""
        chunks = [b"x" * 8, b"x" * 8]
        resp = MagicMock()
        resp.iter_content = MagicMock(return_value=iter(chunks))
        resp.close = MagicMock()

        consumed = []
        with pytest.raises(ProxyDownloadTooLarge):
            for c in iter_capped(resp):
                consumed.append(c)

        assert consumed == [b"x" * 8]  # first chunk passed before the cap tripped
        resp.close.assert_called_once()

    def test_iter_capped_closes_upstream_on_normal_completion(self):
        resp = MagicMock()
        resp.iter_content = MagicMock(return_value=iter([b"hello"]))
        resp.close = MagicMock()
        list(iter_capped(resp))
        resp.close.assert_called_once()


# ----------------------------------------------------------------------
# Timeout resolution — regression guard for LEDG-2249
# ----------------------------------------------------------------------


class ProxyDownloadTimeoutConfigTest(APITestCase):
    """The read timeout drifted to 10s in PRD and 502-ed every slow upstream.

    These lock down the two halves of that failure: the shipped default must
    stay generous, and a config that omits the keys must fall back to it
    instead of raising `KeyError` from inside a request.
    """

    def _timeout_of_call(self, url="https://example.com/x.pdf"):
        """Return the `timeout=` kwarg `open_upstream` passed to `requests.get`."""
        with patch(
            "udata.core.dataset.download_proxy.requests.get",
            return_value=_build_mock_response(),
        ) as g:
            open_upstream(url)
        _, kwargs = g.call_args
        return kwargs.get("timeout")

    @pytest.mark.options(
        DOWNLOAD_PROXY_CONNECT_TIMEOUT_S=7,
        DOWNLOAD_PROXY_READ_TIMEOUT_S=99,
    )
    def test_uses_configured_timeouts(self):
        assert self._timeout_of_call() == (7, 99)

    def test_falls_back_when_config_omits_keys(self):
        """A `udata.cfg` predating the proxy section must not 500 the request."""
        self.app.config.pop("DOWNLOAD_PROXY_CONNECT_TIMEOUT_S", None)
        self.app.config.pop("DOWNLOAD_PROXY_READ_TIMEOUT_S", None)
        assert self._timeout_of_call() == (DEFAULT_CONNECT_TIMEOUT_S, DEFAULT_READ_TIMEOUT_S)

    def test_iter_capped_falls_back_when_config_omits_max_bytes(self):
        self.app.config.pop("DOWNLOAD_PROXY_MAX_BYTES", None)
        resp = MagicMock()
        resp.iter_content = MagicMock(return_value=iter([b"hello"]))
        resp.close = MagicMock()
        assert b"".join(iter_capped(resp)) == b"hello"

    def test_shipped_default_read_timeout_stays_generous(self):
        """The in-code fallback and `Defaults` must not diverge.

        The read timeout is an inter-chunk budget: lowering it truncates
        downloads that are already streaming, so a change here is a
        deliberate decision, not a tuning knob to nudge.
        """
        assert DEFAULT_READ_TIMEOUT_S == 300
        assert Defaults.DOWNLOAD_PROXY_READ_TIMEOUT_S == DEFAULT_READ_TIMEOUT_S
        assert Defaults.DOWNLOAD_PROXY_CONNECT_TIMEOUT_S == DEFAULT_CONNECT_TIMEOUT_S
        assert Defaults.DOWNLOAD_PROXY_MAX_BYTES == DEFAULT_MAX_BYTES

    def test_deployment_config_does_not_lower_read_timeout(self):
        """Catch the drift where it actually happened: the loaded config.

        `Defaults` was never wrong in PRD — `udata.cfg` (or a `.env` feeding
        it) overrode the read timeout downwards. This asserts the *effective*
        value of the app under test, so lowering it in either place fails here
        rather than surfacing as a `502` in production. Raising it is fine.
        """
        effective = self.app.config["DOWNLOAD_PROXY_READ_TIMEOUT_S"]
        assert effective >= DEFAULT_READ_TIMEOUT_S, (
            f"DOWNLOAD_PROXY_READ_TIMEOUT_S is {effective}s, below the "
            f"{DEFAULT_READ_TIMEOUT_S}s floor. The read timeout is an "
            "inter-chunk budget: a short value truncates downloads already in "
            "progress. Check udata.cfg and the environment before relaxing this."
        )


# ----------------------------------------------------------------------
# Endpoint
# ----------------------------------------------------------------------


class ProxyDownloadEndpointTest(APITestCase):
    def _endpoint(self):
        return url_for("api.proxy_download")

    def test_400_when_url_missing(self):
        response = self.get(self._endpoint())
        assert response.status_code == 400

    def test_403_when_canary_url(self):
        response = self.get(self._endpoint() + "?url=http://x.s.inty.io/probe")
        assert response.status_code == 403

    def test_403_when_loopback_url(self):
        response = self.get(self._endpoint() + "?url=http://127.0.0.1/anything")
        assert response.status_code == 403

    def test_502_when_upstream_fails(self):
        with patch(
            "udata.core.dataset.download_proxy.requests.get",
            side_effect=requests.exceptions.ConnectionError("boom"),
        ):
            response = self.get(self._endpoint() + "?url=https://example.com/x.pdf")
        assert response.status_code == 502

    def test_200_attachment_header_and_content_type_propagated(self):
        mock_resp = _build_mock_response(body=b"hello", content_type="application/pdf")
        with patch(
            "udata.core.dataset.download_proxy.requests.get",
            return_value=mock_resp,
        ) as g:
            response = self.get(self._endpoint() + "?url=https://example.com/some/file.pdf")

        assert response.status_code == 200
        assert response.headers["Content-Type"].startswith("application/pdf")
        cd = response.headers["Content-Disposition"]
        assert cd.startswith("attachment;")
        assert 'filename="file.pdf"' in cd
        # `allow_redirects=False` is the SSRF defense — verify it stuck.
        g.assert_called_once()
        _, kwargs = g.call_args
        assert kwargs.get("allow_redirects") is False
        assert kwargs.get("stream") is True

    def test_filename_query_overrides_url_segment(self):
        mock_resp = _build_mock_response(body=b"a,b\n", content_type="text/csv")
        with patch(
            "udata.core.dataset.download_proxy.requests.get",
            return_value=mock_resp,
        ):
            response = self.get(
                self._endpoint() + "?url=https://example.com/api/csv&filename=export.csv"
            )
        assert response.status_code == 200
        assert 'filename="export.csv"' in response.headers["Content-Disposition"]

    def test_response_has_cache_control_no_store(self):
        mock_resp = _build_mock_response()
        with patch(
            "udata.core.dataset.download_proxy.requests.get",
            return_value=mock_resp,
        ):
            response = self.get(self._endpoint() + "?url=https://example.com/x")
        assert "no-store" in response.headers["Cache-Control"]

    def test_default_content_type_when_upstream_missing(self):
        mock_resp = MagicMock()
        mock_resp.headers = {}  # upstream did not advertise a Content-Type
        mock_resp.status_code = 200
        mock_resp.iter_content = MagicMock(return_value=iter([b"raw"]))
        mock_resp.raise_for_status = MagicMock()
        with patch(
            "udata.core.dataset.download_proxy.requests.get",
            return_value=mock_resp,
        ):
            response = self.get(self._endpoint() + "?url=https://example.com/blob")
        assert response.headers["Content-Type"].startswith("application/octet-stream")
