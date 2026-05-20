"""External resource download proxy — see LEDG-1214.

Forces user-facing download of resources whose origin lacks
`Content-Disposition: attachment`. The portal fetches the resource
server-side and streams it back to the browser with the header injected.

SSRF reuse
----------
Same threat model as harvest source fetching (LEDG-1729 / VULN-2084):
the server fetches a caller-supplied URL. We reuse both guards in
order — pattern denylist first (no I/O, so OOB canaries never reach
`socket.getaddrinfo`), then DNS resolution with private/loopback-IP
rejection.
"""

from __future__ import annotations

import re
from urllib.parse import unquote, urlparse

import requests
from flask import Response, current_app, stream_with_context

import udata.uris as uris
from udata.harvest.url_filter import HarvestURLForbidden, check_harvest_url


class ProxyDownloadForbidden(ValueError):
    """Raised when an external URL is rejected by the proxy SSRF guard."""


class ProxyDownloadTooLarge(ValueError):
    """Raised when the streamed response exceeds `DOWNLOAD_PROXY_MAX_BYTES`."""


def check_external_url(url: str) -> None:
    """Run the SSRF guard against `url`.

    Order matters: the pattern denylist runs first (no I/O), then DNS
    resolution with private-IP rejection. Out-of-band canaries are stopped
    before any hostname lookup.

    `uris.validate` is called with explicit `local=False, private=False`
    so the proxy never fetches loopback or private-network addresses, even
    when the global `URLS_ALLOW_LOCAL` / `URLS_ALLOW_PRIVATE` config is
    permissive (the test environment legitimately sets `URLS_ALLOW_LOCAL=
    True` to talk to `local.test`, but the proxy must remain strict).
    """
    try:
        check_harvest_url(url)
    except HarvestURLForbidden as e:
        raise ProxyDownloadForbidden(str(e))
    try:
        uris.validate(url, local=False, private=False)
    except uris.ValidationError as e:
        raise ProxyDownloadForbidden(str(e))


# Strip control chars and path / quoting metacharacters that break the
# RFC 6266 quoted-string form of `Content-Disposition`.
_FILENAME_UNSAFE = re.compile(r'[\x00-\x1f"\\/:*?<>|]+')


def derive_filename(url: str, fallback: str | None = None) -> str:
    """Build a safe filename for `Content-Disposition`.

    Priority: explicit `fallback` (caller arg / resource title) → last path
    segment of `url` → literal `"download"`. Control chars and path
    separators are replaced with `_`.
    """
    candidate = fallback or urlparse(url).path.rsplit("/", 1)[-1]
    candidate = unquote(candidate or "").strip()
    candidate = _FILENAME_UNSAFE.sub("_", candidate)
    return candidate or "download"


def open_upstream(url: str) -> requests.Response:
    """Open a streaming GET against `url` with the proxy's timeouts.

    Redirects are disabled — following them would let an origin point us at a
    denylisted or private host bypassing `check_external_url`. The caller is
    responsible for closing the returned response.
    """
    connect = current_app.config["DOWNLOAD_PROXY_CONNECT_TIMEOUT_S"]
    read = current_app.config["DOWNLOAD_PROXY_READ_TIMEOUT_S"]
    response = requests.get(
        url,
        stream=True,
        timeout=(connect, read),
        allow_redirects=False,
    )
    response.raise_for_status()
    return response


def iter_capped(response: requests.Response):
    """Yield chunks from `response`, capping at `DOWNLOAD_PROXY_MAX_BYTES`.

    Closes the upstream response on completion or overflow. Raises
    `ProxyDownloadTooLarge` mid-stream when the cap is exceeded — Flask will
    propagate the exception and abort the response, so the browser sees a
    truncated download rather than a successful one with bad data.
    """
    max_bytes = current_app.config["DOWNLOAD_PROXY_MAX_BYTES"]
    total = 0
    try:
        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                continue
            total += len(chunk)
            if total > max_bytes:
                raise ProxyDownloadTooLarge(
                    f"Response exceeded DOWNLOAD_PROXY_MAX_BYTES ({max_bytes} bytes)"
                )
            yield chunk
    finally:
        response.close()


def stream_as_attachment(url: str, filename_hint: str | None = None) -> Response:
    """End-to-end helper: validate, fetch, and stream `url` as an attachment.

    Combines `check_external_url` + `open_upstream` + `iter_capped` and
    builds a Flask `Response` with `Content-Disposition: attachment` and
    the upstream `Content-Type` (or `application/octet-stream` when the
    origin omits it). Reused by both the proxy endpoint and the
    `/r/<id>/` resource redirect for `remote` resources.

    Raises:
        ProxyDownloadForbidden: when the URL is rejected by the SSRF guard.
        requests.RequestException: when the upstream call fails.

    Callers are expected to map those to their preferred HTTP status codes.
    """
    check_external_url(url)
    upstream = open_upstream(url)
    filename = derive_filename(url, fallback=filename_hint)
    content_type = upstream.headers.get("Content-Type") or "application/octet-stream"
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Cache-Control": "no-cache, no-store",
    }
    return Response(
        stream_with_context(iter_capped(upstream)),
        status=200,
        content_type=content_type,
        headers=headers,
    )
