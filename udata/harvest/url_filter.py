"""Harvest source URL host filter — SSRF guard for the harvest endpoints.

Defends `POST /api/1/harvest/source/preview/` and other harvest source-creating
endpoints from being weaponized as out-of-band SSRF probes (CWE-918). See
LEDG-1729 / VULN-2084.

Two complementary lists, applied to the URL hostname BEFORE
`udata.uris.validate` runs its DNS resolution:

- `HARVEST_URL_HOST_DENYLIST`: glob patterns for known pentest canary
  services (Burp Collaborator, Interactsh, oast.*). Matched first, always
  enforced.
- `HARVEST_URL_HOST_ALLOWLIST`: optional glob patterns. When set, the
  hostname must match at least one pattern; otherwise rejected. `None`
  (default) skips the allowlist check entirely.

A blocked hostname never reaches `socket.getaddrinfo`, so the audit's
out-of-band DNS leak is closed in addition to the actual HTTP request.

The same `check_harvest_url()` helper is reused inside the backend fetch
path as a defense-in-depth check against DNS rebinding (URL passed form
validation but the hostname resolves elsewhere at fetch time).
"""

from __future__ import annotations

import fnmatch
from urllib.parse import urlparse

from flask import current_app

from udata.i18n import lazy_gettext as _


class HarvestURLForbidden(ValueError):
    """Raised when a harvest source URL is rejected by the SSRF guard."""


def _hostname(url: str) -> str | None:
    try:
        return urlparse(url.strip()).hostname
    except (ValueError, AttributeError):
        return None


def _match_any(hostname: str, patterns) -> bool:
    if not patterns:
        return False
    hostname = hostname.lower()
    return any(fnmatch.fnmatch(hostname, p.lower()) for p in patterns)


def check_harvest_url(url: str) -> None:
    """Raise `HarvestURLForbidden` if the URL hostname is denied.

    Reads `HARVEST_URL_HOST_DENYLIST` and `HARVEST_URL_HOST_ALLOWLIST`
    from the Flask app config. No I/O — pure pattern matching.
    """
    hostname = _hostname(url)
    if not hostname:
        raise HarvestURLForbidden(_("Invalid harvest source URL"))

    denylist = current_app.config.get("HARVEST_URL_HOST_DENYLIST") or ()
    if _match_any(hostname, denylist):
        raise HarvestURLForbidden(
            _("Host '{host}' is blocked for harvest sources").format(host=hostname)
        )

    allowlist = current_app.config.get("HARVEST_URL_HOST_ALLOWLIST")
    if allowlist is not None and not _match_any(hostname, allowlist):
        raise HarvestURLForbidden(
            _("Host '{host}' is not in the harvest source allowlist").format(host=hostname)
        )
