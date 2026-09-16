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

This module also owns `redact_url_credentials()`, the counterpart concern:
`URLS_ALLOW_CREDENTIALS` is true, so a harvest source URL may legitimately
carry `user:password@`. Anything derived from such a URL that is later served
-- a harvest error message, the source url copied onto a harvested
dataservice -- must have that userinfo removed first. See LEDG-2477.
"""

from __future__ import annotations

import fnmatch
import re
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


# `scheme://` followed by userinfo terminated by `@`. Per RFC 3986 section 3.2.1
# the userinfo component cannot contain `/`, `?`, `#` or whitespace unless
# percent-encoded, so `[^/?#\s]*` cannot run past the end of one URL into the
# next. Being greedy, it also handles an unencoded `@` inside a password
# (`user:p@ss@host` -> `***@host`). There is no nested quantifier, so matching
# stays linear.
_URL_USERINFO_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)[^/?#\s]*@")


def redact_url_credentials(text: str | None) -> str | None:
    """Replace the userinfo of every URL in `text` with `***`.

    Takes free-form text, not a URL: the input is typically an exception
    message with a URL somewhere inside it, and there is no reliable way to
    tell where a URL ends in prose. That is why this uses a regex rather than
    `urlsplit`, unlike `HarvestSource.domain`, whose input really is a URL.

    The whole userinfo goes, username included: in many services the username
    alone is the secret (an API token used as the basic-auth user). The `***@`
    marker is kept so that whoever reads the message can still tell the URL
    carried credentials.

    Pure and idempotent; returns `None` and `""` unchanged.
    """
    if not text:
        return text
    return _URL_USERINFO_RE.sub(r"\1***@", text)
