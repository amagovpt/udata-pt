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
dataservice, a resource URL or a remote id a backend builds out of it -- must
have that userinfo removed first. See LEDG-2477 and LEDG-2500.
"""

from __future__ import annotations

import fnmatch
import re
from urllib.parse import urlparse, urlsplit, urlunsplit

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


# The authority of a URL, up to the `@` that ends its userinfo. The scheme is
# optional because `udata.uris.validate` accepts a scheme-relative URL
# (`//user:pass@host/x`), so a source really can be stored in that shape.
#
# The character class is the authority alphabet of RFC 3986 (unreserved,
# percent-encoded, sub-delims, `:`, `@`, and the brackets of an IPv6 literal).
# It deliberately stops at a quote, an angle bracket or a brace: harvest error
# messages carry raw JSON and whole CSW XML documents, where a URL is followed
# immediately -- with no space -- by another field that may hold an email
# address. A looser class would swallow everything in between and print a
# `***@` marker for a source that has no credentials at all.
#
# `@` is inside the class on purpose: being greedy, the match then ends at the
# LAST `@` of the authority, which is what redacts a password containing an
# unencoded `@`. There is no nested quantifier, so matching stays linear.
_URL_USERINFO_RE = re.compile(
    r"(?i)((?:[a-z][a-z0-9+.\-]*:)?//)[A-Za-z0-9\-._~%!$&'()*+,;=:@\[\]]*@"
)


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
    # Runs on every harvest error of every item, and a failing INE harvest
    # saves the job once per item over thousands of items, so the common case
    # -- a message with no `@` in it at all -- must not pay for the scan.
    if not text or "@" not in text:
        return text
    return _URL_USERINFO_RE.sub(r"\1***@", text)


def redact_url_credentials_in_url(url: str | None) -> str | None:
    r"""Replace the userinfo of `url` with `***`. For input that IS a URL.

    The counterpart of `redact_url_credentials` for a field whose whole value
    is a URL -- a resource URL, a harvest item remote id -- rather than prose
    with a URL somewhere inside it. Splitting is both stricter and safer there,
    in the two directions the regex cannot be:

    - It redacts userinfo the regex misses. `udata.uris.URL_REGEX` accepts
      `\S+(?::\S*)?@`, so this portal really accepts (and `requests` really
      sends) a password holding `{`, `|`, `^`, `"`, `<`, `>` or a backtick --
      none of which are in the RFC 3986 authority alphabet the free-text regex
      has to stop at, because in prose it cannot tell where the URL ends.
    - It never reaches past the authority. `https://host/files//report@2026.csv`
      is a legitimate URL that the regex rewrites into `//***@2026.csv`, which
      would corrupt a resource nobody asked us to touch.

    Falls back to the free-text redaction when the value does not parse as a
    URL, so an unexpected shape is still redacted rather than passed through.

    Pure and idempotent; returns `None` and `""` unchanged.
    """
    if not url or "@" not in url:
        return url
    try:
        parts = urlsplit(url)
        netloc = parts.netloc
    except ValueError:
        return redact_url_credentials(url)
    if "@" not in netloc:
        # A URL whose only `@` is in the path, the query or the fragment.
        return url
    # `rpartition` so that a password holding an unencoded `@` goes whole.
    _, _, host = netloc.rpartition("@")
    return urlunsplit(parts._replace(netloc=f"***@{host}"))
