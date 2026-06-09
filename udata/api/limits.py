"""Rate-limit helpers for content-creation API endpoints.

Centralizes the `key_func` and the per-endpoint limit constants so all
content-creation endpoints share a consistent abuse-prevention strategy.

See TICKET-59 / VULN-2078 (community resources) and TICKET-1728 / VULN-2083
(discussions) for context.
"""

from flask_limiter.util import get_remote_address
from flask_security import current_user

# Per-endpoint limit profiles.
# Format: "<count> per <window>; ..." understood by flask-limiter.
#
# These are conservative defaults sized for human use. Calibrate against
# legitimate traffic before tightening further.
# Identity poll (`GET /api/1/me/`). The frontend calls this on every page load
# through a server-side proxy (`frontend/src/app/me/route.ts`), so without an
# explicit per-endpoint limit it falls under the IP-keyed global default
# (`RATELIMIT_DEFAULT`). Behind that proxy every user collapses into a single
# IP bucket, exhausting the shared ceiling and returning 429 — which the
# frontend reads as "logged out". Keyed by `user_or_ip` each authenticated user
# gets their own generous bucket sized for legitimate navigation.
IDENTITY_READ_LIMIT = "60 per minute; 1200 per hour"
# Public, anonymous, idempotent search/list reads that populate the listing
# pages (`GET /api/1/datasets|organizations|reuses/?q=...`). Without an explicit
# per-endpoint limit these fall under the IP-keyed `RATELIMIT_DEFAULT`
# ("200 per hour"). Behind the F5/WAF every visitor collapses into one origin IP
# (docs/infra-adc-waf-impact-ppr-prd.md, incident 4.2), so that 200/hour becomes
# a SHARED ceiling across all anonymous visitors per endpoint: the 200th search
# of the hour returns 429 and the page stops populating for everyone. Anonymous
# traffic cannot be keyed per user, so the only lever is a much higher ceiling
# sized for aggregate public browsing; `user_or_ip` still gives logged-in users
# their own bucket. NOTE: this is an aggregate cap under IP-collapse — calibrate
# against real traffic and pair with response caching (ISR + Flask-Caching) so
# repeated queries never reach the limiter. The per-minute ceiling is kept well
# above the old 200/hour burst capacity (so a legitimate spike never regresses
# vs the default) and there is deliberately NO per-day cap: under IP-collapse a
# daily cap would become a site-wide ceiling that blocks every anonymous
# visitor late in the day — exactly the failure mode this fix removes.
PUBLIC_SEARCH_LIMIT = "300 per minute; 6000 per hour"
CONTENT_CREATE_LIMIT = "5 per minute; 30 per hour; 100 per day"
HEAVY_CREATE_LIMIT = "2 per minute; 5 per hour; 10 per day"
COMMENT_CREATE_LIMIT = "5 per minute; 30 per hour; 100 per day"
UPLOAD_LIMIT = "10 per minute; 100 per hour; 500 per day"
# Opening a brand-new discussion thread is a much rarer human action than
# adding a comment to an existing one, so it gets a tighter ceiling than
# COMMENT_CREATE_LIMIT. Sized for VULN-2083 audit pattern (100+ Burp
# Intruder POSTs on a single dataset): only the first few succeed inside
# the per-minute window, hourly/daily caps absorb burst-then-pause attacks.
DISCUSSION_CREATE_LIMIT = "3 per minute; 10 per hour; 30 per day"


def user_or_ip() -> str:
    """Return a rate-limit key keyed on the authenticated user when present,
    falling back to the remote IP address otherwise.

    Using the user id (instead of the IP alone) prevents bypass by rotating
    proxies/VPNs once the attacker is logged in. API token authentication
    resolves through `current_user` like any other login, so it is covered
    by the same key.
    """
    if current_user.is_authenticated:
        return f"user:{current_user.id}"
    return f"ip:{get_remote_address()}"
