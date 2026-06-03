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
