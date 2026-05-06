"""Rate-limit helpers for content-creation API endpoints.

Centralizes the `key_func` and the per-endpoint limit constants so all
content-creation endpoints share a consistent abuse-prevention strategy.

See TICKET-59 / VULN-2078 for context.
"""

from flask_limiter.util import get_remote_address
from flask_security import current_user

# Per-endpoint limit profiles.
# Format: "<count> per <window>; ..." understood by flask-limiter.
#
# These are conservative defaults sized for human use. Calibrate against
# legitimate traffic before tightening further.
CONTENT_CREATE_LIMIT = "5 per minute; 30 per hour; 100 per day"
HEAVY_CREATE_LIMIT = "2 per minute; 5 per hour; 10 per day"
COMMENT_CREATE_LIMIT = "5 per minute; 30 per hour; 100 per day"
UPLOAD_LIMIT = "10 per minute; 100 per hour; 500 per day"


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
