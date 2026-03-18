import logging
import re
from urllib.parse import urlparse

from udata.api.signals import on_api_call
from udata.core.metrics.events import MetricEvent

log = logging.getLogger(__name__)

# Regex to match a valid udata slug (must contain at least one hyphen followed by
# alphanumeric, e.g. "my-dataset-1") or a 24-char hex MongoDB ObjectId.
_SLUG_OR_OID = r"(?:[a-z0-9]+-[a-z0-9-]*[a-z0-9]|[0-9a-f]{24})"

# Patterns to extract object_type and object_id from API URL paths.
# Only match real object identifiers (slugs with hyphens or ObjectIds),
# which avoids false positives on sub-endpoints like "badges", "licenses", etc.
URL_PATTERNS = [
    (re.compile(rf"/api/[12]/datasets/({_SLUG_OR_OID})(?:/|$)"), "dataset"),
    (re.compile(rf"/api/[12]/reuses/({_SLUG_OR_OID})(?:/|$)"), "reuse"),
    (re.compile(rf"/api/[12]/organizations/({_SLUG_OR_OID})(?:/|$)"), "organization"),
    (re.compile(rf"/api/[12]/dataservices/({_SLUG_OR_OID})(?:/|$)"), "dataservice"),
]


def _extract_object_info(url):
    """Extract object_type and object_id from an API URL path (ignoring query string)."""
    path = urlparse(url).path
    for pattern, object_type in URL_PATTERNS:
        match = pattern.search(path)
        if match:
            return object_type, match.group(1)
    return None, None


def on_api_call_handler(sender, **kwargs):
    """Record API calls as metric events."""
    try:
        object_type, object_id = _extract_object_info(sender)
        MetricEvent.create_event(
            event_type="api_call",
            object_type=object_type,
            object_id=object_id,
            user_id=kwargs.get("uid"),
            ip=kwargs.get("user_ip"),
        )
    except Exception:
        log.exception("Failed to record API call metric")


def connect_listeners():
    """Connect signal listeners for metrics tracking."""
    on_api_call.connect(on_api_call_handler)
