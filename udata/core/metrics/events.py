import hashlib
from datetime import datetime

from udata.mongo import db


def anonymize_ip(ip):
    """Zero the last octet of an IPv4 address for GDPR compliance."""
    if not ip:
        return None
    parts = ip.split(".")
    if len(parts) == 4:
        parts[-1] = "0"
        return ".".join(parts)
    # IPv6: hash the address
    return hashlib.sha256(ip.encode()).hexdigest()[:16]


EVENT_TYPES = ("view", "download", "search", "click", "api_call", "custom")
OBJECT_TYPES = ("dataset", "resource", "reuse", "organization", "dataservice", "page")


class MetricEvent(db.Document):
    """Raw tracking event, auto-deleted after TTL days."""

    event_type = db.StringField(required=True, choices=EVENT_TYPES)
    object_type = db.StringField(choices=OBJECT_TYPES)
    object_id = db.StringField()
    user_id = db.StringField()
    ip = db.StringField()
    user_agent = db.StringField()
    referer = db.StringField()
    extra = db.DictField()
    created_at = db.DateTimeField(default=datetime.utcnow)

    meta = {
        "collection": "metric_event",
        "indexes": [
            {"fields": ["event_type", "object_type", "object_id"]},
            {"fields": ["object_type", "object_id", "created_at"]},
            {"fields": ["created_at"], "expireAfterSeconds": 90 * 86400},
        ],
        "ordering": ["-created_at"],
    }

    @classmethod
    def create_event(
        cls,
        event_type,
        object_type=None,
        object_id=None,
        user_id=None,
        ip=None,
        user_agent=None,
        referer=None,
        extra=None,
    ):
        """Create a metric event with anonymized IP."""
        return cls(
            event_type=event_type,
            object_type=object_type,
            object_id=str(object_id) if object_id else None,
            user_id=str(user_id) if user_id else None,
            ip=anonymize_ip(ip),
            user_agent=user_agent,
            referer=referer,
            extra=extra or {},
        ).save()
