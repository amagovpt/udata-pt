"""
Internal tracking — replaces Matomo/Piwik for page view and download counting.

Each GET request to a detail endpoint (dataset, reuse, organization, dataservice)
creates a TrackingEvent with event_type="view". Each resource redirect (download)
creates an event with event_type="download" and the parent dataset_id.

Deduplication: repeated views from the same IP for the same object within
DEDUP_WINDOW_SECONDS are ignored to avoid inflating counts.

Events are aggregated by the Airflow DAG → PostgreSQL (api-tabular) → MongoDB.
"""

import logging
from datetime import datetime, timedelta

from flask import request

from udata.mongo import db

log = logging.getLogger(__name__)

# Minimum interval (seconds) between two views from the same IP on the same object.
DEDUP_WINDOW_SECONDS = 300  # 5 minutes

# Endpoints tracked as "view": endpoint name → view_arg key
TRACKED_VIEW_ENDPOINTS = {
    "api.dataset": "dataset",
    "api.organization": "organization",
    "api.reuse": "reuse",
    "api.dataservice": "dataservice",
    "apiv2.dataset": "dataset",
}

# Endpoints tracked as "download"
TRACKED_DOWNLOAD_ENDPOINTS = {
    "api.resource_redirect",
}


class TrackingEvent(db.Document):
    """A single tracking event, kept lightweight for high throughput."""

    object_type = db.StringField(required=True, choices=["dataset", "organization", "reuse", "dataservice"])
    object_id = db.StringField(required=True)
    resource_id = db.StringField()  # Set for download events — identifies the specific resource
    event_type = db.StringField(required=True, choices=["view", "download"])
    visitor_ip = db.StringField()
    created_at = db.DateTimeField(default=datetime.utcnow)

    meta = {
        "collection": "tracking_events",
        "indexes": [
            ("object_type", "event_type"),
            ("object_type", "object_id"),
            ("object_id", "event_type", "visitor_ip", "created_at"),
            ("resource_id", "event_type"),
            {"fields": ["created_at"], "expireAfterSeconds": 90 * 86400},  # TTL: 90 days
        ],
        "ordering": ["-created_at"],
    }


def _is_duplicate(object_id: str, event_type: str, visitor_ip: str) -> bool:
    """Check if a recent event from the same IP already exists."""
    cutoff = datetime.utcnow() - timedelta(seconds=DEDUP_WINDOW_SECONDS)
    return TrackingEvent.objects(
        object_id=object_id,
        event_type=event_type,
        visitor_ip=visitor_ip,
        created_at__gte=cutoff,
    ).first() is not None


def _track_resource_download(response):
    """Track a resource download by finding its parent dataset."""
    view_args = request.view_args or {}
    resource_id = view_args.get("id")
    if resource_id is None:
        return

    # Lazy import to avoid circular imports
    from udata.models import Dataset

    dataset = Dataset.objects(resources__id=resource_id).only("id").first()
    if dataset is None:
        return

    TrackingEvent(
        object_type="dataset",
        object_id=str(dataset.id),
        resource_id=str(resource_id),
        event_type="download",
        visitor_ip=request.remote_addr or "unknown",
    ).save()


def track_view(response):
    """After-request hook: record view and download events with deduplication."""
    if request.method != "GET":
        return response

    endpoint = request.endpoint

    # Track downloads (resource redirects return 302, not 200)
    if endpoint in TRACKED_DOWNLOAD_ENDPOINTS and response.status_code in (200, 301, 302):
        try:
            _track_resource_download(response)
        except Exception:
            log.exception("Failed to save download tracking event")
        return response

    # Track views (only successful responses)
    if response.status_code != 200:
        return response

    if endpoint not in TRACKED_VIEW_ENDPOINTS:
        return response

    object_type = TRACKED_VIEW_ENDPOINTS[endpoint]
    view_args = request.view_args or {}
    obj = view_args.get(object_type)
    if obj is None:
        return response

    object_id = str(obj.id) if hasattr(obj, "id") else str(obj)
    visitor_ip = request.remote_addr or "unknown"

    if _is_duplicate(object_id, "view", visitor_ip):
        return response

    try:
        TrackingEvent(
            object_type=object_type,
            object_id=object_id,
            event_type="view",
            visitor_ip=visitor_ip,
        ).save()
    except Exception:
        log.exception("Failed to save view tracking event")

    return response
