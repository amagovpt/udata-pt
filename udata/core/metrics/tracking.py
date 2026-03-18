"""
Internal view tracking — replaces Matomo/Piwik for page view counting.

Each GET request to a detail endpoint (dataset, reuse, organization, dataservice)
creates a lightweight TrackingEvent document in MongoDB. These events are later
aggregated by the Airflow DAG and written to PostgreSQL (api-tabular), from where
the `update-metrics` job pulls them back into dataset.metrics.views.
"""

import logging
from datetime import datetime

from flask import request
from mongoengine import signals

from udata.mongo import db

log = logging.getLogger(__name__)

# Endpoints whose GET requests should be tracked as a "view".
# Maps Flask endpoint name → (model name for api-tabular, id field extractor)
TRACKED_ENDPOINTS = {
    "api.dataset": "dataset",
    "api.organization": "organization",
    "api.reuse": "reuse",
    "api.dataservice": "dataservice",
    "apiv2.dataset": "dataset",
}


class TrackingEvent(db.Document):
    """A single page-view event, kept lightweight for high throughput."""

    object_type = db.StringField(required=True, choices=["dataset", "organization", "reuse", "dataservice"])
    object_id = db.StringField(required=True)
    event_type = db.StringField(default="view")
    created_at = db.DateTimeField(default=datetime.utcnow)

    meta = {
        "collection": "tracking_events",
        "indexes": [
            "object_type",
            "object_id",
            ("object_type", "object_id"),
            {"fields": ["created_at"], "expireAfterSeconds": 90 * 86400},  # TTL: 90 days
        ],
        "ordering": ["-created_at"],
    }


def track_view(response):
    """After-request hook: record a view event for tracked detail endpoints."""
    if response.status_code != 200 or request.method != "GET":
        return response

    endpoint = request.endpoint
    if endpoint not in TRACKED_ENDPOINTS:
        return response

    object_type = TRACKED_ENDPOINTS[endpoint]

    # Extract the object id from the view args (Flask URL converters)
    view_args = request.view_args or {}
    obj = view_args.get(object_type)
    if obj is None:
        return response

    object_id = str(obj.id) if hasattr(obj, "id") else str(obj)

    try:
        TrackingEvent(
            object_type=object_type,
            object_id=object_id,
        ).save()
    except Exception:
        log.exception("Failed to save tracking event")

    return response
