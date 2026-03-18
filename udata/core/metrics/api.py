import logging

from flask import request

from udata.api import API, api
from udata.auth import current_user
from udata.core.metrics.events import EVENT_TYPES, OBJECT_TYPES, MetricEvent

log = logging.getLogger(__name__)

ns = api.namespace("tracking", "Tracking operations")

tracking_parser = api.parser()
tracking_parser.add_argument(
    "event_type", type=str, required=True, location="json", help="Event type"
)
tracking_parser.add_argument("object_type", type=str, location="json", help="Object type")
tracking_parser.add_argument("object_id", type=str, location="json", help="Object identifier")
tracking_parser.add_argument("extra", type=dict, location="json", help="Extra data")


@ns.route("/", endpoint="tracking")
class TrackingAPI(API):
    @api.expect(tracking_parser)
    @api.doc("track_event")
    def post(self):
        """Record a tracking event"""
        try:
            data = request.get_json(silent=True) or {}
            event_type = data.get("event_type")

            if not event_type or event_type not in EVENT_TYPES:
                return {"message": f"Invalid event_type. Must be one of: {EVENT_TYPES}"}, 400

            object_type = data.get("object_type")
            if object_type and object_type not in OBJECT_TYPES:
                return {"message": f"Invalid object_type. Must be one of: {OBJECT_TYPES}"}, 400

            user_id = None
            if current_user and not current_user.is_anonymous:
                user_id = str(current_user.id)

            MetricEvent.create_event(
                event_type=event_type,
                object_type=object_type,
                object_id=data.get("object_id"),
                user_id=user_id,
                ip=request.remote_addr,
                user_agent=request.headers.get("User-Agent"),
                referer=request.headers.get("Referer"),
                extra=data.get("extra"),
            )
            return {"status": "ok"}, 201
        except Exception:
            log.exception("Failed to record tracking event")
            return {"status": "ok"}, 201  # Never fail tracking
