import re

from flask import request

from udata.api import API, api, fields
from udata.api.limits import PUBLIC_READ_LIMIT, VIEW_TRACKING_LIMIT, user_or_ip
from udata.app import limiter
from udata.auth import current_user
from udata.core.metrics.events import MetricEvent

from .models import DatastoryMetrics

ns = api.namespace("datastories", "Datastory related operations")

# A Squidex datastory slug: path segments of letters, digits, `_` and `-`. The
# frontend route is a catch-all (`datastories/[...slug]`), hence the `/`. Nothing
# here can confirm the slug exists in Squidex, so this shape and the rate limit
# are what bound the identifiers an anonymous client can make us store.
SLUG_RE = re.compile(r"^[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*$")
SLUG_MAX_LENGTH = 255
# Listing pages ask for the slugs of the cards they show, a page at a time.
MAX_SLUGS = 100

datastory_metrics_fields = api.model(
    "DatastoryMetrics",
    {
        "slug": fields.String(description="The datastory Squidex slug", readonly=True),
        "metrics": fields.Nested(
            api.model("DatastoryMetricsValues", {"views": fields.Integer(readonly=True)}),
            description="The datastory metrics",
        ),
    },
)


datastory_metrics_list_fields = api.model(
    "DatastoryMetricsList",
    {"data": fields.List(fields.Nested(datastory_metrics_fields), description="One per slug")},
)

datastories_parser = api.parser()
datastories_parser.add_argument(
    "slugs",
    type=str,
    location="args",
    help=f"Comma-separated datastory slugs (at most {MAX_SLUGS})",
)


def _check_slug(slug: str) -> None:
    if len(slug) > SLUG_MAX_LENGTH or not SLUG_RE.match(slug):
        api.abort(400, "Invalid datastory slug")


def _serialize(slug: str, views: int | None = None) -> dict:
    if views is None:
        views = DatastoryMetrics.views_for(slug)
    return {"slug": slug, "metrics": {"views": views}}


@ns.route("/", endpoint="datastories")
class DatastoriesAPI(API):
    decorators = [limiter.limit(PUBLIC_READ_LIMIT, methods=["GET"], key_func=user_or_ip)]

    @api.doc("list_datastories_metrics")
    @api.expect(datastories_parser)
    @api.marshal_with(datastory_metrics_list_fields)
    def get(self):
        """Get the metrics of several datastories at once, in the order asked.

        For listing cards: one request for the whole page instead of one per card. A
        comma cannot appear in a slug, so it separates them; duplicates are dropped.
        """
        raw = datastories_parser.parse_args()["slugs"] or ""
        slugs = list(dict.fromkeys(s for s in raw.split(",") if s))
        if len(slugs) > MAX_SLUGS:
            api.abort(400, f"At most {MAX_SLUGS} slugs per request")
        for slug in slugs:
            _check_slug(slug)
        views = DatastoryMetrics.views_for_many(slugs)
        return {"data": [_serialize(slug, views[slug]) for slug in slugs]}


@ns.route("/<path:slug>/", endpoint="datastory")
class DatastoryAPI(API):
    decorators = [limiter.limit(PUBLIC_READ_LIMIT, methods=["GET"], key_func=user_or_ip)]

    @api.doc("get_datastory_metrics")
    @api.marshal_with(datastory_metrics_fields)
    def get(self, slug):
        """Get a datastory metrics. Reading them does not count as a view."""
        _check_slug(slug)
        return _serialize(slug)


@ns.route("/<path:slug>/views/", endpoint="datastory_views")
class DatastoryViewsAPI(API):
    decorators = [limiter.limit(VIEW_TRACKING_LIMIT, methods=["POST"], key_func=user_or_ip)]

    @api.doc("track_datastory_view")
    @api.marshal_with(datastory_metrics_fields, code=201)
    def post(self, slug):
        """Record a view of a datastory and return its metrics.

        Only the event is written: the `metrics_etl` DAG turns events into the
        cumulative total, as for every other object, so the returned count does not
        include this view until its next run.
        """
        _check_slug(slug)
        MetricEvent.create_event(
            event_type="view",
            object_type="datastory",
            object_id=slug,
            user_id=current_user.id if current_user.is_authenticated else None,
            ip=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            referer=request.headers.get("Referer"),
        )
        return _serialize(slug), 201
