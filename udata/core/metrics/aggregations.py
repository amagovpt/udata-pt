from udata.mongo import db

PERIOD_TYPES = ("daily", "monthly")


class MetricAggregation(db.Document):
    """Pre-aggregated metrics per object per period."""

    object_type = db.StringField(required=True)
    object_id = db.StringField(required=True)
    period = db.StringField(required=True)  # "2026-03-17" or "2026-03"
    period_type = db.StringField(required=True, choices=PERIOD_TYPES)
    views = db.IntField(default=0)
    downloads = db.IntField(default=0)
    api_calls = db.IntField(default=0)

    meta = {
        "collection": "metric_aggregation",
        "indexes": [
            {
                "fields": ["object_type", "object_id", "period_type", "period"],
                "unique": True,
            },
        ],
    }
