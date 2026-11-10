from udata.core.metrics.models import WithMetrics
from udata.mongo import db

__all__ = ("DatastoryMetrics",)


class DatastoryMetrics(WithMetrics, db.Document):
    """Metrics of a datastory, keyed by its Squidex slug.

    Datastories are Squidex content: the frontend fetches them from the CMS, so
    udata holds no document for them and never sees a detail request it could
    count. This collection only keeps their metrics. The slug is the content's
    `data.id.iv`, the same in every locale.

    `metrics.views` is written by the `metrics_etl` DAG (`dadosgov-metrics`) from
    `metric.datastories_total`, like the views of every other object, or by the
    `update-metrics` job when no `METRICS_API` is configured. The DAG upserts by
    slug, so a datastory gets its document on the first run after its first view.
    """

    slug = db.StringField(required=True, unique=True)

    __metrics_keys__ = ["views"]

    meta = {"collection": "datastory_metrics"}

    @classmethod
    def views_for(cls, slug: str) -> int:
        return cls.views_for_many([slug])[slug]

    @classmethod
    def views_for_many(cls, slugs: list[str]) -> dict[str, int]:
        """Views of each slug in one query, 0 for a datastory nobody has viewed yet."""
        views = dict.fromkeys(slugs, 0)
        for doc in cls.objects(slug__in=slugs).only("slug", "metrics"):
            views[doc.slug] = doc.get_metrics()["views"]
        return views
