import logging
import time
from datetime import datetime, timedelta
from functools import wraps

import requests
from flask import current_app

from udata.core.dataservices.models import Dataservice
from udata.core.metrics.aggregations import MetricAggregation
from udata.core.metrics.events import MetricEvent
from udata.core.metrics.signals import on_site_metrics_computed
from udata.models import CommunityResource, Dataset, Organization, Reuse, Site, db
from udata.tasks import job

log = logging.getLogger(__name__)


def log_timing(func):
    @wraps(func)
    def timeit_wrapper(*args, **kwargs):
        model = func.__name__.removeprefix("update_")

        log.info(f"Processing {model}…")
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        total_time = time.perf_counter() - start_time
        log.info(f"Done in {total_time:.4f} seconds.")
        return result

    return timeit_wrapper


def save_model(model: db.Document, model_id: str, metrics: dict[str, int]) -> None:
    try:
        result = model.objects(id=model_id).update(
            **{f"set__metrics__{key}": value for key, value in metrics.items()}
        )

        if result is None:
            log.debug(f"{model.__name__} not found", extra={"id": model_id})
    except Exception as e:
        log.exception(e)


def _fix_pagination_url(next_url: str | None, base_url: str) -> str | None:
    """Replace the host in pagination URLs returned by the external metrics API.

    The external service may return ``next``/``prev`` links pointing to an
    internal address (e.g. ``http://localhost:8005/…``) that is unreachable
    from the udata worker.  We keep the path and query string but swap the
    scheme + host to match the configured ``METRICS_API`` base URL.
    """
    if not next_url:
        return None
    from urllib.parse import urlparse, urlunparse

    parsed_next = urlparse(next_url)
    parsed_base = urlparse(base_url)
    fixed = parsed_next._replace(scheme=parsed_base.scheme, netloc=parsed_base.netloc)
    return urlunparse(fixed)


def iterate_on_metrics(target: str, value_keys: list[str], page_size: int = 50) -> dict:
    """
    Yield all elements with not zero values for the keys inside `value_keys`.
    If you pass ['visit', 'download_resource'], it will do a `OR` and get
    metrics with one of the two values not zero.
    """
    yielded = set()
    metrics_api = current_app.config["METRICS_API"]

    for value_key in value_keys:
        url = f"{metrics_api}/{target}_total/data/"
        url += f"?{value_key}__greater=1&page_size={page_size}"

        with requests.Session() as session:
            while url is not None:
                r = session.get(url, timeout=10)
                r.raise_for_status()
                data = r.json()

                for row in data["data"]:
                    if row["__id"] not in yielded:
                        yielded.add(row["__id"])
                        yield row

                url = _fix_pagination_url(data["links"].get("next"), metrics_api)


@log_timing
def update_resources_and_community_resources():
    for data in iterate_on_metrics("resources", ["download_resource"]):
        if data["dataset_id"] is None:
            save_model_by_id_or_slug(
                CommunityResource,
                data["resource_id"],
                {
                    "views": data["download_resource"],
                },
            )
        else:
            Dataset.objects(resources__id=data["resource_id"]).update(
                **{"set__resources__$__metrics__views": data["download_resource"]}
            )


@log_timing
def update_datasets():
    for data in iterate_on_metrics("datasets", ["visit", "download_resource"]):
        save_model_by_id_or_slug(
            Dataset,
            data["dataset_id"],
            {
                "views": data["visit"],
                "resources_downloads": data["download_resource"],
            },
        )


@log_timing
def update_dataservices():
    for data in iterate_on_metrics("dataservices", ["visit"]):
        save_model_by_id_or_slug(
            Dataservice,
            data["dataservice_id"],
            {
                "views": data["visit"],
            },
        )


@log_timing
def update_reuses():
    for data in iterate_on_metrics("reuses", ["visit"]):
        save_model_by_id_or_slug(Reuse, data["reuse_id"], {"views": data["visit"]})


@log_timing
def update_organizations():
    for data in iterate_on_metrics(
        "organizations", ["visit_dataset", "download_resource", "visit_reuse", "visit_dataservice"]
    ):
        save_model_by_id_or_slug(
            Organization,
            data["organization_id"],
            {
                "views": data.get("visit_dataset") or 0,
                "resource_downloads": data.get("download_resource") or 0,
                "reuse_views": data.get("visit_reuse") or 0,
                "dataservice_views": data.get("visit_dataservice") or 0,
            },
        )


@log_timing
def aggregate_org_downloads():
    """Aggregate resource downloads from datasets into their parent organizations.

    The external metrics API tracks downloads per resource/dataset but does not
    aggregate them at the organization level.  This function sums
    ``metrics.resources_downloads`` across all datasets of each organization and
    stores the total in ``metrics.resource_downloads`` on the organization.
    """
    pipeline = [
        {"$match": {"organization": {"$ne": None}, "metrics.resources_downloads": {"$gt": 0}}},
        {"$group": {"_id": "$organization", "total": {"$sum": "$metrics.resources_downloads"}}},
    ]
    for row in Dataset.objects.aggregate(*pipeline):
        Organization.objects(id=row["_id"]).update(set__metrics__resource_downloads=row["total"])


def update_metrics_for_models():
    log.info("Starting…")
    update_datasets()
    update_resources_and_community_resources()
    update_dataservices()
    update_reuses()
    update_organizations()
    aggregate_org_downloads()


def save_model_by_id_or_slug(model: db.Document, identifier: str, metrics: dict[str, int]) -> None:
    """Update model metrics, looking up by ObjectId first, then by slug."""
    update_kwargs = {f"set__metrics__{key}": value for key, value in metrics.items()}
    try:
        # Try by ObjectId first
        result = model.objects(id=identifier).update(**update_kwargs)
        if result:
            return
    except Exception:
        pass

    # Try by slug
    try:
        result = model.objects(slug=identifier).update(**update_kwargs)
        if result is None:
            log.debug(f"{model.__name__} not found for '{identifier}'")
    except Exception as e:
        log.debug(f"Could not update {model.__name__} '{identifier}': {e}")


@log_timing
def update_metrics_from_internal():
    """Update model metrics from internal MetricEvent data.

    Only "view" events count as page views (sent once per page visit from the frontend).
    "api_call" events are excluded from view counts because a single page visit
    triggers multiple API calls, which would inflate the numbers.
    """
    # Aggregate views per dataset
    pipeline = [
        {"$match": {"event_type": "view", "object_type": "dataset"}},
        {"$group": {"_id": "$object_id", "views": {"$sum": 1}}},
    ]
    for row in MetricEvent.objects.aggregate(*pipeline):
        if row["_id"]:
            save_model_by_id_or_slug(Dataset, row["_id"], {"views": row["views"]})

    # Aggregate downloads per dataset
    pipeline = [
        {"$match": {"event_type": "download", "object_type": "resource"}},
        {"$group": {"_id": "$extra.dataset_id", "downloads": {"$sum": 1}}},
    ]
    for row in MetricEvent.objects.aggregate(*pipeline):
        if row["_id"]:
            save_model_by_id_or_slug(Dataset, row["_id"], {"resources_downloads": row["downloads"]})

    # Aggregate views per reuse
    pipeline = [
        {"$match": {"event_type": "view", "object_type": "reuse"}},
        {"$group": {"_id": "$object_id", "views": {"$sum": 1}}},
    ]
    for row in MetricEvent.objects.aggregate(*pipeline):
        if row["_id"]:
            save_model_by_id_or_slug(Reuse, row["_id"], {"views": row["views"]})

    # Aggregate views per organization
    pipeline = [
        {"$match": {"event_type": "view", "object_type": "organization"}},
        {"$group": {"_id": "$object_id", "views": {"$sum": 1}}},
    ]
    for row in MetricEvent.objects.aggregate(*pipeline):
        if row["_id"]:
            save_model_by_id_or_slug(Organization, row["_id"], {"views": row["views"]})

    # Aggregate views per dataservice
    pipeline = [
        {"$match": {"event_type": "view", "object_type": "dataservice"}},
        {"$group": {"_id": "$object_id", "views": {"$sum": 1}}},
    ]
    for row in MetricEvent.objects.aggregate(*pipeline):
        if row["_id"]:
            save_model_by_id_or_slug(Dataservice, row["_id"], {"views": row["views"]})


@job("aggregate-metrics", route="low.metrics")
def aggregate_metrics(self):
    """Aggregate raw MetricEvent data into MetricAggregation documents."""
    yesterday = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(
        days=1
    )
    day_start = yesterday
    day_end = yesterday + timedelta(days=1)
    day_str = yesterday.strftime("%Y-%m-%d")
    month_str = yesterday.strftime("%Y-%m")

    event_type_to_field = {
        "view": "views",
        "api_call": "api_calls",
        "download": "downloads",
    }

    pipeline = [
        {"$match": {"created_at": {"$gte": day_start, "$lt": day_end}}},
        {
            "$group": {
                "_id": {
                    "object_type": "$object_type",
                    "object_id": "$object_id",
                    "event_type": "$event_type",
                },
                "count": {"$sum": 1},
            }
        },
    ]

    for row in MetricEvent.objects.aggregate(*pipeline):
        obj_type = row["_id"].get("object_type")
        obj_id = row["_id"].get("object_id")
        event_type = row["_id"].get("event_type")

        if not obj_type or not obj_id:
            continue

        field_name = event_type_to_field.get(event_type)
        if not field_name:
            continue

        # Upsert daily aggregation
        MetricAggregation.objects(
            object_type=obj_type,
            object_id=obj_id,
            period_type="daily",
            period=day_str,
        ).update_one(**{f"inc__{field_name}": row["count"]}, upsert=True)

        # Upsert monthly aggregation
        MetricAggregation.objects(
            object_type=obj_type,
            object_id=obj_id,
            period_type="monthly",
            period=month_str,
        ).update_one(**{f"inc__{field_name}": row["count"]}, upsert=True)

    log.info(f"Aggregated metrics for {day_str}")


@job("update-metrics", route="low.metrics")
def update_metrics(self):
    """Update udata objects metrics."""
    if current_app.config.get("METRICS_API"):
        # Legacy external metrics API
        update_metrics_for_models()
    else:
        # Use internal tracking data
        update_metrics_from_internal()


@job("compute-site-metrics")
def compute_site_metrics(self):
    site = Site.objects(id=current_app.config["SITE_ID"]).first()
    site.count_users()
    site.count_org()
    site.count_datasets()
    site.count_resources()
    site.count_reuses()
    site.count_dataservices()
    site.count_followers()
    site.count_discussions()
    site.count_harvesters()
    site.count_max_dataset_followers()
    site.count_max_dataset_reuses()
    site.count_max_reuse_datasets()
    site.count_max_reuse_followers()
    site.count_max_org_followers()
    site.count_max_org_reuses()
    site.count_max_org_datasets()
    site.count_stock_metrics()
    # Sending signal
    on_site_metrics_computed.send(site)
