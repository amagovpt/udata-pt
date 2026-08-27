from flask import current_app, request
from flask_login import current_user
from werkzeug.exceptions import BadRequest

from udata.api import API, api, fields
from udata.api.limits import HARVEST_PREVIEW_LIMIT, user_or_ip
from udata.app import limiter
from udata.auth import admin_permission
from udata.core.dataservices.models import Dataservice
from udata.core.dataset.api_fields import dataset_fields, dataset_ref_fields
from udata.core.dataset.models import Dataset
from udata.core.organization.api_fields import org_ref_fields
from udata.core.user.api_fields import user_ref_fields
from udata.harvest.backends import get_enabled_backends

from . import actions
from .forms import HarvestSourceForm, HarvestSourceValidationForm
from .models import (
    HARVEST_ITEM_STATUS,
    HARVEST_JOB_STATUS,
    VALIDATION_ACCEPTED,
    VALIDATION_STATES,
    HarvestJob,
    HarvestSource,
)

ns = api.namespace("harvest", "Harvest related operations")


error_fields = api.model(
    "HarvestError",
    {
        "created_at": fields.ISODateTime(
            description="The error creation date", required=True, readonly=True
        ),
        "message": fields.String(description="The error short message", required=True),
        "details": fields.Raw(
            attribute=lambda o: o.details if admin_permission else None,
            description="Optional details (only for super-admins)",
            readonly=True,
        ),
    },
)


log_fields = api.model(
    "HarvestError",
    {
        "level": fields.String(required=True),
        "message": fields.String(required=True),
    },
)


item_fields = api.model(
    "HarvestItem",
    {
        "remote_id": fields.String(description="The item remote ID to process", required=True),
        "remote_url": fields.String(description="The item remote url (if available)"),
        "dataset": fields.Nested(
            dataset_ref_fields, description="The processed dataset", allow_null=True
        ),
        "dataservice": fields.Nested(
            Dataservice.__ref_fields__, description="The processed dataservice", allow_null=True
        ),
        "status": fields.String(
            description="The item status", required=True, enum=list(HARVEST_ITEM_STATUS)
        ),
        "created": fields.ISODateTime(description="The item creation date", required=True),
        "started": fields.ISODateTime(description="The item start date"),
        "ended": fields.ISODateTime(description="The item end date"),
        "errors": fields.List(fields.Nested(error_fields), description="The item errors"),
        "logs": fields.List(fields.Nested(log_fields), description="The item logs"),
        "args": fields.List(fields.String, description="The item positional arguments", default=[]),
        "kwargs": fields.Raw(description="The item keyword arguments", default={}),
    },
)

job_fields = api.model(
    "HarvestJob",
    {
        "id": fields.String(description="The job execution ID", required=True),
        "created": fields.ISODateTime(description="The job creation date", required=True),
        "started": fields.ISODateTime(description="The job start date"),
        "ended": fields.ISODateTime(description="The job end date"),
        "status": fields.String(
            description="The job status", required=True, enum=list(HARVEST_JOB_STATUS)
        ),
        "errors": fields.List(
            fields.Nested(error_fields), description="The job initialization errors"
        ),
        "items": fields.List(fields.Nested(item_fields), description="The job collected items"),
        "source": fields.String(description="The source owning the job", required=True),
    },
)

job_page_fields = api.model("HarvestJobPage", fields.pager(job_fields))

# --- Lightweight job listing (avoids serializing the full `items` array) ---
# The jobs LIST only needs per-status counts and the (few) items that failed;
# shipping every HarvestItem makes large jobs (e.g. INE, ~13k items) return
# multi-MB payloads and time out. See the aggregation in `JobsAPI.get`.
item_counts_fields = api.model(
    "HarvestJobItemCounts",
    {
        status: fields.Integer(description=f"Number of {status} items")
        for status in HARVEST_ITEM_STATUS
    }
    | {"total": fields.Integer(description="Total number of items")},
)

error_light_fields = api.model(
    "HarvestErrorLight",
    {
        "message": fields.String(description="The error short message"),
        "details": fields.String(description="Optional details (only for super-admins)"),
    },
)

error_item_fields = api.model(
    "HarvestJobErrorItem",
    {
        "remote_id": fields.String(description="The item remote ID"),
        "remote_url": fields.String(description="The item remote url (if available)"),
        "status": fields.String(description="The item status"),
        "dataset": fields.Nested(
            api.model(
                "HarvestJobErrorItemDataset",
                {
                    "id": fields.String(),
                    "title": fields.String(),
                    "page": fields.String(),
                },
            ),
            allow_null=True,
            description="The processed dataset (if any)",
        ),
        "errors": fields.List(fields.Nested(error_light_fields), description="The item errors"),
    },
)

job_light_fields = api.model(
    "HarvestJobLight",
    {
        "id": fields.String(description="The job execution ID", required=True),
        "created": fields.ISODateTime(description="The job creation date", required=True),
        "started": fields.ISODateTime(description="The job start date"),
        "ended": fields.ISODateTime(description="The job end date"),
        "status": fields.String(description="The job status", required=True),
        "errors": fields.List(
            fields.Nested(error_light_fields), description="The job initialization errors"
        ),
        "source": fields.String(description="The source owning the job", required=True),
        "item_counts": fields.Nested(item_counts_fields, description="Per-status item counts"),
        "error_items": fields.List(
            fields.Nested(error_item_fields), description="Only the items that have errors"
        ),
    },
)

job_light_page_fields = api.model(
    "HarvestJobLightPage",
    {
        "data": fields.List(fields.Nested(job_light_fields)),
        "total": fields.Integer(description="Total number of jobs"),
        "page": fields.Integer(description="The current page"),
        "page_size": fields.Integer(description="The page size"),
        "next_page": fields.String(description="The next page URL if any"),
        "previous_page": fields.String(description="The previous page URL if any"),
    },
)

validation_fields = api.model(
    "HarvestSourceValidation",
    {
        "state": fields.String(
            description="Is it validated or not", enum=list(VALIDATION_STATES), required=True
        ),
        "by": fields.Nested(
            user_ref_fields,
            allow_null=True,
            readonly=True,
            description="Who performed the validation",
        ),
        "on": fields.ISODateTime(
            readonly=True, description="Date date on which validation was performed"
        ),
        "comment": fields.String(
            description="A comment about the validation. Required on rejection"
        ),
    },
)

source_permissions_fields = api.model(
    "HarvestSourcePermissions",
    {
        "edit": fields.Permission(),
        "delete": fields.Permission(),
        "run": fields.Permission(),
        "preview": fields.Permission(),
        "validate": fields.Permission(),
        "schedule": fields.Permission(),
    },
)

source_fields = api.model(
    "HarvestSource",
    {
        "id": fields.String(description="The source unique identifier", readonly=True),
        "name": fields.String(description="The source display name", required=True),
        "description": fields.Markdown(description="The source description"),
        "url": fields.String(description="The source base URL", required=True),
        "backend": fields.String(
            description="The source backend",
            enum=lambda: list(get_enabled_backends().keys()),
            required=True,
        ),
        "config": fields.Raw(description="The configuration as key-value pairs"),
        "created_at": fields.ISODateTime(
            description="The source creation date", required=True, readonly=True
        ),
        "active": fields.Boolean(description="Is this source active", required=True, default=False),
        "autoarchive": fields.Boolean(
            description="If enabled, datasets not present on the remote source will be automatically archived",  # noqa
            required=True,
            default=True,
        ),
        "validation": fields.Nested(
            validation_fields, readonly=True, description="Has the source been validated"
        ),
        "last_job": fields.Nested(
            job_fields, description="The last job for this source", allow_null=True, readonly=True
        ),
        "owner": fields.Nested(
            user_ref_fields, allow_null=True, description="The owner information"
        ),
        "organization": fields.Nested(
            org_ref_fields, allow_null=True, description="The producer organization"
        ),
        "deleted": fields.ISODateTime(description="The source deletion date", readonly=True),
        "datasets_count": fields.Integer(
            description="Number of datasets harvested by this source",
            readonly=True,
            attribute=lambda s: Dataset.objects.filter(harvest__source_id=str(s.id)).count(),
        ),
        "schedule": fields.String(
            description="The source schedule (interval or cron expression)", readonly=True
        ),
        "permissions": fields.Nested(source_permissions_fields, readonly=True),
    },
)

source_page_fields = api.model("HarvestSourcePage", fields.pager(source_fields))


filter_fields = api.model(
    "HarvestFilter",
    {
        "label": fields.String(description="A localized human-readable label"),
        "key": fields.String(description="The filter key"),
        "type": fields.String(description="The filter expected type"),
        "description": fields.String(description="The filter details"),
    },
)

feature_fields = api.model(
    "HarvestFeature",
    {
        "label": fields.String(description="A localized human-readable and descriptive label"),
        "key": fields.String(description="The feature key"),
        "description": fields.String(description="Some details about the behavior"),
        "default": fields.Boolean(description="The feature default state (true is enabled)"),
    },
)

harvest_extra_fields = api.model(
    "HarvestExtraConfig",
    {
        "label": fields.String(description="A localized human-readable and descriptive label"),
        "key": fields.String(description="The config key"),
        "description": fields.String(description="Some details about the behavior"),
        "default": fields.String(description="The config default value"),
    },
)

backend_fields = api.model(
    "HarvestBackend",
    {
        "id": fields.String(description="The backend identifier"),
        "label": fields.String(description="The backend display name"),
        "filters": fields.List(
            fields.Nested(filter_fields), description="The backend supported filters"
        ),
        "features": fields.List(
            fields.Nested(feature_fields), description="The backend optional features"
        ),
        "extra_configs": fields.List(
            fields.Nested(harvest_extra_fields),
            description="The backend extra configuration variables",
        ),
    },
)

preview_dataservice_fields = api.clone(
    "DataservicePreview",
    Dataservice.__ref_fields__,
    {
        "self_web_url": fields.Raw(
            attribute=lambda _d: None, description="The dataservice webpage URL (fake)"
        ),
        "self_api_url": fields.Raw(
            attribute=lambda _d: None, description="The dataservice API URL (fake)"
        ),
    },
)


preview_dataset_fields = api.clone(
    "DatasetPreview",
    dataset_fields,
    {
        "uri": fields.Raw(attribute=lambda _d: None, description="The dataset API URL (fake)"),
        "page": fields.Raw(attribute=lambda _d: None, description="The dataset page URL (fake)"),
    },
)

preview_item_fields = api.clone(
    "HarvestItemPreview",
    item_fields,
    {
        "dataset": fields.Nested(
            preview_dataset_fields, description="The processed dataset", allow_null=True
        ),
        "dataservice": fields.Nested(
            preview_dataservice_fields, description="The processed dataset", allow_null=True
        ),
    },
)

preview_job_fields = api.clone(
    "HarvestJobPreview",
    job_fields,
    {
        "items": fields.List(
            fields.Nested(preview_item_fields), description="The job collected items"
        ),
    },
)

source_parser = api.page_parser()
source_parser.add_argument(
    "owner", type=str, location="args", help="The organization or user ID to filter on"
)
source_parser.add_argument(
    "organization", type=str, location="args", help="Filter by organization ID"
)
source_parser.add_argument(
    "deleted", type=bool, location="args", default=False, help="Include sources flaggued as deleted"
)
source_parser.add_argument("q", type=str, location="args", help="The search query")


@ns.route("/sources/", endpoint="harvest_sources")
class SourcesAPI(API):
    @api.doc("list_harvest_sources")
    @api.expect(source_parser)
    @api.marshal_list_with(source_page_fields)
    def get(self):
        """List all harvest sources"""
        args = source_parser.parse_args()

        sources = HarvestSource.objects()

        if not args["deleted"]:
            sources = sources.visible()

        if args["owner"]:
            sources = sources.owned_by(args["owner"])

        if args["organization"]:
            sources = sources(organization=args["organization"])

        if args["q"]:
            phrase_query = " ".join([f'"{elem}"' for elem in args["q"].split(" ")])
            sources = sources.search_text(phrase_query)

        return sources.paginate(args["page"], args["page_size"])

    @api.secure
    @api.doc("create_harvest_source")
    @api.expect(source_fields)
    @api.marshal_with(source_fields)
    def post(self):
        """Create a new harvest source"""
        form = api.validate(HarvestSourceForm)
        if form.organization.data:
            form.organization.data.permissions["harvest"].test()
        source = actions.create_source(**form.data)
        return source, 201


@ns.route("/source/<harvest_source:source>/", endpoint="harvest_source")
class SourceAPI(API):
    @api.doc("get_harvest_source")
    @api.marshal_with(source_fields)
    def get(self, source: HarvestSource):
        """Get a single source given an ID or a slug"""
        return source

    @api.secure
    @api.doc("update_harvest_source")
    @api.expect(source_fields)
    @api.marshal_with(source_fields)
    def put(self, source: HarvestSource):
        """Update a harvest source"""
        source.permissions["edit"].test()
        form = api.validate(HarvestSourceForm, source)
        source = actions.update_source(source, form.data)
        return source

    @api.secure
    @api.doc("delete_harvest_source")
    @api.marshal_with(source_fields)
    def delete(self, source: HarvestSource):
        source.permissions["delete"].test()
        return actions.delete_source(source), 204


@ns.route("/source/<harvest_source:source>/validate/", endpoint="validate_harvest_source")
class ValidateSourceAPI(API):
    @api.doc("validate_harvest_source")
    @api.secure
    @api.expect(validation_fields)
    @api.marshal_with(source_fields)
    def post(self, source: HarvestSource):
        """Validate or reject an harvest source"""
        source.permissions["validate"].test()
        form = api.validate(HarvestSourceValidationForm)
        if form.state.data == VALIDATION_ACCEPTED:
            return actions.validate_source(source, form.comment.data)
        else:
            return actions.reject_source(source, form.comment.data)


@ns.route("/source/<harvest_source:source>/run/", endpoint="run_harvest_source")
class RunSourceAPI(API):
    @api.doc("run_harvest_source")
    @api.secure
    @api.marshal_with(source_fields)
    def post(self, source: HarvestSource):
        enabled = current_app.config.get("HARVEST_ENABLE_MANUAL_RUN")
        if not enabled and not current_user.sysadmin:
            api.abort(
                400,
                "Cannot run source manually. Please contact the platform if you need to reschedule the harvester.",
            )

        source.permissions["run"].test()

        if source.validation.state != VALIDATION_ACCEPTED:
            api.abort(400, "Source is not validated. Please validate the source before running.")

        actions.launch(source)

        return source


@ns.route("/source/<harvest_source:source>/schedule/", endpoint="schedule_harvest_source")
class ScheduleSourceAPI(API):
    @api.doc("schedule_harvest_source")
    @api.secure
    @api.expect((str, "A cron expression"))
    @api.marshal_with(source_fields)
    def post(self, source: HarvestSource):
        """Schedule an harvest source"""
        source.permissions["schedule"].test()
        # Handle both syntax: quoted and unquoted
        try:
            data = request.json
        except BadRequest:
            data = request.data.decode("utf-8")
        return actions.schedule(source, data)

    @api.doc("unschedule_harvest_source")
    @api.secure
    @api.marshal_with(source_fields)
    def delete(self, source: HarvestSource):
        """Unschedule an harvest source"""
        source.permissions["schedule"].test()
        return actions.unschedule(source), 204


def _names_an_organization() -> bool:
    """Whether the raw request body carries a non-empty `organization`.

    Read before the form is validated, so it cannot rely on the resolved field.
    A body that is not JSON at all answers False and falls through to the
    permission test, then to `api.validate`, which is what turns it into the 400
    it has always been — the alternative, letting `request.get_json` raise here,
    would answer 400 to an unauthorized caller and leak that the payload parsed.
    """
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return False
    return bool(payload.get("organization"))


@ns.route("/source/preview/", endpoint="preview_harvest_source_config")
class PreviewSourceConfigAPI(API):
    # Every request here walks a remote catalogue on the caller's behalf, so the
    # cost is outbound rather than stored. Declared at class level, not on the
    # verb: `decorators` run outside `@api.secure`, which is what keeps the limit
    # counting a flood of unauthorized attempts instead of only the ones that get
    # past authentication.
    decorators = [
        limiter.limit(
            HARVEST_PREVIEW_LIMIT,
            methods=["POST"],
            key_func=user_or_ip,
        ),
    ]

    @api.secure
    @api.expect(source_fields)
    @api.doc("preview_harvest_source_config")
    @api.marshal_with(preview_job_fields)
    def post(self):
        """Preview an harvesting from a source created with the given payload"""
        # Authorized BEFORE `api.validate`, which is the order every other route
        # in this file uses. Validating the form resolves the submitted hostname
        # (`HarvestURLField` -> `URLField.pre_validate` -> `uris.resolve_hostname`,
        # with URLS_RESOLVE_HOSTNAME on), so authorizing afterwards still let any
        # authenticated account fire an out-of-band DNS lookup at any hostname
        # outside HARVEST_URL_HOST_DENYLIST — which is the probe VULN-2084 was
        # about. This closes it for a payload that names no organization; a caller
        # naming an organization they administer still validates first, because
        # resolving the organization needs the form, and that is a smaller and
        # accountable population.
        if not _names_an_organization():
            # No organization to weigh the request against, and this is the one
            # route that makes the server run a harvest backend against a URL the
            # caller chose. Creating a source is inert by comparison: it lands
            # VALIDATION_PENDING, validating is admin_permission, and
            # RunSourceAPI refuses anything not accepted.
            admin_permission.test()

        form = api.validate(HarvestSourceForm)
        if form.organization.data:
            form.organization.data.permissions["harvest"].test()
        return actions.preview_from_config(**form.data)


@ns.route("/source/<harvest_source:source>/preview/", endpoint="preview_harvest_source")
class PreviewSourceAPI(API):
    # Same cost as the config route — `actions.preview` walks the same remote
    # catalogue under the same HARVEST_PREVIEW_MAX_ITEMS — so the same ceiling,
    # and the same `user_or_ip` key. Without this it fell under
    # RATELIMIT_DEFAULT, which is keyed on the remote address: behind the F5
    # every visitor arrives from one origin IP, so that ceiling is shared
    # site-wide and one caller previewing in a loop answers 429 to everybody
    # else. That matters more now that the backoffice sends every read-only
    # preview here.
    decorators = [
        limiter.limit(
            HARVEST_PREVIEW_LIMIT,
            methods=["GET"],
            key_func=user_or_ip,
        ),
    ]

    @api.secure
    @api.doc("preview_harvest_source")
    @api.marshal_with(preview_job_fields)
    def get(self, source: HarvestSource):
        """Preview a single harvest source given an ID or a slug"""
        source.permissions["preview"].test()
        return actions.preview(source)


parser = api.parser()
parser.add_argument("page", type=int, default=1, location="args", help="The page to fetch")
parser.add_argument(
    "page_size", type=int, default=20, location="args", help="The page size to fetch"
)


def _serialize_light_job(doc, dataset_map, source_id, show_details):
    """Serialize an aggregation result row into the lightweight job shape.

    `doc` comes from the `$project` in `JobsAPI.get`: it carries the job
    metadata, pre-computed `item_counts` and only the `error_items` (items
    with a non-empty `errors` array). `dataset_map` resolves the referenced
    datasets in one batched query. `show_details` gates error details to
    super-admins, mirroring `error_fields`.
    """

    def _errors(raw):
        return [
            {"message": e.get("message"), "details": e.get("details") if show_details else None}
            for e in (raw or [])
        ]

    error_items = []
    for it in doc.get("error_items") or []:
        ds = dataset_map.get(it.get("dataset"))
        error_items.append(
            {
                "remote_id": it.get("remote_id"),
                "remote_url": it.get("remote_url"),
                "status": it.get("status"),
                "dataset": ds,
                "errors": _errors(it.get("errors")),
            }
        )

    return {
        "id": str(doc["_id"]),
        "created": doc.get("created"),
        "started": doc.get("started"),
        "ended": doc.get("ended"),
        "status": doc.get("status"),
        "errors": _errors(doc.get("errors")),
        "source": source_id,
        "item_counts": doc.get("item_counts"),
        "error_items": error_items,
    }


@ns.route("/source/<harvest_source:source>/jobs/", endpoint="harvest_jobs")
class JobsAPI(API):
    @api.doc("list_harvest_jobs")
    @api.expect(parser)
    @api.marshal_with(job_light_page_fields)
    def get(self, source: HarvestSource):
        """List all jobs for a given source (lightweight: counts + failed items only).

        The full `items` array is never serialized here — it can be tens of
        thousands of entries (e.g. INE) and would blow up the payload. Per-status
        counts are computed in MongoDB via aggregation and only the items that
        actually have errors are returned. Use `/job/<id>/` for the full detail.
        """
        args = parser.parse_args()
        page = max(args["page"], 1)
        page_size = args["page_size"]

        qs = HarvestJob.objects(source=source)
        total = qs.count()

        counts = {
            status: {
                "$size": {
                    "$filter": {
                        "input": {"$ifNull": ["$items", []]},
                        "as": "i",
                        "cond": {"$eq": ["$$i.status", status]},
                    }
                }
            }
            for status in HARVEST_ITEM_STATUS
        }
        counts["total"] = {"$size": {"$ifNull": ["$items", []]}}
        project = {
            "$project": {
                "created": 1,
                "started": 1,
                "ended": 1,
                "status": 1,
                "errors": 1,
                "item_counts": counts,
                "error_items": {
                    "$filter": {
                        "input": {"$ifNull": ["$items", []]},
                        "as": "i",
                        "cond": {"$gt": [{"$size": {"$ifNull": ["$$i.errors", []]}}, 0]},
                    }
                },
            }
        }

        docs = list(
            qs.order_by("-created")
            .skip((page - 1) * page_size)
            .limit(page_size)
            .aggregate([project])
        )

        # Batch-resolve datasets referenced by the (few) error items.
        dataset_ids = {
            it.get("dataset")
            for doc in docs
            for it in (doc.get("error_items") or [])
            if it.get("dataset")
        }
        dataset_map = {}
        if dataset_ids:
            for ds in Dataset.objects(id__in=list(dataset_ids)):
                dataset_map[ds.id] = {
                    "id": str(ds.id),
                    "title": ds.title,
                    "page": ds.self_web_url(),
                }

        show_details = admin_permission.can()
        source_id = str(source.id)
        data = [_serialize_light_job(doc, dataset_map, source_id, show_details) for doc in docs]

        return {
            "data": data,
            "total": total,
            "page": page,
            "page_size": page_size,
            "next_page": None,
            "previous_page": None,
        }


@ns.route("/job/<string:ident>/", endpoint="harvest_job")
class JobAPI(API):
    @api.doc("get_harvest_job")
    @api.expect(parser)
    @api.marshal_with(job_fields)
    def get(self, ident):
        """Get a single job given an ID"""
        return actions.get_job(ident)


@ns.route("/backends/", endpoint="harvest_backends")
class ListBackendsAPI(API):
    @api.doc("harvest_backends")
    @api.marshal_with(backend_fields)
    def get(self):
        """List all available harvest backends"""
        return sorted(
            [
                {
                    "id": b.name,
                    "label": b.display_name,
                    "filters": [f.as_dict() for f in b.filters],
                    "features": [f.as_dict() for f in b.features],
                    "extra_configs": [f.as_dict() for f in b.extra_configs],
                }
                for b in get_enabled_backends().values()
            ],
            key=lambda b: b["label"],
        )
