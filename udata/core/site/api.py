from datetime import datetime, timezone
from pathlib import Path

from flask import current_app, json, make_response, redirect, request, url_for

from udata.api import API, api, fields
from udata.api_fields import patch
from udata.app import cache
from udata.auth import admin_permission
from udata.core import csv
from udata.core.dataservices.csv import DataserviceCsvAdapter
from udata.core.dataservices.models import Dataservice
from udata.core.dataset.api import DatasetApiParser, catalog_parser
from udata.core.dataset.csv import ResourcesCsvAdapter
from udata.core.dataset.search import DatasetSearch
from udata.core.dataset.tasks import get_queryset as get_csv_queryset
from udata.core.organization.api import OrgApiParser
from udata.core.organization.csv import OrganizationCsvAdapter
from udata.core.organization.models import Organization
from udata.core.post.models import Post
from udata.core.reuse.api import ReuseApiParser
from udata.core.reuse.csv import ReuseCsvAdapter
from udata.core.tags.csv import TagCsvAdapter
from udata.core.tags.models import Tag
from udata.harvest.csv import HarvestSourceCsvAdapter
from udata.harvest.models import HarvestSource
from udata.mail import send_mail
from udata.models import Dataset, Reuse
from udata.rdf import CONTEXT, RDF_EXTENSIONS, graph_response, negociate_content
from udata.utils import multi_to_dict

from .forms import SupportContactForm
from .mails import support_contact
from .models import Site, current_site
from .rdf import build_catalog


def _serialize_image(image_field, size):
    """Safely extract image URL from a MongoEngine ImageField."""
    if not image_field:
        return None
    try:
        return image_field(size, external=True)
    except Exception:
        try:
            return image_field.fs.url(image_field.filename, external=True)
        except Exception:
            return None


def _serialize_dataset(dataset):
    """Serialize a Dataset to lightweight homepage dict."""
    org = dataset.organization
    return {
        "id": str(dataset.id),
        "title": dataset.title,
        "slug": dataset.slug,
        "description": dataset.description,
        "last_modified": dataset.last_modified.isoformat() if dataset.last_modified else None,
        "created_at": dataset.created_at.isoformat() if dataset.created_at else None,
        "organization": {"name": org.name} if org else None,
        "metrics": dataset.metrics or {},
    }


def _serialize_reuse(reuse):
    """Serialize a Reuse to lightweight homepage dict."""
    return {
        "id": str(reuse.id),
        "title": reuse.title,
        "slug": reuse.slug,
        "image": _serialize_image(reuse.image, 500),
        "image_thumbnail": _serialize_image(reuse.image, 100),
        "created_at": reuse.created_at.isoformat() if reuse.created_at else None,
    }


def _serialize_post(post):
    """Serialize a Post to lightweight homepage dict."""
    return {
        "id": str(post.id),
        "name": post.name,
        "slug": post.slug,
        "image": _serialize_image(post.image, 400),
        "image_thumbnail": _serialize_image(post.image, 100),
        "created_at": post.created_at.isoformat() if post.created_at else None,
    }


@api.route("/site/", endpoint="site")
class SiteAPI(API):
    @api.doc(id="get_site")
    @api.marshal_with(Site.__read_fields__)
    def get(self):
        """Site-wide variables"""
        return current_site

    @api.secure(admin_permission)
    @api.doc(id="set_site")
    @api.expect(Site.__write_fields__)
    @api.marshal_with(Site.__read_fields__)
    def patch(self):
        patch(current_site, request)

        current_site.save()
        current_site.reload()
        return current_site


support_contact_fields = api.model(
    "SupportContact",
    {
        "topic": fields.String(
            description="Topic of the support request",
            required=True,
            enum=["question", "bug", "feedback"],
        ),
        "email": fields.String(description="Sender email address", required=True),
        "subject": fields.String(description="Subject line", required=True),
        "message": fields.String(description="Body of the support request", required=True),
    },
)


@api.route("/site/contact/", endpoint="site_contact")
class SiteContactAPI(API):
    @api.doc("submit_support_contact")
    @api.expect(support_contact_fields)
    @api.response(204, "Email sent")
    @api.response(400, "Validation error")
    @api.response(503, "Mail recipient not configured")
    def post(self):
        """Send a support email composed from the public support form."""
        form = api.validate(SupportContactForm)

        recipient = current_app.config.get("MAIL_DEFAULT_RECEIVER") or current_app.config.get(
            "CONTACT_EMAIL"
        )
        if not recipient:
            api.abort(503, "Support recipient is not configured")

        message = support_contact(
            topic=form.topic.data,
            sender_email=form.email.data,
            subject=form.subject.data,
            message=form.message.data,
        )
        send_mail(recipient, message, reply_to=form.email.data)
        return "", 204


@api.route("/site/home/", endpoint="site_home")
class SiteHomeAPI(API):
    @api.doc(id="get_site_home")
    @cache.cached(timeout=300, key_prefix="site_home")
    def get(self):
        """Aggregated homepage data with lightweight serialization"""
        site = current_site
        metrics = site.metrics or {}
        featured = [d for d in (site.settings.home_datasets or []) if d is not None]
        if featured:
            datasets = featured[:6]
        else:
            datasets = Dataset.objects.visible().order_by("-created_at_internal")[:6]
        reuses = Reuse.objects.visible().order_by("-created_at")[:3]
        posts = Post.objects.published()[:3]
        return {
            "site_metrics": {
                "datasets": metrics.get("datasets", 0),
                "organizations": metrics.get("organizations", 0),
                "reuses": metrics.get("reuses", 0),
                "users": metrics.get("users", 0),
            },
            "latest_datasets": [_serialize_dataset(d) for d in datasets],
            "latest_reuses": [_serialize_reuse(r) for r in reuses],
            "latest_posts": [_serialize_post(p) for p in posts],
        }


@api.route("/site/home/datasets/", endpoint="site_home_datasets")
class SiteHomeDatasetsAPI(API):
    @api.doc(id="get_home_featured_datasets")
    def get(self):
        """Return the editorially selected featured datasets for the homepage."""
        datasets = current_site.settings.home_datasets or []
        return [_serialize_dataset(d) for d in datasets if d is not None]

    @api.secure(admin_permission)
    @api.doc(id="set_home_featured_datasets")
    def put(self):
        """Replace the list of featured homepage datasets with the given IDs."""
        ids = request.get_json(force=True)
        if not isinstance(ids, list):
            api.abort(400, "Expected a JSON array of dataset IDs")
        datasets = [Dataset.objects.get_or_404(id=dataset_id) for dataset_id in ids]
        current_site.settings.home_datasets = datasets
        current_site.save()
        cache.delete("site_home")
        return [_serialize_dataset(d) for d in datasets]


@api.route("/site/home/reuses/", endpoint="site_home_reuses")
class SiteHomeReusesAPI(API):
    @api.doc(id="get_home_featured_reuses")
    def get(self):
        """Return the editorially selected featured reuses for the homepage."""
        reuses = current_site.settings.home_reuses or []
        return [_serialize_reuse(r) for r in reuses if r is not None]

    @api.secure(admin_permission)
    @api.doc(id="set_home_featured_reuses")
    def put(self):
        """Replace the list of featured homepage reuses with the given IDs."""
        ids = request.get_json(force=True)
        if not isinstance(ids, list):
            api.abort(400, "Expected a JSON array of reuse IDs")
        reuses = [Reuse.objects.get_or_404(id=reuse_id) for reuse_id in ids]
        current_site.settings.home_reuses = reuses
        current_site.save()
        return [_serialize_reuse(r) for r in reuses]


@api.route("/site/data.<_format>", endpoint="site_dataportal")
class SiteDataPortal(API):
    def get(self, _format):
        """Root RDF endpoint with content negociation handling"""
        url = url_for("api.site_rdf_catalog_format", _format=_format)
        return redirect(url)


@api.route("/site/catalog", endpoint="site_rdf_catalog")
class SiteRdfCatalog(API):
    @api.expect(catalog_parser)
    def get(self):
        """Root RDF endpoint with content negociation handling"""
        _format = RDF_EXTENSIONS[negociate_content()]
        # We sanitize the args used as kwargs in url_for
        params = catalog_parser.parse_args()
        url = url_for("api.site_rdf_catalog_format", _format=_format, **params)
        return redirect(url)


@api.route("/site/catalog.<_format>", endpoint="site_rdf_catalog_format")
class SiteRdfCatalogFormat(API):
    @api.expect(catalog_parser)
    def get(self, _format):
        """
        Return the RDF catalog in the requested format.
        Filtering, sorting and paginating abilities apply to the datasets elements.
        """
        params = catalog_parser.parse_args()
        datasets = DatasetApiParser.parse_filters(Dataset.objects.visible(), params)
        datasets = datasets.paginate(params["page"], params["page_size"])
        dataservices = Dataservice.objects.visible().filter_by_dataset_pagination(
            datasets, params["page"]
        )

        catalog = build_catalog(
            current_site, datasets, dataservices=dataservices, _format=_format, **params
        )
        # bypass flask-restplus make_response, since graph_response
        # is handling the content negociation directly
        return make_response(*graph_response(catalog, _format))


@api.route("/site/datasets.csv", endpoint="site_datasets_csv")
class SiteDatasetsCsv(API):
    def get(self):
        # redirect to EXPORT_CSV dataset if feature is enabled and no filter is set
        exported_models = current_app.config.get("EXPORT_CSV_MODELS", [])
        if not request.args and "dataset" in exported_models:
            return redirect(get_export_url("dataset"))
        search_parser = DatasetSearch.as_request_parser(store_missing=False)
        params = search_parser.parse_args()
        params["facets"] = False
        datasets = DatasetApiParser.parse_filters(get_csv_queryset(Dataset), params)
        adapter = csv.get_adapter(Dataset)
        return csv.stream(adapter(datasets), "datasets")


@api.route("/site/resources.csv", endpoint="site_datasets_resources_csv")
class SiteResourcesCsv(API):
    def get(self):
        # redirect to EXPORT_CSV dataset if feature is enabled and no filter is set
        exported_models = current_app.config.get("EXPORT_CSV_MODELS", [])
        if not request.args and "resource" in exported_models:
            return redirect(get_export_url("resource"))
        search_parser = DatasetSearch.as_request_parser(store_missing=False)
        params = search_parser.parse_args()
        params["facets"] = False
        datasets = DatasetApiParser.parse_filters(get_csv_queryset(Dataset), params)
        return csv.stream(ResourcesCsvAdapter(datasets), "resources")


@api.route("/site/organizations.csv", endpoint="site_organizations_csv")
class SiteOrganizationsCsv(API):
    def get(self):
        params = multi_to_dict(request.args)
        # redirect to EXPORT_CSV dataset if feature is enabled and no filter is set
        exported_models = current_app.config.get("EXPORT_CSV_MODELS", [])
        if not params and "organization" in exported_models:
            return redirect(get_export_url("organization"))
        params["facets"] = False
        organizations = OrgApiParser.parse_filters(get_csv_queryset(Organization), params)
        return csv.stream(OrganizationCsvAdapter(organizations), "organizations")


@api.route("/site/reuses.csv", endpoint="site_reuses_csv")
class SiteReusesCsv(API):
    def get(self):
        params = multi_to_dict(request.args)
        # redirect to EXPORT_CSV dataset if feature is enabled and no filter is set
        exported_models = current_app.config.get("EXPORT_CSV_MODELS", [])
        if not params and "reuse" in exported_models:
            return redirect(get_export_url("reuse"))
        params["facets"] = False
        reuses = ReuseApiParser.parse_filters(get_csv_queryset(Reuse), params)
        return csv.stream(ReuseCsvAdapter(reuses), "reuses")


@api.route("/site/dataservices.csv", endpoint="site_dataservices_csv")
class SiteDataservicesCsv(API):
    def get(self):
        params = multi_to_dict(request.args)
        # redirect to EXPORT_CSV dataset if feature is enabled and no filter is set
        exported_models = current_app.config.get("EXPORT_CSV_MODELS", [])
        if not params and "dataservice" in exported_models:
            return redirect(get_export_url("dataservice"))
        params["facets"] = False
        dataservices = Dataservice.apply_sort_filters(get_csv_queryset(Dataservice))
        return csv.stream(DataserviceCsvAdapter(dataservices), "dataservices")


@api.route("/site/harvests.csv", endpoint="site_harvests_csv")
class SiteHarvestsCsv(API):
    def get(self):
        # redirect to EXPORT_CSV dataset if feature is enabled
        exported_models = current_app.config.get("EXPORT_CSV_MODELS", [])
        if "harvest" in exported_models:
            return redirect(get_export_url("harvest"))
        adapter = HarvestSourceCsvAdapter(get_csv_queryset(HarvestSource).order_by("created_at"))
        return csv.stream(adapter, "harvest")


@api.route("/site/tags.csv", endpoint="site_tags_csv")
class SiteTagsCsv(API):
    def get(self):
        adapter = TagCsvAdapter(Tag.objects.order_by("-total"))
        return csv.stream(adapter, "tags")


@api.route("/site/context.jsonld", endpoint="site_jsonld_context")
class SiteJsonLdContext(API):
    def get(self):
        response = make_response(json.dumps(CONTEXT))
        response.headers["Content-Type"] = "application/ld+json"
        return response


def get_export_url(model):
    did = current_app.config["EXPORT_CSV_DATASET_ID"]
    dataset = Dataset.objects.get_or_404(id=did)
    resource = None
    for r in dataset.resources:
        if r.extras.get("csv-export:model", "") == model:
            resource = r
            break
    if not resource:
        api.abort(404)
    return resource.url


LOG_TAIL_MAX_BYTES = 1 * 1024 * 1024  # 1 MB returned at most


def _resolve_log_dir() -> Path:
    """Return the configured log directory, falling back to /logs then ./logs."""
    configured = current_app.config.get("LOG_DIR")
    if configured:
        return Path(configured)
    container_path = Path("/logs")
    if container_path.is_dir():
        return container_path
    # Fallback for local dev: backend/logs (sibling of the udata package root)
    return Path(current_app.root_path).parent / "logs"


def _log_file_meta(path: Path) -> dict:
    stat = path.stat()
    return {
        "name": path.name,
        "size": stat.st_size,
        "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
    }


@api.route("/site/logs/", endpoint="site_logs")
class SiteLogsAPI(API):
    @api.secure(admin_permission)
    @api.doc(id="list_site_logs")
    def get(self):
        """List log files available on the host (admin only)."""
        log_dir = _resolve_log_dir()
        if not log_dir.is_dir():
            return []
        files = []
        for entry in sorted(log_dir.iterdir(), key=lambda p: p.name):
            if not entry.is_file():
                continue
            try:
                files.append(_log_file_meta(entry))
            except OSError:
                continue
        return files


@api.route("/site/logs/<string:filename>/", endpoint="site_log_content")
class SiteLogContentAPI(API):
    @api.secure(admin_permission)
    @api.doc(id="get_site_log_content")
    def get(self, filename: str):
        """Return the (tailed) content of a log file (admin only)."""
        # Reject any path traversal attempt outright
        if "/" in filename or "\\" in filename or filename in ("", ".", ".."):
            api.abort(400, "Invalid log filename")

        log_dir = _resolve_log_dir()
        if not log_dir.is_dir():
            api.abort(404, "Log directory not available")

        target = log_dir / filename
        try:
            resolved = target.resolve(strict=True)
            log_dir_resolved = log_dir.resolve()
            resolved.relative_to(log_dir_resolved)
        except (FileNotFoundError, ValueError, OSError):
            api.abort(404, "Log file not found")

        if not resolved.is_file():
            api.abort(404, "Log file not found")

        stat = resolved.stat()
        size = stat.st_size
        truncated = False
        try:
            with open(resolved, "rb") as f:
                if size > LOG_TAIL_MAX_BYTES:
                    f.seek(size - LOG_TAIL_MAX_BYTES)
                    f.readline()  # discard partial first line
                    raw = f.read()
                    truncated = True
                else:
                    raw = f.read()
        except OSError:
            api.abort(500, "Could not read log file")

        return {
            "name": resolved.name,
            "size": size,
            "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            "truncated": truncated,
            "content": raw.decode("utf-8", errors="replace"),
        }
