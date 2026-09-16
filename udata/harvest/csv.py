from udata.core import csv

from .models import HarvestSource
from .url_filter import redact_url_credentials


@csv.adapter(HarvestSource)
class HarvestSourceCsvAdapter(csv.Adapter):
    fields = (
        "id",
        "name",
        # `GET /api/1/site/harvests.csv` needs no session, and when the export
        # feature is on this same adapter produces a public downloadable
        # resource. A raw url column would publish the credentials of every
        # source at once -- no id and no failed harvest required, which is
        # broader than the job endpoint this was reported against (LEDG-2477).
        ("url", lambda o: redact_url_credentials(o.url)),
        ("organization", "organization.name"),
        ("organization_id", "organization.id"),
        "backend",
        "created_at",
        ("validation", lambda o: o.validation.state),
    )
