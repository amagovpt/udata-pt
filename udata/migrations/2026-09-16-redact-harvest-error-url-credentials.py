"""
Redact URL credentials already stored by past harvests

`URLS_ALLOW_CREDENTIALS` is true, so a harvest source URL may carry
`user:password@`. Until now everything derived from such a URL was stored
verbatim and served to callers without a session: the text of a `requests`
exception in `HarvestError.message`/`details`, the captured log lines in
`HarvestItem.logs[].message`, and the source URL copied onto every harvested
dataservice in `harvest.source_url`.

The code no longer writes any of those, but the records written before it stay
readable until the jobs are deleted, so this cleans them.

This does NOT un-leak anything. A credential that was publicly readable is
compromised, and the remedy is to rotate it at the remote source; cleaning the
database does not replace telling the source owners.

Only the individual fields that change are written, never a whole `items`
array: a harvest running while this migration does would otherwise have the
items it appended in the meantime overwritten by the stale copy read here.

Idempotent: a second run selects the same documents, finds nothing to change
and writes nothing.
"""

import logging

from udata.harvest.url_filter import redact_url_credentials

log = logging.getLogger(__name__)

# Deliberately wider than the redaction itself: this only picks candidate
# documents, and `redact_url_credentials` decides what actually changes.
USERINFO_PATTERN = "//[^/?#\\s]*@"

JOB_FIELDS = (
    "errors.message",
    "errors.details",
    "items.errors.message",
    "items.errors.details",
    "items.logs.message",
)


def _redact_into(updates, prefix, documents, keys):
    """Collect `{dotted.path: redacted}` for the entries that actually change."""
    for index, document in enumerate(documents or []):
        for key in keys:
            before = document.get(key)
            after = redact_url_credentials(before)
            if after != before:
                updates[f"{prefix}.{index}.{key}"] = after


def migrate(db):
    log.info("Redacting URL credentials stored in harvest jobs...")

    query = {"$or": [{field: {"$regex": USERINFO_PATTERN}} for field in JOB_FIELDS]}
    jobs = 0
    for job in db.harvest_job.find(query, no_cursor_timeout=True):
        updates = {}
        _redact_into(updates, "errors", job.get("errors"), ("message", "details"))
        for index, item in enumerate(job.get("items") or []):
            _redact_into(
                updates, f"items.{index}.errors", item.get("errors"), ("message", "details")
            )
            _redact_into(updates, f"items.{index}.logs", item.get("logs"), ("message",))

        if updates:
            db.harvest_job.update_one({"_id": job["_id"]}, {"$set": updates})
            jobs += 1

    log.info("Redacted %s harvest job(s).", jobs)

    log.info("Redacting the source URL copied onto harvested dataservices...")

    dataservices = 0
    for dataservice in db.dataservice.find(
        {"harvest.source_url": {"$regex": USERINFO_PATTERN}}, no_cursor_timeout=True
    ):
        source_url = dataservice["harvest"]["source_url"]
        redacted = redact_url_credentials(source_url)
        if redacted != source_url:
            db.dataservice.update_one(
                {"_id": dataservice["_id"]},
                {"$set": {"harvest.source_url": redacted}},
            )
            dataservices += 1

    log.info("Redacted %s dataservice(s).", dataservices)
