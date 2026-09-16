"""
Redact URL credentials already stored by past harvests

`URLS_ALLOW_CREDENTIALS` is true, so a harvest source URL may carry
`user:password@`. Until now everything derived from such a URL was stored
verbatim and served to callers without a session: the text of a `requests`
exception in `HarvestError.message`/`details`, and the source URL copied onto
every harvested dataservice in `harvest.source_url`.

The code no longer writes any of those, but the records written before it
stay readable until the jobs are deleted, so this cleans them.

This does NOT un-leak anything. A credential that was publicly readable is
compromised, and the remedy is to rotate it at the remote source; cleaning
the database does not replace telling the source owners.

Idempotent: the filter pattern also matches an already redacted URL, so a
second run selects the same documents and rewrites the identical value.
"""

import logging

from udata.harvest.url_filter import redact_url_credentials

log = logging.getLogger(__name__)

# `scheme://` then anything up to an `@` that is still inside the authority.
# Deliberately wider than the redaction regex: this only picks candidate
# documents, and `redact_url_credentials` decides what actually changes.
USERINFO_PATTERN = "://[^/?#\\s]*@"

JOB_FIELDS = ("errors.message", "errors.details", "items.errors.message", "items.errors.details")


def _redact_errors(errors):
    """Redact a list of embedded harvest errors in place. Returns True if changed."""
    changed = False
    for error in errors or []:
        for key in ("message", "details"):
            before = error.get(key)
            after = redact_url_credentials(before)
            if after != before:
                error[key] = after
                changed = True
    return changed


def migrate(db):
    log.info("Redacting URL credentials stored in harvest job errors...")

    query = {"$or": [{field: {"$regex": USERINFO_PATTERN}} for field in JOB_FIELDS]}
    jobs = 0
    for job in db.harvest_job.find(query):
        changed = _redact_errors(job.get("errors"))
        items = job.get("items") or []
        for item in items:
            changed = _redact_errors(item.get("errors")) or changed

        if changed:
            db.harvest_job.update_one(
                {"_id": job["_id"]},
                {"$set": {"errors": job.get("errors", []), "items": items}},
            )
            jobs += 1

    log.info("Redacted %s harvest job(s).", jobs)

    log.info("Redacting the source URL copied onto harvested dataservices...")

    dataservices = 0
    for dataservice in db.dataservice.find({"harvest.source_url": {"$regex": USERINFO_PATTERN}}):
        source_url = dataservice["harvest"]["source_url"]
        redacted = redact_url_credentials(source_url)
        if redacted != source_url:
            db.dataservice.update_one(
                {"_id": dataservice["_id"]},
                {"$set": {"harvest.source_url": redacted}},
            )
            dataservices += 1

    log.info("Redacted %s dataservice(s).", dataservices)
