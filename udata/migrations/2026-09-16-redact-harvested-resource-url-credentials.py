"""
Redact URL credentials already stored in harvested resources and remote ids

Companion to `2026-09-16-redact-harvest-error-url-credentials.py`, which
cleaned the channels where a credentialed harvest source URL was *metadata*.
This one cleans the two channels that were left standing there because
redacting them has a functional consequence: the `odspt` backend built
`Dataset.resources[].url` and `extras["ods:url"]` out of the source URL, and
the `maaf` backend used the descriptor URL as `HarvestItem.remote_id`. Both are
served to callers without a session, and `/r/<id>` went further and fetched the
file with those credentials on an anonymous caller's behalf.

The code no longer writes any of those (LEDG-2500), so this only cleans what
earlier harvests left behind.

Inventory, run before this was written, against a production-scale restore
(23,080 datasets, 46 harvest sources, data through August 2026): one `odspt`
source and no `maaf` source, neither carrying credentials, and no affected
record in any of the three fields. This is expected to be a no-op; it exists so
the invariant holds for whatever was written between that restore and this
deploy, and its counters are the inventory of the live database.

The harvest source counts are logged for the same reason. A credentialed source
created after that restore and not yet harvested would leave both passes at
zero while still being exactly what the audit asked about.

This does NOT un-leak anything. A credential that was publicly readable is
compromised, and the remedy is to rotate it at the remote source; cleaning the
database does not replace telling the source owners.

Only the individual fields that change are written, never a whole `resources`
or `items` array: a harvest -- or an editor -- writing at the same time would
otherwise have its work overwritten by the stale copy read here.

Idempotent: a second run selects the same documents, finds nothing to change
and writes nothing.
"""

import logging

from udata.harvest.url_filter import redact_url_credentials

log = logging.getLogger(__name__)

# Deliberately wider than the redaction itself: this only picks candidate
# documents, and `redact_url_credentials` decides what actually changes.
USERINFO_PATTERN = "//[^/?#\\s]*@"

# The marker `odspt` writes on every dataset it harvests. Scoping to it matters:
# `Resource.url` is a URLField under `URLS_ALLOW_CREDENTIALS`, so a publisher
# may legitimately have typed a credentialed URL on a resource of their own, and
# that is not this migration's business. `2020-10-16-migrate-ods-resources.py`
# already uses the same marker to mean "an ODS dataset".
ODS_MARKER = "extras.ods:url"


def _count_credentialed_sources(db):
    """Log how many live harvest sources carry userinfo, in total and per backend.

    This is the number the security audit asked for, measured on the live
    database at deploy time rather than on a restore.
    """
    query = {"url": {"$regex": USERINFO_PATTERN}}
    total = db.harvest_source.count_documents(query)
    derived = db.harvest_source.count_documents(dict(query, backend={"$in": ["odspt", "maaf"]}))
    log.info(
        "Harvest sources with credentials in their URL: %s (%s of them odspt/maaf).",
        total,
        derived,
    )


def _redact_ods_datasets(db):
    """Redact the resource URLs and the explore URL of every ODS dataset."""
    query = {
        ODS_MARKER: {"$exists": True},
        "$or": [
            {"resources.url": {"$regex": USERINFO_PATTERN}},
            {ODS_MARKER: {"$regex": USERINFO_PATTERN}},
        ],
    }

    datasets = 0
    for dataset in db.dataset.find(query, no_cursor_timeout=True):
        updates = {}

        for index, resource in enumerate(dataset.get("resources") or []):
            before = resource.get("url")
            after = redact_url_credentials(before)
            if after != before:
                updates[f"resources.{index}.url"] = after

        before = (dataset.get("extras") or {}).get("ods:url")
        after = redact_url_credentials(before)
        if after != before:
            updates[ODS_MARKER] = after

        if updates:
            db.dataset.update_one({"_id": dataset["_id"]}, {"$set": updates})
            datasets += 1

    log.info("Redacted %s dataset(s).", datasets)


def _redact_item_remote_ids(db):
    """Redact the `remote_id` of every harvest item that holds a credentialed URL.

    Not scoped to `maaf`: a `remote_id` carrying userinfo is a credential in a
    public field whichever backend wrote it.
    """
    query = {"items.remote_id": {"$regex": USERINFO_PATTERN}}

    jobs = 0
    for job in db.harvest_job.find(query, no_cursor_timeout=True):
        updates = {}
        for index, item in enumerate(job.get("items") or []):
            before = item.get("remote_id")
            after = redact_url_credentials(before)
            if after != before:
                updates[f"items.{index}.remote_id"] = after

        if updates:
            db.harvest_job.update_one({"_id": job["_id"]}, {"$set": updates})
            jobs += 1

    log.info("Redacted %s harvest job(s).", jobs)


def migrate(db):
    _count_credentialed_sources(db)

    log.info("Redacting URL credentials stored in harvested ODS datasets...")
    _redact_ods_datasets(db)

    log.info("Redacting URL credentials stored in harvest item remote ids...")
    _redact_item_remote_ids(db)
