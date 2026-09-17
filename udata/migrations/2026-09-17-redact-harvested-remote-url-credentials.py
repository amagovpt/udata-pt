"""
Redact URL credentials already stored in harvested remote URLs

Third and last of the series that started with
`2026-09-16-redact-harvest-error-url-credentials.py` (the metadata channels)
and `2026-09-16-redact-harvested-resource-url-credentials.py` (the ODS resource
URLs and the maaf remote ids). The inventory behind that second one concluded
that only `odspt` and `maaf` derived published data from the harvest source
URL. That was incomplete: the CKAN family built `Dataset.harvest.remote_url`
out of the source URL too, through `CkanBackend.dataset_url`, and `ckanpt` and
`dkan` inherit it.

`Dataset.harvest.remote_url` is the worst of the three channels. It is a field
of every dataset, not just the harvested ones an audit would think to look at;
it is served to callers without a session by the dataset API, the public
dataset CSV and the RDF `dcat:landingPage`; it is copied onto
`HarvestItem.remote_url`, which the harvest job API serializes unauthenticated;
and unlike a harvest job, which is eventually purged, it is permanent.

The code no longer writes a credentialed value (LEDG-2504), so this only cleans
what earlier harvests left behind.

Inventory, run before this was written, against a production-scale restore
(23,080 datasets, 46 harvest sources, data through August 2026): no source of
any backend carries `@` in its URL, so no record is affected. This is expected
to be a no-op; it exists so the invariant holds for whatever was written
between that restore and this deploy, and its counters are the inventory of the
live database. A credentialed source created after that restore and not yet
harvested would leave both passes at zero while still being exactly what the
audit asked about, which is why the source counts are logged separately.

`dataset.harvest.remote_id` is counted and NOT rewritten. The question was
worth asking -- `maaf` used a descriptor URL as a remote id, which the previous
migration redacted on `harvest_job.items[].remote_id` -- but no writer puts a
source-derived URL there: the CKAN family uses the package name and then the
package id, and `maaf` replaces the item's remote id with `metadata["id"]`
before the dataset is saved. Rewriting it would have a functional cost,
because `BaseBackend.get_dataset` matches on `harvest.remote_id`, and no write
path justifies paying it. The counter answers the question with live data
instead of by omission; a non-zero result is a new ticket, with the backend
named.

This does NOT un-leak anything. A credential that was publicly readable is
compromised, and the remedy is to rotate it at the remote source; cleaning the
database does not replace telling the source owners.

Only the individual fields that change are written, never a whole `items`
array: a harvest writing at the same time appends to it, and a stale copy read
here would undo that. Each write is also pinned to the values just read, so a
concurrent write makes the update a no-op rather than an overwrite, and
re-running redacts whatever it skipped.

Idempotent: a second run selects the same documents, finds nothing to change
and writes nothing.
"""

import logging

from udata.harvest.url_filter import redact_url_credentials_in_url

log = logging.getLogger(__name__)

# Deliberately wider than the redaction itself: this only picks candidate
# documents, and `redact_url_credentials_in_url` decides what actually changes.
USERINFO_PATTERN = "//[^/?#\\s]*@"

# The backends that build a published URL on the source URL through
# `CkanBackend.dataset_url`. Only used for the log line -- the redaction passes
# below are deliberately not scoped to them.
CKAN_BACKENDS = ["ckan", "ckanpt", "dkan"]


def _count_credentialed_sources(db):
    """Log how many live harvest sources carry userinfo, in total and per backend.

    This is the number the security audit asked for, measured on the live
    database at deploy time rather than on a restore.
    """
    query = {"url": {"$regex": USERINFO_PATTERN}}
    total = db.harvest_source.count_documents(query)
    derived = db.harvest_source.count_documents(dict(query, backend={"$in": CKAN_BACKENDS}))
    log.info(
        "Harvest sources with credentials in their URL: %s (%s of them ckan/ckanpt/dkan).",
        total,
        derived,
    )


def _redact_dataset_remote_urls(db):
    """Redact `harvest.remote_url` on every dataset that holds a credentialed URL.

    Not scoped to the CKAN backends, and not scoped by a marker the way the ODS
    resource pass had to be. `Resource.url` needed that scope because a
    publisher can legitimately type a credentialed URL on a resource of their
    own; `dataset.harvest` has no such writer -- the dataset form does not touch
    it, only harvesters do -- so a `remote_url` carrying userinfo is a
    harvester-derived value in a public field whichever backend wrote it.
    """
    query = {"harvest.remote_url": {"$regex": USERINFO_PATTERN}}

    datasets = 0
    for dataset in db.dataset.find(query, no_cursor_timeout=True):
        before = (dataset.get("harvest") or {}).get("remote_url")
        after = redact_url_credentials_in_url(before)
        if after == before:
            continue

        # Pinned to the value just read: a harvest running at the same time
        # would otherwise have its write silently replaced by this stale one.
        guard = {"_id": dataset["_id"], "harvest.remote_url": before}
        if db.dataset.update_one(guard, {"$set": {"harvest.remote_url": after}}).modified_count:
            datasets += 1

    log.info("Redacted %s dataset(s).", datasets)


def _redact_item_remote_urls(db):
    """Redact the `remote_url` of every harvest item that holds a credentialed URL.

    This is the copy `BaseBackend` makes of the dataset's own `remote_url`, and
    the harvest job API serializes it without requiring a session.
    """
    query = {"items.remote_url": {"$regex": USERINFO_PATTERN}}

    jobs = 0
    for job in db.harvest_job.find(query, no_cursor_timeout=True):
        updates = {}
        seen = {}
        for index, item in enumerate(job.get("items") or []):
            before = item.get("remote_url")
            after = redact_url_credentials_in_url(before)
            if after != before:
                updates[f"items.{index}.remote_url"] = after
                seen[f"items.{index}.remote_url"] = before

        if updates:
            guard = {"_id": job["_id"]}
            guard.update(seen)
            if db.harvest_job.update_one(guard, {"$set": updates}).modified_count:
                jobs += 1

    log.info("Redacted %s harvest job(s).", jobs)


def _count_credentialed_remote_ids(db):
    """Count, without rewriting, the datasets whose `harvest.remote_id` holds userinfo.

    See the module docstring: no writer derives a remote id from the source
    URL, and rewriting one would break the match `BaseBackend.get_dataset`
    makes on it. A non-zero count means a writer was missed, and is a new
    ticket rather than something to fix silently here.
    """
    total = db.dataset.count_documents({"harvest.remote_id": {"$regex": USERINFO_PATTERN}})
    if total:
        log.warning(
            "%s dataset(s) carry credentials in harvest.remote_id; "
            "left untouched on purpose -- see LEDG-2504.",
            total,
        )
    else:
        log.info("No dataset carries credentials in harvest.remote_id.")


def migrate(db):
    _count_credentialed_sources(db)

    log.info("Redacting URL credentials stored in dataset harvest remote urls...")
    _redact_dataset_remote_urls(db)

    log.info("Redacting URL credentials stored in harvest item remote urls...")
    _redact_item_remote_urls(db)

    _count_credentialed_remote_ids(db)
