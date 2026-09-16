"""Replace the harvest source text index and report the sources that still
carry credentials in their URL.

Two halves of the same residue (LEDG-2502).

The text index used to cover `$name, $url`, and the sources route accepts `q`,
so `?q=<password>` returned the source carrying that password -- a confirmation
oracle for anyone who had guessed one. The model now indexes `name` alone, but
MongoDB allows a single text index per collection and refuses to create the new
one next to the old (`IndexOptionsConflict`), so the old one has to be dropped
here: without this migration, the first access to `harvest_source` in a process
running the new code raises `OperationFailure`, not a degraded search.

The sources that already store credentials are reported, never rewritten.
Stripping the userinfo of a stored URL breaks that source's harvest with a 401
that nobody decided, and destroys the only copy of the credential its owner
would need to reconfigure it. After the rejection in `HarvestURLField` and the
index change, what is left is a working-source problem, not an exposure: the
URL is already redacted for readers without `edit`, and the search no longer
confirms it. So this names the sources and lets the operator choose.

An inventory of production found none, so the expected output is a zero.
"""

import logging
from urllib.parse import urlsplit

from mongoengine.connection import get_db
from pymongo.errors import OperationFailure

from udata.models import Harvest as HarvestSource

log = logging.getLogger(__name__)

# Same pattern as `2026-09-16-redact-harvested-resource-url-credentials.py`, and
# deliberately wider than a strict parse: it only picks candidate documents.
USERINFO_PATTERN = "//[^/?#\\s]*@"


def _drop_url_text_index(db):
    """Drop whatever text index covers `url`, then let the model rebuild.

    Matched on its weights rather than on the name `name_text_url_text`: that
    name is MongoDB's default for those fields, not something the code ever
    fixed, and a database that acquired the index by another route would be
    missed by a name lookup.
    """
    collection = get_db().harvest_source

    for name, spec in collection.index_information().items():
        weights = spec.get("weights") or {}
        if "url" not in weights:
            continue
        try:
            collection.drop_index(name)
            log.info("Dropped text index `%s` covering url.", name)
        except OperationFailure:
            log.info("Index `%s` could not be dropped?", name, exc_info=True)

    # Rebuild explicitly rather than through a read like
    # `2025-11-13-delete-user-email-index.py` does: `_get_collection` only calls
    # `ensure_indexes` the first time a process touches the collection, and this
    # command may well have touched it already.
    HarvestSource.ensure_indexes()
    log.info("Recreated the harvest source indexes without url.")


def _report_credentialed_sources(db):
    """Name every source whose URL still carries userinfo. Writes nothing.

    Logs the id, the slug and the host -- never the URL, which is the secret.
    """
    sources = db.harvest_source.find(
        {"url": {"$regex": USERINFO_PATTERN}},
        {"_id": 1, "slug": 1, "name": 1, "url": 1, "deleted": 1, "active": 1},
    )

    total = 0
    for source in sources:
        total += 1
        try:
            host = urlsplit(source.get("url") or "").hostname
        except ValueError:
            host = None
        log.warning(
            "Harvest source %s (slug=%s, host=%s, active=%s, deleted=%s) still has "
            "credentials in its URL. Editing it now requires removing them; "
            "harvesting keeps working until then.",
            source["_id"],
            source.get("slug"),
            host or "?",
            source.get("active"),
            bool(source.get("deleted")),
        )

    log.info("Harvest sources still carrying credentials in their URL: %s.", total)


def migrate(db):
    _drop_url_text_index(db)
    _report_credentialed_sources(db)
