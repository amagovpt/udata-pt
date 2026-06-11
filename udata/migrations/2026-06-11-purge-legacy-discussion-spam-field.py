"""
Purge any remaining legacy `spam` field from Discussion documents.

The 2025-11-27-migrate-spaminfo-to-reports migration already converts legacy
SpamInfo embedded documents to Report objects and unsets the `spam` field.
However, that migration only ran once and is recorded by filename, so it does
not re-run. Environments where a database snapshot (e.g. a production dump) was
restored *after* the original migration ran end up with discussions that still
carry the legacy `spam` subdocument.

Because the current Discussion/Message models no longer declare `spam` and
MongoEngine loads documents in strict mode, any such document raises
`FieldDoesNotExist: The fields "{'spam'}" do not exist on the document
"Discussion"` on read — turning the `/api/1/discussions/` listing into a 500.

These remaining documents are all `not_checked` (never flagged), so no Report
needs to be created — we only unset the stale field. This migration is
idempotent: re-running it on an already-clean database is a no-op.
"""

import logging

log = logging.getLogger(__name__)


def migrate(db):
    log.info("Purging legacy spam field from discussions...")

    discussion_collection = db.discussion

    # Top-level `spam` field on discussions.
    result = discussion_collection.update_many(
        {"spam": {"$exists": True}}, {"$unset": {"spam": ""}}
    )
    log.info(f"Cleaned up spam field from {result.modified_count} discussions")

    # `spam` field on embedded messages.
    result = discussion_collection.update_many(
        {"discussion.spam": {"$exists": True}}, {"$unset": {"discussion.$[].spam": ""}}
    )
    log.info(f"Cleaned up spam field from messages in {result.modified_count} discussions")
