"""
Create the datastory_metrics collection and its unique index on slug

Datastories are Squidex content, so udata has no document to hang their view
count on. `datastory_metrics` keeps it, one document per slug, and the
`metrics_etl` DAG (`dadosgov-metrics`) writes it with an upsert by slug. Without
a unique index, two concurrent upserts for a datastory nobody had viewed before
could both insert, leaving two documents and the reader picking either.

Created here rather than left to mongoengine's lazy index creation, because the
DAG writes the collection directly and may do so before udata ever touches it.
"""

import logging

log = logging.getLogger(__name__)


def migrate(db):
    log.info("Creating unique index on datastory_metrics.slug...")
    db.datastory_metrics.create_index("slug", unique=True, background=True)
    log.info("Index created successfully.")
