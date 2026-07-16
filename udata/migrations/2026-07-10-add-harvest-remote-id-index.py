"""
Add an index on dataset.harvest.remote_id

Harvesters look datasets up by `harvest.remote_id` on every run:
`BaseBackend.get_dataset()` once per remote item, and the INE backend also
uses it as the filter of its bulk upserts and post-create id lookups.
Without an index every one of those lookups is a full collection scan,
which makes large harvests (INE: ~8500 items) take minutes of pure
COLLSCAN time per run.
"""

import logging

log = logging.getLogger(__name__)


def migrate(db):
    log.info("Creating index on dataset.harvest.remote_id...")
    db.dataset.create_index("harvest.remote_id", background=True)
    log.info("Index created successfully.")
