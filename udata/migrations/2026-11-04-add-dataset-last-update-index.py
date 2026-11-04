"""
Add an index on dataset.last_update

`?sort=last_update` orders on this field from two endpoints: the v1 listing,
which has done so for a long time, and the v2 search, which only starts doing
it in this release — until now it named `last_modified_internal` there, a
different date.

Measured on 19874 visible datasets without the index, the plan is SORT over
COLLSCAN: a blocking sort that loads whole documents, resources included,
because neither path excludes them. With the index the sort stage disappears
(FETCH over IXSCAN) and the query drops from 188ms to 57ms.

Created here rather than left to `auto_create_index_on_save`, which would build
it inside whichever request or task first saves a dataset after deploy, with no
record that it happened. `background=True` so it does not block writes while it
builds — seconds at this collection size, but the same courtesy the
harvest.remote_id index was given.
"""

import logging

log = logging.getLogger(__name__)


def migrate(db):
    log.info("Creating index on dataset.last_update...")
    db.dataset.create_index("last_update", background=True)
    log.info("Index created successfully.")
