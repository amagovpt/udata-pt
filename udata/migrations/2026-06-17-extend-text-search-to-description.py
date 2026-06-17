"""
Extend MongoDB text indexes to include description (and acronym where applicable).

Before this migration, full-text search on the dataset, organization and reuse
collections was limited to the title (or name) field only.  After this migration
the following compound text indexes are in place:

  dataset      : title, description, acronym
  organization : name,  description, acronym
  reuse        : title, description

The migration drops any existing text index on each collection (MongoDB allows
only one text index per collection) and recreates it with the expanded field set.
"""

import logging

log = logging.getLogger(__name__)


_TEXT_INDEXES = [
    ("dataset", [("title", "text"), ("description", "text"), ("acronym", "text")]),
    ("organization", [("name", "text"), ("description", "text"), ("acronym", "text")]),
    ("reuse", [("title", "text"), ("description", "text")]),
]


def migrate(db):
    for collection_name, fields in _TEXT_INDEXES:
        collection = db[collection_name]

        for index_name, index_info in collection.index_information().items():
            if "weights" in index_info:
                collection.drop_index(index_name)
                log.info("Dropped existing text index '%s' on '%s'", index_name, collection_name)
                break

        collection.create_index(fields)
        log.info(
            "Created compound text index on '%s' for fields: %s",
            collection_name,
            ", ".join(f for f, _ in fields),
        )

    log.info("Text-index extension migration complete.")
