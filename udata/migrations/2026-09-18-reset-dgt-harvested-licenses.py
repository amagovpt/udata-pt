"""
Clear the cc-by the DGT harvester stamped on every dataset it collected

The backend now derives the licence from the source's `legalConstraints` and
falls back to whatever the dataset already carries, so a producer's correction
survives the next harvest. That fallback is also why this migration has to
exist: the `cc-by` sitting on the 1213 harvested datasets was not written by a
producer, it was written by the constant this release removes. Left in place,
the fallback would read the bug as an editorial decision and preserve it
forever -- the LNEG dataset would go on being CC BY 4.0, which is the whole
complaint.

Three choices worth stating:

`harvest.source_id`, not `harvest.backend`. The latter stores the backend's
DISPLAY name ("Harvester DGT"), so filtering it by "dgt" matches nothing at
all.

Only where the licence is exactly `cc-by`. That is the single value the removed
constant could ever write, so anything else on a DGT-harvested dataset is
somebody's correction and is left alone. A correction that happened to be
`cc-by` is indistinguishable from the bug and is cleared with it; the ids of
everything touched are logged so such a case can be answered afterwards.

`$unset` rather than writing `notspecified`. The next harvest decides from the
source text, and until it runs the API answers `notspecified` anyway --
`license.id` is marshalled with the default licence as its fallback.

Note that the search index is not refreshed: a raw pymongo write fires no
mongoengine signal, so `/api/1/datasets/?license=cc-by` keeps returning these
datasets until the next harvest reindexes them.

Idempotent: a second run finds no `cc-by` left on those datasets.
"""

import logging

log = logging.getLogger(__name__)


def migrate(db):
    log.info("Clearing the harvester-written cc-by on DGT datasets...")

    source_ids = [
        str(source["_id"]) for source in db.harvest_source.find({"backend": "dgt"}, {"_id": 1})
    ]
    if not source_ids:
        log.info("No dgt harvest source found; nothing to do.")
        return

    query = {"harvest.source_id": {"$in": source_ids}, "license": "cc-by"}
    touched = [dataset["_id"] for dataset in db.dataset.find(query, {"_id": 1})]

    result = db.dataset.update_many(query, {"$unset": {"license": ""}})

    log.info(
        "Cleared the license on %s dataset(s) across %s dgt source(s): %s",
        result.modified_count,
        len(source_ids),
        ", ".join(str(dataset_id) for dataset_id in touched) or "none",
    )
