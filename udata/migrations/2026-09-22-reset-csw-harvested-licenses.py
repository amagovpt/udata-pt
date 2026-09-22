"""Clear the cc-by the CSW harvesters stamped on every dataset they collected

Both CSW backends set `License.guess("cc-by")` unconditionally, so the ~3900
datasets of the Portal do Ambiente all claim CC BY 4.0 while their records grant
nothing at all. The backend now derives the licence from `dc:rights` and falls
back to whatever the dataset already carries, so a producer's correction
survives the next harvest. That fallback is also why this migration has to
exist: the `cc-by` sitting on those datasets was not written by a producer, it
was written by the constant this release removes. Left in place, the fallback
would read the bug as an editorial decision and preserve it forever -- which is
the whole complaint that was raised against the DGT harvester.

Four choices worth stating:

`harvest.source_id`, not `harvest.backend`. The latter stores the backend's
DISPLAY name ("Harvester Portal do Ambiente"), so filtering it by "apambiente"
matches nothing -- and it is about to change to "CSW Harvester" on the first
harvest after this deploy, which would make it wrong twice over.

`str()` around the source `_id`. `harvest.source_id` is a StringField and the
backend writes `str(self.source.id)` into it, while `_id` comes back from Mongo
as an ObjectId. Without the cast the `$in` matches nothing and this migration
silently clears zero datasets.

Both backends, not just `cswudata`. The sources migration that runs before this
one rewrites `apambiente` to `cswudata`, but selecting on both makes this
correct whichever order they actually run in, and any `cswudata` source in
another environment carries the same bug anyway.

Only where the licence is exactly `cc-by`. That is the single value the removed
constant could ever write, so anything else on one of these datasets is
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

CSW_BACKENDS = ["apambiente", "cswudata"]


def migrate(db):
    log.info("Clearing the harvester-written cc-by on CSW-harvested datasets...")

    source_ids = [
        # `str`: `harvest.source_id` is a string field, `_id` is an ObjectId.
        str(source["_id"])
        for source in db.harvest_source.find({"backend": {"$in": CSW_BACKENDS}}, {"_id": 1})
    ]
    if not source_ids:
        log.info("No CSW harvest source found; nothing to do.")
        return

    query = {"harvest.source_id": {"$in": source_ids}, "license": "cc-by"}
    touched = [dataset["_id"] for dataset in db.dataset.find(query, {"_id": 1})]

    result = db.dataset.update_many(query, {"$unset": {"license": ""}})

    log.info(
        "Cleared the license on %s dataset(s) across %s CSW source(s).",
        result.modified_count,
        len(source_ids),
    )
    # The ids are what lets a producer's complaint be answered afterwards, but
    # thousands of them on one line is more than syslog and the log shippers
    # keep -- which loses the very thing they are logged for.
    for start in range(0, len(touched), 50):
        log.info(
            "  cleared: %s",
            ", ".join(str(dataset_id) for dataset_id in touched[start : start + 50]),
        )
