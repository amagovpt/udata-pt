"""
This migration heals datasets whose `last_update` predates the resource-mutator fix.

`last_update` is recomputed in `Dataset.clean()`, and until now the three resource
mutators wrote through an atomic update that never reached it. Those are what the API
calls when a publisher uploads, edits or deletes a file, so any dataset touched that way
kept whatever date it already carried. Nothing cures these documents on its own: the
mutators do not call `save()`, and only the INE backend heals its own on the next
harvest. A dataset whose last file was deleted in 2024 would announce 2024 forever, and
its `quality_cached` would keep deriving from that date.

Unlike the 2025-07-18 migration, which saved the whole catalogue to introduce the field,
this one saves only the datasets that actually disagree with their resources. Each
`save()` runs the document's `pre_save`, an extra read in `Auditable.clean()`, a homepage
cache invalidation, and queues a `reindex.delay()` on the `high.search` route. Rewriting
twenty-odd thousand correct documents to fix a few dozen would cost twenty-odd thousand
Celery tasks for nothing. Same reasoning as the 2026-10-01 migration, which also narrows
its target and says why.

`last_modified_internal` is deliberately left alone. `save()` does not stamp it, and that
is what we want: the search sorts on that field, so bumping it would push years-old
datasets to the top of the portal's "most recent" listing for no reason a visitor could
see. The corrected `last_update` still reaches the index, because `save()` fires
`post_save` and the auto-index hook queues the reindex per document.

The final count is a lower bound on how many datasets this environment was serving
wrongly: a document whose write succeeded but whose `post_save` receivers then raised is
logged as an error and not counted. Read it with the error lines, not on its own.

Note also that this iterates every dataset, deleted and private ones included. That is
deliberate — a hidden dataset carries the same wrong date and would serve it the moment
it is restored — but it means a soft-deleted document is saved, which re-fires its
`on_delete` receivers and their metric recounts.
"""

import logging

import click

from udata.core.dataset.models import Dataset
from udata.utils import to_naive_datetime

log = logging.getLogger(__name__)

# Matches the slack the test suite allows, so serialization noise is not treated as drift.
TOLERANCE_SECONDS = 1


def migrate(db):
    log.info("Looking for datasets whose last_update disagrees with their resources")

    total = Dataset.objects().count()
    healed = 0

    with click.progressbar(Dataset.objects().no_cache(), length=total) as datasets:
        for dataset in datasets:
            try:
                expected = dataset.compute_last_update()
                if expected is None or dataset.last_update is None:
                    continue

                drift = to_naive_datetime(expected) - to_naive_datetime(dataset.last_update)
                if abs(drift.total_seconds()) <= TOLERANCE_SECONDS:
                    continue

                # `clean()` recomputes `last_update` and `quality_cached` together, in the
                # order they depend on each other. Re-deriving them here by hand would be
                # a second copy of that order, free to drift from the model.
                dataset.save()
                healed += 1
            except Exception as err:
                log.error(f"Cannot recompute last_update for dataset {dataset.id} {err}")

    log.info(f"Done: {healed} of {total} datasets had a stale last_update and were corrected")
