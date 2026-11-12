"""
This migration gives a date back to datasets whose `last_update` is absent or null.

The field carried `default=lambda: datetime.now(UTC)` until LEDG-2732. MongoEngine
applies a field default when the stored value is missing, and it does so on load, not on
write — so a document without the field answered every read with a fresh timestamp equal
to the instant of that read. Nothing was ever written, which is why the condition never
healed and why it was invisible in the database: two consecutive API calls simply
disagreed, and the one observed dataset sat first under `?sort=last_update` ascending
dated 2026, ahead of datasets from 2007.

Removing the default makes those documents read as `None`, which is honest but not yet
correct. This migration computes the real value for each of them.

Separate from the 2026-10-30 migration on purpose. That one heals documents whose
`last_update` *disagrees* with their resources, and it skips anything reading `None` —
which, after LEDG-2732, is exactly this population. The two conditions do not overlap and
both migrations have to run; neither replaces the other.

The query goes through `__raw__` rather than `Dataset.objects(last_update=None)`. Without
a default, MongoEngine translates the latter correctly, but the raw form also catches
documents where the key is absent altogether, which is the shape actually observed in
production.

`save()` is what writes the value, because `clean()` recomputes `last_update` and
`quality_cached` together in the order they depend on each other; re-deriving them here
would be a second copy of that order, free to drift from the model. It also fires
`post_save`, so the corrected date reaches the search index per document.

Deleted datasets are skipped for the same reason as the 2026-10-30 migration, and that
reason is not performance: `Auditable.post_save` fires `on_delete` for any document
carrying `deleted`, which recounts the owning organisation's metrics and saves it,
stamping the date that organisation's card shows. Fixing a dataset's date is no reason to
overwrite an organisation's. Nothing is lost — a deleted dataset serves its date to
nobody, and restoring one goes through `save()` and therefore `clean()`.

The final count is a lower bound on how many datasets the environment was serving a
fabricated date for: a document whose write succeeded but whose `post_save` receivers then
raised is logged as an error and not counted. Read it with the error lines, not alone.
"""

import logging

import click

from udata.core.dataset.models import Dataset

log = logging.getLogger(__name__)


def migrate(db):
    log.info("Looking for datasets whose last_update is missing or null")

    # `$in: [None]` matches both a stored null and an absent key; `$eq: None` alone would
    # match the same, but the explicit form is the one the other migrations in this
    # directory use for the same question.
    candidates = Dataset.objects(deleted=None).filter(__raw__={"last_update": {"$in": [None]}})

    total = candidates.count()
    healed = 0
    forced = 0

    log.info(f"{total} datasets have no stored last_update")

    with click.progressbar(candidates.no_cache(), length=total) as datasets:
        for dataset in datasets:
            try:
                expected = dataset.compute_last_update()
                if expected is None:
                    # No resources and no own date to fall back on. Writing "now" here
                    # would reintroduce exactly the fabricated date this ticket removed.
                    log.warning(f"Cannot compute a last_update for dataset {dataset.id}, skipped")
                    continue

                try:
                    dataset.save()
                    healed += 1
                except Exception as save_err:
                    # The documents missing this field are, as a population, the ones that
                    # cannot be saved — that is how they came to miss it. The production log
                    # of `2025-07-18-compute-last-update`, the migration that introduced the
                    # field, records fifteen failures: fourteen on an owner `User` still
                    # carrying `apikey` after a dump restore, and one on a resource whose
                    # `filetype` is the legacy value `api`, which the model no longer accepts.
                    #
                    # So a backfill built on `save()` fails on exactly the documents it
                    # exists to repair, and that is what the 2026-10-30 migration does. The
                    # atomic update skips validation and writes the one field we came for.
                    # Deliberately narrow: it corrects the date, it does not pretend to
                    # correct the document — `quality_cached` stays as stale as it was, and
                    # the underlying invalidity is still there to be fixed at its source.
                    Dataset.objects(id=dataset.id).update(set__last_update=expected)
                    forced += 1
                    log.warning(
                        f"Dataset {dataset.id} cannot be saved ({save_err}); "
                        f"wrote last_update directly"
                    )
            except Exception as err:
                log.error(f"Cannot backfill last_update for dataset {dataset.id} {err}")

    log.info(
        f"Done: {healed + forced} of {total} datasets had no last_update and were given one "
        f"({healed} through save, {forced} written directly because the document is invalid)"
    )
