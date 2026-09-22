"""
Unset HarvestSource references to users that no longer exist
"""

import logging

import mongoengine

from udata.harvest.models import HarvestSource

log = logging.getLogger(__name__)


def migrate(db):
    log.info("Processing HarvestSource user references.")

    # `validation.by` has no `reverse_delete_rule` -- mongoengine refuses one on
    # an EmbeddedDocument field -- so it is left dangling by any removal of a
    # user, and dereferencing it during marshalling used to fail the whole
    # sources listing.
    by_count = 0
    for source in HarvestSource.objects(validation__by__ne=None).no_cache():
        try:
            source.validation.by
        except mongoengine.errors.DoesNotExist as e:
            by_count += 1
            # Logged per source, because the counters below say how much was
            # repaired and nothing says *what*: after this runs, the only record
            # of who validated these sources is this line.
            log.info(f"Unsetting validation.by on HarvestSource {source.id}: {e}")
            HarvestSource.objects(pk=source.pk).update_one(set__validation__by=None)

    # `owner` does carry `reverse_delete_rule=NULLIFY`, but that only runs when
    # the user is removed through the ORM, and these references went dangling
    # through direct writes to the database. The same held for `periodic_task`,
    # which has NULLIFY and still needed the 2025-10-29 migration.
    #
    # This is the only thing here that repairs a dangling `owner`: unlike
    # `validation.by`, it is dereferenced by the permission checks behind the
    # `url` and `config` attributes, well before any field could tolerate it.
    #
    # Atomic updates throughout, rather than `save()`. For `owner` there is no
    # choice: `Owned.clean` refetches the document whenever `owner` changes, to
    # remember the previous holder, and reading that previous value raises the
    # very error being repaired. `validation.by` follows for symmetry and
    # because a repair should not run document validation on data it did not
    # come to fix — one legacy source failing `validate()` would abort the whole
    # migration partway, and everything after it would silently go unrepaired.
    owner_count = 0
    for source in HarvestSource.objects(owner__ne=None).no_cache():
        try:
            source.owner
        except mongoengine.errors.DoesNotExist as e:
            owner_count += 1
            log.info(f"Unsetting owner on HarvestSource {source.id}: {e}")
            HarvestSource.objects(pk=source.pk).update_one(unset__owner=True)

    log.info(f"Unset {by_count} dangling validation.by in HarvestSource objects")
    log.info(f"Unset {owner_count} dangling owner in HarvestSource objects")
