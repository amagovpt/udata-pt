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
        except mongoengine.errors.DoesNotExist:
            by_count += 1
            source.validation.by = None
            source.save()

    # `owner` does carry `reverse_delete_rule=NULLIFY`, but that only runs when
    # the user is removed through the ORM, and these references went dangling
    # through direct writes to the database. The same held for `periodic_task`,
    # which has NULLIFY and still needed the 2025-10-29 migration.
    #
    # This is the only thing here that repairs a dangling `owner`: unlike
    # `validation.by`, it is dereferenced by the permission checks behind the
    # `url` and `config` attributes, well before any field could tolerate it.
    #
    # An atomic update rather than `save()`, because a dangling `owner` cannot
    # be saved at all: `Owned.clean` refetches the document whenever `owner`
    # changes, to remember the previous holder, and reading that previous value
    # raises the very error being repaired. `update_one` does not run `clean`.
    owner_count = 0
    for source in HarvestSource.objects(owner__ne=None).no_cache():
        try:
            source.owner
        except mongoengine.errors.DoesNotExist:
            owner_count += 1
            HarvestSource.objects(pk=source.pk).update_one(unset__owner=True)

    log.info(f"Unset {by_count} dangling validation.by in HarvestSource objects")
    log.info(f"Unset {owner_count} dangling owner in HarvestSource objects")
