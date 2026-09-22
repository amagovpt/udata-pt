"""Move the APAmbiente harvest sources onto the generic CSW backend.

The `apambiente` backend is gone: it spoke CSW through owslib exactly like
`cswudata`, minus the record's subjects, its bounding box, its dates and every
link after the first -- and with a pagination loop that never terminated on the
shape the last page has.

Rewriting the source rather than recreating it is the whole point of doing this
in a migration: the source keeps its `_id`, so its periodic task still points at
it, and the datasets it harvested keep matching it on `harvest.source_id`.

The producer tag travels with it. The old backend hard-coded `apambiente.pt`;
the new one reads a `default_tag` extra config and falls back to the source
hostname, which for this source would be `sniambgeoportal.apambiente.pt` -- a
different tag on 3900-odd datasets. Writing the old value explicitly is what
keeps that from happening.

Idempotent: a second run finds no `apambiente` source left, and a source that
already carries a `default_tag` is never given a second one.
"""

import logging

from mongoengine.errors import ValidationError

from udata.harvest.models import HarvestSource

log = logging.getLogger(__name__)

LEGACY_BACKEND = "apambiente"
TARGET_BACKEND = "cswudata"
DEFAULT_TAG = "apambiente.pt"


def migrate(db):
    log.info("Moving %s harvest sources onto %s...", LEGACY_BACKEND, TARGET_BACKEND)

    migrated = 0
    for source in HarvestSource.objects(backend=LEGACY_BACKEND):
        extra_configs = list(source.config.get("extra_configs") or [])
        present = {entry.get("key") for entry in extra_configs}

        if "default_tag" not in present:
            extra_configs.append({"key": "default_tag", "value": DEFAULT_TAG})
            source.config["extra_configs"] = extra_configs

        source.backend = TARGET_BACKEND

        try:
            source.save()
        except ValidationError as e:
            # One unsaveable source must not stop the ones after it in cursor
            # order: those are exactly the ones left pointing at a backend that
            # no longer exists, which fails their next scheduled harvest.
            log.error("Failed to save source %s: %s", source.id, e)
            continue

        migrated += 1
        log.info("Migrated source %s (%s): %s", source.id, source.name, extra_configs)

    log.info("Moved %s source(s) onto %s.", migrated, TARGET_BACKEND)
