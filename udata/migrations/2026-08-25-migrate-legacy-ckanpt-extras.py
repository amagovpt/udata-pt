"""
Move the extras the CKAN PT backend used to write onto the harvest metadata.

`2022-10-10-migrate-harvest-extras.py` moved `remote_url`, `ckan:name` and
`ckan:source` out of `Dataset.extras` and deleted the `harvest:` ones. The
`ckanpt` backend, being a copy-paste fork frozen before that change, kept writing
them back on every run - so the datasets it harvested carry both shapes.

The backend converged on upstream and no longer writes them, which is why this
has to be a migration rather than something the next harvest fixes: sources that
are no longer harvested would keep those extras forever.

Only datasets of CKAN PT sources are touched. `cswudata` writes `extras.remote_url`
too and is a separate problem, so the selection is deliberately scoped rather than
keyed on the extras alone.
"""

import logging

from mongoengine.errors import ValidationError

from udata.core.dataset.models import HarvestDatasetMetadata
from udata.harvest.models import HarvestSource
from udata.models import Dataset

log = logging.getLogger(__name__)

# `update_dataset_harvest_info` stores the backend's *display name*, not its name,
# and datasets harvested before that field existed have none at all - so the
# source ids are the primary selector and this is only a safety net.
CKANPT_DISPLAY_NAME = "CKAN PT"

# extra key -> harvest metadata field it belongs on. `harvest:name` has no field:
# the source name is reachable through `harvest.source_id`, so it is only dropped.
MOVED = {
    "remote_url": "remote_url",
    "ckan:name": "ckan_name",
    "ckan:source": "ckan_source",
}
DROPPED = ("harvest:name",)


def migrate(db):
    log.info("Processing datasets harvested by ckanpt.")

    source_ids = [str(source.id) for source in HarvestSource.objects(backend="ckanpt").only("id")]
    log.info(f"Found {len(source_ids)} ckanpt harvest sources")

    datasets = (
        Dataset.objects(
            __raw__={
                "$and": [
                    {
                        "$or": [
                            {"harvest.source_id": {"$in": source_ids}},
                            {"harvest.backend": CKANPT_DISPLAY_NAME},
                        ]
                    },
                    {
                        "$or": [
                            {f"extras.{key}": {"$exists": True}}
                            for key in list(MOVED) + list(DROPPED)
                        ]
                    },
                ]
            }
        )
        .no_cache()
        .timeout(False)
    )

    count = 0
    for dataset in datasets:
        if not dataset.harvest:
            dataset.harvest = HarvestDatasetMetadata()

        for key, field in MOVED.items():
            value = dataset.extras.pop(key, None)
            # A value already on the harvest metadata was written by the converged
            # backend and is the current one; the extra is the stale copy.
            if value and not getattr(dataset.harvest, field, None):
                setattr(dataset.harvest, field, value)

        for key in DROPPED:
            dataset.extras.pop(key, None)

        try:
            dataset.save()
        except ValidationError as e:
            log.error(f"Failed to save dataset {dataset.id}: {e}")
        else:
            count += 1

    log.info(f"Modified {count} datasets")
