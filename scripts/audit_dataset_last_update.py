#!/usr/bin/env python3
"""Count datasets whose stored `last_update` disagrees with the resources it claims to describe.

`Dataset.last_update` is published as "The resources last modification date", but until
the resource mutators were fixed it was only ever recomputed in `Dataset.clean()`, which
the API's resource endpoints never reach. Documents touched through those endpoints kept
whatever date they happened to carry. This script measures how many, and by how much,
so the size of the backfill is known before it runs.

Read-only. It opens no write path and calls no `save()`.

Run with:

    UDATA_SETTINGS=$(pwd)/udata.cfg uv run python scripts/audit_dataset_last_update.py

Flags
-----
--tolerance-seconds
    Difference below which the two dates count as equal. Defaults to 1, matching the
    slack the test suite allows, so sub-second serialization noise is not reported as
    drift.

--limit
    Stop after this many datasets. Note the bias: `Dataset` orders by
    `-created_at_internal`, so this samples the *newest* datasets, not a random slice.
    Newer datasets have had fewer chances to drift, so a limited run understates the
    problem. Run without it before quoting a number.

--worst
    How many of the worst offenders to list. Defaults to 20.
"""

import argparse
import os
import sys
from collections import Counter
from pathlib import Path

# Default to a project udata.cfg if the operator did not provide UDATA_SETTINGS.
if "UDATA_SETTINGS" not in os.environ:
    cfg = Path(__file__).resolve().parent.parent / "udata.cfg"
    if cfg.exists():
        os.environ["UDATA_SETTINGS"] = str(cfg)

from udata.app import create_app  # noqa: E402
from udata.core.dataset.models import Dataset  # noqa: E402
from udata.utils import to_naive_datetime  # noqa: E402


def branch_of(dataset: Dataset) -> str:
    """Which branch of `compute_last_update()` this dataset takes.

    Mirrors the method's own structure so the report can say *why* a group is immune,
    rather than only how many are. The value itself always comes from the model.
    """
    if dataset.harvest and dataset.harvest.modified_at:
        return "harvest.modified_at"
    if dataset.resources:
        return "resources"
    return "dataset date"


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--tolerance-seconds", type=float, default=1.0)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--worst", type=int, default=20)
    args = parser.parse_args()

    app = create_app()
    with app.app_context():
        queryset = Dataset.objects().no_cache()
        if args.limit:
            queryset = queryset.limit(args.limit)

        branches = Counter()
        total = 0
        unreadable = 0
        would_write_null = []
        drifted = []

        for dataset in queryset:
            total += 1
            branches[branch_of(dataset)] += 1

            try:
                # The rule lives in the model. Reimplementing it here would let this
                # script and the fix drift apart and agree with each other anyway.
                expected = dataset.compute_last_update()
            except Exception as e:  # noqa: BLE001 - one bad document must not stop the count
                unreadable += 1
                print(f"WARN: could not compute for {dataset.id}: {e}")
                continue

            if expected is None:
                # Not an unreadable document: one where the fix would write `None` into
                # a required field through `update()`, which does not validate. Reachable
                # for a legacy dataset with no resources and no stored date. These are
                # the only documents the fix can make worse, so they are named, not
                # lumped in with the rest.
                would_write_null.append(dataset.slug)
                continue

            if dataset.last_update is None:
                unreadable += 1
                continue

            drift = to_naive_datetime(expected) - to_naive_datetime(dataset.last_update)
            delta = drift.total_seconds()
            if abs(delta) > args.tolerance_seconds:
                drifted.append((delta / 86400, dataset.slug, branch_of(dataset)))

        print(f"datasets inspected: {total}")
        print(f"could not be read:  {unreadable}")
        print(f"would write null:   {len(would_write_null)}   <- the fix can only worsen these")
        print()
        print("by compute_last_update() branch:")
        for name, count in branches.most_common():
            print(f"  {name:22} {count:6}  ({count / max(total, 1) * 100:5.1f}%)")

        forward = [d for d in drifted if d[0] > 0]
        backward = [d for d in drifted if d[0] < 0]
        print()
        print(f"stale: {len(drifted)} ({len(drifted) / max(total, 1) * 100:.2f}%)")
        print(f"  would move forward: {len(forward)}")
        print(f"  would move back:    {len(backward)}")

        if would_write_null:
            print()
            print("datasets with no computable date (fix them before deploying):")
            for slug in would_write_null[: args.worst]:
                print(f"  {slug}")

        if drifted:
            print()
            print(f"worst {min(args.worst, len(drifted))} (days, slug, branch):")
            for days, slug, branch in sorted(drifted, key=lambda d: -abs(d[0]))[: args.worst]:
                print(f"  {days:+10.1f}  {str(slug)[:48]:50} {branch}")

        return 0


if __name__ == "__main__":
    sys.exit(main())
