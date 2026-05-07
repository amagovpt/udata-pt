#!/usr/bin/env python3
"""Clean up community resources created by the VULN-2078 PoC.

The KITS24 audit produced ~106 community resources on a single dataset via
Burp Intruder. This script identifies and (optionally) deletes those rows.

Run on PPR/PRD (not CI) with:

    UDATA_SETTINGS=$(pwd)/udata.cfg uv run python scripts/cleanup_vuln_2078_poc.py \
        --dataset-slug <slug-from-auditor> \
        --since 2026-04-08T00:00:00Z \
        --until 2026-04-08T23:59:59Z

Without `--apply` the script runs in dry-run mode and just prints what would
be deleted. Re-run with `--apply` once the operator has reviewed the list.

Flags
-----
--dataset-id / --dataset-slug
    Identify the affected dataset. At least one is required.

--since / --until
    Optional ISO-8601 timestamps to restrict the deletion window. When the
    auditor provides the exact time of the PoC, narrowing the window avoids
    deleting legitimate community resources created before or after.

--owner-email
    Optional email of the audit user account, restricts the query to
    resources owned by that user. Strongly recommended when the auditor's
    account is known.

--xss-payload-pattern
    Optional case-insensitive substring searched in `title`, `description`,
    and `url`. Defaults to `<img src=x onerror`. Pass `""` to disable.

--apply
    Actually delete. Without it the script only lists.
"""

import argparse
import os
import sys
from datetime import datetime
from pathlib import Path

# Default to a project udata.cfg if the operator did not provide UDATA_SETTINGS.
if "UDATA_SETTINGS" not in os.environ:
    cfg = Path(__file__).resolve().parent.parent / "udata.cfg"
    if cfg.exists():
        os.environ["UDATA_SETTINGS"] = str(cfg)

from udata.app import create_app  # noqa: E402
from udata.core.dataset.models import CommunityResource, Dataset  # noqa: E402
from udata.core.user.models import User  # noqa: E402


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--dataset-id")
    parser.add_argument("--dataset-slug")
    parser.add_argument("--since")
    parser.add_argument("--until")
    parser.add_argument("--owner-email")
    parser.add_argument("--xss-payload-pattern", default="<img src=x onerror")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    if not (args.dataset_id or args.dataset_slug):
        parser.error("at least one of --dataset-id or --dataset-slug is required")

    app = create_app()
    with app.app_context():
        dataset = None
        if args.dataset_id:
            dataset = Dataset.objects(id=args.dataset_id).first()
        if not dataset and args.dataset_slug:
            dataset = Dataset.objects(slug=args.dataset_slug).first()

        if dataset is None:
            print(f"ERROR: dataset not found (id={args.dataset_id!r}, slug={args.dataset_slug!r})")
            return 2

        query = {"dataset": dataset}
        if args.owner_email:
            owner = User.objects(email=args.owner_email).first()
            if owner is None:
                print(f"ERROR: owner not found for email {args.owner_email!r}")
                return 2
            query["owner"] = owner

        since = parse_iso(args.since)
        until = parse_iso(args.until)
        if since:
            query["created_at_internal__gte"] = since
        if until:
            query["created_at_internal__lte"] = until

        candidates = CommunityResource.objects(**query)

        if args.xss_payload_pattern:
            pattern = args.xss_payload_pattern.lower()
            filtered = [
                r
                for r in candidates
                if pattern in (r.title or "").lower()
                or pattern in (r.description or "").lower()
                or pattern in (r.url or "").lower()
            ]
        else:
            filtered = list(candidates)

        if not filtered:
            print(f"No matching community resources found on dataset {dataset.slug}.")
            return 0

        print(f"Dataset: {dataset.title} (slug={dataset.slug}, id={dataset.id})")
        print(f"Match count: {len(filtered)}")
        print("---")
        for r in filtered:
            print(
                f"  id={r.id}  created_at={r.created_at_internal.isoformat()}  "
                f"owner={getattr(r.owner, 'email', '?')}  "
                f"title={r.title!r}  url={r.url!r}"
            )

        if not args.apply:
            print("---")
            print("Dry-run only. Re-run with --apply to delete.")
            return 0

        for r in filtered:
            r.delete()
        print("---")
        print(f"Deleted {len(filtered)} community resources.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
