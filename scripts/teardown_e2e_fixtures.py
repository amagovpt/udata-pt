#!/usr/bin/env python3
"""
Tear down the e2e fixtures created by `seed_e2e_fixtures.py`.

Safe to run even if no fixtures exist; the script silently skips missing
records. The admin and editor users themselves are NOT removed — they are
created once via `udata user create` and reused across runs.

Usage (from backend/):
    uv run python scripts/teardown_e2e_fixtures.py
    uv run python scripts/teardown_e2e_fixtures.py --fixtures ../frontend/tests/.fixtures/e2e-fixtures.json
"""

import argparse
import json
import sys
from pathlib import Path

from udata.app import create_app
from udata.core.dataservices.models import Dataservice  # noqa: F401
from udata.core.dataset.models import Dataset
from udata.core.organization.models import Organization
from udata.core.reuse.models import Reuse


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fixtures",
        default=str(
            Path(__file__).resolve().parent.parent.parent
            / "frontend"
            / "tests"
            / ".fixtures"
            / "e2e-fixtures.json"
        ),
        help="Path to the fixtures metadata JSON.",
    )
    args = parser.parse_args()

    fixtures_path = Path(args.fixtures)
    if not fixtures_path.exists():
        print(f"No fixtures file at {fixtures_path}; nothing to tear down.")
        return 0

    fixtures = json.loads(fixtures_path.read_text())

    app = create_app()
    with app.app_context():
        # Order matters: reuses + datasets reference org; delete dependents first.
        reuse_id = fixtures.get("reuse", {}).get("id")
        if reuse_id:
            reuse = Reuse.objects(id=reuse_id).first()
            if reuse:
                reuse.delete()
                print(f"Deleted reuse {reuse_id}")

        dataset_id = fixtures.get("dataset", {}).get("id")
        if dataset_id:
            dataset = Dataset.objects(id=dataset_id).first()
            if dataset:
                dataset.delete()
                print(f"Deleted dataset {dataset_id}")

        org_id = fixtures.get("organization", {}).get("id")
        if org_id:
            org = Organization.objects(id=org_id).first()
            if org:
                org.delete()
                print(f"Deleted organization {org_id}")

    fixtures_path.unlink(missing_ok=True)
    print("Teardown complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
