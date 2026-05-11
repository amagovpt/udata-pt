#!/usr/bin/env python3
"""
Seed deterministic fixtures for the e2e Playwright suite.

Creates:
  - an organisation owned by e2e-admin (admin role) and e2e-editor (editor role)
  - a dataset belonging to the organisation, with one resource
  - a reuse belonging to the organisation, linking the dataset
  - a community resource attached to the dataset

Writes the IDs/slugs to `frontend/tests/.fixtures/e2e-fixtures.json` so the
Playwright suite (and the matching teardown script) can reference them by
key. Existing fixtures with the same identifying name are reused — running
the seed twice is idempotent.

Usage (from backend/):
    uv run python scripts/seed_e2e_fixtures.py
    uv run python scripts/seed_e2e_fixtures.py --output ../frontend/tests/.fixtures/e2e-fixtures.json
"""

import argparse
import json
import sys
from pathlib import Path

from udata.app import create_app
# Pre-register all referenced documents — Reuse references Dataservice, etc.
from udata.core.dataservices.models import Dataservice  # noqa: F401
from udata.core.dataset.models import Dataset, License, Resource
from udata.core.organization.models import Member, Organization
from udata.core.reuse.models import Reuse
from udata.core.user.models import User

ADMIN_EMAIL = "e2e-admin@dados.gov.pt"
EDITOR_EMAIL = "e2e-editor@dados.gov.pt"
ORG_NAME = "E2E Test Organization"
ORG_SLUG = "e2e-test-organization"
DATASET_TITLE = "E2E Test Dataset"
DATASET_SLUG = "e2e-test-dataset"
REUSE_TITLE = "E2E Test Reuse"
REUSE_SLUG = "e2e-test-reuse"
RESOURCE_TITLE = "E2E Test Resource"

# XSS regression fixtures (consumed by tests/e2e/frontend-vulnerabilities/).
# Slugs are stable so the Playwright suite can navigate by URL. The payloads
# below are written to the DB via `update_one(set__description=...)`, which
# bypasses Reuse/Organization/Dataset.pre_save sanitization — that is the
# point: we want to test the FRONTEND rendering layer in the worst case where
# a malicious record has somehow landed in MongoDB despite the backend's
# defense-in-depth. If frontend regresses (e.g. someone reintroduces
# dangerouslySetInnerHTML on `description`), one of the XSS flags below will
# fire when Playwright visits the page.
XSS_ORG_SLUG = "e2e-xss-test-organization"
XSS_ORG_NAME = "E2E XSS Test Organization"
XSS_DATASET_SLUG = "e2e-xss-test-dataset"
XSS_DATASET_TITLE_SAFE = "E2E XSS Test Dataset"
XSS_REUSE_SLUG = "e2e-xss-test-reuse"
XSS_REUSE_TITLE_SAFE = "E2E XSS Test Reuse"

# Each payload sets a unique flag on `window.__xssFlags`. The frontend spec
# reads the object back via `page.evaluate` and asserts every flag is
# undefined. The keys here MUST stay in sync with
# `frontend/tests/e2e/frontend-vulnerabilities/_payloads.ts`.
_XSS_VECTORS = [
    '<img src=x onerror="window.__xssFlags = (window.__xssFlags || {}); '
    'window.__xssFlags.imgOnError = 1">',
    "<script>window.__xssFlags = (window.__xssFlags || {}); "
    "window.__xssFlags.scriptTag = 1;</script>",
    '<svg onload="window.__xssFlags = (window.__xssFlags || {}); '
    'window.__xssFlags.svgOnLoad = 1"></svg>',
    "[click-here](javascript:window.__xssFlags = (window.__xssFlags || {}); "
    "window.__xssFlags.javascriptLink = 1)",
    '<iframe srcdoc="<script>parent.__xssFlags = (parent.__xssFlags || {}); '
    'parent.__xssFlags.iframeSrcDoc = 1;</script>"></iframe>',
]
XSS_DESCRIPTION_PAYLOAD = "\n\n".join(_XSS_VECTORS)
# Title is plain text in the frontend (never markdown), so a single inline
# vector is enough to detect regressions like a raw {title} interpolation
# inside dangerouslySetInnerHTML.
XSS_TITLE_PAYLOAD = (
    '<img src=x onerror="window.__xssFlags = (window.__xssFlags || {}); '
    'window.__xssFlags.titleImgOnError = 1">'
)


def get_or_create_org(admin: User, editor: User) -> Organization:
    org = Organization.objects(slug=ORG_SLUG).first()
    if org:
        # Make sure the e2e users are still members.
        existing_user_ids = {m.user.id for m in org.members if m.user}
        wanted = []
        if admin.id not in existing_user_ids:
            wanted.append(Member(user=admin, role="admin"))
        if editor.id not in existing_user_ids:
            wanted.append(Member(user=editor, role="editor"))
        if wanted:
            org.members.extend(wanted)
            org.save()
        return org

    org = Organization(
        name=ORG_NAME,
        slug=ORG_SLUG,
        description="Organisation auto-created by the e2e seed script.",
        members=[
            Member(user=admin, role="admin"),
            Member(user=editor, role="editor"),
        ],
    )
    org.save()
    return org


def get_or_create_dataset(org: Organization) -> Dataset:
    dataset = Dataset.objects(slug=DATASET_SLUG).first()
    if dataset:
        return dataset

    licence = License.objects.first()
    dataset = Dataset(
        title=DATASET_TITLE,
        slug=DATASET_SLUG,
        description="Dataset auto-created by the e2e seed script.",
        organization=org,
        license=licence,
        tags=["e2e", "test-fixture"],
    )
    dataset.resources.append(
        Resource(
            title=RESOURCE_TITLE,
            description="Resource auto-created by the e2e seed script.",
            url="https://example.com/e2e-resource.csv",
            format="csv",
        )
    )
    dataset.save()
    return dataset


def get_or_create_reuse(org: Organization, dataset: Dataset) -> Reuse:
    reuse = Reuse.objects(slug=REUSE_SLUG).first()
    if reuse:
        if dataset not in reuse.datasets:
            reuse.datasets.append(dataset)
            reuse.save()
        return reuse

    reuse = Reuse(
        title=REUSE_TITLE,
        slug=REUSE_SLUG,
        description="Reuse auto-created by the e2e seed script.",
        url="https://example.com/e2e-reuse",
        type="api",
        topic="open_data_tools",
        organization=org,
        datasets=[dataset],
    )
    reuse.save()
    return reuse


def get_or_create_xss_org(admin: User, editor: User) -> Organization:
    org = Organization.objects(slug=XSS_ORG_SLUG).first()
    if org is None:
        org = Organization(
            name=XSS_ORG_NAME,
            slug=XSS_ORG_SLUG,
            description="placeholder — overwritten by update_one() below",
            members=[
                Member(user=admin, role="admin"),
                Member(user=editor, role="editor"),
            ],
        )
        org.save()
    # Bypass pre_save by issuing a raw $set. We want the malicious payload to
    # land in the DB untouched so the rendering pipeline is what actually
    # gets exercised.
    Organization.objects(id=org.id).update_one(set__description=XSS_DESCRIPTION_PAYLOAD)
    org.reload()
    return org


def get_or_create_xss_dataset(org: Organization) -> Dataset:
    dataset = Dataset.objects(slug=XSS_DATASET_SLUG).first()
    if dataset is None:
        licence = License.objects.first()
        dataset = Dataset(
            title=XSS_DATASET_TITLE_SAFE,
            slug=XSS_DATASET_SLUG,
            description="placeholder — overwritten by update_one() below",
            organization=org,
            license=licence,
            tags=["e2e", "xss-fixture"],
        )
        dataset.resources.append(
            Resource(
                title="E2E XSS Test Resource",
                description="placeholder",
                url="https://example.com/e2e-xss-resource.csv",
                format="csv",
            )
        )
        dataset.save()
    Dataset.objects(id=dataset.id).update_one(set__description=XSS_DESCRIPTION_PAYLOAD)
    dataset.reload()
    return dataset


def get_or_create_xss_reuse(org: Organization, dataset: Dataset) -> Reuse:
    reuse = Reuse.objects(slug=XSS_REUSE_SLUG).first()
    if reuse is None:
        reuse = Reuse(
            title=XSS_REUSE_TITLE_SAFE,
            slug=XSS_REUSE_SLUG,
            description="placeholder — overwritten by update_one() below",
            url="https://example.com/e2e-xss-reuse",
            type="api",
            topic="open_data_tools",
            organization=org,
            datasets=[dataset],
        )
        reuse.save()
    Reuse.objects(id=reuse.id).update_one(
        set__description=XSS_DESCRIPTION_PAYLOAD,
        set__title=XSS_TITLE_PAYLOAD,
    )
    reuse.reload()
    return reuse


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        default=str(
            Path(__file__).resolve().parent.parent.parent
            / "frontend"
            / "tests"
            / ".fixtures"
            / "e2e-fixtures.json"
        ),
        help="Path to write fixture metadata JSON to.",
    )
    args = parser.parse_args()

    app = create_app()
    with app.app_context():
        admin = User.objects(email=ADMIN_EMAIL).first()
        if admin is None:
            print(
                f"ERROR: admin user {ADMIN_EMAIL!r} not found — run "
                "`udata user create --admin` first.",
                file=sys.stderr,
            )
            return 1
        editor = User.objects(email=EDITOR_EMAIL).first()
        if editor is None:
            print(
                f"ERROR: editor user {EDITOR_EMAIL!r} not found — run "
                "`udata user create` first.",
                file=sys.stderr,
            )
            return 1

        org = get_or_create_org(admin, editor)
        dataset = get_or_create_dataset(org)
        reuse = get_or_create_reuse(org, dataset)
        xss_org = get_or_create_xss_org(admin, editor)
        xss_dataset = get_or_create_xss_dataset(xss_org)
        xss_reuse = get_or_create_xss_reuse(xss_org, xss_dataset)

        fixtures = {
            "admin": {"id": str(admin.id), "email": admin.email, "slug": admin.slug},
            "editor": {"id": str(editor.id), "email": editor.email, "slug": editor.slug},
            "organization": {
                "id": str(org.id),
                "slug": org.slug,
                "name": org.name,
            },
            "dataset": {
                "id": str(dataset.id),
                "slug": dataset.slug,
                "title": dataset.title,
                "resource_id": str(dataset.resources[0].id) if dataset.resources else None,
            },
            "reuse": {
                "id": str(reuse.id),
                "slug": reuse.slug,
                "title": reuse.title,
            },
            "xss_organization": {
                "id": str(xss_org.id),
                "slug": xss_org.slug,
            },
            "xss_dataset": {
                "id": str(xss_dataset.id),
                "slug": xss_dataset.slug,
            },
            "xss_reuse": {
                "id": str(xss_reuse.id),
                "slug": xss_reuse.slug,
            },
        }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(fixtures, indent=2, ensure_ascii=False))
    print(f"Seed complete — wrote {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
