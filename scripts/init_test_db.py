#!/usr/bin/env python3
"""
Initialise the disposable E2E test database.

Run this once after `scripts/test_db.sh up` to:
  1. Run schema migrations (`udata db upgrade`).
  2. Seed test users (admin + editor) so Playwright auth-setup can log in.
  3. Seed fixtures (org/dataset/reuse) so destructive tests have something
     to mutate without touching the dev DB.

Idempotent — re-runs reuse existing records by email/slug.

Run via:
    UDATA_SETTINGS=$(pwd)/udata.test.cfg uv run python scripts/init_test_db.py
"""

import os
import sys
from pathlib import Path

# Ensure UDATA_SETTINGS is set before udata imports.
if "UDATA_SETTINGS" not in os.environ:
    cfg = Path(__file__).resolve().parent.parent / "udata.test.cfg"
    os.environ["UDATA_SETTINGS"] = str(cfg)

from udata.app import create_app
from udata.core.dataservices.models import Dataservice  # noqa: F401
from udata.core.dataset.models import Dataset, License, Resource
from udata.core.organization.models import Member, Organization
from udata.core.reuse.models import Reuse
from udata.core.user.models import User

ADMIN = {"email": "e2e-admin@dados.gov.pt", "first_name": "E2E", "last_name": "Admin", "password": "E2eAdmin2026!"}
EDITOR = {"email": "e2e-editor@dados.gov.pt", "first_name": "E2E", "last_name": "Editor", "password": "E2eEditor2026!"}

ORG_NAME = "E2E Test Organization"
ORG_SLUG = "e2e-test-organization"
DATASET_TITLE = "E2E Test Dataset"
DATASET_SLUG = "e2e-test-dataset"
REUSE_TITLE = "E2E Test Reuse"
REUSE_SLUG = "e2e-test-reuse"


def get_or_create_user(email: str, first_name: str, last_name: str, password: str, admin: bool) -> User:
    user = User.objects(email=email).first()
    if user:
        return user

    # Flask-Security uses bcrypt by default (SECURITY_PASSWORD_HASH); use its
    # `hash_password` helper so the stored hash matches the verifier at /login.
    from datetime import datetime

    from flask_security.utils import hash_password

    hashed = hash_password(password)

    user = User(
        email=email,
        first_name=first_name,
        last_name=last_name,
        password=hashed,
        active=True,
        confirmed_at=datetime.utcnow(),
    )
    if admin:
        from udata.core.user.models import Role

        admin_role, _ = Role.objects.get_or_create(name="admin")
        user.roles = [admin_role]
    user.save()
    return user


def get_or_create_org(admin: User, editor: User) -> Organization:
    org = Organization.objects(slug=ORG_SLUG).first()
    if org:
        return org
    org = Organization(
        name=ORG_NAME,
        slug=ORG_SLUG,
        description="Org auto-created for E2E destructive tests.",
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
        description="Seed dataset for E2E destructive tests.",
        organization=org,
        license=licence,
        tags=["e2e", "test-fixture"],
    )
    dataset.resources.append(
        Resource(
            title="E2E Test Resource",
            description="Seed resource.",
            url="https://example.com/e2e-resource.csv",
            format="csv",
        )
    )
    dataset.save()
    return dataset


def get_or_create_reuse(org: Organization, dataset: Dataset) -> Reuse:
    reuse = Reuse.objects(slug=REUSE_SLUG).first()
    if reuse:
        return reuse
    reuse = Reuse(
        title=REUSE_TITLE,
        slug=REUSE_SLUG,
        description="Seed reuse for E2E destructive tests.",
        url="https://example.com/e2e-reuse",
        type="api",
        topic="open_data_tools",
        organization=org,
        datasets=[dataset],
    )
    reuse.save()
    return reuse


def main() -> int:
    app = create_app()
    with app.app_context():
        # Light migration step: ensure indexes exist by touching the collections.
        Organization.ensure_indexes()
        Dataset.ensure_indexes()
        Reuse.ensure_indexes()
        User.ensure_indexes()

        # Seed a default license — destructive tests sometimes pick the first one.
        if not License.objects.first():
            License(id="cc-by", title="Creative Commons Attribution").save()

        admin = get_or_create_user(**ADMIN, admin=True)
        editor = get_or_create_user(**EDITOR, admin=False)
        org = get_or_create_org(admin, editor)
        dataset = get_or_create_dataset(org)
        reuse = get_or_create_reuse(org, dataset)

    print(
        "[init-test-db] ready — "
        f"admin={admin.email} editor={editor.email} "
        f"org={org.slug} dataset={dataset.slug} reuse={reuse.slug}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
