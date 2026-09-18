"""Tests for the migration that adds CC BY-NC and CC BY-NC-ND (LEDG-2518).

It lives here, next to the other migration tests, because that is where
`load_migration` is and because the migration exists only to serve the DGT
harvester's licence derivation.

Two properties matter: both licences end up present and resolvable by the exact
id lookup the harvester uses, and nothing an administrator already created by
hand is rewritten.
"""

import pytest
from mongoengine.connection import get_db

from udata.core.dataset.models import License
from udata.tests.api import PytestOnlyDBTestCase

from .test_ckanpt_migrations import load_migration

MIGRATION = "2026-09-18-add-cc-nc-nd-licenses.py"


class AddCcNcNdLicensesMigrationTest(PytestOnlyDBTestCase):
    @pytest.fixture(autouse=True)
    def migration(self):
        self.migrate = load_migration(MIGRATION).migrate

    def test_creates_both_licenses(self):
        self.migrate(get_db())

        by_nc = License.objects(id="cc-by-nc").first()
        by_nc_nd = License.objects(id="cc-by-nc-nd").first()
        assert by_nc is not None
        assert by_nc_nd is not None
        assert by_nc.url == "https://creativecommons.org/licenses/by-nc/4.0/"
        assert by_nc_nd.url == "https://creativecommons.org/licenses/by-nc-nd/4.0/"
        assert by_nc.active and by_nc_nd.active
        assert by_nc.slug and by_nc_nd.slug

    def test_exact_lookup_resolves_after_migration(self):
        # This is the call the harvester makes; a document that cannot be
        # looked up by id is of no use to it.
        self.migrate(get_db())

        assert License.objects(id="cc-by-nc-nd").first().id == "cc-by-nc-nd"

    def test_second_run_writes_nothing(self):
        db = get_db()
        self.migrate(db)
        before = list(db.license.find().sort("_id"))

        self.migrate(db)

        assert list(db.license.find().sort("_id")) == before

    def test_existing_license_is_not_overwritten(self):
        db = get_db()
        db.license.insert_one(
            {
                "_id": "cc-by-nc",
                "title": "Licença feita à mão",
                "slug": "licenca-feita-a-mao",
                "url": "https://example.pt/licenca",
                "active": True,
            }
        )

        self.migrate(db)

        kept = db.license.find_one({"_id": "cc-by-nc"})
        assert kept["title"] == "Licença feita à mão"
        assert kept["url"] == "https://example.pt/licenca"
        # The other one is still created.
        assert db.license.find_one({"_id": "cc-by-nc-nd"}) is not None
