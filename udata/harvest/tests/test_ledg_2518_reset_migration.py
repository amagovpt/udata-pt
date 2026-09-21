"""Tests for the DGT license reset migration (LEDG-2518).

Two properties, the same pair every migration in this series has to hold: the
harvester-written `cc-by` really goes, and nothing else does. The selection is
the part most likely to be wrong, so it is tested from both sides -- a DGT
source whose datasets must be cleared, and the two ways of looking like one
without being one.
"""

import pytest
from mongoengine.connection import get_db

from udata.core.dataset.factories import DatasetFactory, LicenseFactory
from udata.tests.api import PytestOnlyDBTestCase

from .factories import HarvestSourceFactory
from .test_ckanpt_migrations import load_migration

MIGRATION = "2026-09-18-reset-dgt-harvested-licenses.py"


class ResetDgtHarvestedLicensesMigrationTest(PytestOnlyDBTestCase):
    @pytest.fixture(autouse=True)
    def migration(self):
        self.migrate = load_migration(MIGRATION).migrate

    def _harvested(self, source, license_id, backend_label="Harvester DGT"):
        dataset = DatasetFactory(license=LicenseFactory(id=license_id, title=license_id))
        get_db().dataset.update_one(
            {"_id": dataset.id},
            {"$set": {"harvest": {"source_id": str(source.id), "backend": backend_label}}},
        )
        return dataset

    def _license_of(self, dataset):
        return get_db().dataset.find_one({"_id": dataset.id}).get("license")

    def test_cc_by_on_a_dgt_source_is_unset(self):
        dataset = self._harvested(HarvestSourceFactory(backend="dgt"), "cc-by")

        self.migrate(get_db())

        assert self._license_of(dataset) is None

    def test_manual_license_on_a_dgt_source_is_kept(self):
        # Only cc-by was ever written by the harvester; anything else is a
        # correction somebody made.
        dataset = self._harvested(HarvestSourceFactory(backend="dgt"), "cc-by-nc")

        self.migrate(get_db())

        assert self._license_of(dataset) == "cc-by-nc"

    def test_cc_by_on_another_backend_is_kept(self):
        dataset = self._harvested(
            HarvestSourceFactory(backend="ckan"), "cc-by", backend_label="CKAN"
        )

        self.migrate(get_db())

        assert self._license_of(dataset) == "cc-by"

    def test_the_display_name_is_not_the_filter(self):
        # harvest.backend stores the display name, so a dataset can carry
        # "Harvester DGT" while belonging to another source. The source_id is
        # what decides.
        dataset = self._harvested(HarvestSourceFactory(backend="ogc"), "cc-by")

        self.migrate(get_db())

        assert self._license_of(dataset) == "cc-by"

    def test_nothing_else_moves(self):
        dataset = self._harvested(HarvestSourceFactory(backend="dgt"), "cc-by")
        before = get_db().dataset.find_one({"_id": dataset.id})

        self.migrate(get_db())

        after = get_db().dataset.find_one({"_id": dataset.id})
        assert after.pop("license", None) is None
        before.pop("license", None)
        assert after == before

    def test_second_run_is_a_noop(self):
        db = get_db()
        self._harvested(HarvestSourceFactory(backend="dgt"), "cc-by")
        self.migrate(db)
        before = list(db.dataset.find().sort("_id"))

        self.migrate(db)

        assert list(db.dataset.find().sort("_id")) == before

    def test_no_dgt_source_is_a_noop(self):
        dataset = self._harvested(
            HarvestSourceFactory(backend="ckan"), "cc-by", backend_label="CKAN"
        )

        self.migrate(get_db())

        assert self._license_of(dataset) == "cc-by"
