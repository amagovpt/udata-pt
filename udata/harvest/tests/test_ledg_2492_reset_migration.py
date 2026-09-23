"""Tests for the CSW license reset migration (LEDG-2492).

Two properties, the same pair every migration in this series has to hold: the
harvester-written `cc-by` really goes, and nothing else does. The selection is
the part most likely to be wrong -- it joins two collections on a field whose
type differs from the one it is matched against -- so it is tested from both
sides, and from the state the deploy actually leaves behind.
"""

import pytest
from mongoengine.connection import get_db

from udata.core.dataset.factories import DatasetFactory, LicenseFactory
from udata.tests.api import PytestOnlyDBTestCase

from .factories import HarvestSourceFactory
from .test_ckanpt_migrations import load_migration

MIGRATION = "2026-09-22-reset-csw-harvested-licenses.py"
SOURCES_MIGRATION = "2026-09-22-apambiente-sources-to-cswudata.py"


class ResetCswHarvestedLicensesMigrationTest(PytestOnlyDBTestCase):
    @pytest.fixture(autouse=True)
    def migration(self):
        self.migrate = load_migration(MIGRATION).migrate

    def _harvested(self, source, license_id, backend_label="Harvester Portal do Ambiente"):
        dataset = DatasetFactory(license=LicenseFactory(id=license_id, title=license_id))
        get_db().dataset.update_one(
            {"_id": dataset.id},
            {"$set": {"harvest": {"source_id": str(source.id), "backend": backend_label}}},
        )
        return dataset

    def _license_of(self, dataset):
        return get_db().dataset.find_one({"_id": dataset.id}).get("license")

    def test_cc_by_on_an_apambiente_source_is_unset(self):
        dataset = self._harvested(HarvestSourceFactory(backend="apambiente"), "cc-by")

        self.migrate(get_db())

        assert self._license_of(dataset) is None

    def test_cc_by_on_a_cswudata_source_is_unset(self):
        # The same constant was in the generic backend, so any source already
        # running on it carries the same bug.
        dataset = self._harvested(
            HarvestSourceFactory(backend="cswudata"), "cc-by", backend_label="CSW Harvester"
        )

        self.migrate(get_db())

        assert self._license_of(dataset) is None

    def test_manual_license_is_kept(self):
        # Only cc-by was ever written by the harvester; anything else is a
        # correction somebody made.
        dataset = self._harvested(HarvestSourceFactory(backend="apambiente"), "cc-by-nc")

        self.migrate(get_db())

        assert self._license_of(dataset) == "cc-by-nc"

    def test_cc_by_on_another_backend_is_kept(self):
        dataset = self._harvested(
            HarvestSourceFactory(backend="ckan"), "cc-by", backend_label="CKAN"
        )

        self.migrate(get_db())

        assert self._license_of(dataset) == "cc-by"

    def test_the_display_name_is_not_the_filter(self):
        # A dataset whose `harvest.backend` says APAmbiente but whose source is
        # something else must not be cleared: the display name is not the slug,
        # and it changes on the first harvest after this deploy.
        dataset = self._harvested(
            HarvestSourceFactory(backend="ckan"),
            "cc-by",
            backend_label="Harvester Portal do Ambiente",
        )

        self.migrate(get_db())

        assert self._license_of(dataset) == "cc-by"

    def test_is_idempotent(self):
        dataset = self._harvested(HarvestSourceFactory(backend="apambiente"), "cc-by")

        self.migrate(get_db())
        self.migrate(get_db())

        assert self._license_of(dataset) is None

    def test_runs_correctly_after_the_sources_migration(self):
        # The state the deploy actually produces: the sources migration has
        # already rewritten the backend to `cswudata`, so selecting only on
        # `apambiente` would clear nothing at all.
        source = HarvestSourceFactory(backend="apambiente")
        dataset = self._harvested(source, "cc-by")
        load_migration(SOURCES_MIGRATION).migrate(get_db())

        self.migrate(get_db())

        assert self._license_of(dataset) is None
