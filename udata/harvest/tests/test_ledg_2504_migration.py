"""Tests for the harvest remote-url credential redaction migration (LEDG-2504).

Third in the series after `test_ledg_2477_migration.py` and
`test_ledg_2500_migration.py`, and the same two properties have to hold: the
credentials really go, and nothing else in the document moves. What is specific
here is the two deliberate asymmetries with the LEDG-2500 migration -- this one
runs unscoped, because no publisher-facing form writes `dataset.harvest`, and
it counts `harvest.remote_id` without rewriting it.
"""

import logging

import pytest
from mongoengine.connection import get_db

from udata.tests.api import PytestOnlyDBTestCase

from .test_ckanpt_migrations import load_migration

MIGRATION = "2026-09-17-redact-harvested-remote-url-credentials.py"

CREDENTIALED_HOST = "https://harvestuser:sup3rs3cr3t@ckan.example.pt"
REDACTED_HOST = "https://***@ckan.example.pt"
REMOTE_URL = f"{CREDENTIALED_HOST}/dataset/leaky"
REDACTED_REMOTE_URL = f"{REDACTED_HOST}/dataset/leaky"


class RedactHarvestedRemoteUrlCredentialsMigrationTest(PytestOnlyDBTestCase):
    @pytest.fixture(autouse=True)
    def migration(self):
        self.migrate = load_migration(MIGRATION).migrate

    def _harvested_dataset(self):
        return {
            "title": "Leaky",
            "slug": "leaky",
            "harvest": {
                "remote_url": REMOTE_URL,
                "remote_id": "ckan-0001",
                "backend": "CKAN",
            },
            "resources": [{"title": "Export", "url": "https://ckan.example.pt/a.csv"}],
        }

    def test_dataset_remote_url_is_redacted(self):
        db = get_db()
        db.dataset.insert_one(self._harvested_dataset())

        self.migrate(db)

        dataset = db.dataset.find_one({})
        assert dataset["harvest"]["remote_url"] == REDACTED_REMOTE_URL
        assert "sup3rs3cr3t" not in str(dataset)
        # Everything else in the document is left exactly as it was.
        assert dataset["title"] == "Leaky"
        assert dataset["slug"] == "leaky"
        assert dataset["harvest"]["remote_id"] == "ckan-0001"
        assert dataset["harvest"]["backend"] == "CKAN"
        assert dataset["resources"][0]["url"] == "https://ckan.example.pt/a.csv"

    def test_job_item_remote_urls_are_redacted(self):
        """Only the item that holds a credentialed URL moves."""
        db = get_db()
        db.harvest_job.insert_one(
            {
                "status": "done",
                "items": [
                    {"remote_id": "ckan-0001", "remote_url": REMOTE_URL, "status": "done"},
                    {
                        "remote_id": "ckan-0002",
                        "remote_url": "https://ckan.example.pt/dataset/clean",
                        "status": "done",
                    },
                ],
            }
        )

        self.migrate(db)

        job = db.harvest_job.find_one({})
        assert job["items"][0]["remote_url"] == REDACTED_REMOTE_URL
        assert job["items"][0]["remote_id"] == "ckan-0001"
        assert job["items"][0]["status"] == "done"
        assert job["items"][1]["remote_url"] == "https://ckan.example.pt/dataset/clean"

    def test_it_is_not_scoped_to_the_ckan_backends(self):
        """Unlike the ODS pass, this one has no marker: `dataset.harvest` has no other writer."""
        db = get_db()
        dataset = self._harvested_dataset()
        dataset["harvest"]["backend"] = "DCAT"
        db.dataset.insert_one(dataset)

        self.migrate(db)

        assert db.dataset.find_one({})["harvest"]["remote_url"] == REDACTED_REMOTE_URL

    def test_the_legacy_extras_copy_is_redacted_too(self):
        """Two earlier migrations moved this extra, both scoped and both skipping failures."""
        db = get_db()
        dataset = self._harvested_dataset()
        dataset["extras"] = {"remote_url": REMOTE_URL, "ckan:name": "leaky"}
        db.dataset.insert_one(dataset)

        self.migrate(db)

        dataset = db.dataset.find_one({})
        assert dataset["extras"]["remote_url"] == REDACTED_REMOTE_URL
        assert dataset["extras"]["ckan:name"] == "leaky"
        assert "sup3rs3cr3t" not in str(dataset)

    def test_a_credentialed_remote_id_is_counted_but_left_alone(self, caplog):
        """Rewriting it would break the match `BaseBackend.get_dataset` makes on it.

        Counting it is the migration's whole deliverable for `remote_id`, so the
        warning is asserted too: a silent pass would look identical to a missing
        one.
        """
        db = get_db()
        dataset = self._harvested_dataset()
        dataset["harvest"]["remote_url"] = "https://ckan.example.pt/dataset/clean"
        dataset["harvest"]["remote_id"] = REMOTE_URL
        db.dataset.insert_one(dataset)
        before = db.dataset.find_one({})

        with caplog.at_level(logging.WARNING):
            self.migrate(db)

        assert db.dataset.find_one({}) == before
        warnings = [record.getMessage() for record in caplog.records if record.levelno >= 30]
        assert any("harvest.remote_id" in message for message in warnings), warnings
        # The counter reports how many, never the credentialed value itself.
        assert not any("sup3rs3cr3t" in message for message in warnings)

    def test_documents_without_credentials_are_untouched(self):
        db = get_db()
        db.dataset.insert_one(
            {
                "title": "Clean",
                "harvest": {"remote_url": "https://ckan.example.pt/dataset/clean"},
            }
        )
        db.harvest_job.insert_one(
            {
                "status": "done",
                "items": [{"remote_url": "https://ckan.example.pt/dataset/clean"}],
            }
        )
        dataset_before = db.dataset.find_one({})
        job_before = db.harvest_job.find_one({})

        self.migrate(db)

        assert db.dataset.find_one({}) == dataset_before
        assert db.harvest_job.find_one({}) == job_before

    def test_migration_is_idempotent(self):
        """The filter also matches `://***@`, so a second run must be a no-op."""
        db = get_db()
        db.dataset.insert_one(self._harvested_dataset())
        db.harvest_job.insert_one({"status": "done", "items": [{"remote_url": REMOTE_URL}]})

        self.migrate(db)
        once_dataset = db.dataset.find_one({})
        once_job = db.harvest_job.find_one({})

        self.migrate(db)

        assert db.dataset.find_one({}) == once_dataset
        assert db.harvest_job.find_one({}) == once_job
