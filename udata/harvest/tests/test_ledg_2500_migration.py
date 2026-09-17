"""Tests for the harvested-resource credential redaction migration (LEDG-2500).

Companion to `test_ledg_2477_migration.py`, and the same pair of properties has
to hold: the credentials really go, and nothing else in the document moves. The
extra property here is the scoping -- a credentialed URL a publisher typed on
their own resource is not this migration's business.
"""

import pytest
from mongoengine.connection import get_db

from udata.tests.api import PytestOnlyDBTestCase

from .test_ckanpt_migrations import load_migration

MIGRATION = "2026-09-16-redact-harvested-resource-url-credentials.py"

CREDENTIALED_HOST = "https://harvestuser:sup3rs3cr3t@transparencia.example.pt"
REDACTED_HOST = "https://***@transparencia.example.pt"
EXPLORE_URL = f"{CREDENTIALED_HOST}/explore/dataset/ods-dataset/"
REDACTED_EXPLORE_URL = f"{REDACTED_HOST}/explore/dataset/ods-dataset/"
CSV_URL = f"{EXPLORE_URL}download?format=csv"
REDACTED_CSV_URL = f"{REDACTED_EXPLORE_URL}download?format=csv"
ATTACHMENT_URL = f"{CREDENTIALED_HOST}/api/datasets/1.0/ods-dataset/attachments/att-1"
REDACTED_ATTACHMENT_URL = f"{REDACTED_HOST}/api/datasets/1.0/ods-dataset/attachments/att-1"
DESCRIPTOR_URL = "https://harvestuser:sup3rs3cr3t@example.pt/maaf/dataset.xml"
REDACTED_DESCRIPTOR_URL = "https://***@example.pt/maaf/dataset.xml"


class RedactHarvestedResourceCredentialsMigrationTest(PytestOnlyDBTestCase):
    @pytest.fixture(autouse=True)
    def migration(self):
        self.migrate = load_migration(MIGRATION).migrate

    def _ods_dataset(self):
        return {
            "title": "Leaky",
            "slug": "leaky",
            "extras": {"ods:url": EXPLORE_URL, "ods:has_records": True},
            "resources": [
                {"title": "Export to CSV", "url": CSV_URL, "format": "csv"},
                {"title": "Notice", "url": ATTACHMENT_URL, "format": "pdf"},
            ],
        }

    def test_ods_resource_urls_and_explore_url_are_redacted(self):
        db = get_db()
        db.dataset.insert_one(self._ods_dataset())

        self.migrate(db)

        dataset = db.dataset.find_one({})
        assert [resource["url"] for resource in dataset["resources"]] == [
            REDACTED_CSV_URL,
            REDACTED_ATTACHMENT_URL,
        ]
        assert dataset["extras"]["ods:url"] == REDACTED_EXPLORE_URL
        assert "sup3rs3cr3t" not in str(dataset)
        # Everything else in the document is left exactly as it was.
        assert dataset["title"] == "Leaky"
        assert dataset["slug"] == "leaky"
        assert dataset["extras"]["ods:has_records"] is True
        assert [resource["title"] for resource in dataset["resources"]] == [
            "Export to CSV",
            "Notice",
        ]

    def test_maaf_remote_ids_are_redacted(self):
        """Only the item that holds a credentialed URL moves."""
        db = get_db()
        db.harvest_job.insert_one(
            {
                "status": "done",
                "items": [
                    {"remote_id": DESCRIPTOR_URL, "status": "failed"},
                    {"remote_id": "maaf-0001", "status": "done"},
                ],
            }
        )

        self.migrate(db)

        job = db.harvest_job.find_one({})
        assert job["items"][0]["remote_id"] == REDACTED_DESCRIPTOR_URL
        assert job["items"][0]["status"] == "failed"
        assert job["items"][1]["remote_id"] == "maaf-0001"

    def test_a_credentialed_url_on_a_non_ods_dataset_is_left_alone(self):
        """A publisher's own credentialed resource URL is not this migration's business."""
        db = get_db()
        dataset = self._ods_dataset()
        del dataset["extras"]["ods:url"]
        db.dataset.insert_one(dataset)
        before = db.dataset.find_one({})

        self.migrate(db)

        assert db.dataset.find_one({}) == before

    def test_documents_without_credentials_are_untouched(self):
        db = get_db()
        db.dataset.insert_one(
            {
                "title": "Clean",
                "extras": {"ods:url": REDACTED_EXPLORE_URL.replace("***@", "")},
                "resources": [{"title": "Export", "url": "https://example.pt/a.csv"}],
            }
        )
        db.harvest_job.insert_one({"status": "done", "items": [{"remote_id": "ods-dataset"}]})
        dataset_before = db.dataset.find_one({})
        job_before = db.harvest_job.find_one({})

        self.migrate(db)

        assert db.dataset.find_one({}) == dataset_before
        assert db.harvest_job.find_one({}) == job_before

    def test_migration_is_idempotent(self):
        """The filter also matches `://***@`, so a second run must be a no-op."""
        db = get_db()
        db.dataset.insert_one(self._ods_dataset())
        db.harvest_job.insert_one({"status": "done", "items": [{"remote_id": DESCRIPTOR_URL}]})

        self.migrate(db)
        once_dataset = db.dataset.find_one({})
        once_job = db.harvest_job.find_one({})

        self.migrate(db)

        assert db.dataset.find_one({}) == once_dataset
        assert db.harvest_job.find_one({}) == once_job
