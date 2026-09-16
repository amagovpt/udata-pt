"""Tests for the harvest credential redaction migration (LEDG-2477).

The code no longer writes a source URL password anywhere it is served, but the
records written before it stay readable until the jobs are deleted. What the
migration has to prove is the usual pair: the credentials really go, and
nothing else in the document moves.
"""

import pytest
from mongoengine.connection import get_db

from udata.tests.api import PytestOnlyDBTestCase

from .test_ckanpt_migrations import load_migration

CREDENTIALED = "https://harvestuser:sup3rs3cr3t@www.ine.pt/broken.xml"
REDACTED = "https://***@www.ine.pt/broken.xml"
LEAKY_MESSAGE = f"500 Server Error: None for url: {CREDENTIALED}"
CLEAN_MESSAGE = f"500 Server Error: None for url: {REDACTED}"


class RedactHarvestErrorCredentialsMigrationTest(PytestOnlyDBTestCase):
    @pytest.fixture(autouse=True)
    def migration(self):
        self.migrate = load_migration("2026-09-16-redact-harvest-error-url-credentials.py").migrate

    def test_stored_error_credentials_are_redacted(self):
        """Both levels of errors, and the dataservice copy, lose the password."""
        db = get_db()
        db.harvest_job.insert_one(
            {
                "status": "failed",
                "errors": [{"message": LEAKY_MESSAGE, "details": f"Traceback… {CREDENTIALED}"}],
                "items": [
                    {
                        "remote_id": "1",
                        "status": "failed",
                        "errors": [{"message": LEAKY_MESSAGE, "details": None}],
                    }
                ],
            }
        )
        db.dataservice.insert_one(
            {"title": "Leaky", "harvest": {"source_url": CREDENTIALED, "backend": "DCAT"}}
        )

        self.migrate(db)

        job = db.harvest_job.find_one({})
        assert job["errors"][0]["message"] == CLEAN_MESSAGE
        assert "sup3rs3cr3t" not in job["errors"][0]["details"]
        assert job["items"][0]["errors"][0]["message"] == CLEAN_MESSAGE
        assert job["items"][0]["errors"][0]["details"] is None

        dataservice = db.dataservice.find_one({})
        assert dataservice["harvest"]["source_url"] == REDACTED
        # Everything else in the document is left exactly as it was.
        assert dataservice["harvest"]["backend"] == "DCAT"
        assert dataservice["title"] == "Leaky"

    def test_documents_without_credentials_are_untouched(self):
        """A job with no credentials anywhere must come back byte for byte."""
        db = get_db()
        document = {
            "status": "failed",
            "errors": [{"message": "boom", "details": None}],
            "items": [
                {
                    "remote_id": "1",
                    "status": "failed",
                    "errors": [
                        {"message": "404 Client Error for url: https://www.ine.pt/gone.xml"}
                    ],
                }
            ],
        }
        db.harvest_job.insert_one(dict(document))
        before = db.harvest_job.find_one({})

        self.migrate(db)

        assert db.harvest_job.find_one({}) == before

    def test_migration_is_idempotent(self):
        """The filter also matches `://***@`, so a second run must be a no-op."""
        db = get_db()
        db.harvest_job.insert_one({"status": "failed", "errors": [{"message": LEAKY_MESSAGE}]})
        db.dataservice.insert_one({"harvest": {"source_url": CREDENTIALED}})

        self.migrate(db)
        once_job = db.harvest_job.find_one({})
        once_dataservice = db.dataservice.find_one({})

        self.migrate(db)

        assert db.harvest_job.find_one({}) == once_job
        assert db.dataservice.find_one({}) == once_dataservice
