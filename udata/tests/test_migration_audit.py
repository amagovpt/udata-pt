"""
LEDG-2655: the nine states, one test each.

`udata db status` has three answers and paints three different problems with
the same green date. These tests are the definition of the difference, and the
reason the page can be trusted where the command could not.

Most of them take no database: `classify` is a function from a dict to a
string, which is the whole point of keeping it out of the command.
"""

from datetime import UTC, datetime
from pathlib import Path
from textwrap import dedent

import pytest
from mongoengine.connection import get_db

from udata.db import migrations
from udata.db.migration_audit import (
    ALL_STATES,
    ANOMALOUS_STATES,
    APPLIED,
    APPLIED_WITH_ERRORS,
    EMPTY_RECORD,
    FAILED,
    LEGACY,
    NOT_APPLIED,
    ORPHAN,
    RECORDED_AFTER_FAILURE,
    RECORDED_ONLY,
    audit_migrations,
    classify,
    summarize,
)
from udata.tests.api import PytestOnlyDBTestCase

MIGRATION_SOURCE = """\
    def migrate(db):
        db.test_audit_collection.insert_one({"ok": True})
    """


def op(success=True, output=None, traceback=None):
    return {
        "date": datetime.now(UTC),
        "type": "migrate",
        "output": output if output is not None else [],
        "success": success,
        "traceback": traceback,
    }


def recorded_only_op(success=True):
    """What `execute(recordonly=True)` writes: type "migrate", like a real run."""
    return op(success=success, output=[["info", migrations.RECORDED_ONLY_MESSAGE]])


class ClassifyTest:
    def test_no_record_at_all(self):
        assert classify(None, on_disk=True) == NOT_APPLIED

    def test_record_without_ops_is_legacy(self):
        # Pre-2.0 documents, which old dumps still carry.
        assert classify({"filename": "x.py"}, on_disk=True) == LEGACY

    def test_record_with_no_operations_is_anomalous(self):
        assert classify({"ops": []}, on_disk=True) == EMPTY_RECORD

    def test_last_operation_failed(self):
        assert classify({"ops": [op(success=False)]}, on_disk=True) == FAILED

    def test_recorded_but_never_run(self):
        assert classify({"ops": [recorded_only_op()]}, on_disk=True) == RECORDED_ONLY

    def test_marked_by_hand_after_failing(self):
        doc = {"ops": [op(success=False), recorded_only_op()]}
        assert classify(doc, on_disk=True) == RECORDED_AFTER_FAILURE

    def test_last_real_run_failed_even_if_something_follows(self):
        doc = {"ops": [op(success=True), op(success=False), recorded_only_op()]}
        assert classify(doc, on_disk=True) == RECORDED_AFTER_FAILURE

    def test_succeeded_while_logging_errors(self):
        doc = {"ops": [op(output=[["error", "could not convert 3 datasets"]])]}
        assert classify(doc, on_disk=True) == APPLIED_WITH_ERRORS

    def test_record_without_a_file_is_orphan(self):
        assert classify({"ops": [op()]}, on_disk=False) == ORPHAN

    def test_plain_success(self):
        assert classify({"ops": [op()]}, on_disk=True) == APPLIED

    def test_failure_wins_over_orphan(self):
        """A failed migration whose file is gone is still a failure.

        The missing file is bookkeeping; the failure is the thing somebody has
        to act on, so it must not be hidden behind the gentler state.
        """
        assert classify({"ops": [op(success=False)]}, on_disk=False) == FAILED

    def test_tolerates_output_stored_as_a_string(self):
        """🚩 Real records hold `"output": "ok"` rather than a list of pairs.

        The repository's own suite inserts one (test_migrations.py). Iterating
        it unpacks characters and raises -- an audit that dies on the old
        records audits nothing, and the old records are the reason it exists.
        """
        doc = {"ops": [{"date": datetime.now(UTC), "output": "ok", "success": True}]}
        assert classify(doc, on_disk=True) == APPLIED


class SummarizeTest:
    def test_counts_every_state_even_at_zero(self):
        summary = summarize([{"state": APPLIED}])
        assert set(summary["counts"]) == set(ALL_STATES)
        assert summary["counts"][FAILED] == 0

    def test_a_healthy_portal_is_clean(self):
        summary = summarize([{"state": APPLIED}, {"state": APPLIED}])
        assert summary["clean"] is True
        assert summary["anomalies"] == 0

    def test_one_anomaly_is_enough_to_lose_the_verdict(self):
        summary = summarize([{"state": APPLIED}, {"state": RECORDED_ONLY}])
        assert summary["clean"] is False
        assert summary["anomalies"] == 1

    def test_orphan_and_legacy_are_not_anomalies(self):
        """🚩 The decision that keeps the green verdict reachable.

        An orphaned record is what syncing with upstream leaves behind, and
        legacy records are what old dumps contain. Counting either would mean
        no environment is ever clean, and a verdict that can never be green
        tells nobody anything.
        """
        summary = summarize([{"state": ORPHAN}, {"state": LEGACY}])
        assert summary["clean"] is True
        assert ORPHAN not in ANOMALOUS_STATES
        assert LEGACY not in ANOMALOUS_STATES


class MigrationAuditDBTest(PytestOnlyDBTestCase):
    """The three that need a real migration file and a real database.

    The file is written into udata/migrations and removed afterwards, the way
    MigrationsCommandsTest already does: `files()` is imported inside the
    functions that use it, so there is nothing on the module to patch, and a
    real file is what `execute()` actually loads anyway.
    """

    FILENAME = "test_migration_audit_temp.py"

    @pytest.fixture(autouse=True)
    def _migration(self):
        path = Path(__file__).parent.parent / "migrations" / self.FILENAME
        path.write_text(dedent(MIGRATION_SOURCE))
        yield
        if path.exists():
            path.unlink()
        get_db().migrations.delete_one({"filename": self.FILENAME})

    def test_the_message_is_a_stored_format_and_not_a_label(self):
        """🚩 The literal, pinned on purpose, because a shared constant does not
        protect it.

        Rename the constant and both the writer and the audit change together,
        so every test still passes -- while every record ALREADY in the
        database keeps the old text and silently stops being classified. The
        34 records that made LEDG-2654 are exactly those: written long ago,
        read today.

        The string is a wire format, not a label. Changing it is a migration of
        its own, and this test is where somebody is made to notice.
        """
        assert migrations.RECORDED_ONLY_MESSAGE == "Recorded only"

    def test_a_recorded_only_run_is_classified_as_such(self):
        """🚩 The test the whole module rests on.

        Nothing in the document says a migration was only recorded: `type` is
        "migrate" either way. The sole trace is a string in the output, which
        means a reader that looks for the wrong string silently loses a state.

        This one runs `execute(recordonly=True)` for real and demands the
        classification, so the writer and the reader are proved to agree. What
        it does NOT catch is the message changing -- both sides read the same
        constant and move together. That is the test above.
        """
        migrations.get(self.FILENAME).execute(recordonly=True)

        entry = next(e for e in audit_migrations() if e["filename"] == self.FILENAME)

        assert entry["state"] == RECORDED_ONLY
        assert entry["marked"] == 1
        assert entry["failed_runs"] == 0

    def test_a_real_run_is_applied(self):
        migrations.get(self.FILENAME).execute()

        entry = next(e for e in audit_migrations() if e["filename"] == self.FILENAME)

        assert entry["state"] == APPLIED
        assert entry["marked"] == 0

    def test_the_errors_themselves_travel_not_just_their_count(self):
        """ "11 errors logged" with nothing to read is the frustration this
        page exists to end, and whoever is looking has no shell to go and find
        them in.
        """
        from udata.db.migration_audit import MESSAGE_COUNT_LIMIT, _entry

        doc = {
            "ops": [
                {
                    "date": datetime.now(UTC),
                    "success": True,
                    "output": [["error", f"dataset {i} could not be converted"] for i in range(30)],
                }
            ]
        }

        entry = _entry("x.py", doc, on_disk=True)

        # The true count is never truncated, so a capped list cannot misreport
        # how bad it was.
        assert entry["errors"] == 30
        assert len(entry["messages"]) == MESSAGE_COUNT_LIMIT
        assert "dataset 0 could not be converted" in entry["messages"][0]

    def test_a_migration_without_errors_carries_an_empty_list(self):
        from udata.db.migration_audit import _entry

        entry = _entry("x.py", {"ops": [op()]}, on_disk=True)

        assert entry["errors"] == 0
        assert entry["messages"] == []

    def test_a_migration_marked_after_failing_shows_why_it_failed(self):
        """🚩 The state where the detail matters most, and where reading the
        last operation gives nothing.

        The last op is the marking somebody added: no errors, no traceback.
        The failure is in the one before, and that is what has to surface --
        otherwise the most alarming row on the page is also the emptiest.
        """
        from udata.db.migration_audit import _entry

        doc = {
            "ops": [
                op(success=False, output=[["error", "boom"]], traceback="Traceback: boom"),
                recorded_only_op(),
            ]
        }

        entry = _entry("x.py", doc, on_disk=True)

        assert entry["state"] == RECORDED_AFTER_FAILURE
        assert entry["messages"] == ["boom"]
        assert entry["traceback"] == "Traceback: boom"

    def test_a_legacy_record_still_says_when_and_what(self):
        """Pre-2.0 documents keep date and output at the top level.

        43 of them in a developer database rendered as blank rows until this:
        the data was there, one level up from where the reader was looking.
        """
        from udata.db.migration_audit import _entry

        doc = {
            "filename": "2015-05-06-migrate-issues.js",
            "date": datetime(2018, 4, 30, 16, 14, tzinfo=UTC),
            "output": "Recorded only",
        }

        entry = _entry("2015-05-06-migrate-issues.js", doc, on_disk=False)

        assert entry["state"] == LEGACY
        assert entry["date"].startswith("2018-04-30")
        assert entry["messages"] == ["Recorded only"]

    def test_the_payload_never_carries_migration_source(self):
        """add_record stores inspect.getsource() on every operation."""
        migrations.get(self.FILENAME).execute()

        for entry in audit_migrations():
            assert "script" not in entry
