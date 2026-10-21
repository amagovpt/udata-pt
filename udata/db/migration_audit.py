"""
Classify what the ``migrations`` collection actually says, record by record.

``udata db status`` knows three answers — a green date, "Not applied", or the
last status in red — and the green one covers several situations that are not
"applied successfully":

- a migration recorded without ever running (what restoring a dump produces);
- one that failed, was marked by hand, and left the schema half-done;
- one that ran, logged errors, and reported success anyway.

LEDG-2654 was the bill for that: PPR came back from a production dump with 34
migrations claiming to be applied, and nobody could see it until the backend
refused to start.

🚩 THIS MODULE DOES NOT USE ``Record`` OR ``Migration``, and that is not
stylistic. ``Record.ok``, ``.status`` and ``.last_date`` all index ``ops[-1]``,
so a document with no ``ops`` raises TypeError and one with ``ops == []``
raises IndexError — the two anomalies this audit exists to surface are exactly
the ones those properties crash on. And ``Migration(filename)`` raises
FileNotFoundError when the file is gone, while ``list_available()`` only walks
the disk, so an orphaned record is unreachable through either.
"""

from datetime import datetime
from importlib.resources import files

from mongoengine.connection import get_db

from udata.db.migrations import RECORDED_ONLY_MESSAGE

#: Log levels that mean something went wrong inside a migration that still
#: reported success. They are swallowed today: nothing reads them back.
ERROR_LEVELS = ("warning", "error", "critical", "exception")

#: Longest error message and traceback carried in the payload. Enough to
#: recognise the failure without shipping a whole stack to a browser.
MESSAGE_LIMIT = 500
TRACEBACK_LIMIT = 4000

NOT_APPLIED = "not_applied"
LEGACY = "legacy"
EMPTY_RECORD = "empty_record"
FAILED = "failed"
RECORDED_ONLY = "recorded_only"
RECORDED_AFTER_FAILURE = "recorded_after_failure"
APPLIED_WITH_ERRORS = "applied_with_errors"
ORPHAN = "orphan"
APPLIED = "applied"

ALL_STATES = (
    NOT_APPLIED,
    LEGACY,
    EMPTY_RECORD,
    FAILED,
    RECORDED_ONLY,
    RECORDED_AFTER_FAILURE,
    APPLIED_WITH_ERRORS,
    ORPHAN,
    APPLIED,
)

#: What makes an environment unhealthy.
#:
#: 🚩 ORPHAN and LEGACY are deliberately absent. A record whose file is gone is
#: the ordinary result of syncing with upstream, and legacy records are what
#: old dumps contain; counting either would make the "no anomalies" verdict
#: unreachable for ever, and a verdict that can never be green says nothing.
ANOMALOUS_STATES = frozenset(
    {NOT_APPLIED, EMPTY_RECORD, FAILED, RECORDED_ONLY, RECORDED_AFTER_FAILURE, APPLIED_WITH_ERRORS}
)


def _output_pairs(op):
    """
    The (level, message) pairs of one operation, tolerating what is really
    stored.

    🚩 ``output`` is not always a list of pairs. Records written by older
    versions hold a plain string -- the repository's own test suite inserts
    ``"output": "ok"`` -- and iterating that unpacks characters and raises.
    An audit that crashes on the old records is an audit of nothing.
    """
    output = op.get("output")
    if not isinstance(output, (list, tuple)):
        return []

    pairs = []
    for entry in output:
        if isinstance(entry, (list, tuple)) and len(entry) == 2:
            pairs.append((str(entry[0]), str(entry[1])))
    return pairs


def _is_recorded_only(op):
    """True when this operation recorded the migration instead of running it."""
    return any(message == RECORDED_ONLY_MESSAGE for _, message in _output_pairs(op))


def _error_messages(op):
    return [message for level, message in _output_pairs(op) if level.lower() in ERROR_LEVELS]


def classify(doc, on_disk):
    """
    The state of one migration, from its record and whether its file exists.

    Pure: takes the document, returns a string. The order below IS the rule --
    each test asserts one branch of it.
    """
    if doc is None:
        return NOT_APPLIED

    ops = doc.get("ops")
    if ops is None:
        # Pre-2.0 format: a record with no operation history at all.
        return LEGACY
    if not ops:
        # A record that exists and claims nothing. Written by hand, or by an
        # import that lost the operations.
        return EMPTY_RECORD

    last = ops[-1]
    if not last.get("success"):
        return FAILED

    executed = [op for op in ops if not _is_recorded_only(op)]
    if not executed:
        return RECORDED_ONLY

    failed_runs = [op for op in executed if not op.get("success")]
    if failed_runs:
        # It ran, it failed, and the record ends well: somebody marked it.
        return RECORDED_AFTER_FAILURE

    if _error_messages(executed[-1]):
        return APPLIED_WITH_ERRORS

    if not on_disk:
        return ORPHAN

    return APPLIED


def _entry(filename, doc, on_disk):
    state = classify(doc, on_disk)
    ops = (doc or {}).get("ops") or []
    executed = [op for op in ops if not _is_recorded_only(op)]
    marked = [op for op in ops if _is_recorded_only(op)]
    failed_runs = [op for op in executed if not op.get("success")]

    last = ops[-1] if ops else None
    date = last.get("date") if last else None

    messages = _error_messages(last) if last else []
    # The traceback travels only where it is the answer to a question somebody
    # is asking. Those states are few by definition, and without it "it failed"
    # sends whoever has no shell straight back where they started.
    traceback = (
        last.get("traceback") if last and state in (FAILED, RECORDED_AFTER_FAILURE) else None
    )

    return {
        "filename": filename,
        "state": state,
        "date": date.isoformat() if isinstance(date, datetime) else None,
        "ops": len(ops),
        # These two are what separate "recorded once" from "failed three times
        # and then marked by hand".
        "marked": len(marked),
        "failed_runs": len(failed_runs),
        "errors": len(messages),
        "message": messages[-1][:MESSAGE_LIMIT] if messages else None,
        "traceback": traceback[:TRACEBACK_LIMIT] if traceback else None,
    }


def audit_migrations():
    """Every migration known to the disk or to the database, classified."""
    disk = {item.name for item in files("udata").joinpath("migrations").iterdir() if item.is_file()}

    # 🚩 ops.script is excluded, and that is not an optimisation. add_record
    # stores inspect.getsource() of the whole migration on EVERY operation, so
    # the unprojected collection carries the source of 69 migrations many times
    # over -- megabytes, down a request that has no use for any of it. The
    # source lives in the repository.
    docs = {doc["filename"]: doc for doc in get_db().migrations.find({}, {"ops.script": 0})}

    return [
        _entry(filename, docs.get(filename), filename in disk)
        for filename in sorted(disk | set(docs))
    ]


def summarize(entries):
    """
    Counts per state, and one boolean that decides the verdict.

    ``clean`` is computed here rather than in the page so the command and the
    page cannot disagree about the same environment, and so that filtering a
    table can never change what the verdict says.
    """
    counts = {state: 0 for state in ALL_STATES}
    for entry in entries:
        counts[entry["state"]] += 1

    anomalies = sum(counts[state] for state in ANOMALOUS_STATES)

    return {
        "total": len(entries),
        "counts": counts,
        "anomalies": anomalies,
        "clean": anomalies == 0,
    }
