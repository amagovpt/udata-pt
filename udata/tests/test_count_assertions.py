"""Guard against unfiltered count assertions creeping back into the test tree.

mongoengine routes a `QuerySet.count()` with **no filter** to
`collection.estimated_document_count()`, which reads WiredTiger's collection
metadata instead of counting::

    if not filter and set(kwargs) <= {"max_time_ms"}:
        return collection.estimated_document_count(**kwargs)
    else:
        return collection.count_documents(filter=filter, **kwargs)

That metadata is derived from the real contents and drifts in **both**
directions in databases produced by ordinary suite runs:

* estimated 1 / actual 0 -- a false red: a correct test fails;
* estimated 0 / actual 1 -- a false **green**: ``assert X.objects.count() == 0``
  passes with a document still in the collection.

The second is the dangerous one, because a test written precisely to catch an
orphan reports green with the orphan there.

Use instead:

* ``len(list(Model.objects))`` for a genuine "how many in total" check, or
* ``Model.objects(field=value).count()`` -- a *filtered* count, which is
  routed to ``count_documents()`` and is exact -- when the test can name what
  it expects to find or not find.

Production code is not covered by this guard: outside tests the speed of an
estimate is usually worth its imprecision, and the remaining unfiltered counts
there are progress-bar lengths and CLI report figures that nobody decides
anything with. The two that fed a *published* metric were made exact in
`udata/core/site/models.py`.
"""

import re
from pathlib import Path

import udata

# Every unfiltered shape, all routed to `estimated_document_count()`:
#     Model.objects.count()
#     Model.objects().count()
#     Model.objects.all().count() / .filter() / .no_cache() / .order_by(...)
# and any chain of those. A filtered call -- `Model.objects(field=x).count()` --
# does not match, because the first parentheses are required to be empty.
#
# What this cannot catch, because it reads text and not syntax: a queryset held
# in a variable and counted later (`qs = M.objects` ... `qs.count()`), and a
# `.count()` wrapped onto its own line. Neither exists in the tree today.
UNFILTERED_COUNT = re.compile(
    r"\.objects(\(\))?(\.(all|filter|no_cache)\(\)|\.order_by\([^)]*\))*\.count\(\)"
)

# What counts as a test module is pytest's definition, from `pyproject.toml`
# (`python_files = ["test_*.py"]`), plus everything under a `tests/` directory --
# not a hand-maintained list, which goes stale the first time someone adds a
# module outside `tests/` (`udata/core/avatars/test_avatar_api.py` is already one).
#
# `udata/migrations/` is excluded deliberately: `test_migrations.py` writes
# `udata/migrations/test_migration_temp.py` at runtime and removes it in its
# teardown, so under `-n 4` a walk racing that test would match a file that is
# gone by the time it is read. The `FileNotFoundError` below is the second belt.
EXCLUDED_DIRS = ("migrations",)


def _test_sources():
    root = Path(udata.__file__).parent
    seen = set()
    for path in sorted(list(root.glob("**/tests/**/*.py")) + list(root.rglob("test_*.py"))):
        if any(part in EXCLUDED_DIRS for part in path.relative_to(root).parts):
            continue
        if path not in seen:
            seen.add(path)
            yield path


def test_no_unfiltered_count_in_tests():
    """No test may assert on a count that mongoengine only estimates."""
    here = Path(__file__).resolve()
    offenders = []

    for path in _test_sources():
        if path.resolve() == here:
            continue
        try:
            source = path.read_text(encoding="utf-8")
        except (FileNotFoundError, UnicodeDecodeError):
            # A file that vanished mid-walk is not an offender.
            continue
        for lineno, line in enumerate(source.splitlines(), start=1):
            if UNFILTERED_COUNT.search(line):
                offenders.append(f"{path.relative_to(Path(udata.__file__).parent)}:{lineno}")

    assert not offenders, (
        "Unfiltered `.count()` found in the test tree. mongoengine routes it to "
        "`estimated_document_count()`, which can report zero while a document is "
        "still there -- see this module's docstring for the two replacements:\n  "
        + "\n  ".join(offenders)
    )
