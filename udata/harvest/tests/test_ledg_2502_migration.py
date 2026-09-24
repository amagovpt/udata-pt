"""Tests for the harvest source text index migration (LEDG-2502).

Two properties. The index really changes -- which is what stops the new code
from raising `IndexOptionsConflict` the first time it touches the collection --
and a source that still carries credentials is named without its secret and
left byte for byte as it was.
"""

import pytest
from mongoengine.connection import get_db

from udata.tests.api import PytestOnlyDBTestCase

from .test_ckanpt_migrations import MIGRATIONS, load_migration

MIGRATION = "2026-08-24-drop-harvest-source-url-text-index.py"

# The first migration to touch `HarvestSource` through mongoengine triggers
# `ensure_indexes`, which MongoDB refuses while the old text index is there. So
# the index migration has to sort before every migration that reads the model
# and can be pending at the same time as it -- the ckanpt ones of 2026-08-25
# were, and tst failed on the first of them before the index was ever replaced.
FIRST_MIGRATION_THAT_CAN_BE_PENDING_WITH_IT = "2026-08-25"

CREDENTIALED_URL = "https://harvestuser:sup3rs3cr3t@www.ine.pt/broken.xml"


def text_index_weights(collection):
    return {
        name: spec["weights"]
        for name, spec in collection.index_information().items()
        if "weights" in spec
    }


class DropHarvestSourceURLTextIndexMigrationTest(PytestOnlyDBTestCase):
    @pytest.fixture(autouse=True)
    def migration(self):
        self.migrate = load_migration(MIGRATION).migrate

    @pytest.fixture(autouse=True)
    def old_index(self):
        """Put the collection back in its pre-migration shape.

        Unconditional, not defensive: `drop_db` truncates documents and never
        drops indexes ("the schemas don't change between tests"), and this
        ticket is precisely a schema change -- so by the time this runs, the
        new `name_text` is already there and MongoDB would refuse the old one
        next to it.
        """
        from udata.models import Harvest

        collection = get_db().harvest_source
        collection.drop_indexes()
        collection.create_index(
            [("name", "text"), ("url", "text")],
            weights={"name": 10, "url": 5},
            default_language="french",
        )
        yield
        # Put the model's own indexes back even when the test failed before
        # `migrate` could. `drop_db` never touches indexes, and the collection
        # is cached per process, so a failure here would otherwise strip the
        # unique `slug` index for every test that runs after it in this worker.
        collection.drop_indexes()
        Harvest.ensure_indexes()

    def test_url_text_index_is_replaced_by_name_only(self):
        collection = get_db().harvest_source
        assert any("url" in w for w in text_index_weights(collection).values())

        self.migrate(get_db())

        weights = text_index_weights(collection)
        assert not any("url" in w for w in weights.values())
        assert {"name": 10} in weights.values()

    def test_credentialed_sources_are_reported_without_the_secret(self, caplog):
        collection = get_db().harvest_source
        collection.insert_one(
            {"name": "Fonte legada", "slug": "legada", "url": CREDENTIALED_URL, "active": True}
        )
        stored = collection.find_one({"slug": "legada"})

        self.migrate(get_db())

        messages = [record.getMessage() for record in caplog.records]
        assert any("legada" in message and "www.ine.pt" in message for message in messages)
        # The report names the source, never what it is hiding.
        assert not any("sup3rs3cr3t" in message for message in messages)
        assert not any("harvestuser" in message for message in messages)
        # And it reports: the URL is left exactly as it was found.
        assert collection.find_one({"slug": "legada"}) == stored

    def test_reports_nothing_when_no_source_carries_credentials(self, caplog):
        get_db().harvest_source.insert_one(
            {"name": "Fonte limpa", "slug": "limpa", "url": "https://www.ine.pt/feed.xml"}
        )

        self.migrate(get_db())

        assert not any("limpa" in record.getMessage() for record in caplog.records)


def test_index_migration_sorts_before_the_migrations_that_read_the_model():
    """Filename order is execution order (`migrations.list_available`)."""
    later = sorted(
        path.name
        for path in MIGRATIONS.glob("*.py")
        if path.name >= FIRST_MIGRATION_THAT_CAN_BE_PENDING_WITH_IT
        and path.name != MIGRATION
        and "udata.harvest.models" in path.read_text()
    )

    assert later, "the migrations this ordering protects have moved; update the test"
    assert MIGRATION < later[0], (
        f"{later[0]} would trigger `ensure_indexes` before {MIGRATION} drops the old index"
    )
