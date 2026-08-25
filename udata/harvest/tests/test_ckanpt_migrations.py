"""Tests for the CKAN PT data migrations (LEDG-2319).

The migrations move config out of places it should never have been written to, so
what they must prove is that nothing is lost on the way: the harvester ends up
reading the same values it read before, and running twice changes nothing.
"""

import importlib.util
from pathlib import Path

import pytest
from mongoengine.connection import get_db

from udata.core.dataset.factories import LicenseFactory
from udata.core.spatial.factories import GeoZoneFactory
from udata.harvest.backends.ckanpt import CkanPTBackend
from udata.harvest.tests.factories import HarvestSourceFactory
from udata.tests.api import PytestOnlyDBTestCase

MIGRATIONS = Path(__file__).parents[2] / "migrations"


def load_migration(filename):
    """Import a migration by filename: they are dated, so not importable as modules."""
    path = MIGRATIONS / filename
    spec = importlib.util.spec_from_file_location(path.stem.replace("-", "_"), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def extra_configs(source):
    source.reload()
    return {entry["key"]: entry["value"] for entry in source.config.get("extra_configs") or []}


class DescriptionConfigMigrationTest(PytestOnlyDBTestCase):
    @pytest.fixture(autouse=True)
    def migration(self):
        self.migrate = load_migration(
            "2026-08-25-ckanpt-description-config-to-extra-configs.py"
        ).migrate

    def source(self, description, backend="ckanpt", config=None):
        return HarvestSourceFactory(backend=backend, description=description, config=config or {})

    def test_geozones_move_to_extra_configs(self):
        """The shape six of the seven production sources are in."""
        zone = GeoZoneFactory()
        source = self.source(
            '{"description": "Dados Abertos Lisboa", "geozones": ["%s"]}' % zone.id
        )

        self.migrate(get_db())

        assert extra_configs(source) == {"geozones": zone.id}
        assert source.description == "Dados Abertos Lisboa"

    def test_license_moves_to_extra_configs(self):
        """The shape the seventh is in."""
        zone = GeoZoneFactory()
        LicenseFactory(id="cc-by")
        source = self.source(
            '{"description": "Harvester Oeiras", "geozones": ["%s"], "license": "cc-by"}' % zone.id
        )

        self.migrate(get_db())

        assert extra_configs(source) == {"geozones": zone.id, "license": "cc-by"}
        assert source.description == "Harvester Oeiras"

    def test_several_geozones_become_one_comma_separated_value(self):
        first, second = GeoZoneFactory(), GeoZoneFactory()
        source = self.source('{"geozones": ["%s", "%s"]}' % (first.id, second.id))

        self.migrate(get_db())

        assert extra_configs(source) == {"geozones": f"{first.id},{second.id}"}

    def test_the_harvester_reads_the_same_zones_afterwards(self):
        """The point of the migration: no loss between the two storage places."""
        zone = GeoZoneFactory()
        source = self.source('{"geozones": ["%s"]}' % zone.id)

        self.migrate(get_db())
        source.reload()

        assert CkanPTBackend(source, dryrun=True).configured_geozones == [zone]

    def test_prose_description_is_left_alone(self):
        source = self.source("Dados abertos do municipio.")

        self.migrate(get_db())

        source.reload()
        assert source.config.get("extra_configs") is None
        assert source.description == "Dados abertos do municipio."

    @pytest.mark.parametrize("description", [None, "", "2026", "[1, 2]", '{"license": '])
    def test_a_description_that_is_not_config_is_left_alone(self, description):
        """Justiça has no description at all; the rest never parsed as config."""
        source = self.source(description)

        self.migrate(get_db())

        source.reload()
        assert source.config.get("extra_configs") is None
        assert source.description == description

    def test_a_json_object_without_config_keys_is_left_alone(self):
        source = self.source('{"title": "Dados abertos"}')

        self.migrate(get_db())

        source.reload()
        assert source.config.get("extra_configs") is None
        assert source.description == '{"title": "Dados abertos"}'

    def test_is_idempotent(self):
        zone = GeoZoneFactory()
        source = self.source('{"description": "Porto", "geozones": ["%s"]}' % zone.id)

        self.migrate(get_db())
        self.migrate(get_db())

        assert extra_configs(source) == {"geozones": zone.id}
        assert source.description == "Porto"

    def test_an_existing_extra_config_wins(self):
        """Someone may have configured the source through the form already."""
        zone, configured = GeoZoneFactory(), GeoZoneFactory()
        source = self.source(
            '{"geozones": ["%s"]}' % zone.id,
            config={"extra_configs": [{"key": "geozones", "value": configured.id}]},
        )

        self.migrate(get_db())

        assert extra_configs(source) == {"geozones": configured.id}

    def test_filters_already_on_the_source_are_kept(self):
        zone = GeoZoneFactory()
        filters = [{"key": "organization", "value": "turismo-de-portugal-ip", "type": "exclude"}]
        source = self.source('{"geozones": ["%s"]}' % zone.id, config={"filters": filters})

        self.migrate(get_db())

        source.reload()
        assert source.config["filters"] == filters

    def test_an_unknown_geozone_is_migrated_anyway(self, caplog):
        """Dropping it would lose what the admin meant; the backend warns and skips."""
        source = self.source('{"geozones": ["pt:concelho:0000"]}')

        self.migrate(get_db())

        assert extra_configs(source) == {"geozones": "pt:concelho:0000"}
        assert any("pt:concelho:0000" in record.getMessage() for record in caplog.records)

    def test_other_backends_are_left_alone(self):
        source = self.source('{"geozones": ["pt:concelho:1106"]}', backend="dcat")

        self.migrate(get_db())

        source.reload()
        assert source.config.get("extra_configs") is None
        assert source.description == '{"geozones": ["pt:concelho:1106"]}'
