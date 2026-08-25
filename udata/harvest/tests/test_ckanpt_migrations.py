"""Tests for the CKAN PT data migrations (LEDG-2319).

The migrations move config out of places it should never have been written to, so
what they must prove is that nothing is lost on the way: the harvester ends up
reading the same values it read before, and running twice changes nothing.
"""

import importlib.util
import json
from pathlib import Path
from unittest import mock

import pytest
from mongoengine.connection import get_db
from mongoengine.errors import ValidationError

from udata.core.dataset.factories import DatasetFactory, LicenseFactory
from udata.core.dataset.models import HarvestDatasetMetadata
from udata.core.spatial.factories import GeoZoneFactory
from udata.harvest.backends.ckanpt import CkanPTBackend
from udata.harvest.models import HarvestSource
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

    @pytest.mark.parametrize(
        "blob",
        [
            '{"license": null, "geozones": null}',
            '{"license": false, "geozones": false}',
            '{"license": "", "geozones": []}',
            '{"license": "   ", "geozones": ["  "]}',
        ],
    )
    def test_a_config_key_with_no_usable_value_is_skipped(self, blob):
        """`str(None)` is "None", which would settle in the form as a junk value."""
        source = self.source(blob)

        self.migrate(get_db())

        assert extra_configs(source) == {}

    def test_prose_outside_the_description_key_is_logged_before_it_is_replaced(self, caplog):
        """There is no down migration, so the only recovery is the log."""
        source = self.source('{"license": "cc-by", "notes": "Harvester do municipio de Braga"}')

        self.migrate(get_db())

        source.reload()
        assert source.description == ""
        assert extra_configs(source) == {"license": "cc-by"}
        assert any("Harvester do municipio de Braga" in r.getMessage() for r in caplog.records)

    def test_a_config_only_blob_is_replaced_without_a_warning(self):
        """Nothing to lose: the blob held config and nothing else."""
        zone = GeoZoneFactory()
        source = self.source('{"geozones": ["%s"]}' % zone.id)

        self.migrate(get_db())

        source.reload()
        assert source.description == ""

    def test_a_non_string_description_value_is_not_written_back(self, caplog):
        """`HarvestSource.description` is a `StringField`: a nested object raises."""
        source = self.source('{"geozones": ["pt:distrito:11"], "description": {"pt": "Porto"}}')

        self.migrate(get_db())

        source.reload()
        assert source.description == ""
        assert extra_configs(source) == {"geozones": "pt:distrito:11"}
        assert any('{"pt": "Porto"}' in record.getMessage() for record in caplog.records)

    def test_a_source_that_fails_to_save_does_not_stop_the_run(self, caplog):
        """The sources after it in cursor order are the ones left un-migrated.

        And those are exactly the ones exposed to the pre-migration behaviour, so
        the loop has to survive one bad document.
        """
        zone = GeoZoneFactory()
        self.source('{"description": "Falha", "geozones": ["%s"]}' % zone.id)
        self.source('{"description": "Porto", "geozones": ["%s"]}' % zone.id)

        real_save = HarvestSource.save
        calls = []

        def save(self, *args, **kwargs):
            calls.append(self.id)
            if len(calls) == 1:
                raise ValidationError("forced")
            return real_save(self, *args, **kwargs)

        with mock.patch.object(HarvestSource, "save", save):
            self.migrate(get_db())

        assert len(calls) == 2, "the run stopped at the first failure"
        assert any("Failed to save source" in record.getMessage() for record in caplog.records)
        # Whichever the cursor reached second is migrated; the other is untouched.
        migrated = [
            source
            for source in HarvestSource.objects(backend="ckanpt")
            if source.config.get("extra_configs")
        ]
        assert len(migrated) == 1

    def test_an_unknown_geozone_cannot_forge_a_log_line(self, caplog):
        forged = "x\nWARNING [udata] Harvest source approved by sysadmin"
        source = self.source(json.dumps({"geozones": [forged]}))

        self.migrate(get_db())

        assert extra_configs(source) == {"geozones": forged}
        forged_lines = [r for r in caplog.records if "approved by sysadmin" in r.getMessage()]
        assert len(forged_lines) == 1
        assert "\n" not in forged_lines[0].getMessage()

    def test_other_backends_are_left_alone(self):
        source = self.source('{"geozones": ["pt:concelho:1106"]}', backend="dcat")

        self.migrate(get_db())

        source.reload()
        assert source.config.get("extra_configs") is None
        assert source.description == '{"geozones": ["pt:concelho:1106"]}'


class LegacyExtrasMigrationTest(PytestOnlyDBTestCase):
    @pytest.fixture(autouse=True)
    def migration(self):
        self.migrate = load_migration("2026-08-25-migrate-legacy-ckanpt-extras.py").migrate

    def harvested(self, source, backend="CKAN PT", **extras):
        return DatasetFactory(
            extras=extras,
            harvest=HarvestDatasetMetadata(source_id=str(source.id), backend=backend),
        )

    def test_extras_move_onto_the_harvest_metadata(self):
        source = HarvestSourceFactory(backend="ckanpt")
        dataset = self.harvested(
            source,
            **{
                "remote_url": "https://dados.example.pt/dataset/x",
                "ckan:name": "x",
                "ckan:source": "https://dados.example.pt/x",
                "harvest:name": "Dados Abertos X",
                "keep-me": "yes",
            },
        )

        self.migrate(get_db())

        dataset.reload()
        assert dataset.harvest.remote_url == "https://dados.example.pt/dataset/x"
        assert dataset.harvest.ckan_name == "x"
        assert dataset.harvest.ckan_source == "https://dados.example.pt/x"
        assert dataset.extras == {"keep-me": "yes"}

    def test_a_value_already_on_the_harvest_metadata_is_not_overwritten(self):
        source = HarvestSourceFactory(backend="ckanpt")
        dataset = DatasetFactory(
            extras={"remote_url": "https://stale.example.pt/x"},
            harvest=HarvestDatasetMetadata(
                source_id=str(source.id),
                backend="CKAN PT",
                remote_url="https://current.example.pt/x",
            ),
        )

        self.migrate(get_db())

        dataset.reload()
        assert dataset.harvest.remote_url == "https://current.example.pt/x"
        assert "remote_url" not in dataset.extras

    def test_is_idempotent(self):
        source = HarvestSourceFactory(backend="ckanpt")
        dataset = self.harvested(source, **{"remote_url": "https://dados.example.pt/dataset/x"})

        self.migrate(get_db())
        self.migrate(get_db())

        dataset.reload()
        assert dataset.harvest.remote_url == "https://dados.example.pt/dataset/x"
        assert dataset.extras == {}

    def test_datasets_of_other_backends_are_left_alone(self):
        """`cswudata` writes `extras.remote_url` too, and is out of scope here."""
        source = HarvestSourceFactory(backend="csw-udata")
        dataset = DatasetFactory(
            extras={"remote_url": "https://dados.example.pt/dataset/x"},
            harvest=HarvestDatasetMetadata(source_id=str(source.id), backend="CSW-udata"),
        )

        self.migrate(get_db())

        dataset.reload()
        assert dataset.extras == {"remote_url": "https://dados.example.pt/dataset/x"}
        assert dataset.harvest.remote_url is None

    def test_a_dataset_with_no_harvest_backend_is_found_by_its_source(self):
        """294 of the 1413 predate `harvest.backend` being written at all."""
        source = HarvestSourceFactory(backend="ckanpt")
        dataset = self.harvested(
            source, backend=None, **{"ckan:name": "x", "harvest:name": "Dados Abertos X"}
        )

        self.migrate(get_db())

        dataset.reload()
        assert dataset.harvest.ckan_name == "x"
        assert dataset.extras == {}

    def test_a_dataset_whose_source_is_gone_is_found_by_its_backend(self):
        """A deleted source leaves its datasets behind; the display name catches them."""
        dataset = DatasetFactory(
            extras={"ckan:name": "x"},
            harvest=HarvestDatasetMetadata(source_id="deadbeefdeadbeefdeadbeef", backend="CKAN PT"),
        )

        self.migrate(get_db())

        dataset.reload()
        assert dataset.harvest.ckan_name == "x"
        assert dataset.extras == {}
