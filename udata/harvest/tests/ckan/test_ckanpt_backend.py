"""Tests for the CKAN PT backend.

Two concerns live here. The harvest config (`license`, `geozones`) that this
backend carries as a JSON blob in the source description, a free-text field in the
UI where anything that is not a JSON object means "no config" - in a preview
(`dryrun=True`) exactly as in a real harvest (LEDG-2315). And the behaviour the
backend now inherits from `CkanBackend` instead of duplicating it (LEDG-2319).
"""

import json
import logging
from contextlib import contextmanager
from unittest import mock
from urllib.parse import urljoin

import pytest

from udata.core.dataset.factories import LicenseFactory
from udata.core.organization.factories import OrganizationFactory
from udata.core.spatial.factories import GeoZoneFactory
from udata.harvest import actions
from udata.harvest.backends.ckanpt import CkanPTBackend
from udata.harvest.tests.factories import HarvestSourceFactory
from udata.models import Dataset, Organization, Resource
from udata.tests.api import PytestOnlyDBTestCase
from udata.utils import faker

DATASET_NAME = "ckanpt-dataset"
BACKEND_LOGGER = "udata.harvest.backends.ckanpt"


@contextmanager
def caplog_at_warning(logger_name):
    """Collect a logger's warnings without pytest's `caplog`, which `mock.patch` hides."""
    records = []

    class Collector(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = Collector(level=logging.WARNING)
    logger = logging.getLogger(logger_name)
    logger.addHandler(handler)
    try:
        yield records
    finally:
        logger.removeHandler(handler)


def ckanpt_organization(acronym):
    return {
        "id": faker.uuid4(),
        "name": acronym,
        "title": faker.company(),
        "description": faker.sentence(),
        "created": faker.date(),
        "revision_timestamp": faker.date(),
        "revision_id": faker.uuid4(),
        "is_organization": True,
        "state": "active",
        "image_url": faker.uri(),
        "type": "organization",
        "approval_status": "approved",
    }


def ckanpt_package(acronym):
    """A minimal package payload accepted by the CKAN schema and by CkanPTBackend."""
    return {
        "success": True,
        "result": {
            "id": faker.uuid4(),
            "name": DATASET_NAME,
            "title": faker.sentence(),
            "notes": faker.paragraph(),
            "license_id": None,
            "license_title": None,
            "tags": [],
            "extras": [],
            "metadata_created": faker.date(),
            "metadata_modified": faker.date(),
            "organization": ckanpt_organization(acronym),
            "private": False,
            "type": "dataset",
            "state": "active",
            "author": None,
            "author_email": None,
            "maintainer": None,
            "maintainer_email": None,
            "resources": [
                {
                    "id": faker.uuid4(),
                    "position": 0,
                    "name": faker.sentence(),
                    "description": faker.paragraph(),
                    "format": "CSV",
                    "mimetype": "text/csv",
                    "size": 1024,
                    "hash": None,
                    "created": faker.date(),
                    "last_modified": faker.date(),
                    "url": faker.uri(),
                    "resource_type": "file",
                }
            ],
        },
    }


@pytest.mark.options(HARVESTER_BACKENDS=["ckanpt"])
class CkanPTBackendTest(PytestOnlyDBTestCase):
    @pytest.fixture(autouse=True)
    def setup_remote(self, ckan, rmock):
        self.org = OrganizationFactory(acronym="ckanpt-org")
        self.package = ckanpt_package(self.org.acronym)
        rmock.get(
            ckan.PACKAGE_LIST_URL,
            json={"success": True, "result": [DATASET_NAME]},
            status_code=200,
            headers={"Content-Type": "application/json"},
        )
        rmock.get(
            ckan.PACKAGE_SHOW_URL,
            json=self.package,
            status_code=200,
            headers={"Content-Type": "application/json"},
        )
        self.ckan_url = ckan.BASE_URL
        self.ckan = ckan
        self.rmock = rmock

    def remote_returns_the_package(self):
        """Re-register the mock after mutating the payload; the last one registered wins."""
        self.rmock.get(
            self.ckan.PACKAGE_SHOW_URL,
            json=self.package,
            status_code=200,
            headers={"Content-Type": "application/json"},
        )

    def source(self, description):
        return HarvestSourceFactory(
            backend="ckanpt",
            url=self.ckan_url,
            description=description,
            organization=self.org,
        )

    def configured(self, license=None, geozones=None, description=""):
        """A source carrying its config in `extra_configs`, not in the description."""
        extra_configs = [
            {"key": key, "value": value}
            for key, value in (("license", license), ("geozones", geozones))
            if value is not None
        ]
        return HarvestSourceFactory(
            backend="ckanpt",
            url=self.ckan_url,
            description=description,
            organization=self.org,
            config={"extra_configs": extra_configs},
        )

    def assert_previewed_one_item(self, job):
        assert job.status == "done", [error.message for error in job.errors]
        assert job.errors == []
        assert len(job.items) == 1
        item = job.items[0]
        assert item.status == "done", [error.message for error in item.errors]
        assert item.dataset is not None
        assert len(Dataset.objects) == 0
        return item.dataset

    def test_preview_with_prose_description(self):
        """The default case: the description is plain prose, not config."""
        source = self.source("Harvester dos dados abertos do municipio.")

        dataset = self.assert_previewed_one_item(actions.preview(source))

        assert dataset.title == self.package["result"]["title"]

    def test_preview_with_empty_description(self):
        dataset = self.assert_previewed_one_item(actions.preview(self.source("")))

        assert dataset.title == self.package["result"]["title"]

    def test_preview_with_scalar_json_description(self):
        """`json.loads` accepts bare scalars; they are not a config either."""
        self.assert_previewed_one_item(actions.preview(self.source("2026")))

    def test_preview_with_array_json_description(self):
        self.assert_previewed_one_item(actions.preview(self.source("[1, 2]")))

    def test_preview_with_malformed_json_description(self):
        self.assert_previewed_one_item(actions.preview(self.source('{"license": ')))

    def test_preview_ignores_a_json_description(self, caplog):
        """The description is free text again: config left there no longer applies."""
        license = LicenseFactory()
        zone = GeoZoneFactory()
        source = self.source(json.dumps({"license": license.id, "geozones": [zone.id]}))

        with caplog.at_level(logging.WARNING, logger=BACKEND_LOGGER):
            dataset = self.assert_previewed_one_item(actions.preview(source))

        assert dataset.license != license
        assert not dataset.spatial
        warnings = self.backend_warnings(caplog)
        assert len(warnings) == 1
        assert "no longer read" in warnings[0]

    def test_preview_with_extra_configs(self):
        license = LicenseFactory()
        zone = GeoZoneFactory()
        source = self.configured(license=license.id, geozones=zone.id)

        dataset = self.assert_previewed_one_item(actions.preview(source))

        assert dataset.license == license
        assert [z.id for z in dataset.spatial.zones] == [zone.id]

    def test_run_with_extra_configs(self):
        """The real harvest honours the configured license and zones."""
        license = LicenseFactory()
        zone = GeoZoneFactory()
        source = self.configured(license=license.id, geozones=zone.id)

        actions.run(source)

        source.reload()
        job = source.get_last_job()
        assert job.status == "done", [error.message for error in job.errors]
        dataset = Dataset.objects.get(id=job.items[0].dataset.id)
        assert dataset.license == license
        assert [z.id for z in dataset.spatial.zones] == [zone.id]

    def test_several_geozones_travel_comma_separated(self):
        """`HarvestExtraConfig` only admits scalars, so the list travels as CSV."""
        first, second = GeoZoneFactory(), GeoZoneFactory()
        source = self.configured(geozones=f" {first.id} , {second.id} ,")

        dataset = self.assert_previewed_one_item(actions.preview(source))

        assert [z.id for z in dataset.spatial.zones] == [first.id, second.id]

    def test_unknown_geozone_is_skipped(self, caplog):
        """A typo in the config must not fail every dataset of the source."""
        zone = GeoZoneFactory()
        source = self.configured(geozones=f"no-such-zone,{zone.id}")

        with caplog.at_level(logging.WARNING, logger=BACKEND_LOGGER):
            dataset = self.assert_previewed_one_item(actions.preview(source))

        assert [z.id for z in dataset.spatial.zones] == [zone.id]
        warnings = self.backend_warnings(caplog)
        assert len(warnings) == 1
        assert "no-such-zone" in warnings[0]

    def test_unknown_configured_license_falls_back(self, caplog):
        """An id that matches no license must not fail the whole harvest."""
        default = LicenseFactory(id="notspecified")
        source = self.configured(license="no-such-license")

        with caplog.at_level(logging.WARNING, logger=BACKEND_LOGGER):
            dataset = self.assert_previewed_one_item(actions.preview(source))

        assert dataset.license == default
        warnings = self.backend_warnings(caplog)
        assert len(warnings) == 1
        assert "no-such-license" in warnings[0]

    def test_configured_license_is_matched_case_insensitively(self):
        """Identifiers are stored lower case but typed by hand."""
        license = LicenseFactory(id="cc-by-4.0")
        source = self.configured(license="  CC-BY-4.0  ")

        dataset = self.assert_previewed_one_item(actions.preview(source))

        assert dataset.license == license

    def test_configured_license_cannot_inject_mongo_operators(self, caplog):
        """The identifier comes from user input and must never reach the query."""
        LicenseFactory(id="notspecified")
        target = LicenseFactory(id="cc-by")
        source = self.configured(license={"$regex": "^cc"})

        with caplog.at_level(logging.WARNING, logger=BACKEND_LOGGER):
            dataset = self.assert_previewed_one_item(actions.preview(source))

        assert dataset.license != target
        assert dataset.license.id == "notspecified"
        assert len(self.backend_warnings(caplog)) == 1

    def test_configured_license_cannot_forge_log_lines(self, caplog):
        """A crafted identifier must not be able to fake a log entry."""
        LicenseFactory(id="notspecified")
        forged = "x\nWARNING [udata] Harvest source approved by sysadmin"
        source = self.configured(license=forged)

        with caplog.at_level(logging.WARNING, logger=BACKEND_LOGGER):
            self.assert_previewed_one_item(actions.preview(source))

        warnings = self.backend_warnings(caplog)
        assert len(warnings) == 1
        assert "\n" not in warnings[0]

    def test_unknown_license_is_only_logged_once_per_job(self, caplog):
        """`default_license` runs per dataset; the job must not collect one line each."""
        LicenseFactory(id="notspecified")
        second = dict(self.package["result"], id=faker.uuid4(), name="ckanpt-dataset-2")
        self.rmock.get(
            self.ckan.PACKAGE_LIST_URL,
            json={"success": True, "result": [DATASET_NAME, "ckanpt-dataset-2"]},
            status_code=200,
            headers={"Content-Type": "application/json"},
        )
        self.rmock.get(
            urljoin(self.ckan.PACKAGE_SHOW_URL, "?id=ckanpt-dataset-2"),
            json={"success": True, "result": second},
            status_code=200,
            headers={"Content-Type": "application/json"},
        )
        source = self.configured(license="no-such-license")

        with caplog.at_level(logging.WARNING, logger=BACKEND_LOGGER):
            job = actions.preview(source)

        assert len(job.items) == 2
        assert len(self.backend_warnings(caplog)) == 1

    def test_remote_license_wins_over_configured_one(self):
        """The config is a fallback, not an override."""
        configured = LicenseFactory()
        remote = LicenseFactory()
        self.package["result"]["license_id"] = remote.id
        source = self.configured(license=configured.id)

        dataset = self.assert_previewed_one_item(actions.preview(source))

        assert dataset.license == remote

    def test_run_with_prose_description(self):
        source = self.source("Harvester dos dados abertos do municipio.")

        actions.run(source)

        source.reload()
        job = source.get_last_job()
        assert job.status == "done", [error.message for error in job.errors]
        assert len(Dataset.objects) == 1

    def backend_warnings(self, caplog):
        return [
            record.getMessage()
            for record in caplog.records
            if record.name == BACKEND_LOGGER and record.levelno == logging.WARNING
        ]

    @pytest.mark.parametrize(
        ("description", "warns"),
        [
            ('{"geozones": ["pt:distrito:11"]}', True),  # config that no longer applies
            ('{"title": "Dados abertos"}', False),  # a JSON object, but never config
            ('{"license": ', False),  # a typo that never parsed, so never applied
            ("[1, 2]", False),
            ("2026", False),
        ],
    )
    def test_legacy_config_in_the_description_is_logged(self, caplog, description, warns):
        """Only a description that really was config gets a deprecation warning."""
        source = self.source(description)

        with caplog.at_level(logging.WARNING, logger=BACKEND_LOGGER):
            self.assert_previewed_one_item(actions.preview(source))

        warnings = self.backend_warnings(caplog)
        assert len(warnings) == (1 if warns else 0)
        if warns:
            assert str(source.id) in warnings[0]

    def test_warning_names_an_unsaved_source(self, caplog):
        """`preview_from_config` has no source id yet - the very path of this fix."""
        with caplog.at_level(logging.WARNING, logger=BACKEND_LOGGER):
            actions.preview_from_config(
                name="A new harvester",
                url=self.ckan_url,
                backend="ckanpt",
                description='{"license": "cc-by"}',
                organization=self.org,
            )

        warnings = self.backend_warnings(caplog)
        assert len(warnings) == 1
        assert "A new harvester" in warnings[0]
        assert "None" not in warnings[0]

    @pytest.mark.parametrize(
        ("description", "warns"),
        [
            # Decoded before the shape test, so bytes config still warns.
            (b'{"geozones": ["pt:distrito:11"]}', True),
            # Rendered by `safe_unicode` as "{'license': 1}", which is not JSON.
            ({"license": 1}, False),
            (True, False),
            (None, False),
        ],
    )
    def test_non_string_description_is_handled(self, caplog, description, warns):
        """A StringField, but a CLI or a migration can still put anything in it."""
        source = self.source("placeholder")
        source.description = description

        with caplog.at_level(logging.WARNING, logger=BACKEND_LOGGER):
            CkanPTBackend(source, dryrun=True)

        assert len(self.backend_warnings(caplog)) == (1 if warns else 0)

    # --- Behaviour now inherited from CkanBackend instead of duplicated (LEDG-2319)

    def test_remote_frequency_is_mapped(self):
        """The fork hardcoded `frequency = "unknown"` for every dataset it harvested."""
        self.package["result"]["extras"] = [{"key": "frequency", "value": "monthly"}]

        dataset = self.assert_previewed_one_item(actions.preview(self.source("")))

        assert dataset.frequency == "monthly"

    def test_remote_url_lands_on_harvest_metadata(self):
        """The fork wrote back the extras the 2022-10-10 migration had removed."""
        dataset = self.assert_previewed_one_item(actions.preview(self.source("")))

        assert dataset.harvest.remote_url == f"{self.ckan_url}/dataset/{DATASET_NAME}"
        assert dataset.harvest.ckan_name == DATASET_NAME
        assert "remote_url" not in dataset.extras
        assert "ckan:name" not in dataset.extras
        assert "harvest:name" not in dataset.extras

    def test_reharvest_preserves_a_license_set_on_the_portal(self):
        """Upstream keeps a stored license; the configured one is only a default."""
        configured = LicenseFactory()
        chosen = LicenseFactory()
        source = self.configured(license=configured.id)

        actions.run(source)
        dataset = Dataset.objects.first()
        assert dataset.license == configured
        dataset.license = chosen
        dataset.save()

        actions.run(source)

        dataset.reload()
        assert dataset.license == chosen

    # --- Behaviour that is genuinely PT and survives as an override

    def test_source_hostname_is_tagged(self):
        dataset = self.assert_previewed_one_item(actions.preview(self.source("")))

        assert "localhost" in dataset.tags

    def test_run_creates_an_unknown_organization(self):
        """Upstream never touches `dataset.organization`; this portal maps it."""
        self.package["result"]["organization"]["name"] = "brand-new-org"

        actions.run(self.source(""))

        assert Organization.objects(acronym="brand-new-org").count() == 1
        assert Dataset.objects.first().organization.acronym == "brand-new-org"

    def test_configured_geozones_win_over_the_remote_spatial_text(self):
        remote = GeoZoneFactory()
        configured = GeoZoneFactory()
        self.package["result"]["extras"] = [{"key": "spatial-text", "value": remote.name}]
        source = self.configured(geozones=configured.id)

        dataset = self.assert_previewed_one_item(actions.preview(source))

        assert [z.id for z in dataset.spatial.zones] == [configured.id]

    def test_resource_urls_are_slash_normalized(self):
        self.package["result"]["resources"][0]["url"] = "http://dados.example.pt//a//b.csv"

        dataset = self.assert_previewed_one_item(actions.preview(self.source("")))

        assert dataset.resources[0].url == "http://dados.example.pt/a/b.csv"

    def test_resources_dropped_at_source_are_pruned(self):
        """Upstream keeps every resource it ever harvested; this portal prunes."""
        source = self.source("")
        dropped = dict(
            self.package["result"]["resources"][0],
            id=faker.uuid4(),
            url=faker.unique_url(),
        )
        self.package["result"]["resources"].append(dropped)

        actions.run(source)
        dataset = Dataset.objects.first()
        assert len(dataset.resources) == 2
        kept_id = dataset.resources[0].id
        dataset.resources.append(
            Resource(title="Uploaded on the portal", url=faker.unique_url(), filetype="file")
        )
        dataset.save()

        self.package["result"]["resources"].remove(dropped)
        self.remote_returns_the_package()
        actions.run(source)

        dataset.reload()
        assert [r.id for r in dataset.resources if r.filetype == "remote"] == [kept_id]
        assert [r.title for r in dataset.resources if r.filetype == "file"] == [
            "Uploaded on the portal"
        ]

    def test_preview_does_not_prune_resources(self):
        """A preview reports what the source has; it does not act on it."""
        source = self.source("")
        actions.run(source)
        dataset = Dataset.objects.first()
        harvested_id = dataset.resources[0].id

        self.package["result"]["resources"] = [
            dict(self.package["result"]["resources"][0], id=faker.uuid4(), url=faker.unique_url())
        ]
        self.remote_returns_the_package()
        job = actions.preview(source)

        assert job.items[0].status == "done", [e.message for e in job.items[0].errors]
        assert harvested_id in [r.id for r in job.items[0].dataset.resources]
        dataset.reload()
        assert [r.id for r in dataset.resources] == [harvested_id]

    # --- The config is only type-checked, and a preview needs nothing but a login

    def test_many_unknown_geozones_produce_one_warning(self, caplog):
        """One log record whatever the input size.

        Warning per identifier let a 20k-entry value buy minutes of server time and
        a `HarvestJob` too big to save, from any authenticated account through
        `POST /harvest/source/preview/`. The single `id__in` query behind this is
        not observable from here; what is observable is that the log does not scale
        with the input.
        """
        zone = GeoZoneFactory()
        source = self.configured(
            geozones=",".join([zone.id] + [f"no-such-{i}" for i in range(200)])
        )

        with caplog.at_level(logging.WARNING, logger=BACKEND_LOGGER):
            zones = CkanPTBackend(source, dryrun=True).configured_geozones

        assert zones == [zone]
        warnings = self.backend_warnings(caplog)
        # One for the cap, one naming the unknown ones - not 200.
        assert len(warnings) == 2

    def test_geozones_are_capped(self, caplog):
        zones = [GeoZoneFactory() for _ in range(3)]
        source = self.configured(geozones=",".join(z.id for z in zones))

        with caplog.at_level(logging.WARNING, logger=BACKEND_LOGGER):
            with mock.patch.object(CkanPTBackend, "MAX_GEOZONES", 2):
                resolved = CkanPTBackend(source, dryrun=True).configured_geozones

        assert resolved == zones[:2]
        assert "keeping the first 2" in self.backend_warnings(caplog)[0]

    def test_repeated_geozones_are_deduplicated(self):
        zone = GeoZoneFactory()
        source = self.configured(geozones=f"{zone.id},{zone.id},{zone.id}")

        dataset = self.assert_previewed_one_item(actions.preview(source))

        assert [z.id for z in dataset.spatial.zones] == [zone.id]

    def test_a_non_string_geozones_value_is_ignored(self):
        """The form only type-checks; a CLI or a migration can write anything."""
        source = self.configured(geozones={"$ne": None})

        dataset = self.assert_previewed_one_item(actions.preview(source))

        assert dataset.spatial is None

    def test_an_unsaved_source_name_cannot_forge_a_log_line(self, caplog):
        """`source_label` falls back to the name, which is free text from the caller.

        These warnings are captured into `HarvestLog` and rendered in the admin job
        detail, so a newline in the name would show as a log entry of its own.
        """
        forged = "ok\nWARNING [udata.harvest] Harvest source approved by sysadmin"

        with caplog.at_level(logging.WARNING, logger=BACKEND_LOGGER):
            actions.preview_from_config(
                name=forged,
                url=self.ckan_url,
                backend="ckanpt",
                organization=self.org,
                config={"extra_configs": [{"key": "geozones", "value": "no-such-zone"}]},
            )

        warnings = self.backend_warnings(caplog)
        assert len(warnings) == 1
        assert "\n" not in warnings[0]
        assert "approved by sysadmin" in warnings[0]

    def test_a_remote_cannot_claim_an_uploaded_resource_to_get_it_pruned(self):
        """Upstream matches by id and sets `filetype = "remote"` on every match.

        So reading `filetype` after `super()` is too late: a remote publishing a
        resource whose id collides with a portal upload would have turned that
        upload into a harvested resource - the `/r/<id>` permalink serving remote
        content - and the next run would prune it.
        """
        source = self.source("")
        actions.run(source)
        dataset = Dataset.objects.first()
        uploaded = Resource(title="Uploaded on the portal", url=faker.unique_url(), filetype="file")
        dataset.resources.append(uploaded)
        dataset.save()

        # The remote claims the uploaded resource's id, then stops publishing it.
        self.package["result"]["resources"] = [
            dict(self.package["result"]["resources"][0], id=str(uploaded.id))
        ]
        self.remote_returns_the_package()
        actions.run(source)
        self.package["result"]["resources"] = [
            dict(self.package["result"]["resources"][0], id=faker.uuid4(), url=faker.unique_url())
        ]
        self.remote_returns_the_package()
        actions.run(source)

        dataset.reload()
        kept = {resource.id: resource for resource in dataset.resources}
        assert uploaded.id in kept
        assert kept[uploaded.id].filetype == "file"
        assert kept[uploaded.id].url == uploaded.url

    # --- What converging on upstream must not break

    def test_remote_dates_are_recorded(self):
        """`created_at_internal` drives `DEFAULT_SORTING` on the public listing.

        Upstream records the remote dates only on `harvest.created_at`, so without
        this override every newly harvested dataset would sort as published today.
        """
        self.package["result"]["metadata_created"] = "1999-05-27T00:00:00"
        self.package["result"]["metadata_modified"] = "2003-09-04T00:00:00"

        dataset = self.assert_previewed_one_item(actions.preview(self.source("")))

        assert dataset.created_at_internal.year == 1999
        assert dataset.last_modified_internal.year == 2003
        assert dataset.harvest.created_at.year == 1999

    @pytest.mark.parametrize(
        "geometry",
        [
            '{"type": "Point", "coordinates": [-9.1, 38.7]}',
            '{"coordinates": [[[0, 0], [1, 1], [1, 0], [0, 0]]]}',
            '{"type": "GeometryCollection", "geometries": []}',
        ],
    )
    def test_an_unsupported_remote_geometry_does_not_fail_the_item(self, caplog, geometry):
        """Upstream raises `HarvestException` for anything but Polygon/MultiPolygon.

        That fails the whole item - title, resources, configured zones and all - for
        datasets that have harvested here for years, because the fork parsed the
        value and threw it away.
        """
        self.package["result"]["extras"] = [{"key": "spatial", "value": geometry}]

        with caplog.at_level(logging.WARNING, logger=BACKEND_LOGGER):
            dataset = self.assert_previewed_one_item(actions.preview(self.source("")))

        assert dataset.title == self.package["result"]["title"]
        assert "unsupported spatial geometry" in self.backend_warnings(caplog)[0]

    def test_a_supported_remote_geometry_is_still_mapped(self):
        self.package["result"]["extras"] = [
            {
                "key": "spatial",
                "value": '{"type": "Polygon", "coordinates": [[[0, 0], [1, 1], [1, 0], [0, 0]]]}',
            }
        ]

        dataset = self.assert_previewed_one_item(actions.preview(self.source("")))

        assert dataset.spatial.geom["type"] == "MultiPolygon"

    def test_a_configured_zone_survives_an_unsupported_remote_geometry(self):
        """The zones override runs after `super()`, so a raise there loses them too."""
        zone = GeoZoneFactory()
        self.package["result"]["extras"] = [
            {"key": "spatial", "value": '{"type": "Point", "coordinates": [-9.1, 38.7]}'}
        ]

        dataset = self.assert_previewed_one_item(actions.preview(self.configured(geozones=zone.id)))

        assert [z.id for z in dataset.spatial.zones] == [zone.id]

    def test_stored_zones_survive_a_harvest_with_no_configured_zones(self):
        """The window between deploying this code and running the migration.

        A source whose config still lives in its description resolves no zones, and
        upstream - unlike the fork - rebuilds `dataset.spatial` from the remote
        extras. Without this the ~1100 datasets whose only spatial coverage came
        from that config would lose it, irreversibly.
        """
        zone = GeoZoneFactory()
        configured = self.configured(geozones=zone.id)
        actions.run(configured)
        dataset = Dataset.objects.first()
        assert [z.id for z in dataset.spatial.zones] == [zone.id]

        # Same source, config back in the description, and a remote that now
        # publishes a geometry of its own.
        configured.config = {}
        configured.description = json.dumps({"geozones": [zone.id]})
        configured.save()
        self.package["result"]["extras"] = [
            {
                "key": "spatial",
                "value": '{"type": "Polygon", "coordinates": [[[0, 0], [1, 1], [1, 0], [0, 0]]]}',
            }
        ]
        self.remote_returns_the_package()
        actions.run(configured)

        dataset.reload()
        assert [z.id for z in dataset.spatial.zones] == [zone.id]
        # Not merged with the remote geometry: `SpatialCoverage` refuses to hold
        # both, so keeping the zones means dropping the geometry.
        assert dataset.spatial.geom is None

    def test_the_remote_payload_is_not_reused_between_items(self):
        """`_remote_data` is stashed in `validate`; a stale stash must be impossible."""
        other_org = OrganizationFactory(acronym="second-org")
        second = ckanpt_package(other_org.acronym)["result"]
        second["name"] = "ckanpt-dataset-2"
        self.rmock.get(
            self.ckan.PACKAGE_LIST_URL,
            json={"success": True, "result": [DATASET_NAME, "ckanpt-dataset-2"]},
            status_code=200,
            headers={"Content-Type": "application/json"},
        )
        self.rmock.get(
            urljoin(self.ckan.PACKAGE_SHOW_URL, "?id=ckanpt-dataset-2"),
            json={"success": True, "result": second},
            status_code=200,
            headers={"Content-Type": "application/json"},
        )

        job = actions.preview(self.source(""))

        assert len(job.items) == 2
        by_title = {item.dataset.title: item.dataset for item in job.items}
        assert by_title[self.package["result"]["title"]].organization.acronym == "ckanpt-org"
        assert by_title[second["title"]].organization.acronym == "second-org"
        for item in job.items:
            assert len(item.dataset.resources) == 1

    def test_http_error_fails_the_item(self):
        """Inherited from upstream: `get_action` calls `raise_for_status`.

        The copy of `get_action` this backend used to carry had no
        `raise_for_status`, so a 5xx whose body happened to be a well-formed CKAN
        envelope was harvested as if it had succeeded.
        """
        self.rmock.get(
            self.ckan.PACKAGE_SHOW_URL,
            json=self.package,
            status_code=500,
            headers={"Content-Type": "application/json"},
        )

        job = actions.preview(self.source(""))

        assert len(job.items) == 1
        assert job.items[0].status == "failed"

    def test_preview_does_not_persist_an_unknown_organization(self):
        """A preview persists nothing, the organization mapping included.

        `inner_process_dataset` used to save the organization with no `dryrun`
        guard, so previewing a source whose remote organization was unknown created
        it for real - reachable by any authenticated account through the preview
        endpoint, which is a write primitive it was never meant to hand out.
        """
        self.package["result"]["organization"]["name"] = "brand-new-org"

        dataset = self.assert_previewed_one_item(actions.preview(self.source("")))

        assert Organization.objects(acronym="brand-new-org").count() == 0
        # The item is not left without an organization: `get_dataset` seeds a new
        # dataset with the one the source is attached to, and the guard leaves that
        # in place instead of overwriting it with an unknown remote.
        assert dataset.organization == self.org

    def test_preview_maps_a_known_organization(self):
        """The other half of the guard: an organization that exists is still mapped.

        Not writing in a preview must not degrade into not resolving at all - the
        item has to keep showing the organization the dataset would be filed under.
        """
        dataset = self.assert_previewed_one_item(actions.preview(self.source("")))

        assert dataset.organization == self.org

    def test_prose_description_is_not_logged(self, caplog):
        """Prose is the normal case: it must not log on every single run."""
        source = self.source("Harvester dos dados abertos do municipio.")

        with caplog.at_level(logging.WARNING, logger=BACKEND_LOGGER):
            self.assert_previewed_one_item(actions.preview(source))

        assert self.backend_warnings(caplog) == []
