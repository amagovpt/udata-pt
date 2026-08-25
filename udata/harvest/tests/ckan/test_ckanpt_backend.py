"""Tests for the CKAN PT backend.

Two concerns live here. The harvest config (`license`, `geozones`) that this
backend carries as a JSON blob in the source description, a free-text field in the
UI where anything that is not a JSON object means "no config" - in a preview
(`dryrun=True`) exactly as in a real harvest (LEDG-2315). And the behaviour the
backend now inherits from `CkanBackend` instead of duplicating it (LEDG-2319).
"""

import json
import logging
from urllib.parse import urljoin

import pytest

from udata.core.dataset.factories import LicenseFactory
from udata.core.organization.factories import OrganizationFactory
from udata.core.spatial.factories import GeoZoneFactory
from udata.harvest import actions
from udata.harvest.backends.ckanpt import CkanPTBackend
from udata.harvest.tests.factories import HarvestSourceFactory
from udata.models import Dataset, Organization
from udata.tests.api import PytestOnlyDBTestCase
from udata.utils import faker

DATASET_NAME = "ckanpt-dataset"
BACKEND_LOGGER = "udata.harvest.backends.ckanpt"


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
class CkanPTHarvestConfigTest(PytestOnlyDBTestCase):
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
        "description",
        [b'{"geozones": ["pt:distrito:11"]}', {"license": 1}, True, None],
    )
    def test_non_string_description_is_handled(self, description):
        """A StringField, but a CLI or a migration can still put anything in it."""
        source = self.source("placeholder")
        source.description = description

        backend = CkanPTBackend(source, dryrun=True)

        assert backend.configured_geozones == []

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

    def test_preview_persists_an_unknown_organization(self):
        """Characterisation, not an endorsement: a preview should persist nothing.

        `inner_process_dataset` saves the organization with no `dryrun` guard, so
        previewing a source whose remote organization is unknown creates it for
        real. Pre-existing and out of scope here (it is not about the description
        being JSON), but the assertion above only holds because the fixture
        pre-creates the organization - so it is documented rather than implied.
        """
        self.package["result"]["organization"]["name"] = "brand-new-org"

        actions.preview(self.source(""))

        assert Organization.objects(acronym="brand-new-org").count() == 1

    def test_prose_description_is_not_logged(self, caplog):
        """Prose is the normal case: it must not log on every single run."""
        source = self.source("Harvester dos dados abertos do municipio.")

        with caplog.at_level(logging.WARNING, logger=BACKEND_LOGGER):
            self.assert_previewed_one_item(actions.preview(source))

        assert self.backend_warnings(caplog) == []
