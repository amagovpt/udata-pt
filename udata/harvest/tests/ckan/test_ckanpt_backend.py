"""Harvest config parsing for the CKAN PT backend (LEDG-2315).

This backend carries its optional config (`license`, `geozones`) as a JSON blob in
the source description, which is a free-text field in the UI. Anything that is not
a JSON object means "no config" - in a preview (`dryrun=True`) exactly as in a real
harvest.
"""

import json

import pytest

from udata.core.organization.factories import OrganizationFactory
from udata.core.spatial.factories import GeoZoneFactory
from udata.harvest import actions
from udata.harvest.tests.factories import HarvestSourceFactory
from udata.models import Dataset
from udata.tests.api import PytestOnlyDBTestCase
from udata.utils import faker

DATASET_NAME = "ckanpt-dataset"


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

    def source(self, description):
        return HarvestSourceFactory(
            backend="ckanpt",
            url=self.ckan_url,
            description=description,
            organization=self.org,
        )

    def assert_previewed_one_item(self, job):
        assert job.status == "done", [error.message for error in job.errors]
        assert job.errors == []
        assert len(job.items) == 1
        item = job.items[0]
        assert item.status == "done", [error.message for error in item.errors]
        assert item.dataset is not None
        # A preview must not persist anything.
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

    def test_preview_with_malformed_json_description(self):
        self.assert_previewed_one_item(actions.preview(self.source('{"license": ')))

    def test_preview_with_json_description(self):
        """A valid JSON description still feeds `harvest_config`."""
        zone = GeoZoneFactory()
        source = self.source(json.dumps({"geozones": [zone.id]}))

        dataset = self.assert_previewed_one_item(actions.preview(source))

        assert [z.id for z in dataset.spatial.zones] == [zone.id]

    def test_run_with_json_description(self):
        """The real harvest keeps honouring a valid JSON config."""
        zone = GeoZoneFactory()
        source = self.source(json.dumps({"geozones": [zone.id]}))

        actions.run(source)

        source.reload()
        job = source.get_last_job()
        assert job.status == "done", [error.message for error in job.errors]
        dataset = Dataset.objects.get(id=job.items[0].dataset.id)
        assert [z.id for z in dataset.spatial.zones] == [zone.id]

    def test_run_with_prose_description(self):
        source = self.source("Harvester dos dados abertos do municipio.")

        actions.run(source)

        source.reload()
        job = source.get_last_job()
        assert job.status == "done", [error.message for error in job.errors]
        assert len(Dataset.objects) == 1
