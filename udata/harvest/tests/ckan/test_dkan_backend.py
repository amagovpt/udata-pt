import json
import os
from datetime import datetime

import pytest

from udata.core.organization.factories import OrganizationFactory
from udata.harvest import actions
from udata.harvest.tests.factories import HarvestSourceFactory
from udata.models import Dataset
from udata.tests.api import PytestOnlyDBTestCase


def data_path(filename):
    """Get a test data path"""
    return os.path.join(os.path.dirname(__file__), "data", filename)


@pytest.mark.options(HARVESTER_BACKENDS=["dkan"])
class DkanBackendTest(PytestOnlyDBTestCase):
    def test_dkan_french_w_license(self, rmock):
        """CKAN Harvester should accept the minimum dataset payload"""
        DKAN_URL = "https://harvest.me/"
        API_URL = "{}api/3/action/".format(DKAN_URL)
        PACKAGE_LIST_URL = "{}package_list".format(API_URL)
        PACKAGE_SHOW_URL = "{}package_show".format(API_URL)

        with open(data_path("dkan-french-w-license.json")) as ifile:
            data = json.loads(ifile.read())

        org = OrganizationFactory()
        source = HarvestSourceFactory(backend="dkan", url=DKAN_URL, organization=org)
        rmock.get(
            PACKAGE_LIST_URL,
            json={"success": True, "result": ["fake-name"]},
            status_code=200,
            headers={"Content-Type": "application/json"},
        )
        rmock.get(
            PACKAGE_SHOW_URL,
            json=data,
            status_code=200,
            headers={"Content-Type": "application/json"},
        )
        actions.run(source)
        source.reload()
        assert source.get_last_job().status == "done"

        datasets = Dataset.objects.filter(organization=org)
        assert len(datasets) > 0

        dataset = datasets.get(**{"harvest__remote_id": "04be6288-696d-4331-850d-a144871a7e3a"})
        assert dataset.harvest.created_at == datetime(2019, 12, 10, 0, 0)
        assert dataset.harvest.modified_at is None
        assert len(dataset.resources) == 2
        assert "xlsx" in [r.format for r in dataset.resources]


CREDENTIALED_DKAN_URL = "https://harvestuser:sup3rs3cr3t@harvest.me"
REDACTED_DKAN_URL = "https://***@harvest.me"


@pytest.mark.options(HARVESTER_BACKENDS=["dkan"])
class DkanCredentialedSourceTest(PytestOnlyDBTestCase):
    """`dkan` subclasses `CkanBackend` without overriding `dataset_url`.

    That inheritance is why LEDG-2504 covers three backends and not two, and
    asserting it here is what stops a future `DkanBackend.dataset_url` override
    from quietly reintroducing the leak.
    """

    def test_dkan_inherits_the_redaction_and_still_authenticates(self, rmock):
        api_url = "{}/api/3/action/".format(CREDENTIALED_DKAN_URL)
        with open(data_path("dkan-french-w-license.json")) as ifile:
            data = json.loads(ifile.read())
        # This fixture wraps its package in a list, as DKAN's package_show does.
        package = data["result"][0]
        name = package["name"]
        # The fixture declares its own `url`, which would override `remote_url`
        # and leave `dataset_url()` -- the path under test -- unexercised.
        package.pop("url", None)

        org = OrganizationFactory()
        source = HarvestSourceFactory(backend="dkan", url=CREDENTIALED_DKAN_URL, organization=org)
        # Registered on the credentialed URL on purpose: `requests` keeps the
        # userinfo in the prepared URL and `requests_mock` matches the whole
        # netloc, so a plain registration would not match the real request.
        rmock.get(
            "{}package_list".format(api_url),
            json={"success": True, "result": [name]},
            status_code=200,
            headers={"Content-Type": "application/json"},
        )
        rmock.get(
            "{}package_show".format(api_url),
            json=data,
            status_code=200,
            headers={"Content-Type": "application/json"},
        )

        actions.run(source)
        source.reload()

        job = source.get_last_job()
        assert [item.status for item in job.items] == ["done"], [
            error.message for item in job.items for error in item.errors
        ]
        dataset = job.items[0].dataset
        assert dataset.harvest.remote_url.startswith(REDACTED_DKAN_URL)
        assert "sup3rs3cr3t" not in str(dataset.to_mongo())
        assert "harvestuser" not in str(dataset.to_mongo())
        # The fetch keeps the credentials; asserted non-vacuously.
        action_requests = [r for r in rmock.request_history if "/api/3/action/" in r.url]
        assert action_requests
        assert all("harvestuser" in request.url for request in action_requests)
