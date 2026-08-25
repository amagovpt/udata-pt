"""Tests for the OpenDataSoft PT backend.

Only the organization mapping is covered here: it is the one place this backend
writes to the database on its own, outside what `BaseBackend` already guards.
"""

import pytest

from udata.core.organization.factories import OrganizationFactory
from udata.models import Organization
from udata.tests.api import PytestOnlyDBTestCase

from ..backends.odspt import OdsBackendPT
from .factories import HarvestSourceFactory

ODS_URL = "https://transparencia.example.pt"
SEARCH_URL = "{0}/api/datasets/1.0/search/".format(ODS_URL)


def _ods_payload(publisher):
    """The smallest ODS search response `inner_process_dataset` will accept."""
    return {
        "nhits": 1,
        "datasets": [
            {
                "datasetid": "ods-dataset",
                "has_records": True,
                "features": [],
                "fields": [],
                "metas": {
                    "title": "Dataset A",
                    "publisher": publisher,
                    "modified": "2026-01-01T00:00:00+00:00",
                    "records_count": 1,
                },
            }
        ],
    }


@pytest.mark.options(HARVESTER_BACKENDS=["odspt"])
class OdsBackendPTOrganizationTest(PytestOnlyDBTestCase):
    def _source(self):
        # No organization on the source: `get_dataset` then leaves the field empty,
        # so what the backend does with the remote publisher is what is under test.
        return HarvestSourceFactory(backend="odspt", url=ODS_URL, organization=None, owner=None)

    def test_preview_does_not_persist_an_unknown_publisher(self, rmock):
        """A preview persists nothing, the organization mapping included.

        The backend used to create and save the publisher with no `dryrun` guard,
        which the preview endpoint made reachable by any authenticated account.
        """
        rmock.get(SEARCH_URL, json=_ods_payload("brand-new-org"))

        job = OdsBackendPT(self._source(), dryrun=True).harvest()

        assert [item.status for item in job.items] == ["done"]
        assert Organization.objects(acronym="brand-new-org").count() == 0
        assert job.items[0].dataset.organization is None

    def test_preview_says_an_unknown_publisher_would_be_created(self, rmock):
        """The gap between preview and run is logged onto the item, not swallowed."""
        rmock.get(SEARCH_URL, json=_ods_payload("brand-new-org"))

        job = OdsBackendPT(self._source(), dryrun=True).harvest()

        messages = [entry.message for entry in job.items[0].logs]
        assert any("brand-new-org" in message for message in messages), messages

    def test_preview_maps_a_known_publisher(self, rmock):
        """Not writing must not degrade into not resolving at all."""
        org = OrganizationFactory(acronym="known-org")
        rmock.get(SEARCH_URL, json=_ods_payload("known-org"))

        job = OdsBackendPT(self._source(), dryrun=True).harvest()

        assert job.items[0].dataset.organization == org

    def test_run_creates_an_unknown_publisher(self, rmock):
        """A real harvest keeps creating the organization, as before."""
        rmock.get(SEARCH_URL, json=_ods_payload("brand-new-org"))

        job = OdsBackendPT(self._source()).harvest()

        assert [item.status for item in job.items] == ["done"]
        assert Organization.objects(acronym="brand-new-org").count() == 1
        assert job.items[0].dataset.organization.acronym == "brand-new-org"
