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

        # Asserted at WARNING on purpose: `init_logging` pins the app logger, which
        # the collector hangs off, at WARNING outside debug and testing.
        entries = [entry for entry in job.items[0].logs if "brand-new-org" in entry.message]
        assert entries, [entry.message for entry in job.items[0].logs]
        assert [entry.level for entry in entries] == ["WARNING"]

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


CREDENTIALED_ODS_URL = "https://harvestuser:sup3rs3cr3t@transparencia.example.pt"
CREDENTIALED_SEARCH_URL = "{0}/api/datasets/1.0/search/".format(CREDENTIALED_ODS_URL)
REDACTED_ODS_URL = "https://***@transparencia.example.pt"


def _ods_payload_with_attachment(publisher):
    """The same minimal payload, plus one attachment to exercise `extra_file_url`."""
    payload = _ods_payload(publisher)
    payload["datasets"][0]["attachments"] = [
        {
            "id": "att-1",
            "title": "Notice",
            "description": "A note",
            "mimetype": "application/pdf",
            "url": "odsfile://notice.pdf",
        }
    ]
    return payload


@pytest.mark.options(HARVESTER_BACKENDS=["odspt"])
class OdsBackendPTCredentialedSourceTest(PytestOnlyDBTestCase):
    """A source URL carrying `user:password@` must not reach what is published.

    `URLS_ALLOW_CREDENTIALS` is true, so a source that needs basic auth really
    is configured that way. The resource URLs and `extras["ods:url"]` this
    backend derives from it are read without a session, and `/r/<id>` would
    even fetch the file with those credentials on an anonymous caller's behalf
    (LEDG-2500).
    """

    def _source(self):
        return HarvestSourceFactory(
            backend="odspt", url=CREDENTIALED_ODS_URL, organization=None, owner=None
        )

    def test_public_urls_carry_no_credentials_while_the_fetch_keeps_them(self, rmock):
        # Registered on the credentialed URL on purpose: `requests` keeps the
        # userinfo in the prepared URL and `requests_mock` matches the whole
        # netloc, so a plain registration would not match the real request.
        rmock.get(CREDENTIALED_SEARCH_URL, json=_ods_payload_with_attachment("brand-new-org"))

        job = OdsBackendPT(self._source()).harvest()

        assert [item.status for item in job.items] == ["done"], [
            error.message for item in job.items for error in item.errors
        ]
        dataset = job.items[0].dataset
        assert dataset.resources, "the payload should have produced resources"
        for resource in dataset.resources:
            assert "sup3rs3cr3t" not in resource.url
            assert "harvestuser" not in resource.url
            assert resource.url.startswith(REDACTED_ODS_URL)
        assert dataset.extras["ods:url"] == "{0}/explore/dataset/ods-dataset/".format(
            REDACTED_ODS_URL
        )
        # The attachment goes through `extra_file_url`, a different code path
        # from the exports, so assert it was actually among them.
        assert any(
            resource.url.startswith("{0}/api/datasets/1.0/".format(REDACTED_ODS_URL))
            for resource in dataset.resources
        )
        # The harvest itself still authenticates: redacting what is published
        # must not cost the fetch its credentials. Asserted non-vacuously --
        # `all(...)` over an empty history would pass on its own.
        assert rmock.request_history
        assert all("harvestuser" in request.url for request in rmock.request_history)

    def test_reharvest_matches_resources_by_their_redacted_url(self, rmock):
        """`get_resource` matches on the stored URL, which is now the redacted one."""
        rmock.get(CREDENTIALED_SEARCH_URL, json=_ods_payload_with_attachment("brand-new-org"))
        source = self._source()

        first = OdsBackendPT(source).harvest()
        before = [(resource.id, resource.url) for resource in first.items[0].dataset.resources]

        second = OdsBackendPT(source).harvest()
        after = [(resource.id, resource.url) for resource in second.items[0].dataset.resources]

        assert after == before
