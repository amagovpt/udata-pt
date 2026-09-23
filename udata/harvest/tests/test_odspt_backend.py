"""Tests for the OpenDataSoft PT backend."""

import copy
import json
import os

import pytest

from udata.core.dataset.constants import UpdateFrequency
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


# One dataset recorded verbatim from `transparencia.sns.gov.pt` on 2026-09-23, via
# `/api/datasets/1.0/search/?rows=1&interopmetas=true&refine.datasetid=...`. Chosen
# among the 44 of 144 that carry `bbox`, `dcat.created`, `dcat.issued`,
# `dcat.accrualperiodicity`, `dcat.creator`, `dcat.contributor` and `dcat.spatial`
# together, so one record exercises every field the backend reads from the source.
SNS_DATASET_PATH = os.path.join(os.path.dirname(__file__), "odspt", "sns_dataset.json")
with open(SNS_DATASET_PATH, encoding="utf-8") as fh:
    SNS_PAYLOAD = json.load(fh)
SNS_DATASET = SNS_PAYLOAD["datasets"][0]
SNS_DATASET_ID = SNS_DATASET["datasetid"]


def _sns_payload(dcat=None, **metas):
    """The recorded payload, with `dcat` and `metas` fields overridden.

    A value of `None` removes the field instead.
    """
    payload = copy.deepcopy(SNS_PAYLOAD)
    dataset = payload["datasets"][0]
    for block, overrides in (
        (dataset["interop_metas"]["dcat"], dcat or {}),
        (dataset["metas"], metas),
    ):
        for key, value in overrides.items():
            if value is None:
                block.pop(key, None)
            else:
                block[key] = value
    return payload


@pytest.mark.options(HARVESTER_BACKENDS=["odspt"])
class OdsBackendPTSnsTestCase(PytestOnlyDBTestCase):
    """Harvests the recorded SNS dataset through the real search endpoint."""

    def harvest(self, rmock, payload=None, source=None):
        rmock.get(SEARCH_URL, json=payload or _sns_payload())
        source = source or HarvestSourceFactory(
            backend="odspt", url=ODS_URL, organization=None, owner=None
        )
        job = OdsBackendPT(source).harvest()
        assert [item.status for item in job.items] == ["done"], [
            error.message for item in job.items for error in item.errors
        ]
        return job.items[0].dataset


# Every distinct `dcat.accrualperiodicity` among the 144 SNS datasets on 2026-09-23,
# spelled exactly as published -- trailing spaces and doubled spaces included.
OBSERVED_ODS_PERIODICITIES = {
    "Mensal": UpdateFrequency.MONTHLY,
    "Mensal ": UpdateFrequency.MONTHLY,
    "monthly": UpdateFrequency.MONTHLY,
    "Diária": UpdateFrequency.DAILY,
    "Diaria": UpdateFrequency.DAILY,
    "Diário": UpdateFrequency.DAILY,
    "Diário (novembro a março)": UpdateFrequency.DAILY,
    "Diária (dias úteis)": UpdateFrequency.DAILY,
    "Anual": UpdateFrequency.ANNUAL,
    "annual": UpdateFrequency.ANNUAL,
    "Trimestral": UpdateFrequency.QUARTERLY,
    "Semestral": UpdateFrequency.SEMIANNUAL,
    "Quinzenal": UpdateFrequency.BIWEEKLY,
    # Combinations resolve to the most frequent of their parts.
    "Anual | Mensal": UpdateFrequency.MONTHLY,
    "Anual | Mensal ": UpdateFrequency.MONTHLY,
    "Anual | Trimestral": UpdateFrequency.QUARTERLY,
    "Trimestral | Mensal": UpdateFrequency.MONTHLY,
    "Quadrimestral  | Mensal": UpdateFrequency.MONTHLY,
    "Mensal | Semestral": UpdateFrequency.MONTHLY,
    "Semestral | Mensal": UpdateFrequency.MONTHLY,
}


class OdsBackendPTFrequencyTest(OdsBackendPTSnsTestCase):
    """`dcat.accrualperiodicity` becomes the dataset's frequency."""

    def test_mensal_maps_to_monthly(self, rmock):
        # What the recorded dataset publishes.
        assert SNS_DATASET["interop_metas"]["dcat"]["accrualperiodicity"] == "Mensal"
        assert self.harvest(rmock).frequency == UpdateFrequency.MONTHLY

    def test_every_observed_value_maps_off_unknown(self):
        """The whole of what the source publishes, and none of it lands on UNKNOWN."""
        assert len(OBSERVED_ODS_PERIODICITIES) == 20  # + one dataset without a value
        for published, expected in OBSERVED_ODS_PERIODICITIES.items():
            frequency = OdsBackendPT._frequency(published)
            assert frequency == expected, published
            assert frequency != UpdateFrequency.UNKNOWN, published

    def test_quadrimestral_alone_is_three_times_a_year(self):
        assert OdsBackendPT._frequency("Quadrimestral") == UpdateFrequency.THREE_TIMES_A_YEAR

    def test_a_part_with_no_period_only_counts_alone(self):
        assert OdsBackendPT._frequency("Ocasional | Anual") == UpdateFrequency.ANNUAL
        assert OdsBackendPT._frequency("Ocasional") == UpdateFrequency.IRREGULAR

    @pytest.mark.parametrize("published", [None, "", "Quando calha", "|", 42])
    def test_no_usable_value_is_unknown(self, published):
        assert OdsBackendPT._frequency(published) == UpdateFrequency.UNKNOWN

    def test_a_dataset_without_the_field_is_unknown(self, rmock):
        dataset = self.harvest(rmock, _sns_payload(dcat={"accrualperiodicity": None}))
        assert dataset.frequency == UpdateFrequency.UNKNOWN
