"""Tests for the OpenDataSoft PT backend."""

import copy
import json
import os
from datetime import UTC, datetime, timedelta

import pytest

from udata.core.dataset.constants import UpdateFrequency
from udata.core.dataset.factories import LicenseFactory
from udata.core.organization.factories import OrganizationFactory
from udata.models import License, Organization
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

    @pytest.mark.parametrize(
        "published, expected",
        [
            # The deltas tie on each of these pairs; the order of the parts must not
            # decide.
            ("Anual | Semestral", UpdateFrequency.SEMIANNUAL),
            ("Semestral | Anual", UpdateFrequency.SEMIANNUAL),
            ("Anual | Quadrimestral", UpdateFrequency.THREE_TIMES_A_YEAR),
            ("Quadrimestral | Anual", UpdateFrequency.THREE_TIMES_A_YEAR),
            ("Semanal | Mensal", UpdateFrequency.WEEKLY),
        ],
    )
    def test_a_combination_does_not_depend_on_the_order_of_its_parts(self, published, expected):
        assert OdsBackendPT._frequency(published) == expected

    @pytest.mark.parametrize("published", [None, "", "Quando calha", "|", 42])
    def test_no_usable_value_is_unknown(self, published):
        assert OdsBackendPT._frequency(published) == UpdateFrequency.UNKNOWN

    def test_a_dataset_without_the_field_is_unknown(self, rmock):
        dataset = self.harvest(rmock, _sns_payload(dcat={"accrualperiodicity": None}))
        assert dataset.frequency == UpdateFrequency.UNKNOWN


class OdsBackendPTLicenseTest(OdsBackendPTSnsTestCase):
    """The source publishes no licence, so the default stands."""

    def test_a_null_license_keeps_the_default(self, rmock):
        LicenseFactory(id="notspecified", title="License Not Specified", url=None)
        LicenseFactory(id="cc-by", title="Creative Commons Attribution", url=None)
        assert "license" not in SNS_DATASET["metas"]

        dataset = self.harvest(rmock)

        assert dataset.license is not None
        assert dataset.license == License.default()
        assert not hasattr(OdsBackendPT, "LICENSES")

    def test_a_published_license_is_still_guessed(self, rmock):
        LicenseFactory(id="notspecified", title="License Not Specified", url=None)
        LicenseFactory(id="cc-by", title="Creative Commons Attribution", url=None)

        dataset = self.harvest(rmock, _sns_payload(license="cc-by"))

        assert dataset.license.id == "cc-by"


class OdsBackendPTDatesTest(OdsBackendPTSnsTestCase):
    """`dcat.created` and `dcat.issued` become the dataset's dates."""

    def test_the_dcat_dates_land_on_the_harvest_metadata_and_the_listing_date(self, rmock):
        # As recorded: created 2016-01-24, issued 2018-12-31.
        dataset = self.harvest(rmock)
        assert dataset.harvest.created_at == datetime(2016, 1, 24)
        assert dataset.harvest.issued_at == datetime(2018, 12, 31)
        assert dataset.created_at == datetime(2018, 12, 31)
        # What `DEFAULT_SORTING` sorts the public listing on.
        assert dataset.created_at_internal == dataset.created_at

    def test_created_stands_in_without_issued(self, rmock):
        dataset = self.harvest(rmock, _sns_payload(dcat={"issued": None}))
        assert dataset.harvest.issued_at is None
        assert dataset.created_at_internal == datetime(2016, 1, 24)

    def test_no_dates_leave_the_listing_date_alone(self, rmock):
        before = datetime.now(UTC) - timedelta(minutes=1)
        dataset = self.harvest(rmock, _sns_payload(dcat={"created": None, "issued": None}))
        assert dataset.harvest.created_at is None
        assert dataset.created_at_internal > before

    @pytest.mark.parametrize("published", ["não é uma data", "1623715200000"])
    def test_an_unreadable_date_does_not_fail_the_item(self, rmock, published):
        dataset = self.harvest(rmock, _sns_payload(dcat={"issued": published}))
        assert dataset.harvest.issued_at is None
        assert dataset.created_at_internal == datetime(2016, 1, 24)

    @pytest.mark.parametrize("published", [20181231, ["2018-12-31"], {"date": "2018"}])
    def test_a_date_that_is_not_text_does_not_fail_the_item(self, rmock, published):
        dataset = self.harvest(rmock, _sns_payload(dcat={"issued": published}))
        assert dataset.harvest.issued_at is None
        assert dataset.created_at_internal == datetime(2016, 1, 24)

    def test_a_future_date_is_refused(self, rmock):
        ahead = (datetime.now(UTC) + timedelta(days=365)).isoformat()
        dataset = self.harvest(rmock, _sns_payload(dcat={"issued": ahead}))
        assert dataset.harvest.issued_at is None

    def test_the_dates_survive_a_re_harvest(self, rmock):
        source = HarvestSourceFactory(backend="odspt", url=ODS_URL, organization=None, owner=None)
        self.harvest(rmock, source=source)
        dataset = self.harvest(rmock, source=source)
        assert dataset.harvest.issued_at == datetime(2018, 12, 31)
        assert dataset.created_at_internal == datetime(2018, 12, 31)


class OdsBackendPTDcatExtrasTest(OdsBackendPTSnsTestCase):
    """Authorship and coverage text into the extras, `metas.bbox` into the coverage."""

    def test_creator_contributor_and_spatial_text_reach_the_extras(self, rmock):
        # As recorded: creator ACSS, contributor SPMS, "Portugal Continental".
        dataset = self.harvest(rmock)
        assert dataset.extras["ods:creator"] == "ACSS"
        assert dataset.extras["ods:contributor"] == "SPMS"
        assert dataset.extras["ods:spatial"] == "Portugal Continental"
        # Prose, deliberately not parsed nor kept.
        assert "ods:temporal" not in dataset.extras
        assert dataset.temporal_coverage is None

    def test_markup_is_stripped_from_the_extras(self, rmock):
        payload = _sns_payload(dcat={"creator": "<script>alert(1)</script><b>ACSS</b>"})
        dataset = self.harvest(rmock, payload)
        # `sanitize_strict` drops the tags and keeps their text.
        assert "<" not in dataset.extras["ods:creator"]
        assert dataset.extras["ods:creator"].endswith("ACSS")

    def test_an_extra_the_source_stops_publishing_is_removed(self, rmock):
        source = HarvestSourceFactory(backend="odspt", url=ODS_URL, organization=None, owner=None)
        self.harvest(rmock, source=source)
        dataset = self.harvest(rmock, _sns_payload(dcat={"contributor": None}), source=source)
        assert "ods:contributor" not in dataset.extras

    def test_the_bbox_becomes_the_spatial_coverage(self, rmock):
        dataset = self.harvest(rmock)
        assert dataset.spatial.geom["type"] == "MultiPolygon"
        (ring,) = dataset.spatial.geom["coordinates"][0]
        # The envelope of the recorded polygon, `[minx, miny]` first.
        assert ring[0] == [-9.418267076835036, 37.02389728277922]
        assert ring[2] == [-6.768198050558567, 41.80565318092704]

    def test_no_bbox_yields_no_coverage(self, rmock):
        dataset = self.harvest(rmock, _sns_payload(bbox=None))
        assert dataset.spatial is None

    @pytest.mark.parametrize(
        "bbox",
        [
            "lixo",
            {"type": "Point", "coordinates": [-9.1, 38.7]},
            {"type": "Polygon", "coordinates": [[["a", "b"]]]},
            {"type": "Polygon", "coordinates": [[[-120000, -300000], [165000, 280000]]]},
        ],
    )
    def test_an_unusable_bbox_does_not_fail_the_item(self, rmock, bbox):
        dataset = self.harvest(rmock, _sns_payload(bbox=bbox))
        assert dataset.spatial is None
