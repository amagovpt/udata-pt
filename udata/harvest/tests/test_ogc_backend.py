import json
import logging
import os
from datetime import date

import pytest

from udata.core.dataset.factories import LicenseFactory
from udata.core.dataset.models import Resource
from udata.core.organization.factories import OrganizationFactory
from udata.models import ContactPoint, Dataset
from udata.tests.api import PytestOnlyDBTestCase

from ..backends.ogc import OGCBackend
from ..models import HarvestJob
from .factories import HarvestSourceFactory

OGC_URL = "https://geoportal.example.pt/ogc-api/collections?f=jsonld"


def _ogc_payload(items):
    return json.dumps({"dataset": items})


def _item(remote_id, name, keywords):
    return {
        "@id": remote_id,
        "name": name,
        "description": "desc",
        "keywords": keywords,
        "distribution": [],
    }


class OGCBackendFilterTest(PytestOnlyDBTestCase):
    def _backend(self, filters=None):
        config = {"filters": filters} if filters is not None else {}
        source = HarvestSourceFactory(backend="ogc", config=config)
        return OGCBackend(source)

    def test_tags_filter_is_declared(self):
        keys = [f.key for f in OGCBackend.filters]
        assert "tags" in keys

    def test_no_filters_matches_everything(self):
        backend = self._backend()
        assert backend._matches_filters(["geo", "transport"])
        assert backend._matches_filters([])

    def test_include_filter_keeps_matching_only(self):
        backend = self._backend([{"key": "tags", "value": "geo", "type": "include"}])
        assert backend._matches_filters(["geo", "transport"])
        assert not backend._matches_filters(["transport"])
        assert not backend._matches_filters([])

    def test_include_is_the_default_mode(self):
        # A filter without an explicit "type" behaves as include.
        backend = self._backend([{"key": "tags", "value": "geo"}])
        assert backend._matches_filters(["geo"])
        assert not backend._matches_filters(["transport"])

    def test_exclude_filter_drops_matching(self):
        backend = self._backend([{"key": "tags", "value": "geo", "type": "exclude"}])
        assert not backend._matches_filters(["geo", "transport"])
        assert backend._matches_filters(["transport"])

    def test_filter_is_case_insensitive(self):
        backend = self._backend([{"key": "tags", "value": "Geo", "type": "include"}])
        assert backend._matches_filters(["GEO"])

    def test_string_keywords_are_supported(self):
        backend = self._backend([{"key": "tags", "value": "geo", "type": "include"}])
        assert backend._matches_filters("geo")
        assert not backend._matches_filters("transport")

    def test_multiple_include_filters_require_all(self):
        backend = self._backend(
            [
                {"key": "tags", "value": "geo", "type": "include"},
                {"key": "tags", "value": "transport", "type": "include"},
            ]
        )
        assert backend._matches_filters(["geo", "transport"])
        assert not backend._matches_filters(["geo"])

    def test_blank_filter_value_is_ignored(self):
        backend = self._backend([{"key": "tags", "value": "", "type": "include"}])
        assert backend._matches_filters([])
        assert backend._matches_filters(["geo"])


@pytest.mark.options(HARVESTER_BACKENDS=["ogc"])
class OGCBackendHarvestTest(PytestOnlyDBTestCase):
    def test_harvest_applies_include_tags_filter(self, rmock):
        payload = _ogc_payload(
            [
                _item("a", "Dataset A", ["geo", "dados.gov"]),
                _item("b", "Dataset B", ["transport"]),
                _item("c", "Dataset C", ["dados.gov"]),
            ]
        )
        rmock.get(OGC_URL, text=payload)
        source = HarvestSourceFactory(
            backend="ogc",
            url=OGC_URL,
            config={"filters": [{"key": "tags", "value": "dados.gov", "type": "include"}]},
        )

        job = OGCBackend(source).harvest()

        remote_ids = {item.remote_id for item in job.items}
        assert remote_ids == {"a", "c"}

    def test_harvest_applies_exclude_tags_filter(self, rmock):
        payload = _ogc_payload(
            [
                _item("a", "Dataset A", ["dados.gov"]),
                _item("b", "Dataset B", ["transport"]),
            ]
        )
        rmock.get(OGC_URL, text=payload)
        source = HarvestSourceFactory(
            backend="ogc",
            url=OGC_URL,
            config={"filters": [{"key": "tags", "value": "dados.gov", "type": "exclude"}]},
        )

        job = OGCBackend(source).harvest()

        remote_ids = {item.remote_id for item in job.items}
        assert remote_ids == {"b"}

    def test_harvest_without_filter_keeps_all(self, rmock):
        payload = _ogc_payload(
            [
                _item("a", "Dataset A", ["geo"]),
                _item("b", "Dataset B", ["transport"]),
            ]
        )
        rmock.get(OGC_URL, text=payload)
        source = HarvestSourceFactory(backend="ogc", url=OGC_URL, config={})

        job = OGCBackend(source).harvest()

        remote_ids = {item.remote_id for item in job.items}
        assert remote_ids == {"a", "b"}


GEOJSON_URL = "https://geoportal.example.pt/collections/a/items?f=json"
CSV_URL = "https://geoportal.example.pt/collections/a/items.csv"


def _distribution(url, encoding_format, description="Items as GeoJSON"):
    # The real source leaves `name` unset and labels its distributions through
    # `description`, so the fixture does the same. The default is one of the
    # labels the backend catalogues, which is what every test that does not care
    # about the selection needs in order to get a resource at all.
    return {"contentURL": url, "encodingFormat": encoding_format, "description": description}


def _item_with_distributions(distributions, name="Dataset A"):
    item = _item("a", name, ["geo"])
    item["distribution"] = distributions
    return item


@pytest.mark.options(HARVESTER_BACKENDS=["ogc"])
class OGCResourceIdentityTest(PytestOnlyDBTestCase):
    """Resources must keep their id — hence their permalink — across harvests.

    They used to be wiped and rebuilt on every run (LEDG-2251).
    """

    def _harvest(self, rmock, source, distributions, name="Dataset A"):
        rmock.get(OGC_URL, text=_ogc_payload([_item_with_distributions(distributions, name)]))
        job = OGCBackend(source).harvest()
        assert [item.status for item in job.items] == ["done"]
        return Dataset.objects(__raw__={"harvest.remote_id": "a"}).first()

    def test_reharvest_keeps_the_resource_ids(self, rmock):
        source = HarvestSourceFactory(backend="ogc", url=OGC_URL, config={})
        distributions = [
            _distribution(GEOJSON_URL, "application/geo+json"),
            _distribution(CSV_URL, "text/csv", "Items as CSV"),
        ]
        before = [r.id for r in self._harvest(rmock, source, distributions).resources]
        assert len(before) == 2

        dataset = self._harvest(rmock, source, distributions)

        assert [r.id for r in dataset.resources] == before

    def test_renamed_dataset_keeps_the_resource_ids(self, rmock):
        source = HarvestSourceFactory(backend="ogc", url=OGC_URL, config={})
        distributions = [_distribution(CSV_URL, "text/csv", "Items as CSV")]
        before = [r.id for r in self._harvest(rmock, source, distributions).resources]

        dataset = self._harvest(rmock, source, distributions, name="Dataset A revisto")

        assert dataset.title == "Dataset A revisto"
        assert [r.id for r in dataset.resources] == before

    def test_distribution_dropped_upstream_disappears(self, rmock):
        source = HarvestSourceFactory(backend="ogc", url=OGC_URL, config={})
        distributions = [
            _distribution(GEOJSON_URL, "application/geo+json"),
            _distribution(CSV_URL, "text/csv", "Items as CSV"),
        ]
        kept_id = self._harvest(rmock, source, distributions).resources[0].id

        dataset = self._harvest(rmock, source, distributions[:1])

        assert [r.url for r in dataset.resources] == [GEOJSON_URL]
        assert [r.id for r in dataset.resources] == [kept_id]


def _item_with_provider(provider_name, provider_email, remote_id="a"):
    item = _item(remote_id, "Dataset A", ["geo"])
    item["provider"] = {"name": provider_name, "contactPoint": {"email": provider_email}}
    return item


@pytest.mark.options(HARVESTER_BACKENDS=["ogc"])
class OGCBackendContactPointTest(PytestOnlyDBTestCase):
    """The provider mapping is the one place this backend writes on its own.

    `get_dataset` only fills `dataset.organization` when the source carries one,
    and the provider block is skipped without an organization or an owner - so the
    source needs an organization for any of this to run.
    """

    def _source(self):
        return HarvestSourceFactory(
            backend="ogc", url=OGC_URL, config={}, organization=OrganizationFactory()
        )

    def test_preview_does_not_create_a_contact_point(self, rmock):
        """A preview persists nothing, the provider mapping included.

        The backend used to `get_or_create` the contact point with no `dryrun`
        guard, which the preview endpoint made reachable by any authenticated
        account. Upstream fixed the same thing in the DCAT path; this backend
        carries its own copy of the code and never got it.
        """
        rmock.get(OGC_URL, text=_ogc_payload([_item_with_provider("Camara", "geo@example.pt")]))

        job = OGCBackend(self._source(), dryrun=True).harvest()

        assert [item.status for item in job.items] == ["done"]
        # `len(list(...))` rather than `.count()`: mongoengine routes an *unfiltered*
        # count to `estimated_document_count()`, which reads collection metadata and
        # can be wrong in either direction, so a harvest that created too many or too
        # few documents could go unnoticed.
        assert len(list(ContactPoint.objects)) == 0
        assert job.items[0].dataset.contact_points == []

    def test_preview_reuses_an_existing_contact_point(self, rmock):
        """Not writing must not degrade into not resolving at all."""
        source = self._source()
        contact = ContactPoint.objects.create(
            name="Camara",
            email="geo@example.pt",
            role="publisher",
            organization=source.organization,
        )
        rmock.get(OGC_URL, text=_ogc_payload([_item_with_provider("Camara", "geo@example.pt")]))

        job = OGCBackend(source, dryrun=True).harvest()

        assert job.items[0].dataset.contact_points == [contact]

    def test_preview_fails_on_duplicates_like_a_real_run_does(self, rmock):
        """A preview must predict the run, including how it breaks.

        `get_or_create` ends on a `get`, so two contact points matching the lookup
        fail the item on a real harvest. Resolving with `first()` instead would
        report the item as fine and silently pick one of them.
        """
        source = self._source()
        for contact_form in ("https://a.example.pt", "https://b.example.pt"):
            ContactPoint.objects.create(
                name="Camara",
                email="geo@example.pt",
                contact_form=contact_form,
                role="publisher",
                organization=source.organization,
            )
        rmock.get(OGC_URL, text=_ogc_payload([_item_with_provider("Camara", "geo@example.pt")]))

        preview = OGCBackend(source, dryrun=True).harvest()
        run = OGCBackend(source).harvest()

        assert [item.status for item in preview.items] == ["failed"]
        assert [item.status for item in run.items] == ["failed"]

    def test_run_creates_the_contact_point(self, rmock):
        """A real harvest keeps creating it, as before."""
        rmock.get(OGC_URL, text=_ogc_payload([_item_with_provider("Camara", "geo@example.pt")]))

        job = OGCBackend(self._source()).harvest()

        assert [item.status for item in job.items] == ["done"]
        assert len(list(ContactPoint.objects)) == 1
        assert job.items[0].dataset.contact_points[0].email == "geo@example.pt"


SCHEMA_URL = "https://geoportal.example.pt/collections/a/schema?f=json"
ITEMS_JSONLD_URL = "https://geoportal.example.pt/collections/a/items?f=jsonld"
ITEMS_HTML_URL = "https://geoportal.example.pt/collections/a/items?f=html"
DOCUMENT_URL = "https://geoportal.example.pt/collections/a?f=json"


@pytest.mark.options(HARVESTER_BACKENDS=["ogc"])
class OGCDistributionSelectionTest(PytestOnlyDBTestCase):
    """Only three of the source's distributions are catalogued (LEDG-2512).

    The source publishes thirteen per collection; six are HTML and were already
    dropped, and of the remaining seven the portal keeps the two item downloads
    and the collection schema.
    """

    def _harvest(self, rmock, source, distributions, name="Dataset A"):
        rmock.get(OGC_URL, text=_ogc_payload([_item_with_distributions(distributions, name)]))
        job = OGCBackend(source).harvest()
        assert [item.status for item in job.items] == ["done"]
        return Dataset.objects(__raw__={"harvest.remote_id": "a"}).first()

    def test_only_target_distributions_are_kept(self, rmock):
        source = HarvestSourceFactory(backend="ogc", url=OGC_URL, config={})
        distributions = [
            _distribution(DOCUMENT_URL, "application/json", "This document as JSON"),
            _distribution(GEOJSON_URL, "application/geo+json", "Items as GeoJSON"),
            _distribution(ITEMS_JSONLD_URL, "application/ld+json", "Items as RDF (GeoJSON-LD)"),
            _distribution(SCHEMA_URL, "application/schema+json", "Schema of collection in JSON"),
            # Carries the "Items as" prefix but is HTML: the MIME filter has to
            # run first, or this one is catalogued and the dataset gets four.
            _distribution(ITEMS_HTML_URL, "text/html", "Items as HTML"),
        ]

        dataset = self._harvest(rmock, source, distributions)

        assert [r.url for r in dataset.resources] == [GEOJSON_URL, ITEMS_JSONLD_URL, SCHEMA_URL]

    def test_missing_target_does_not_fail_the_harvest(self, rmock):
        """A source that stops publishing one of the three is not an error."""
        source = HarvestSourceFactory(backend="ogc", url=OGC_URL, config={})
        distributions = [
            _distribution(DOCUMENT_URL, "application/json", "This document as JSON"),
            _distribution(GEOJSON_URL, "application/geo+json", "Items as GeoJSON"),
        ]

        dataset = self._harvest(rmock, source, distributions)

        assert [r.url for r in dataset.resources] == [GEOJSON_URL]

    def test_a_source_that_matches_nothing_is_logged(self, rmock, caplog):
        """The one way this can break without anyone noticing.

        If the source renames its labels, every distribution is dropped, the
        dataset loses its resources and the item still reports `done`. That has
        to leave a trace, or the first report is a user asking where the
        downloads went.
        """
        source = HarvestSourceFactory(backend="ogc", url=OGC_URL, config={})
        distributions = [
            _distribution(GEOJSON_URL, "application/geo+json", "Objetos como GeoJSON"),
            _distribution(SCHEMA_URL, "application/schema+json", "Esquema da coleção"),
        ]

        with caplog.at_level(logging.WARNING, logger="udata.harvest.backends.ogc"):
            dataset = self._harvest(rmock, source, distributions)

        assert dataset.resources == []
        assert "no distribution" in caplog.text
        assert "Objetos como GeoJSON" in caplog.text

    def test_a_distribution_without_a_label_is_not_catalogued(self, rmock):
        """A non-string `description` is treated as absent, never raised on."""
        source = HarvestSourceFactory(backend="ogc", url=OGC_URL, config={})
        distributions = [
            {"contentURL": DOCUMENT_URL, "encodingFormat": "application/json"},
            {
                "contentURL": SCHEMA_URL,
                "encodingFormat": "application/schema+json",
                "description": {"@value": "Schema of collection in JSON"},
            },
            _distribution(GEOJSON_URL, "application/geo+json", "Items as GeoJSON"),
        ]

        dataset = self._harvest(rmock, source, distributions)

        assert [r.url for r in dataset.resources] == [GEOJSON_URL]

    def test_items_as_is_renamed_after_the_dataset(self, rmock):
        source = HarvestSourceFactory(backend="ogc", url=OGC_URL, config={})
        distributions = [
            _distribution(GEOJSON_URL, "application/geo+json", "Items as GeoJSON"),
            _distribution(ITEMS_JSONLD_URL, "application/ld+json", "Items as RDF (GeoJSON-LD)"),
        ]

        dataset = self._harvest(rmock, source, distributions, name="Rede Ciclável")

        assert [(r.title, r.format, r.url) for r in dataset.resources] == [
            ("Rede Ciclável como GeoJSON", "GeoJSON", GEOJSON_URL),
            ("Rede Ciclável como RDF (GeoJSON-LD)", "JSON-LD", ITEMS_JSONLD_URL),
        ]

    def test_schema_keeps_its_label(self, rmock):
        source = HarvestSourceFactory(backend="ogc", url=OGC_URL, config={})
        distributions = [
            _distribution(SCHEMA_URL, "application/schema+json", "Schema of collection in JSON")
        ]

        dataset = self._harvest(rmock, source, distributions, name="Rede Ciclável")

        assert [(r.title, r.format, r.url) for r in dataset.resources] == [
            ("Schema of collection in JSON", "SCHEMA+JSON", SCHEMA_URL)
        ]


TML_COLLECTION = os.path.join(os.path.dirname(__file__), "ogc", "tml_collection.jsonld")

# The seven the backend used to catalogue, in source order. The four that are
# dropped come first so the assertions below read as "these go, those stay".
TML_DROPPED_URLS = [
    "https://geoportal.tmlmobilidade.pt/ogc-api?f=json",
    "https://geoportal.tmlmobilidade.pt/ogc-api/collections/cml_ciclovia_estacionamento?f=json",
    "https://geoportal.tmlmobilidade.pt/ogc-api/collections/cml_ciclovia_estacionamento?f=jsonld",
    "https://geoportal.tmlmobilidade.pt/ogc-api/collections/"
    "cml_ciclovia_estacionamento/queryables?f=json",
]
TML_ITEMS_GEOJSON_URL = (
    "https://geoportal.tmlmobilidade.pt/ogc-api/collections/"
    "cml_ciclovia_estacionamento/items?f=json"
)
TML_ITEMS_JSONLD_URL = (
    "https://geoportal.tmlmobilidade.pt/ogc-api/collections/"
    "cml_ciclovia_estacionamento/items?f=jsonld"
)
TML_SCHEMA_URL = (
    "https://geoportal.tmlmobilidade.pt/ogc-api/collections/"
    "cml_ciclovia_estacionamento/schema?f=json"
)


def _tml_item(title="Rede Ciclável"):
    """One real TML collection, recorded from the source, under a given title.

    Recorded rather than transcribed: a hand-written copy of thirteen
    distributions can agree with wrong code precisely in the `description`
    field the selection reads.
    """
    with open(TML_COLLECTION, encoding="utf-8") as recorded:
        collection = json.load(recorded)
    collection["@id"] = "a"
    collection["name"] = title
    return collection


@pytest.mark.options(HARVESTER_BACKENDS=["ogc"])
class OGCTMLPayloadTest(PytestOnlyDBTestCase):
    """The selection and the renaming, read against the source's own payload."""

    def _harvest(self, rmock, source, title="Rede Ciclável"):
        rmock.get(OGC_URL, text=_ogc_payload([_tml_item(title)]))
        job = OGCBackend(source).harvest()
        assert [item.status for item in job.items] == ["done"]
        return Dataset.objects(__raw__={"harvest.remote_id": "a"}).first()

    def test_the_recorded_collection_still_has_thirteen_distributions(self):
        """The fixture is only evidence while it matches what was recorded."""
        item = _tml_item()

        assert len(item["distribution"]) == 13
        assert all(dist.get("name") is None for dist in item["distribution"])

    def test_tml_payload_yields_the_three_expected_resources(self, rmock):
        source = HarvestSourceFactory(backend="ogc", url=OGC_URL, config={})

        dataset = self._harvest(rmock, source)

        assert [(r.title, r.format, r.url) for r in dataset.resources] == [
            ("Schema of collection in JSON", "SCHEMA+JSON", TML_SCHEMA_URL),
            ("Rede Ciclável como GeoJSON", "GeoJSON", TML_ITEMS_GEOJSON_URL),
            ("Rede Ciclável como RDF (GeoJSON-LD)", "JSON-LD", TML_ITEMS_JSONLD_URL),
        ]

    def test_first_harvest_after_deploy_drops_four_and_keeps_three_ids(self, rmock):
        """The transition the datasets in production actually go through.

        They already hold the seven resources the old code created, so the run
        that matters is the second one: four permalinks go, and the three that
        stay have to be the same resources, not new ones wearing new ids.
        """
        source = HarvestSourceFactory(backend="ogc", url=OGC_URL, config={})
        dataset = self._harvest(rmock, source)
        # Seed the four the old code also created. `filetype="remote"` is the
        # value the backend writes; left at the `Resource` default of "file"
        # they would read as portal uploads and be preserved on purpose.
        for url in TML_DROPPED_URLS:
            dataset.resources.append(Resource(title="Old", url=url, filetype="remote"))
        dataset.save()
        dataset.reload()
        assert len(dataset.resources) == 7
        kept_ids = {r.url: r.id for r in dataset.resources if r.url not in TML_DROPPED_URLS}

        dataset = self._harvest(rmock, source)

        assert [r.url for r in dataset.resources] == [
            TML_SCHEMA_URL,
            TML_ITEMS_GEOJSON_URL,
            TML_ITEMS_JSONLD_URL,
        ]
        assert {r.url: r.id for r in dataset.resources} == kept_ids

    def test_the_source_hostname_is_the_tag_not_dgterritorio(self, rmock):
        source = HarvestSourceFactory(backend="ogc", url=OGC_URL, config={})
        dataset = self._harvest(rmock, source)

        # `TagListField` slugifies, as it did with the constant.
        assert "geoportal-example-pt" in dataset.tags
        assert "ogcapi-dgterritorio-gov-pt" not in dataset.tags

    def test_a_re_harvest_drops_the_old_dgterritorio_tag(self, rmock):
        """The datasets in production already carry it; no migration removes it."""
        source = HarvestSourceFactory(backend="ogc", url=OGC_URL, config={})
        dataset = self._harvest(rmock, source)
        dataset.tags.append("ogcapi.dgterritorio.gov.pt")
        dataset.save()

        dataset = self._harvest(rmock, source)

        assert "ogcapi-dgterritorio-gov-pt" not in dataset.tags

    def test_the_collection_url_becomes_the_remote_url(self, rmock):
        source = HarvestSourceFactory(backend="ogc", url=OGC_URL, config={})
        dataset = self._harvest(rmock, source)

        assert dataset.harvest.remote_url == (
            "https://geoportal.tmlmobilidade.pt/ogc-api/collections/cml_ciclovia_estacionamento"
        )
        # The harvest item carries it too, which is what the preview shows.
        (item,) = HarvestJob.objects.order_by("-created").first().items
        assert item.remote_url == dataset.harvest.remote_url

    @pytest.mark.parametrize("url", [None, "", "not a url", "/ogc-api/collections/relative"])
    def test_a_missing_or_unusable_url_does_not_fail_the_item(self, rmock, url):
        item = _tml_item()
        item["url"] = url
        rmock.get(OGC_URL, text=_ogc_payload([item]))
        source = HarvestSourceFactory(backend="ogc", url=OGC_URL, config={})
        job = OGCBackend(source).harvest()
        assert [item.status for item in job.items] == ["done"]
        dataset = Dataset.objects(__raw__={"harvest.remote_id": "a"}).first()
        assert dataset.harvest.remote_url is None

    def test_a_manual_upload_survives_the_transition(self, rmock):
        """Resources uploaded on the portal never belonged to the harvester."""
        source = HarvestSourceFactory(backend="ogc", url=OGC_URL, config={})
        dataset = self._harvest(rmock, source)
        dataset.resources.append(
            Resource(title="Ficheiro carregado à mão", url=CSV_URL, filetype="file")
        )
        dataset.save()

        dataset = self._harvest(rmock, source)

        assert [r.title for r in dataset.resources if r.filetype == "file"] == [
            "Ficheiro carregado à mão"
        ]


CC_BY_URL = "https://creativecommons.org/licenses/by/4.0/"
ODBL_URL = "https://opendatacommons.org/licenses/odbl/1-0/"


@pytest.mark.options(HARVESTER_BACKENDS=["ogc"])
class OGCLicenseTest(PytestOnlyDBTestCase):
    """The collection's licence, then the catalogue's, then `notspecified`."""

    def _harvest(self, rmock, item, catalogue_license=None):
        LicenseFactory(id="cc-by", title="Creative Commons Attribution", url=CC_BY_URL)
        LicenseFactory(id="odc-odbl", title="Open Database License", url=ODBL_URL)
        LicenseFactory(id="notspecified", title="License Not Specified", url=None)
        payload = {"dataset": [item]}
        if catalogue_license:
            payload["license"] = catalogue_license
        rmock.get(OGC_URL, text=json.dumps(payload))
        source = HarvestSourceFactory(backend="ogc", url=OGC_URL, config={})
        job = OGCBackend(source).harvest()
        assert [item.status for item in job.items] == ["done"]
        return Dataset.objects(__raw__={"harvest.remote_id": "a"}).first()

    def test_the_catalogue_license_stands_in_for_a_silent_item(self, rmock):
        item = _item("a", "Rede", [])
        dataset = self._harvest(rmock, item, catalogue_license=CC_BY_URL)
        assert dataset.license.id == "cc-by"

    def test_the_item_license_wins_over_the_catalogue(self, rmock):
        item = {**_item("a", "Rede", []), "license": ODBL_URL}
        dataset = self._harvest(rmock, item, catalogue_license=CC_BY_URL)
        assert dataset.license.id == "odc-odbl"

    def test_no_license_anywhere_is_notspecified(self, rmock):
        dataset = self._harvest(rmock, _item("a", "Rede", []))
        assert dataset.license.id == "notspecified"


@pytest.mark.options(HARVESTER_BACKENDS=["ogc"])
class OGCTemporalCoverageTest(PytestOnlyDBTestCase):
    """`temporalCoverage` becomes the dataset's `DateRange` when it names dates."""

    def _harvest(self, rmock, temporal):
        item = _tml_item()
        if temporal is None:
            item.pop("temporalCoverage")
        else:
            item["temporalCoverage"] = temporal
        rmock.get(OGC_URL, text=_ogc_payload([item]))
        source = HarvestSourceFactory(backend="ogc", url=OGC_URL, config={})
        job = OGCBackend(source).harvest()
        assert [item.status for item in job.items] == ["done"], [
            error.message for item in job.items for error in item.errors
        ]
        return Dataset.objects(__raw__={"harvest.remote_id": "a"}).first()

    def test_none_slash_none_yields_no_coverage(self, rmock):
        # What every recorded TML collection publishes.
        assert _tml_item()["temporalCoverage"] == "None/None"
        dataset = self._harvest(rmock, "None/None")
        assert dataset.temporal_coverage is None
        assert "temporal_coverage" not in dataset.extras

    def test_an_iso_interval_becomes_a_date_range(self, rmock):
        dataset = self._harvest(rmock, "2020-01-01/2021-12-31")
        assert dataset.temporal_coverage.start == date(2020, 1, 1)
        assert dataset.temporal_coverage.end == date(2021, 12, 31)

    @pytest.mark.parametrize("temporal", ["2020-01-01/..", "2020-01-01/None"])
    def test_an_open_end_keeps_the_start(self, rmock, temporal):
        dataset = self._harvest(rmock, temporal)
        assert dataset.temporal_coverage.start == date(2020, 1, 1)
        assert dataset.temporal_coverage.end is None

    def test_a_single_year_covers_the_year(self, rmock):
        dataset = self._harvest(rmock, "2020")
        assert dataset.temporal_coverage.start == date(2020, 1, 1)
        assert dataset.temporal_coverage.end == date(2020, 12, 31)

    @pytest.mark.parametrize("temporal", ["janeiro a março", "2020-13-45/2021-01-01", None])
    def test_unreadable_text_does_not_fail_the_item(self, rmock, temporal):
        dataset = self._harvest(rmock, temporal)
        assert dataset.temporal_coverage is None

    def test_the_raw_extra_left_by_earlier_harvests_is_removed(self, rmock):
        dataset = self._harvest(rmock, "None/None")
        dataset.extras["temporal_coverage"] = "None/None"
        dataset.save()
        dataset = self._harvest(rmock, "None/None")
        assert "temporal_coverage" not in dataset.extras
