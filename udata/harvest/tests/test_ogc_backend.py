import json

import pytest

from udata.core.organization.factories import OrganizationFactory
from udata.models import ContactPoint, Dataset
from udata.tests.api import PytestOnlyDBTestCase

from ..backends.ogc import OGCBackend
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


def _distribution(url, encoding_format, name="Distribution"):
    return {"contentURL": url, "encodingFormat": encoding_format, "name": name}


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
            _distribution(CSV_URL, "text/csv"),
        ]
        before = [r.id for r in self._harvest(rmock, source, distributions).resources]
        assert len(before) == 2

        dataset = self._harvest(rmock, source, distributions)

        assert [r.id for r in dataset.resources] == before

    def test_renamed_dataset_keeps_the_resource_ids(self, rmock):
        source = HarvestSourceFactory(backend="ogc", url=OGC_URL, config={})
        distributions = [_distribution(CSV_URL, "text/csv")]
        before = [r.id for r in self._harvest(rmock, source, distributions).resources]

        dataset = self._harvest(rmock, source, distributions, name="Dataset A revisto")

        assert dataset.title == "Dataset A revisto"
        assert [r.id for r in dataset.resources] == before

    def test_distribution_dropped_upstream_disappears(self, rmock):
        source = HarvestSourceFactory(backend="ogc", url=OGC_URL, config={})
        distributions = [
            _distribution(GEOJSON_URL, "application/geo+json"),
            _distribution(CSV_URL, "text/csv"),
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
        assert ContactPoint.objects.count() == 0
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
        assert ContactPoint.objects.count() == 1
        assert job.items[0].dataset.contact_points[0].email == "geo@example.pt"
