import json

import pytest

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
