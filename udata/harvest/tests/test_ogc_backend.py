from udata.tests.api import PytestOnlyDBTestCase

from ..backends.ogc import OGCBackend
from .factories import HarvestSourceFactory


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
