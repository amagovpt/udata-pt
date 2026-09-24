"""Pure URL and format helpers shared by the harvester backends.

Both defects these cover were reported against the APAmbiente catalogue
(LEDG-2250), but the helpers are generic: the tests moved here with the
functions, when the CSW backends were merged.
"""

import pytest

from ..backends.tools.harvester_utils import (
    MIME_FORMATS,
    bbox_to_spatial_coverage,
    build_resource_url,
    collapse_duplicated_path,
    guess_format_from_mime,
    guess_url_format,
)

GEODOCS = "https://sniambgeoviewer.apambiente.pt/GeoDocs/geoportaldocs"

# Verbatim `dct:references` value of record {DCFDE102-CAE9-415B-9D70-43EC25677DC7},
# "Metas nacionais e europeias de redução de emissões de GEE": the path is
# concatenated with itself, and the resulting link 404s upstream.
DUPLICATED_REFERENCE = (
    f"{GEODOCS}/_Clima/PortalAcaoClimatica_Emissoes2030/meta_2030_0.xlsx"
    "_Clima/PortalAcaoClimatica_Emissoes2030/meta_2030_0.xlsx"
)
EXPECTED_URL = f"{GEODOCS}/_Clima/PortalAcaoClimatica_Emissoes2030/meta_2030_0.xlsx"


class BuildResourceUrlTest:
    def test_self_concatenated_path_is_collapsed(self):
        assert build_resource_url(DUPLICATED_REFERENCE) == EXPECTED_URL

    def test_backslashes_and_duplication_are_repaired_together(self):
        raw = (
            "https://sniambgeoviewer.apambiente.pt\\GeoDocs\\geoportaldocs"
            "\\_Clima\\PortalAcaoClimatica_Emissoes2030\\meta_2030_0.xlsx"
            "_Clima\\PortalAcaoClimatica_Emissoes2030\\meta_2030_0.xlsx"
        )
        assert build_resource_url(raw) == EXPECTED_URL

    def test_healthy_url_is_left_alone(self):
        url = f"{GEODOCS}/_Clima/PortalAcaoClimatica_Emissoes2030/Meta_2030.xlsx"
        assert build_resource_url(url) == url


class CollapseDuplicatedPathTest:
    def test_repetition_starting_at_a_segment_boundary(self):
        assert collapse_duplicated_path("https://host/a/b/c/b/c") == "https://host/a/b/c"

    def test_single_repeated_segment_is_preserved(self):
        # A real path may legitimately repeat one segment; only a multi-segment
        # tail repeating verbatim is treated as the upstream defect.
        url = "https://host/relatorios/relatorios"
        assert collapse_duplicated_path(url) == url

    @pytest.mark.parametrize(
        "url",
        [
            "",
            "https://host",
            "https://host/",
            "https://host/a/b/c.pdf",
        ],
    )
    def test_nothing_to_collapse(self, url):
        assert collapse_duplicated_path(url) == url

    def test_query_and_fragment_are_untouched(self):
        url = "https://host/a/b/c/b/c?x=1#frag"
        assert collapse_duplicated_path(url) == "https://host/a/b/c?x=1#frag"


class GuessUrlFormatTest:
    @pytest.mark.parametrize(
        "path,expected",
        [
            ("/rea/rea2025_highlights_en.pdf", "pdf"),
            ("/Geodocs/shpzips/d307_snirh_hidro_fdw_pub.ZIP", "zip"),
            ("/REA/REA2016/REA_APA_Final.ppsx", "ppsx"),
            # The defect this ticket reported: a four-letter extension used to
            # be rewritten to `wms` purely because it was longer than three.
            ("/_Clima/PortalAcaoClimatica_Emissoes2030/meta_2030_0.xlsx", "xlsx"),
        ],
    )
    def test_extension_comes_from_the_last_path_segment(self, path, expected):
        assert guess_url_format(f"https://sniambgeoviewer.apambiente.pt{path}") == expected

    def test_percent_encoded_segment(self):
        url = f"{GEODOCS}/_Prevencao_gestao_riscos/Legisla%C3%A7%C3%A3o.pdf"
        assert guess_url_format(url) == "pdf"

    def test_ogc_service_query_wins_over_the_missing_extension(self):
        url = (
            "https://inspire.apambiente.pt/getogc/services/INSPIRE/PF_CELE/"
            "MapServer/WMSServer?SERVICE=WMS&REQUEST=GetCapabilities"
        )
        assert guess_url_format(url) == "wms"

    def test_dotted_host_does_not_leak_into_the_format(self):
        # `url.split(".")[-1]` used to return the whole path for extension-less
        # URLs, which then tripped the length heuristic and became `wms`.
        url = "https://sniambgeoportal.apambiente.pt/geoportal/thumbnail?uuid=%7BABC%7D"
        assert guess_url_format(url) == "remote"

    @pytest.mark.parametrize("url", ["", None, f"{GEODOCS}/PNA/2015/PNA2015.pdf_Relatorio_2"])
    def test_unusable_input_falls_back(self, url):
        assert guess_url_format(url) == "remote"

    def test_fallback_is_configurable(self):
        assert guess_url_format("https://host/no-extension", fallback="unknown") == "unknown"


class BuildResourceUrlPreservesQueryTest:
    """Only the path is repaired: geoportals nest URLs in query strings."""

    def test_a_nested_url_in_the_query_survives(self):
        url = "https://host/proxy?url=https://other.example/data.csv"
        assert build_resource_url(url) == url

    def test_a_getmap_request_survives(self):
        url = "https://geoportal.example.pt/wms?SERVICE=WMS&REQUEST=GetMap&LAYERS=a"
        assert build_resource_url(url) == url

    def test_the_path_is_still_collapsed_with_a_query_present(self):
        url = "https://host/a//b?url=https://other//y"
        assert build_resource_url(url) == "https://host/a/b?url=https://other//y"


class GuessFormatFromMimeTest:
    """The single MIME-to-format guess, shared by `odspt` and `ogc` (LEDG-2493)."""

    @pytest.mark.parametrize(
        "mime,expected",
        [
            ("application/json", "json"),
            ("application/ld+json", "jsonld"),
            ("application/xml", "xml"),
            ("text/xml", "xml"),
            ("application/csv", "csv"),
            ("text/csv", "csv"),
            ("application/xls", "xls"),
            ("application/xlsx", "xlsx"),
            ("application/geo+json", "geojson"),
            ("application/gml+xml", "gml"),
        ],
    )
    def test_the_curated_table(self, mime, expected):
        assert guess_format_from_mime(mime) == expected

    def test_the_table_covers_every_mime_the_sources_publish(self):
        # Pinned so a table entry cannot be dropped by accident: these are the
        # types the OGC and ODS feeds send.
        assert set(MIME_FORMATS) == {
            "application/json",
            "application/ld+json",
            "application/xml",
            "text/xml",
            "application/csv",
            "text/csv",
            "application/xls",
            "application/xlsx",
            "application/geo+json",
            "application/gml+xml",
        }

    def test_the_table_wins_over_mimetypes(self):
        # `mimetypes.guess_extension("application/xml")` answers `.xsl`, which is
        # an artefact of the standard library's table rather than the format of
        # the resource. The order of the two steps is the fix, so it is pinned.
        assert guess_format_from_mime("application/xml") == "xml"

    def test_a_mime_outside_the_table_falls_to_mimetypes(self):
        assert guess_format_from_mime("application/pdf") == "pdf"

    def test_the_spellings_mimetypes_does_not_know(self):
        # These three resolved to nothing before the table was shared: `odspt`
        # only had `mimetypes`, which answers `None` for all of them.
        assert guess_format_from_mime("application/csv") == "csv"
        assert guess_format_from_mime("application/xls") == "xls"
        assert guess_format_from_mime("application/xlsx") == "xlsx"

    def test_case_and_padding_do_not_matter(self):
        assert guess_format_from_mime("  Application/GEO+JSON ") == "geojson"
        # Outside the table too: `mimetypes` is asked the normalized type, not
        # the raw one, which it would answer `None` to.
        assert guess_format_from_mime(" Application/PDF ") == "pdf"

    def test_an_unknown_mime_falls_back_to_the_url(self):
        url = "https://host/exports/dataset.csv?download=1"
        assert guess_format_from_mime("application/x-made-up", url) == "csv"

    def test_the_url_is_read_through_the_single_url_guess(self):
        # `guess_url_format` reads the last path segment only; the previous
        # `os.path.splitext` over the whole URL is what LEDG-2250 fixed.
        url = "https://host.with.dots/exports/dataset"
        assert guess_format_from_mime("application/x-made-up", url) is None

    def test_no_mime_reads_the_url(self):
        assert guess_format_from_mime(None, "https://host/file.json") == "json"

    def test_a_long_extension_is_not_a_format(self):
        # `guess_url_format` drops anything over five characters as upstream
        # noise (LEDG-2250), so `.geojson` only ever comes from the MIME type.
        assert guess_format_from_mime(None, "https://host/file.geojson") is None
        assert guess_format_from_mime("application/geo+json", "https://host/x") == "geojson"

    @pytest.mark.parametrize("mime", [None, ""])
    def test_a_missing_mime_no_longer_raises(self, mime):
        # `mimetypes.guess_extension(None)` raises `AttributeError`, which used
        # to fail the whole harvested item for an attachment without a type.
        assert guess_format_from_mime(mime) is None

    def test_the_fallback_is_the_last_resort(self):
        assert guess_format_from_mime(None, None, fallback="unknown") == "unknown"
        assert guess_format_from_mime("application/x-made-up", fallback="remote") == "remote"


class BboxToSpatialCoverageTest:
    """The one bbox -> `SpatialCoverage` step the DGT, OGC and ODS backends share."""

    def test_a_box_becomes_a_multipolygon_coverage(self):
        coverage = bbox_to_spatial_coverage([(-8.13, 37.46, -7.77, 37.68)])
        assert coverage.geom["type"] == "MultiPolygon"
        (ring,) = coverage.geom["coordinates"][0]
        assert ring[0] == [-8.13, 37.46]

    def test_several_boxes_become_several_polygons(self):
        coverage = bbox_to_spatial_coverage(
            [(-8.49, 39.52, -6.69, 41.81), (-31.27, 36.93, -25.01, 39.72)]
        )
        assert len(coverage.geom["coordinates"]) == 2

    def test_no_box_yields_no_coverage(self):
        assert bbox_to_spatial_coverage([]) is None

    @pytest.mark.parametrize(
        "box",
        [
            (float("nan"),) * 4,
            (float("-inf"), 37.0, -7.0, float("inf")),
            # Projected metres, not degrees.
            (-120000, -300000, 165000, 280000),
            (-8.13, 37.46, -7.77),
            ("west", "south", "east", "north"),
        ],
    )
    def test_an_unusable_box_yields_no_coverage(self, box):
        assert bbox_to_spatial_coverage([box]) is None

    def test_an_unusable_box_is_dropped_and_the_rest_kept(self):
        coverage = bbox_to_spatial_coverage(
            [(-120000, -300000, 165000, 280000), (-8.13, 37.46, -7.77, 37.68)]
        )
        assert len(coverage.geom["coordinates"]) == 1
