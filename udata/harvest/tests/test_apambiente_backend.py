"""Resource URL, format and identity for the APAmbiente CSW harvester.

URL and format mapping come from LEDG-2250, resource identity from LEDG-2251.
"""

import pytest

from udata.tests.api import PytestOnlyDBTestCase

from ..backends.apambiente import PortalAmbienteBackend, build_resource_url
from ..backends.tools.harvester_utils import collapse_duplicated_path, guess_url_format
from .factories import HarvestSourceFactory
from .id_stability import harvest, harvested_dataset, resource_ids, resource_urls

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


CSW_URL = "https://sniambgeoportal.apambiente.pt/geoportal/csw"
REMOTE_ID = "{DCFDE102-CAE9-415B-9D70-43EC25677DC7}"
WMS_SERVICE_URL = (
    "https://inspire.apambiente.pt/getogc/services/INSPIRE/PF_CELE/MapServer/WMSServer"
)


def _payload(url, title="Metas de redução de emissões", record_type="dataset"):
    return {
        "remote_id": REMOTE_ID,
        "title": title,
        "description": "Descrição do registo",
        "url": url,
        "type": record_type,
    }


@pytest.mark.options(HARVESTER_BACKENDS=["apambiente"])
class ApambienteResourceIdentityTest(PytestOnlyDBTestCase):
    """The single resource of each record must keep its id across harvests.

    It used to be dropped and rebuilt on every run, so its download permalink
    changed every night (LEDG-2251).
    """

    def _source(self):
        return HarvestSourceFactory(backend="apambiente", url=CSW_URL)

    def test_reharvest_keeps_the_resource_id(self):
        source = self._source()
        harvest(PortalAmbienteBackend, source, REMOTE_ID, items=_payload(EXPECTED_URL))
        before = resource_ids(REMOTE_ID)
        assert len(before) == 1

        harvest(PortalAmbienteBackend, source, REMOTE_ID, items=_payload(EXPECTED_URL))

        assert resource_ids(REMOTE_ID) == before

    def test_title_change_keeps_the_resource_id(self):
        source = self._source()
        harvest(PortalAmbienteBackend, source, REMOTE_ID, items=_payload(EXPECTED_URL))
        before = resource_ids(REMOTE_ID)

        harvest(
            PortalAmbienteBackend,
            source,
            REMOTE_ID,
            items=_payload(EXPECTED_URL, title="Metas revistas"),
        )

        assert resource_ids(REMOTE_ID) == before
        assert [r.title for r in harvested_dataset(REMOTE_ID).resources] == ["Metas revistas"]

    def test_url_change_upstream_replaces_the_resource(self):
        # A different URL is a different resource: its id cannot be preserved,
        # and the stale one must not linger.
        source = self._source()
        harvest(PortalAmbienteBackend, source, REMOTE_ID, items=_payload(EXPECTED_URL))

        harvest(
            PortalAmbienteBackend,
            source,
            REMOTE_ID,
            items=_payload(WMS_SERVICE_URL, record_type="liveData"),
        )

        assert resource_urls(REMOTE_ID) == [WMS_SERVICE_URL]
        assert [r.format for r in harvested_dataset(REMOTE_ID).resources] == ["wms"]
