"""DGT harvester: resource identity (LEDG-2251) and licence derivation (LEDG-2518)."""

import copy
import json
import os
from datetime import UTC, datetime, timedelta

import pytest

from udata.core.dataset.constants import UpdateFrequency
from udata.core.dataset.factories import LicenseFactory
from udata.models import License
from udata.tests.api import PytestOnlyDBTestCase

from ..backends.dgt import (
    DERIVED_LICENSE_EXTRA,
    MAX_CONSTRAINT_ENTRIES,
    MAX_CONSTRAINT_LENGTH,
    DGTBackend,
    format_from_link,
    license_id_from_legal_constraints,
)
from ..backends.tools.harvester_utils import bbox_to_multipolygon, map_iso_maintenance_frequency
from .factories import HarvestSourceFactory
from .id_stability import harvest, harvested_dataset, resource_ids, resource_urls

DGT_URL = "https://snig.dgterritorio.gov.pt/rndg/srv/por/q?_content_type=json"
REMOTE_ID = "8c3d4f1a-0000-4000-8000-000000000001"
WMS_URL = "https://snig.dgterritorio.gov.pt/geoserver/wms?service=WMS&request=GetCapabilities"
ZIP_URL = "https://snig.dgterritorio.gov.pt/downloads/cartografia.zip"


def _payload(urls, title="Carta administrativa"):
    return {
        "remote_id": REMOTE_ID,
        "title": title,
        "description": "Limites administrativos oficiais",
        "keywords": ["geo"],
        "resources": [{"url": url, "type": "WWW:LINK", "format": "zip"} for url in urls],
    }


@pytest.mark.options(HARVESTER_BACKENDS=["dgt"])
class DGTResourceIdentityTest(PytestOnlyDBTestCase):
    def _source(self):
        return HarvestSourceFactory(backend="dgt", url=DGT_URL)

    def test_reharvest_keeps_the_resource_ids(self):
        source = self._source()
        harvest(DGTBackend, source, REMOTE_ID, items=_payload([WMS_URL, ZIP_URL]))
        before = resource_ids(REMOTE_ID)
        assert len(before) == 2

        harvest(DGTBackend, source, REMOTE_ID, items=_payload([WMS_URL, ZIP_URL]))

        assert resource_ids(REMOTE_ID) == before

    def test_metadata_changes_do_not_cost_the_id(self):
        source = self._source()
        harvest(DGTBackend, source, REMOTE_ID, items=_payload([ZIP_URL]))
        before = resource_ids(REMOTE_ID)

        harvest(DGTBackend, source, REMOTE_ID, items=_payload([ZIP_URL], title="Novo título"))

        assert resource_ids(REMOTE_ID) == before
        # DGT names its resources after the dataset, so the refresh is visible.
        assert [r.title for r in harvested_dataset(REMOTE_ID).resources] == ["Novo título"]

    def test_resource_dropped_upstream_disappears(self):
        source = self._source()
        harvest(DGTBackend, source, REMOTE_ID, items=_payload([WMS_URL, ZIP_URL]))
        wms_id = resource_ids(REMOTE_ID)[0]

        harvest(DGTBackend, source, REMOTE_ID, items=_payload([WMS_URL]))

        assert resource_urls(REMOTE_ID) == [WMS_URL]
        assert resource_ids(REMOTE_ID) == [wms_id]


class DGTLegalConstraintsFieldTest:
    """`legalConstraints` comes in three shapes from the GeoNetwork index."""

    def test_a_list_is_kept_as_is(self):
        record = {
            "legalConstraints": [
                "Acesso público sem restrições",
                "Direitos de Propriedade Intelectual",
            ]
        }
        assert DGTBackend._legal_constraints(record) == [
            "Acesso público sem restrições",
            "Direitos de Propriedade Intelectual",
        ]

    def test_a_bare_string_becomes_a_list(self):
        record = {"legalConstraints": "Sem restrições"}
        assert DGTBackend._legal_constraints(record) == ["Sem restrições"]

    def test_a_missing_field_is_empty(self):
        assert DGTBackend._legal_constraints({}) == []
        assert DGTBackend._legal_constraints({"legalConstraints": None}) == []

    def test_blank_and_non_string_entries_are_dropped(self):
        record = {"legalConstraints": ["  Sem restrições  ", "", "   ", None, 42]}
        assert DGTBackend._legal_constraints(record) == ["Sem restrições"]


# Verbatim from the SNIG index (checked live against the source on 2026-09-18).
# The wording is the fixture: a paraphrase would stop testing the text the
# harvester actually meets.
SNIT_TEXT = (
    "A informação disponibilizada no SNIT destina-se à consulta e visualização, sendo "
    "interdita a sua comercialização. A informação obtida através do SNIT, nomeadamente "
    "utilizando a funcionalidade de impressão, não se destina a ser utilizada para a "
    "instrução de procedimentos administrativos, salvo autorização expressa por parte da "
    "entidade pública responsável pelo procedimento. A sua incorporação em documentos "
    "publicados implica sempre a indicação dos diplomas legais e regulamentares que lhe "
    "estão associados. A presente informação geográfica é disponibilizada em regime de "
    "dados abertos, ao abrigo da licença Creative Commons Attribution 4.0 International "
    "(CC BY 4.0). Nos termos desta licença, a utilização da informação é permitida, "
    "incluindo a sua reprodução, adaptação e reutilização, para os fins entendidos, desde "
    "que seja assegurada a devida atribuição da fonte, com referência clara à entidade "
    "disponibilizadora dos dados e à licença aplicável. Contacte a DGT para obter mais "
    "informações (https://www.dgterritorio.gov.pt)."
)

# The Azores wording ENDS with the CC BY URL. Truncating the fixture before it
# would let the test pass while the source records still came out cc-by.
AZORES_TEXT = (
    "A reprodução e cópia para usos não comerciais é autorizada nos termos de licença "
    "Creative Commons – Atribuição 4.0 Internacional (CC BY 4.0). O uso comercial sem "
    "consentimento por escrito da Direção Regional de Políticas Marítimas/Governo dos "
    "Açores é expressamente proibido. Sempre que o utilizador publique e/ou divulgue, por "
    "meio analógico ou digital, informação geográfica propriedade da Direção Regional de "
    "Políticas Marítimas (DRPM), ainda que parcialmente adaptada, deverá atribuir os "
    "respetivos créditos. Termos da licença Creative Commons: "
    "[https://creativecommons.org/licenses/by/4.0/]"
)

PUBLIC_ACCESS = "Acesso público sem restrições"
DGT_CONTACT_FORM_TEXT = (
    "Visualização e descarregamento de dados a pedido através de Formulário de Contacto da "
    "DGT (https://www.dgterritorio.gov.pt/formulario-contacto#no-back) para o assunto "
    "Cartografia. Uso sem restrições mas sujeito a atribuição de créditos com inclusão do "
    'texto "Informação geográfica cedida pela Direção-Geral do Território".'
)


class DGTLicenseResolutionTest:
    """The licence the source grants, read out of the real `legalConstraints`."""

    def test_snit_text_grants_cc_by(self):
        # The interdiction is aimed at the SNIT portal; the grant is aimed at
        # the data, is named, and says "para os fins entendidos".
        assert license_id_from_legal_constraints([SNIT_TEXT, "Sem restrições"]) == "cc-by"

    def test_azores_non_commercial_grant_has_no_license(self):
        # Same text names CC BY and forbids commercial use OF THE DATA, so the
        # grant does not hold -- even though it ends with the CC BY URL.
        assert license_id_from_legal_constraints([PUBLIC_ACCESS, AZORES_TEXT]) is None

    def test_ipr_only_has_no_license(self):
        # The LNEG complaint: no licence declared at all.
        assert (
            license_id_from_legal_constraints(
                [PUBLIC_ACCESS, "Direitos de Propriedade Intelectual"]
            )
            is None
        )

    def test_explicit_cc_by_label_resolves(self):
        constraints = [
            PUBLIC_ACCESS,
            "Licença de utilização - CC-BY-4.0 (https://creativecommons.org/licenses/by/4.0/)",
        ]
        assert license_id_from_legal_constraints(constraints) == "cc-by"

    def test_label_without_a_url_resolves(self):
        # The label-bearing fixtures all carry the licence URL too, so the URL
        # branch alone would satisfy them. This one exercises the code branch.
        assert license_id_from_legal_constraints(["Licença de utilização - CC-BY-4.0"]) == "cc-by"

    def test_label_without_a_url_resolves_for_sa_and_nc_nd(self):
        assert license_id_from_legal_constraints(["Licença de utilização - CC-BY-SA-4.0"]) == (
            "cc-by-sa"
        )
        assert license_id_from_legal_constraints(["Licença de utilização - CC BY-NC-ND 4.0"]) == (
            "cc-by-nc-nd"
        )

    def test_code_written_without_a_separator_resolves(self):
        # `CCBY` is the one spelling the pattern accepts, so it has to
        # normalize rather than become a code nothing maps.
        assert license_id_from_legal_constraints(["Licença CCBY-4.0"]) == "cc-by"
        assert license_id_from_legal_constraints(["Licença CCBY-NC 4.0"]) == "cc-by-nc"

    def test_bare_cc_by_url_resolves(self):
        constraints = [PUBLIC_ACCESS, "https://creativecommons.org/licenses/by/4.0/"]
        assert license_id_from_legal_constraints(constraints) == "cc-by"

    def test_misspelled_domain_url_resolves(self):
        # Bare URL on purpose: with the `CC-BY` label the code branch would
        # answer and the URL pattern would never be exercised.
        assert (
            license_id_from_legal_constraints(["https://creativecoomons.org/licenses/by/4.0/"])
            == "cc-by"
        )

    def test_malformed_version_path_resolves(self):
        assert (
            license_id_from_legal_constraints(["https://creativecommons.org/licenses/by4.0/"])
            == "cc-by"
        )

    def test_en_dash_label_resolves(self):
        # No URL: with one, the URL branch would answer and the en dash would
        # never be part of what is tested.
        assert license_id_from_legal_constraints(["Licença de utilização – CC-BY-4.0"]) == "cc-by"

    def test_cc_by_sa_resolves(self):
        constraints = [
            PUBLIC_ACCESS,
            "Licença de utilização - CC-BY-SA-4.0 (https://creativecommons.org/licenses/by-sa/4.0/)",
        ]
        assert license_id_from_legal_constraints(constraints) == "cc-by-sa"

    def test_nc_nd_code_resolves(self):
        constraints = [
            PUBLIC_ACCESS,
            "Licença de utilização - CC BY-NC-ND 4.0 "
            "(https://creativecommons.org/licenses/by-nc-nd/4.0/)",
        ]
        assert license_id_from_legal_constraints(constraints) == "cc-by-nc-nd"

    def test_nc_nd_is_not_vetoed_by_the_restriction_rule(self):
        # An NC code already says what the restriction says; the veto is only
        # there to stop a permissive code being granted alongside one.
        constraints = ["CC BY-NC 4.0, uso comercial expressamente proibido"]
        assert license_id_from_legal_constraints(constraints) == "cc-by-nc"

    def test_use_without_conditions_has_no_license(self):
        # "No conditions" is an access policy, not a licence grant.
        assert (
            license_id_from_legal_constraints([PUBLIC_ACCESS, "acesso e uso sem condições"]) is None
        )

    def test_non_license_url_is_ignored(self):
        assert license_id_from_legal_constraints([PUBLIC_ACCESS, DGT_CONTACT_FORM_TEXT]) is None

    def test_conflicting_entries_have_no_license(self):
        # Ambiguity does not grant: the same stance `License.guess_one` takes
        # when two candidates tie.
        constraints = [
            "https://creativecommons.org/licenses/by/4.0/",
            "https://creativecommons.org/licenses/by-nc-nd/4.0/",
        ]
        assert license_id_from_legal_constraints(constraints) is None

    def test_empty_and_missing_have_no_license(self):
        assert license_id_from_legal_constraints([]) is None
        assert license_id_from_legal_constraints(["Sem restrições", "Sem restrições"]) is None


def _index_record(remote_id, legal_constraints, title="Carta geológica", link=None, **fields):
    """One record shaped the way the SNIG `fast=index` response shapes it.

    The default `link` deliberately keeps the five fields it has always had,
    rather than the six the source really publishes: every licence test below
    goes through it, so it doubles as the proof that a short link is tolerated.
    `link` and `**fields` let a test carry a verbatim record instead.
    """
    record = {
        "geonet:info": {"uuid": remote_id},
        "defaultTitle": title,
        "defaultAbstract": "Cartografia temática",
        "keyword": ["geo"],
        "link": f"nome|desc|{ZIP_URL}|WWW:LINK|zip" if link is None else link,
    }
    if legal_constraints is not None:
        record["legalConstraints"] = legal_constraints
    record.update(fields)
    return record


def _index_payload(records):
    return json.dumps({"metadata": records})


# Two records copied verbatim out of the SNIG index on 2026-09-21, via
# `?_content_type=json&fast=index&resultType=details`. Both are named in
# LEDG-2530 and both are load-bearing here: the LNEG one is the record the
# producer complained about, and its URL carries no file extension at all;
# the hidrografico one is an OGC API endpoint, whose format has no other
# source than the label the index puts on it.
LNEG_REMOTE_ID = "20df57a5-76db-4c5e-ae78-45e423e4a88f"
LNEG_LINK = (
    "|Página de descarregamento do PDF a partir do Geoportal da Energia e Geologia"
    "|https://geoportal.lneg.pt/dados_abertos/info_recursosminerais?Id=1704"
    "|WWW:LINK-1.0-http--link|text/html|1"
)
LNEG_URL = "https://geoportal.lneg.pt/dados_abertos/info_recursosminerais?Id=1704"

OGC_API_REMOTE_ID = "d7b1eb8d-7b44-4a2d-adca-97088a6589f9"
OGC_API_LINK = (
    "||https://api-features.hidrografico.pt/collections/depcnt_400_800"
    "|OGC API - Features|OGC API - Features|1"
)
OGC_API_URL = "https://api-features.hidrografico.pt/collections/depcnt_400_800"


class DGTLinkFormatTest:
    """`format_from_link`: what the source says first, the URL only last."""

    def test_the_mime_type_names_the_format(self):
        assert format_from_link("WWW:LINK-1.0-http--link", "text/html", LNEG_URL) == "html"

    def test_an_ogc_api_label_is_read_from_the_link(self):
        # Neither the URL nor a `SERVICE=` parameter names this one.
        assert format_from_link("OGC API - Features", "OGC API - Features", OGC_API_URL) == (
            "ogcapi-features"
        )

    def test_the_sources_own_transposition_is_tolerated(self):
        assert format_from_link("OCG API - Maps", "OCG API - Maps", OGC_API_URL) == "ogcapi-maps"

    def test_a_versioned_ogc_protocol_resolves_to_its_service(self):
        assert format_from_link("OGC:WFS-2.0.0-http-get-capabilities", None, OGC_API_URL) == "wfs"

    def test_the_wms_capabilities_mime_resolves_to_wms(self):
        assert format_from_link("OGC:WMS", "application/vnd.ogc.wms_xml", WMS_URL) == "wms"

    def test_text_plain_falls_through_to_the_url(self):
        # 243 of the 733 links sampled carry `text/plain`, in front of WFS
        # endpoints, zip archives and PDFs alike. Believing it would be worse
        # than ignoring it.
        assert format_from_link("", "text/plain", ZIP_URL) == "zip"
        assert format_from_link("", "text/plain", WMS_URL) == "wms"

    def test_an_unknown_label_falls_through_to_the_url(self):
        assert format_from_link("something", "n.a", ZIP_URL) == "zip"

    def test_a_url_with_no_extension_is_not_mined_for_one(self):
        # The bug this replaces: `split(".")[-1]` over the whole URL returned
        # `pt/dados_abertos/info_recursosminerais?Id=1704`.
        assert format_from_link(None, None, LNEG_URL) == "remote"

    @pytest.mark.parametrize(
        "protocol,mimetype,url,expected",
        [
            ("WWW:LINK-1.0-http--link", "text/html", LNEG_URL, "html"),
            ("OGC API - Features", "OGC API - Features", OGC_API_URL, "ogcapi-features"),
            ("OGC:WMS", "application/vnd.ogc.wms_xml", WMS_URL, "wms"),
            ("", "text/plain", ZIP_URL, "zip"),
            (None, None, LNEG_URL, "remote"),
            (None, None, "https://cdd.dgterritorio.gov.pt/dgt-fe/mapa?collection=LAZ", "remote"),
            (
                None,
                None,
                "https://geo.dgterritorio.gov.pt/pt/idea-api/collections/Ortofoto_2024",
                "remote",
            ),
            ("n.a", "n.a", "", "remote"),
        ],
    )
    def test_no_resolved_format_is_a_url_fragment(self, protocol, mimetype, url, expected):
        """Criterion 1, over every branch of the resolution.

        The expected value is asserted alongside it: `"/" not in x` on its own
        would pass against a function that always returned `"remote"`.
        """
        resolved = format_from_link(protocol, mimetype, url)
        assert resolved == expected
        assert "/" not in resolved and "?" not in resolved, resolved


@pytest.mark.options(HARVESTER_BACKENDS=["dgt"])
class DGTResourceFormatTest(PytestOnlyDBTestCase):
    """The format a real harvest ends up writing on the resource."""

    def _harvest(self, rmock, remote_id, link):
        rmock.get(DGT_URL, text=_index_payload([_index_record(remote_id, None, link=link)]))
        source = HarvestSourceFactory(backend="dgt", url=DGT_URL)
        job = DGTBackend(source).harvest()
        assert [item.status for item in job.items] == ["done"], [
            error.message for item in job.items for error in item.errors
        ]
        return harvested_dataset(remote_id)

    def test_the_lneg_record_no_longer_gets_a_url_fragment(self, rmock):
        dataset = self._harvest(rmock, LNEG_REMOTE_ID, LNEG_LINK)
        (resource,) = dataset.resources
        assert resource.url == LNEG_URL
        assert resource.format == "html"

    def test_an_ogc_api_record_is_catalogued_by_its_label(self, rmock):
        dataset = self._harvest(rmock, OGC_API_REMOTE_ID, OGC_API_LINK)
        (resource,) = dataset.resources
        assert resource.url == OGC_API_URL
        assert resource.format == "ogcapi-features"


class DGTLinkParsingTest:
    """`DGTBackend._parse_link`: the six fields, and what a short one does."""

    def test_the_six_fields_are_read(self):
        parsed = DGTBackend._parse_link(LNEG_LINK)
        assert parsed["url"] == LNEG_URL
        assert parsed["description"] == (
            "Página de descarregamento do PDF a partir do Geoportal da Energia e Geologia"
        )
        assert parsed["type"] == "WWW:LINK-1.0-http--link"
        assert parsed["format"] == "text/html"

    def test_an_empty_name_is_none_rather_than_empty(self):
        # The LNEG record carries a description but no name: field 0 is empty.
        assert DGTBackend._parse_link(LNEG_LINK)["title"] is None

    def test_a_link_with_neither_name_nor_description(self):
        parsed = DGTBackend._parse_link(OGC_API_LINK)
        assert parsed["title"] is None
        assert parsed["description"] is None
        assert parsed["url"] == OGC_API_URL

    def test_a_five_field_link_does_not_raise(self):
        parsed = DGTBackend._parse_link(f"nome|desc|{ZIP_URL}|WWW:LINK|zip")
        assert parsed["url"] == ZIP_URL
        assert parsed["format"] == "zip"

    def test_a_pipe_in_the_description_does_not_shift_the_url(self):
        # Read from the right: the four trailing fields are fixed, the free
        # text is the only part that can hold a separator. Positionally from
        # the left, the URL would be read as "B" and `URLField` would fail the
        # whole item.
        parsed = DGTBackend._parse_link(f"Nome|Carta de A|B|{ZIP_URL}|WWW:LINK|text/csv|1")
        assert parsed["url"] == ZIP_URL
        assert parsed["title"] == "Nome"
        assert parsed["description"] == "Carta de A|B"
        assert parsed["format"] == "text/csv"

    def test_a_link_with_no_url_names_no_resource(self):
        assert DGTBackend._parse_link("nome|desc") is None
        assert DGTBackend._parse_link("") is None
        assert DGTBackend._parse_link("||") is None

    def test_a_link_that_is_not_a_string_names_no_resource(self):
        assert DGTBackend._parse_link(None) is None
        assert DGTBackend._parse_link({"url": ZIP_URL}) is None

    def test_the_title_is_sanitized(self):
        # `Dataset.pre_save` sanitizes the dataset title and both descriptions,
        # but never `resource.title`.
        parsed = DGTBackend._parse_link(f"<b>Carta</b>|desc|{ZIP_URL}|WWW:LINK|zip")
        assert parsed["title"] == "Carta"


@pytest.mark.options(HARVESTER_BACKENDS=["dgt"])
class DGTResourceMetadataHarvestTest(PytestOnlyDBTestCase):
    """The title and description a real harvest writes, and the ids it keeps."""

    def _harvest(self, rmock, records):
        rmock.get(DGT_URL, text=_index_payload(records))
        source = HarvestSourceFactory(backend="dgt", url=DGT_URL)
        return DGTBackend(source).harvest()

    def test_a_named_link_uses_the_sources_own_name(self, rmock):
        link = f"Carta administrativa (SHP)|Descarregamento directo|{ZIP_URL}|WWW:LINK|zip"
        self._harvest(rmock, [_index_record(REMOTE_ID, None, link=link)])
        (resource,) = harvested_dataset(REMOTE_ID).resources
        assert resource.title == "Carta administrativa (SHP)"
        assert resource.description == "Descarregamento directo"

    def test_the_lneg_description_survives_the_harvest(self, rmock):
        self._harvest(rmock, [_index_record(LNEG_REMOTE_ID, None, link=LNEG_LINK)])
        (resource,) = harvested_dataset(LNEG_REMOTE_ID).resources
        assert resource.description.startswith("Página de descarregamento do PDF")
        # No name in the source, so the dataset title stands in.
        assert resource.title == "Carta geológica"

    def test_a_link_without_a_name_keeps_the_dataset_title(self, rmock):
        self._harvest(rmock, [_index_record(OGC_API_REMOTE_ID, None, link=OGC_API_LINK)])
        (resource,) = harvested_dataset(OGC_API_REMOTE_ID).resources
        assert resource.title == "Carta geológica"
        assert resource.description is None

    def test_the_protocol_never_reaches_the_resource_type(self, rmock):
        # `Resource.type` is a closed choice field; `OGC:WMS` would fail
        # validation and take every item of every DGT source with it.
        link = f"nome|desc|{WMS_URL}|OGC:WMS|application/vnd.ogc.wms_xml|1"
        job = self._harvest(rmock, [_index_record(REMOTE_ID, None, link=link)])
        assert [item.status for item in job.items] == ["done"], [
            error.message for item in job.items for error in item.errors
        ]
        (resource,) = harvested_dataset(REMOTE_ID).resources
        assert resource.type == "main"
        assert resource.format == "wms"

    def test_a_malformed_link_does_not_take_the_job_down(self, rmock):
        """The split used to run unguarded inside `inner_harvest`.

        An `IndexError` there does not fail one item: it raises out of
        `inner_harvest`, so the job ends `failed` and none of the other records
        is processed at all.
        """
        job = self._harvest(
            rmock,
            [
                _index_record("bad-record-0000-4000-8000-000000000001", None, link="nome|desc"),
                _index_record(REMOTE_ID, None),
            ],
        )
        assert job.status == "done"
        assert [item.status for item in job.items] == ["done", "done"], [
            error.message for item in job.items for error in item.errors
        ]
        # The good record was processed, the bad one produced no resource.
        assert len(harvested_dataset(REMOTE_ID).resources) == 1
        assert harvested_dataset("bad-record-0000-4000-8000-000000000001").resources == []

    def test_new_titles_and_formats_do_not_cost_the_resource_ids(self, rmock):
        """Criterion 5: `sync_resources` reconciles by URL, so the id survives.

        `DGTResourceIdentityTest` proves this through `id_stability.harvest`,
        which stubs `inner_harvest` out entirely and so never exercises the
        pipe-split path this ticket rewrote. This one goes through the real
        `inner_harvest`, over the two fields it now changes.
        """
        first = f"Nome antigo|Descrição antiga|{ZIP_URL}|WWW:LINK|text/plain|1"
        self._harvest(rmock, [_index_record(REMOTE_ID, None, link=first)])
        before = resource_ids(REMOTE_ID)
        assert len(before) == 1

        second = f"Nome novo|Descrição nova|{ZIP_URL}|WWW:LINK-1.0-http--link|application/pdf|1"
        self._harvest(rmock, [_index_record(REMOTE_ID, None, link=second)])
        assert resource_ids(REMOTE_ID) == before
        assert resource_urls(REMOTE_ID) == [ZIP_URL]

        (resource,) = harvested_dataset(REMOTE_ID).resources
        assert resource.title == "Nome novo"
        assert resource.description == "Descrição nova"
        assert resource.format == "pdf"


@pytest.mark.options(HARVESTER_BACKENDS=["dgt"])
class DGTLicenseHarvestTest(PytestOnlyDBTestCase):
    """The licence a real harvest ends up writing on the dataset."""

    def _licenses(self):
        # The test database carries no licences, and LicenseFactory would give
        # each one a random id, so the ones under test are seeded by id.
        LicenseFactory(id="notspecified", title="License Not Specified")
        LicenseFactory(id="cc-by", title="Creative Commons Attribution 4.0 - CC BY 4.0")
        LicenseFactory(
            id="cc-by-nc-nd",
            title="Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 - CC BY-NC-ND 4.0",
        )

    def _harvest(self, rmock, legal_constraints, remote_id=REMOTE_ID):
        rmock.get(DGT_URL, text=_index_payload([_index_record(remote_id, legal_constraints)]))
        source = HarvestSourceFactory(backend="dgt", url=DGT_URL)
        job = DGTBackend(source).harvest()
        assert [item.status for item in job.items] == ["done"], [
            error.message for item in job.items for error in item.errors
        ]
        return harvested_dataset(remote_id)

    def test_snit_record_is_cc_by(self, rmock):
        self._licenses()
        dataset = self._harvest(rmock, [SNIT_TEXT, "Sem restrições"])
        assert dataset.license.id == "cc-by"

    def test_ipr_record_is_notspecified(self, rmock):
        # The LNEG complaint: the source declares no licence, so neither do we.
        self._licenses()
        dataset = self._harvest(rmock, [PUBLIC_ACCESS, "Direitos de Propriedade Intelectual"])
        assert dataset.license.id == "notspecified"

    def test_missing_legal_constraints_is_notspecified(self, rmock):
        self._licenses()
        dataset = self._harvest(rmock, None)
        assert dataset.license.id == "notspecified"

    def test_nc_nd_record_gets_the_nc_nd_license(self, rmock):
        self._licenses()
        dataset = self._harvest(
            rmock,
            [
                PUBLIC_ACCESS,
                "Licença de utilização - CC BY-NC-ND 4.0 "
                "(https://creativecommons.org/licenses/by-nc-nd/4.0/)",
            ],
        )
        assert dataset.license.id == "cc-by-nc-nd"

    def test_manual_license_survives_a_source_without_one(self, rmock):
        # A producer corrected the licence in the back office. Before this
        # change every harvest stamped cc-by back over it.
        self._licenses()
        self._harvest(rmock, [PUBLIC_ACCESS, "Direitos de Propriedade Intelectual"])
        dataset = harvested_dataset(REMOTE_ID)
        dataset.license = LicenseFactory(id="cc-by-nc", title="CC BY-NC 4.0")
        dataset.save()

        dataset = self._harvest(rmock, [PUBLIC_ACCESS, "Direitos de Propriedade Intelectual"])

        assert dataset.license.id == "cc-by-nc"

    def test_source_license_overrides_what_the_dataset_carries(self, rmock):
        self._licenses()
        self._harvest(rmock, [PUBLIC_ACCESS, "Direitos de Propriedade Intelectual"])

        dataset = self._harvest(rmock, [SNIT_TEXT, "Sem restrições"])

        assert dataset.license.id == "cc-by"

    def test_legal_constraints_are_stored_in_extras(self, rmock):
        self._licenses()
        constraints = [PUBLIC_ACCESS, "Direitos de Propriedade Intelectual"]
        dataset = self._harvest(rmock, constraints)
        assert dataset.extras["harvest:legal_constraints"] == constraints

    def test_a_source_without_constraints_stores_an_empty_list(self, rmock):
        self._licenses()
        dataset = self._harvest(rmock, None)
        assert dataset.extras["harvest:legal_constraints"] == []


class DGTRestrictedGrantTest:
    """Wordings that restrict the grant the source appears to make."""

    def test_a_restriction_in_a_sibling_entry_still_counts(self):
        # ISO 19115 separates use constraints from other constraints, so the
        # grant and the restriction qualifying it arrive as two strings.
        constraints = [
            "Licença Creative Commons Atribuição (CC BY 4.0). "
            "Termos: https://creativecommons.org/licenses/by/4.0/",
            "O uso comercial sem consentimento por escrito é expressamente proibido.",
        ]
        assert license_id_from_legal_constraints(constraints) is None

    def test_the_restriction_is_recognised_in_its_natural_word_order(self):
        # "é proibido o uso comercial" is how Portuguese puts it, and an
        # order-sensitive pattern would miss exactly that.
        assert (
            license_id_from_legal_constraints(
                ["Licença CC BY 4.0. É proibido o uso comercial dos dados."]
            )
            is None
        )

    def test_utilizacao_comercial_is_recognised(self):
        assert (
            license_id_from_legal_constraints(
                ["Licença CC BY 4.0. É proibida a utilização comercial dos dados."]
            )
            is None
        )

    def test_nao_permitido_is_recognised(self):
        assert (
            license_id_from_legal_constraints(
                ["Licença CC BY 4.0. Não é permitido o uso comercial dos dados."]
            )
            is None
        )

    def test_english_wording_is_recognised(self):
        assert license_id_from_legal_constraints(["CC BY 4.0. Non-commercial use only."]) is None

    def test_the_snit_wording_is_not_caught_by_any_of_them(self):
        # The guard that keeps the largest slice of the source from turning on
        # a restriction aimed at the portal rather than at the data.
        assert license_id_from_legal_constraints([SNIT_TEXT, "Sem restrições"]) == "cc-by"


class DGTConflictingCodesTest:
    """Two licences named at once grant neither."""

    def test_a_boilerplate_url_does_not_override_a_restrictive_code(self):
        # The URL is generic guidance about Creative Commons; the code is the
        # licence. Reading the URL first would grant more than the source does.
        constraints = [
            "Os dados são disponibilizados sob CC BY-NC 4.0. Sobre as licenças "
            "Creative Commons consulte https://creativecommons.org/licenses/by/4.0/"
        ]
        assert license_id_from_legal_constraints(constraints) is None

    def test_two_codes_in_one_entry_grant_neither(self):
        constraints = ["Dados derivados sob CC BY 4.0; originais sob CC BY-NC 4.0"]
        assert license_id_from_legal_constraints(constraints) is None


class DGTUntrustedInputTest:
    """The source decides its own prose; the bounds are ours."""

    def test_markup_is_stripped_before_it_reaches_extras(self):
        # extras are marshalled raw by the API and copied into the search
        # document, and nothing downstream cleans them: pre_save only covers
        # the title and the description.
        record = {"legalConstraints": ["<script>alert(1)</script>Licença CC-BY-4.0"]}
        stored = DGTBackend._legal_constraints(record)[0]
        assert "<script>" not in stored
        assert "Licença CC-BY-4.0" in stored

    def test_markup_does_not_cost_the_license(self):
        record = {"legalConstraints": ["<b>Licença de utilização</b> - CC-BY-4.0"]}
        assert license_id_from_legal_constraints(DGTBackend._legal_constraints(record)) == "cc-by"

    def test_entries_are_capped(self):
        record = {"legalConstraints": ["Sem restrições"] * (MAX_CONSTRAINT_ENTRIES + 10)}
        assert len(DGTBackend._legal_constraints(record)) == MAX_CONSTRAINT_ENTRIES

    def test_an_entry_is_truncated(self):
        record = {"legalConstraints": ["a" * (MAX_CONSTRAINT_LENGTH + 100)]}
        assert len(DGTBackend._legal_constraints(record)[0]) == MAX_CONSTRAINT_LENGTH

    def test_a_pathological_run_does_not_hang_the_resolver(self):
        # An unbounded gap in the restriction pattern cost 7.9s per 128 KiB of
        # full-stop-free prose, reachable through the synchronous harvest
        # preview endpoint.
        import time

        constraints = ["proibida " * 2000]
        started = time.perf_counter()
        license_id_from_legal_constraints(constraints)
        assert time.perf_counter() - started < 1

    def test_text_beyond_the_decidable_length_grants_nothing(self):
        # Fail closed: a prefix could omit the restriction that withholds the
        # licence, so nothing is granted at all.
        constraints = ["CC BY 4.0 " + "x" * 25000]
        assert license_id_from_legal_constraints(constraints) is None


CC_BY_LABEL = "Licença de utilização - CC-BY-4.0 (https://creativecommons.org/licenses/by/4.0/)"
IPR_ONLY = "Direitos de Propriedade Intelectual"
AZORES_SHORT = (
    "A reprodução e cópia para usos não comerciais é autorizada nos termos de licença "
    "Creative Commons – Atribuição (CC-BY). O uso comercial é expressamente proibido."
)


@pytest.mark.options(HARVESTER_BACKENDS=["dgt"])
class DGTLicenseWithdrawalTest(PytestOnlyDBTestCase):
    """A source can take back a licence it stopped granting."""

    def _licenses(self):
        LicenseFactory(id="notspecified", title="License Not Specified")
        LicenseFactory(id="cc-by", title="Creative Commons Attribution 4.0 - CC BY 4.0")
        LicenseFactory(id="cc-by-nc", title="Creative Commons Attribution-NonCommercial 4.0")

    def _harvest(self, rmock, legal_constraints):
        rmock.get(DGT_URL, text=_index_payload([_index_record(REMOTE_ID, legal_constraints)]))
        source = HarvestSourceFactory(backend="dgt", url=DGT_URL)
        job = DGTBackend(source).harvest()
        assert [item.status for item in job.items] == ["done"], [
            error.message for item in job.items for error in item.errors
        ]
        return harvested_dataset(REMOTE_ID)

    def test_a_withdrawn_license_is_not_kept_forever(self, rmock):
        # The mirror image of the bug this ticket fixes: keeping whatever the
        # dataset carries would mean our own previous write outlives the grant
        # it came from.
        self._licenses()
        assert self._harvest(rmock, [CC_BY_LABEL]).license.id == "cc-by"

        dataset = self._harvest(rmock, [PUBLIC_ACCESS, IPR_ONLY])

        assert dataset.license.id == "notspecified"

    def test_a_license_restricted_upstream_is_not_kept(self, rmock):
        self._licenses()
        self._harvest(rmock, [CC_BY_LABEL])

        dataset = self._harvest(rmock, [AZORES_SHORT])

        assert dataset.license.id == "notspecified"

    def test_a_manual_edit_still_survives(self, rmock):
        # The Q4 guarantee, unchanged: a correction a producer made by hand is
        # not what we wrote, so it stays.
        self._licenses()
        self._harvest(rmock, [CC_BY_LABEL])
        dataset = harvested_dataset(REMOTE_ID)
        dataset.license = License.objects(id="cc-by-nc").first()
        dataset.save()

        dataset = self._harvest(rmock, [PUBLIC_ACCESS, IPR_ONLY])

        assert dataset.license.id == "cc-by-nc"

    def test_a_manual_edit_clears_the_derived_marker(self, rmock):
        self._licenses()
        self._harvest(rmock, [CC_BY_LABEL])
        dataset = harvested_dataset(REMOTE_ID)
        dataset.license = License.objects(id="cc-by-nc").first()
        dataset.save()

        dataset = self._harvest(rmock, [PUBLIC_ACCESS, IPR_ONLY])

        assert DERIVED_LICENSE_EXTRA not in dataset.extras

    def test_the_extra_records_what_we_derived(self, rmock):
        self._licenses()
        dataset = self._harvest(rmock, [CC_BY_LABEL])
        assert dataset.extras[DERIVED_LICENSE_EXTRA] == "cc-by"

        dataset = self._harvest(rmock, [PUBLIC_ACCESS, IPR_ONLY])
        assert dataset.extras[DERIVED_LICENSE_EXTRA] == "notspecified"


@pytest.mark.options(HARVESTER_BACKENDS=["dgt"])
class DGTPublicationDateTest(PytestOnlyDBTestCase):
    """`created_at` from the source, written where the property can read it."""

    def _harvest(self, rmock, remote_id=REMOTE_ID, **fields):
        rmock.get(DGT_URL, text=_index_payload([_index_record(remote_id, None, **fields)]))
        source = HarvestSourceFactory(backend="dgt", url=DGT_URL)
        job = DGTBackend(source).harvest()
        assert [item.status for item in job.items] == ["done"], [
            error.message for item in job.items for error in item.errors
        ]
        return harvested_dataset(remote_id)

    def test_the_publication_date_becomes_the_creation_date(self, rmock):
        dataset = self._harvest(rmock, publicationDate="2021-06-15")
        assert dataset.harvest.created_at == datetime(2021, 6, 15)
        assert dataset.created_at == datetime(2021, 6, 15)

    def test_the_reference_date_stands_in(self, rmock):
        # The LNEG record is exactly this shape: no publicationDate, a
        # referenceDate of 2020-12-31.
        dataset = self._harvest(
            rmock, remote_id=LNEG_REMOTE_ID, link=LNEG_LINK, referenceDate="2020-12-31"
        )
        assert dataset.harvest.created_at == datetime(2020, 12, 31)

    def test_the_publication_date_wins_over_the_reference_date(self, rmock):
        dataset = self._harvest(rmock, publicationDate="2021-06-15", referenceDate="2019-01-01")
        assert dataset.harvest.created_at == datetime(2021, 6, 15)

    def test_several_publication_dates_resolve_to_the_earliest(self, rmock):
        # One record in 400 publishes a list; it was first published on the
        # earliest of them, not on whichever the index lists first.
        dataset = self._harvest(rmock, publicationDate=["2022-08-24", "2020-02-01", "2023-10-30"])
        assert dataset.harvest.created_at == datetime(2020, 2, 1)

    def test_a_record_without_any_date_is_not_failed(self, rmock):
        dataset = self._harvest(rmock)
        assert dataset.harvest.created_at is None
        assert dataset.created_at == dataset.created_at_internal

    def test_an_unparseable_date_is_not_failed(self, rmock):
        """The old assignment would have raised `AttributeError` here.

        `Dataset.created_at` has no setter, so uncommenting the original block
        would have failed every record carrying a date -- not just the bad one.
        """
        dataset = self._harvest(rmock, publicationDate="não é uma data")
        assert dataset.harvest.created_at is None

    def test_a_numeric_timestamp_does_not_fail_the_item(self, rmock):
        """`dateutil` raises OverflowError here, not ParserError."""
        dataset = self._harvest(rmock, publicationDate="1623715200000")
        assert dataset.harvest.created_at is None

    def test_an_unreadable_publication_date_falls_back_to_the_reference_date(self, rmock):
        dataset = self._harvest(rmock, publicationDate="não é uma data", referenceDate="2020-12-31")
        assert dataset.harvest.created_at == datetime(2020, 12, 31)

    def test_a_future_date_is_refused(self, rmock):
        ahead = (datetime.now(UTC) + timedelta(days=365)).strftime("%Y-%m-%d")
        dataset = self._harvest(rmock, publicationDate=ahead)
        assert dataset.harvest.created_at is None

    def test_the_date_survives_a_re_harvest(self, rmock):
        """`update_dataset_harvest_info` runs after this and must not clear it."""
        self._harvest(rmock, publicationDate="2021-06-15")
        dataset = self._harvest(rmock, publicationDate="2021-06-15")
        assert dataset.harvest.created_at == datetime(2021, 6, 15)


class DGTFrequencyMappingTest:
    """`map_iso_maintenance_frequency` over the codelist the source uses."""

    @pytest.mark.parametrize(
        "published,expected",
        [
            # The eight values the DGT index actually carries, by frequency.
            ("asNeeded", UpdateFrequency.PUNCTUAL),
            ("notPlanned", UpdateFrequency.NOT_PLANNED),
            ("unknown", UpdateFrequency.UNKNOWN),
            ("daily", UpdateFrequency.DAILY),
            ("continual", UpdateFrequency.CONTINUOUS),
            ("annually", UpdateFrequency.ANNUAL),
            ("biannually", UpdateFrequency.SEMIANNUAL),
            ("irregular", UpdateFrequency.IRREGULAR),
            # The rest of the codelist.
            ("weekly", UpdateFrequency.WEEKLY),
            ("fortnightly", UpdateFrequency.BIWEEKLY),
            ("monthly", UpdateFrequency.MONTHLY),
            ("quarterly", UpdateFrequency.QUARTERLY),
            ("biennially", UpdateFrequency.BIENNIAL),
            ("semimonthly", UpdateFrequency.SEMIMONTHLY),
            ("periodic", UpdateFrequency.OTHER),
        ],
    )
    def test_the_codelist_maps_onto_the_vocabulary(self, published, expected):
        assert map_iso_maintenance_frequency(published) == expected

    @pytest.mark.parametrize("published", ["asNeeded", "AS_NEEDED", " as needed ", "ASNEEDED"])
    def test_casing_and_separators_do_not_matter(self, published):
        assert map_iso_maintenance_frequency(published) == UpdateFrequency.PUNCTUAL

    @pytest.mark.parametrize("published", [None, "", "   ", "sempre que der jeito", "n/a"])
    def test_anything_unnamed_is_unknown(self, published):
        assert map_iso_maintenance_frequency(published) == UpdateFrequency.UNKNOWN


@pytest.mark.options(HARVESTER_BACKENDS=["dgt"])
class DGTFrequencyHarvestTest(PytestOnlyDBTestCase):
    """The frequency a real harvest writes on the dataset."""

    def _harvest(self, rmock, **fields):
        rmock.get(DGT_URL, text=_index_payload([_index_record(REMOTE_ID, None, **fields)]))
        source = HarvestSourceFactory(backend="dgt", url=DGT_URL)
        job = DGTBackend(source).harvest()
        assert [item.status for item in job.items] == ["done"], [
            error.message for item in job.items for error in item.errors
        ]
        return harvested_dataset(REMOTE_ID)

    def test_the_sources_frequency_reaches_the_dataset(self, rmock):
        dataset = self._harvest(rmock, updateFrequency="asNeeded")
        assert dataset.frequency == UpdateFrequency.PUNCTUAL

    def test_the_lneg_record_is_not_planned(self, rmock):
        dataset = self._harvest(rmock, updateFrequency="notPlanned")
        assert dataset.frequency == UpdateFrequency.NOT_PLANNED

    def test_a_record_without_a_frequency_is_unknown(self, rmock):
        dataset = self._harvest(rmock)
        assert dataset.frequency == UpdateFrequency.UNKNOWN

    def test_an_unmapped_frequency_does_not_fail_the_item(self, rmock):
        dataset = self._harvest(rmock, updateFrequency="sempre que der jeito")
        assert dataset.frequency == UpdateFrequency.UNKNOWN


# The LNEG record's own bounding box, verbatim: Neves-Corvo, in the Alentejo.
LNEG_GEO_BOX = "-8.13|37.46|-7.77|37.68"


class DGTGeoBoxTest:
    """`_geo_boxes` and `bbox_to_multipolygon`."""

    def test_the_lneg_box_is_read_as_four_numbers(self):
        assert DGTBackend._geo_boxes({"geoBox": LNEG_GEO_BOX}) == [(-8.13, 37.46, -7.77, 37.68)]

    def test_several_boxes_are_all_kept(self):
        published = [
            "-8.49706|39.52706|-6.693817|41.819792",
            "-8.482288|39.532618|-6.822819|41.353713",
        ]
        assert len(DGTBackend._geo_boxes({"geoBox": published})) == 2

    @pytest.mark.parametrize(
        "published",
        [None, "", "lixo", "-8.13|37.46", "-8.13|37.46|-7.77", "a|b|c|d", {"minx": 1}],
    )
    def test_anything_that_is_not_four_numbers_is_dropped(self, published):
        assert DGTBackend._geo_boxes({"geoBox": published}) == []

    def test_the_ring_is_closed_and_counter_clockwise(self):
        geom = bbox_to_multipolygon([(-8.13, 37.46, -7.77, 37.68)])
        assert geom["type"] == "MultiPolygon"
        (ring,) = geom["coordinates"][0]
        assert len(ring) == 5
        assert ring[0] == ring[-1]
        assert ring == [
            [-8.13, 37.46],
            [-7.77, 37.46],
            [-7.77, 37.68],
            [-8.13, 37.68],
            [-8.13, 37.46],
        ]

    def test_the_axes_are_longitude_then_latitude(self):
        """What the swap guard cannot catch: lon and lat transposed.

        A closed five-vertex ring looks identical either way round, so the
        values are asserted. Mainland Portugal sits at lon -6..-10, lat 37..42.
        """
        geom = bbox_to_multipolygon(DGTBackend._geo_boxes({"geoBox": LNEG_GEO_BOX}))
        (ring,) = geom["coordinates"][0]
        for longitude, latitude in ring:
            assert -10 < longitude < -6, ring
            assert 36 < latitude < 43, ring

    def test_an_inverted_box_is_normalized(self):
        inverted = bbox_to_multipolygon([(-7.77, 37.68, -8.13, 37.46)])
        upright = bbox_to_multipolygon([(-8.13, 37.46, -7.77, 37.68)])
        assert inverted == upright

    def test_a_point_becomes_a_polygon_with_area(self):
        geom = bbox_to_multipolygon([(-8.13, 37.46, -8.13, 37.46)])
        (ring,) = geom["coordinates"][0]
        assert len({tuple(vertex) for vertex in ring}) == 4
        width = ring[1][0] - ring[0][0]
        height = ring[2][1] - ring[1][1]
        assert width > 0 and height > 0


@pytest.mark.options(HARVESTER_BACKENDS=["dgt"])
class DGTSpatialHarvestTest(PytestOnlyDBTestCase):
    """The spatial coverage a real harvest writes on the dataset."""

    def _harvest(self, rmock, remote_id=REMOTE_ID, **fields):
        rmock.get(DGT_URL, text=_index_payload([_index_record(remote_id, None, **fields)]))
        source = HarvestSourceFactory(backend="dgt", url=DGT_URL)
        job = DGTBackend(source).harvest()
        assert [item.status for item in job.items] == ["done"], [
            error.message for item in job.items for error in item.errors
        ]
        return harvested_dataset(remote_id)

    def test_a_record_with_a_geobox_gets_spatial_coverage(self, rmock):
        dataset = self._harvest(
            rmock, remote_id=LNEG_REMOTE_ID, link=LNEG_LINK, geoBox=LNEG_GEO_BOX
        )
        assert dataset.spatial is not None
        assert dataset.spatial.geom["type"] == "MultiPolygon"
        (ring,) = dataset.spatial.geom["coordinates"][0]
        assert ring[0] == [-8.13, 37.46]

    def test_a_record_without_a_geobox_has_no_coverage(self, rmock):
        dataset = self._harvest(rmock)
        assert dataset.spatial is None

    @pytest.mark.parametrize(
        "published",
        [
            "lixo",
            # `float` reads these without complaint, and a non-finite corner
            # reaches the model intact and fails the item at save time -- the
            # swap guard cannot catch it, since every NaN comparison is false.
            "nan|nan|nan|nan",
            "-inf|37.0|-7.0|inf",
            # Projected metres, not degrees: several thousand degrees off the
            # map, and nothing downstream would reject it.
            "-120000|-300000|165000|280000",
        ],
    )
    def test_an_unusable_geobox_does_not_fail_the_item(self, rmock, published):
        dataset = self._harvest(rmock, geoBox=published)
        assert dataset.spatial is None

    def test_several_boxes_become_several_polygons(self, rmock):
        dataset = self._harvest(
            rmock,
            geoBox=[
                "-8.49706|39.52706|-6.693817|41.819792",
                "-8.482288|39.532618|-6.822819|41.353713",
            ],
        )
        assert len(dataset.spatial.geom["coordinates"]) == 2


class DGTSourceTagTest(PytestOnlyDBTestCase):
    """The tag names the host the record was harvested from."""

    def test_the_tag_is_the_hostname_of_the_source(self, rmock):
        url = "https://snig.example.pt/rndg/srv/por/q?_content_type=json"
        rmock.get(url, text=_index_payload([_index_record(REMOTE_ID, None)]))
        source = HarvestSourceFactory(backend="dgt", url=url)
        job = DGTBackend(source).harvest()
        assert [item.status for item in job.items] == ["done"]

        # `TagListField` slugifies, as it did with the constant.
        dataset = harvested_dataset(REMOTE_ID)
        assert "snig-example-pt" in dataset.tags
        assert "snig-dgterritorio-gov-pt" not in dataset.tags


# One record copied verbatim out of the SNIG index on 2026-09-23, via
# `?_content_type=json&fast=index&resultType=details&from=1&to=1`, with the
# editor's `userinfo` removed. It carries no `publicationDate` -- only a
# `referenceDate` and a `changeDate` -- and two `responsibleParty` entries.
SNIG_RECORD_PATH = os.path.join(os.path.dirname(__file__), "dgt", "snig_record.json")
with open(SNIG_RECORD_PATH, encoding="utf-8") as fh:
    SNIG_RECORD = json.load(fh)["metadata"][0]
SNIG_REMOTE_ID = SNIG_RECORD["geonet:info"]["uuid"]


def _recorded_record(**overrides):
    """The recorded SNIG record, with `overrides` set and `None` values removed."""
    record = copy.deepcopy(SNIG_RECORD)
    for key, value in overrides.items():
        if value is None:
            record.pop(key, None)
        else:
            record[key] = value
    return record


class DGTChangeDateTest(PytestOnlyDBTestCase):
    """The dates the listing and `Dataset.last_modified` read, from the source."""

    def _harvest(self, rmock, **overrides):
        rmock.get(DGT_URL, text=_index_payload([_recorded_record(**overrides)]))
        source = HarvestSourceFactory(backend="dgt", url=DGT_URL)
        job = DGTBackend(source).harvest()
        assert [item.status for item in job.items] == ["done"], [
            error.message for item in job.items for error in item.errors
        ]
        return harvested_dataset(SNIG_REMOTE_ID)

    def test_the_publication_date_also_drives_the_listing_order(self, rmock):
        dataset = self._harvest(rmock, publicationDate="2016-07-01")
        assert dataset.harvest.created_at == datetime(2016, 7, 1)
        # What `DEFAULT_SORTING` sorts the public listing on.
        assert dataset.created_at_internal == datetime(2016, 7, 1)

    def test_the_recorded_reference_date_stands_in_for_the_listing_too(self, rmock):
        # The record as published: `publicationDate` is absent.
        dataset = self._harvest(rmock)
        assert dataset.harvest.created_at == datetime(2016, 6, 17)
        assert dataset.created_at_internal == datetime(2016, 6, 17)

    def test_the_change_date_is_the_last_modification(self, rmock):
        dataset = self._harvest(rmock)
        assert dataset.harvest.modified_at == datetime(2018, 4, 7)
        assert dataset.last_modified_internal == datetime(2018, 4, 7)
        assert dataset.last_modified == datetime(2018, 4, 7)

    def test_several_change_dates_resolve_to_the_latest(self, rmock):
        dataset = self._harvest(rmock, changeDate=["2018-04-07", "2021-03-02", "2019-01-01"])
        assert dataset.harvest.modified_at == datetime(2021, 3, 2)

    @pytest.mark.parametrize("published", ["não é uma data", "1623715200000"])
    def test_an_unreadable_change_date_does_not_fail_the_item(self, rmock, published):
        dataset = self._harvest(rmock, changeDate=published)
        assert dataset.harvest.modified_at is None

    def test_a_future_change_date_is_refused(self, rmock):
        ahead = (datetime.now(UTC) + timedelta(days=365)).strftime("%Y-%m-%d")
        dataset = self._harvest(rmock, changeDate=ahead)
        assert dataset.harvest.modified_at is None

    def test_a_record_without_dates_keeps_the_harvest_dates(self, rmock):
        dataset = self._harvest(rmock, referenceDate=None, changeDate=None)
        assert dataset.harvest.created_at is None
        assert dataset.harvest.modified_at is None
