"""DGT harvester: resource identity (LEDG-2251) and licence derivation (LEDG-2518)."""

import json

import pytest

from udata.core.dataset.factories import LicenseFactory
from udata.models import License
from udata.tests.api import PytestOnlyDBTestCase

from ..backends.dgt import (
    DERIVED_LICENSE_EXTRA,
    MAX_CONSTRAINT_ENTRIES,
    MAX_CONSTRAINT_LENGTH,
    DGTBackend,
    license_id_from_legal_constraints,
)
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


def _index_record(remote_id, legal_constraints, title="Carta geológica"):
    """One record shaped the way the SNIG `fast=index` response shapes it."""
    record = {
        "geonet:info": {"uuid": remote_id},
        "defaultTitle": title,
        "defaultAbstract": "Cartografia temática",
        "keyword": ["geo"],
        "link": f"nome|desc|{ZIP_URL}|WWW:LINK|zip",
    }
    if legal_constraints is not None:
        record["legalConstraints"] = legal_constraints
    return record


def _index_payload(records):
    return json.dumps({"metadata": records})


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
