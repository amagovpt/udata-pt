"""Behaviour of the INE HVD harvester: resource identity (LEDG-2251) and the
metadata it reads from the catalogue rather than hardcoding."""

import pytest

from udata.core.dataset.constants import UpdateFrequency
from udata.tests.api import PytestOnlyDBTestCase

from ..backends.inehvd import INEHvdBackend
from .factories import HarvestSourceFactory
from .id_stability import harvest, harvested_dataset, resource_ids, resource_urls

INEHVD_URL = "https://www.ine.pt/ine/xml_indic_hvd.jsp?opc=3&lang=PT"
REMOTE_ID = "0001"
DATASET_URL = "https://www.ine.pt/js/0001.json"
METAINFO_URL = "https://www.ine.pt/js/0001_metainfo.json"


def _indicator_xml(
    urls,
    title="Indicador HVD",
    periodicity="Anual",
    geo_lastlevel=None,
    source_description=None,
    update_type=None,
    metainfo_url=None,
):
    """Build an indicator fixture.

    `periodicity` keeps the value the existing tests were written against, and every other
    metadata kwarg defaults to `None` meaning "element not emitted", so those fixtures stay
    byte-for-byte identical.
    """
    slots = "".join(
        f"<{tag}><![CDATA[{url}]]></{tag}>" for tag, url in urls.items() if url is not None
    )
    extra = ""
    if geo_lastlevel:
        extra += f"<geo_lastlevel><![CDATA[{geo_lastlevel}]]></geo_lastlevel>"
    if source_description:
        extra += f"<source><![CDATA[{source_description}]]></source>"
    if update_type:
        extra += f"<update_type><![CDATA[{update_type}]]></update_type>"
    if metainfo_url:
        extra += f"<html><metainfo_url><![CDATA[{metainfo_url}]]></metainfo_url></html>"
    return (
        "<?xml version='1.0' encoding='UTF-8'?>"
        "<indicators>"
        f"<indicator id='{REMOTE_ID}'>"
        f"<title><![CDATA[{title}]]></title>"
        "<description><![CDATA[Descricao do indicador]]></description>"
        "<keywords>INE,estatistica</keywords>"
        f"<periodicity><![CDATA[{periodicity}]]></periodicity>"
        f"<json>{slots}</json>"
        f"{extra}"
        "</indicator>"
        "</indicators>"
    )


@pytest.mark.options(HARVESTER_BACKENDS=["inehvd"])
class INEHvdResourceIdentityTest(PytestOnlyDBTestCase):
    def _harvest(self, rmock, source, urls, title="Indicador HVD"):
        # The backend appends `varcd`/`lang` to the source URL; requests-mock
        # matches on the path, so one registration covers both requests.
        rmock.get("https://www.ine.pt/ine/xml_indic_hvd.jsp", text=_indicator_xml(urls, title))
        return harvest(INEHvdBackend, source, REMOTE_ID)

    def test_reharvest_keeps_the_resource_ids(self, rmock):
        source = HarvestSourceFactory(backend="inehvd", url=INEHVD_URL)
        urls = {"json_dataset": DATASET_URL, "json_metainfo": METAINFO_URL}
        self._harvest(rmock, source, urls)
        before = resource_ids(REMOTE_ID)
        assert len(before) == 2

        self._harvest(rmock, source, urls)

        assert resource_ids(REMOTE_ID) == before

    def test_title_change_upstream_keeps_the_resource_ids(self, rmock):
        source = HarvestSourceFactory(backend="inehvd", url=INEHVD_URL)
        urls = {"json_dataset": DATASET_URL, "json_metainfo": METAINFO_URL}
        self._harvest(rmock, source, urls)
        before = resource_ids(REMOTE_ID)

        self._harvest(rmock, source, urls, title="Indicador HVD revisto")

        assert harvested_dataset(REMOTE_ID).title == "Indicador HVD revisto"
        assert resource_ids(REMOTE_ID) == before

    def test_resource_dropped_upstream_disappears(self, rmock):
        source = HarvestSourceFactory(backend="inehvd", url=INEHVD_URL)
        self._harvest(rmock, source, {"json_dataset": DATASET_URL, "json_metainfo": METAINFO_URL})
        dataset_resource_id = resource_ids(REMOTE_ID)[0]

        self._harvest(rmock, source, {"json_dataset": DATASET_URL, "json_metainfo": None})

        assert resource_urls(REMOTE_ID) == [DATASET_URL]
        assert resource_ids(REMOTE_ID) == [dataset_resource_id]


@pytest.mark.options(HARVESTER_BACKENDS=["inehvd"])
class INEHvdSourceMetadataTest(PytestOnlyDBTestCase):
    """The HVD harvester reads the same catalogue as `ine`, so it maps it the same way."""

    URLS = {"json_dataset": DATASET_URL, "json_metainfo": METAINFO_URL}

    def _harvest(self, rmock, source, **kwargs):
        rmock.get(
            "https://www.ine.pt/ine/xml_indic_hvd.jsp",
            text=_indicator_xml(self.URLS, **kwargs),
        )
        harvest(INEHvdBackend, source, REMOTE_ID)
        return harvested_dataset(REMOTE_ID)

    def _source(self):
        return HarvestSourceFactory(backend="inehvd", url=INEHVD_URL)

    def test_periodicity_with_leading_space_maps_off_unknown(self, rmock):
        dataset = self._harvest(rmock, self._source(), periodicity=" Mensal")

        assert dataset.frequency == UpdateFrequency.MONTHLY

    def test_periodicity_the_previous_mapping_could_not_name(self, rmock):
        """ "Decenal" is 1786 indicators, and the superseded map sent all of them to unknown."""
        dataset = self._harvest(rmock, self._source(), periodicity="Decenal")

        assert dataset.frequency == UpdateFrequency.DECENNIAL

    def test_sexenal_becomes_other(self, rmock):
        dataset = self._harvest(rmock, self._source(), periodicity="Sexenal")

        assert dataset.frequency == UpdateFrequency.OTHER

    def test_unrecognised_periodicity_stays_unknown(self, rmock):
        dataset = self._harvest(rmock, self._source(), periodicity="De vez em quando")

        assert dataset.frequency == UpdateFrequency.UNKNOWN

    def test_source_tag_is_the_source_hostname(self, rmock):
        dataset = self._harvest(rmock, self._source())

        # Slugified on save, giving the same tag the `ine` backend stores.
        assert "www-ine-pt" in dataset.tags
        assert "ine.pt" not in dataset.tags

    def test_extras_include_metainfo_url_and_optional_update_type(self, rmock):
        dataset = self._harvest(
            rmock,
            self._source(),
            geo_lastlevel="Portugal",
            source_description="INE, Índice de preços",
            update_type="A",
            metainfo_url="https://www.ine.pt/xurl/metax/0001/PT",
        )

        assert dataset.extras["geo_lastlevel"] == "Portugal"
        assert dataset.extras["source_description"] == "INE, Índice de preços"
        assert dataset.extras["update_type"] == "A"
        assert dataset.extras["metainfo_url"] == "https://www.ine.pt/xurl/metax/0001/PT"

    def test_update_type_is_absent_when_the_source_omits_it(self, rmock):
        dataset = self._harvest(rmock, self._source(), geo_lastlevel="Portugal")

        assert "update_type" not in dataset.extras
