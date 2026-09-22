"""Resource identity across generic CSW harvests (LEDG-2251)."""

from types import SimpleNamespace

import pytest

from udata.core.dataset.factories import LicenseFactory
from udata.models import License
from udata.tests.api import PytestOnlyDBTestCase

from ..backends.cswudata import CSWUdataBackend, resource_format
from ..backends.tools.harvester_utils import DERIVED_LICENSE_EXTRA
from .factories import HarvestSourceFactory
from .id_stability import harvest, harvested_dataset, resource_ids, resource_urls

CSW_URL = "https://geoportal.example.pt/geoportal/csw"
REMOTE_ID = "{ABCDEF01-0000-4000-8000-000000000001}"
WMS_URL = "https://geoportal.example.pt/services/INSPIRE/MapServer/WMSServer"
FILE_URL = "https://geoportal.example.pt/docs/relatorio.pdf"


def _payload(resources, title="Registo CSW"):
    return {
        "id": REMOTE_ID,
        "title": title,
        "description": "Descrição do registo",
        "tags": ["ambiente"],
        "type": "dataset",
        "resources": resources,
    }


def _wms(name="Serviço WMS"):
    return {"url": WMS_URL, "protocol": "OGC:WMS", "name": name}


def _file(name="Relatório"):
    return {"url": FILE_URL, "protocol": "WWW:DOWNLOAD-1.0-http--download", "name": name}


@pytest.mark.options(HARVESTER_BACKENDS=["cswudata"])
class CswUdataResourceIdentityTest(PytestOnlyDBTestCase):
    def _source(self):
        return HarvestSourceFactory(backend="cswudata", url=CSW_URL)

    def test_reharvest_keeps_the_resource_ids(self):
        source = self._source()
        harvest(CSWUdataBackend, source, REMOTE_ID, items=_payload([_wms(), _file()]))
        before = resource_ids(REMOTE_ID)
        assert len(before) == 2

        harvest(CSWUdataBackend, source, REMOTE_ID, items=_payload([_wms(), _file()]))

        assert resource_ids(REMOTE_ID) == before

    def test_renamed_resource_keeps_its_id(self):
        source = self._source()
        harvest(CSWUdataBackend, source, REMOTE_ID, items=_payload([_wms()]))
        before = resource_ids(REMOTE_ID)

        harvest(CSWUdataBackend, source, REMOTE_ID, items=_payload([_wms("Outro nome")]))

        assert resource_ids(REMOTE_ID) == before
        assert [r.title for r in harvested_dataset(REMOTE_ID).resources] == ["Outro nome"]

    def test_resource_dropped_upstream_disappears(self):
        source = self._source()
        harvest(CSWUdataBackend, source, REMOTE_ID, items=_payload([_wms(), _file()]))
        wms_id = resource_ids(REMOTE_ID)[0]

        harvest(CSWUdataBackend, source, REMOTE_ID, items=_payload([_wms()]))

        assert resource_urls(REMOTE_ID) == [WMS_URL]
        assert resource_ids(REMOTE_ID) == [wms_id]


@pytest.mark.options(HARVESTER_BACKENDS=["cswudata"])
class CswUdataDefaultTagTest(PytestOnlyDBTestCase):
    """Every dataset carries a tag naming its producer, plus the record's own.

    The producer tag used to be read from a `default_tag` key on the source
    config, which the source form has no way of writing -- only declared extra
    configs are stored -- so it was unreachable and every source fell back to
    the literal "csw" (LEDG-2492).
    """

    def _source(self, default_tag=None):
        config = {"extra_configs": [{"key": "default_tag", "value": default_tag}]}
        return HarvestSourceFactory(
            backend="cswudata", url=CSW_URL, config=config if default_tag else {}
        )

    def test_configured_default_tag_is_written(self):
        source = self._source(default_tag="apambiente.pt")

        harvest(CSWUdataBackend, source, REMOTE_ID, items=_payload([_file()]))

        # Stored slugified, as every tag is: the dotted form is what a human
        # types into the source form.
        assert "apambiente-pt" in harvested_dataset(REMOTE_ID).tags

    def test_hostname_is_the_fallback_tag(self):
        source = self._source()

        harvest(CSWUdataBackend, source, REMOTE_ID, items=_payload([_file()]))

        assert "geoportal-example-pt" in harvested_dataset(REMOTE_ID).tags

    def test_subjects_become_tags(self):
        source = self._source(default_tag="apambiente.pt")

        harvest(CSWUdataBackend, source, REMOTE_ID, items=_payload([_file()]))

        # `_payload` carries the record's own subjects; they join the producer tag
        # instead of replacing it.
        assert set(harvested_dataset(REMOTE_ID).tags) == {"apambiente-pt", "ambiente"}


GEODOCS = "https://sniambgeoviewer.apambiente.pt/GeoDocs/geoportaldocs"

# Verbatim `dct:references` value of a real Esri Geoportal record: the path is
# concatenated with itself, and the resulting link 404s upstream (LEDG-2250).
DUPLICATED_REFERENCE = (
    f"{GEODOCS}/_Clima/PortalAcaoClimatica_Emissoes2030/meta_2030_0.xlsx"
    "_Clima/PortalAcaoClimatica_Emissoes2030/meta_2030_0.xlsx"
)
REPAIRED_URL = f"{GEODOCS}/_Clima/PortalAcaoClimatica_Emissoes2030/meta_2030_0.xlsx"

ESRI_DATA_SCHEME = "urn:x-esri:specification:ServiceType:ArcIMS:Metadata:Server"


class ResourceFormatTest:
    """`resource_format` reads the declared link before falling back to the URL."""

    def test_ogc_protocol_names_the_service(self):
        assert resource_format("ogc:wfs", "dataset", WMS_URL) == "wfs"

    def test_bare_wms_protocol_without_a_prefix(self):
        assert resource_format("wms", "dataset", WMS_URL) == "wms"

    def test_live_data_record_is_wms(self):
        assert resource_format("", "liveData", WMS_URL) == "wms"

    def test_mime_type_protocol(self):
        assert resource_format("image/jpeg", "dataset", "https://host/tile") == "jpeg"

    def test_extension_less_url_falls_back_to_remote(self):
        assert resource_format("", "dataset", "https://host/no-extension") == "remote"

    def test_a_four_letter_extension_survives(self):
        # The heuristic this replaced rewrote anything longer than three
        # characters to `wms`, publishing spreadsheets as map services.
        assert resource_format("", "dataset", REPAIRED_URL) == "xlsx"


@pytest.mark.options(HARVESTER_BACKENDS=["cswudata"])
class CswUdataResourceFormatTest(PytestOnlyDBTestCase):
    def _source(self):
        return HarvestSourceFactory(backend="cswudata", url=CSW_URL)

    def test_duplicated_reference_is_repaired_and_typed_xlsx(self):
        source = self._source()
        reference = {"url": DUPLICATED_REFERENCE, "scheme": ESRI_DATA_SCHEME}

        harvest(CSWUdataBackend, source, REMOTE_ID, items=_payload([reference]))

        assert resource_urls(REMOTE_ID) == [REPAIRED_URL]
        assert [r.format for r in harvested_dataset(REMOTE_ID).resources] == ["xlsx"]

    def test_scheme_is_read_like_protocol(self):
        # The Esri Geoportal declares the link type under `scheme`; this backend
        # only ever looked at `protocol`, so the service went out untyped.
        source = self._source()
        reference = {"url": WMS_URL, "scheme": "OGC:WMS"}

        harvest(CSWUdataBackend, source, REMOTE_ID, items=_payload([reference]))

        assert [r.format for r in harvested_dataset(REMOTE_ID).resources] == ["wms"]

    def test_both_link_shapes_become_resources(self):
        source = self._source()
        payload = _payload([_wms(), {"url": FILE_URL, "scheme": ESRI_DATA_SCHEME}])

        harvest(CSWUdataBackend, source, REMOTE_ID, items=payload)

        assert sorted(resource_urls(REMOTE_ID)) == sorted([WMS_URL, FILE_URL])


class FakeCatalogue:
    """Enough of `owslib`'s `CatalogueServiceWeb` to drive `inner_harvest`.

    The real client is not exercised on purpose: what these tests are about is
    the loop around it -- which records it collects and when it stops -- not
    owslib's XML parsing.
    """

    def __init__(self, url, timeout=None):
        self.url = url
        self.operations = []
        self.results = {}
        self.records = {}
        self.calls = []
        self.pages = []

    def getrecords2(self, maxrecords=10, startposition=1, esn=None):
        self.calls.append({"maxrecords": maxrecords, "startposition": startposition})
        if maxrecords == 1:
            # The probe request: only `matches` is read from it.
            self.results = {"matches": self.matches, "nextrecord": 1}
            self.records = {}
            return
        records, nextrecord = self.pages.pop(0)
        self.results = {"matches": self.matches, "nextrecord": nextrecord}
        self.records = {record.identifier: record for record in records}


def csw_record(remote_id=REMOTE_ID, uris=None, references=None, **fields):
    """A `CswRecord`-shaped object carrying only what `inner_harvest` reads."""
    return SimpleNamespace(
        identifier=remote_id,
        title=fields.get("title", "Registo CSW"),
        abstract=fields.get("abstract", "Descrição do registo"),
        subjects=fields.get("subjects", []),
        bbox=fields.get("bbox"),
        type=fields.get("type", "dataset"),
        created=fields.get("created"),
        modified=fields.get("modified"),
        uris=uris or [],
        references=references or [],
    )


def run_inner_harvest(monkeypatch, rmock, source, pages, matches):
    """Run a real `inner_harvest` against `pages`, returning the fake catalogue."""
    catalogue = {}

    def build(url, timeout=None):
        client = FakeCatalogue(url, timeout=timeout)
        client.matches = matches
        client.pages = list(pages)
        catalogue["client"] = client
        return client

    monkeypatch.setattr("udata.harvest.backends.cswudata.CatalogueServiceWeb", build)
    # `inner_harvest` resolves redirects with a guarded GET before touching owslib.
    rmock.get(CSW_URL, text="")

    backend = CSWUdataBackend(source)
    backend.harvest()
    return catalogue["client"]


@pytest.mark.options(HARVESTER_BACKENDS=["cswudata"])
class CswUdataRecordLinksTest(PytestOnlyDBTestCase):
    """`dc:URI` and `dct:references` are both read, never one instead of the other."""

    def _source(self):
        return HarvestSourceFactory(backend="cswudata", url=CSW_URL)

    def test_references_survive_a_record_that_also_has_a_uri(self, monkeypatch, rmock):
        # One `dc:URI` -- a thumbnail is enough -- used to discard every
        # reference, and with it the resource the dataset was published with,
        # whose id then died on the next harvest.
        record = csw_record(
            uris=[{"url": WMS_URL, "protocol": "OGC:WMS"}],
            references=[{"url": FILE_URL, "scheme": ESRI_DATA_SCHEME}],
        )

        run_inner_harvest(monkeypatch, rmock, self._source(), [([record], 0)], matches=1)

        assert sorted(resource_urls(REMOTE_ID)) == sorted([WMS_URL, FILE_URL])

    def test_a_link_announced_in_both_lists_yields_one_resource(self, monkeypatch, rmock):
        # Summing the two lists is only safe because `sync_resources` reconciles
        # by URL; without that, a catalogue announcing a link in both fields
        # would publish it twice.
        record = csw_record(
            uris=[{"url": FILE_URL, "protocol": "WWW:DOWNLOAD-1.0-http--download"}],
            references=[{"url": FILE_URL, "scheme": ESRI_DATA_SCHEME}],
        )

        run_inner_harvest(monkeypatch, rmock, self._source(), [([record], 0)], matches=1)

        assert resource_urls(REMOTE_ID) == [FILE_URL]


ESRI_METADATA_SCHEME = "urn:x-esri:specification:ServiceType:ArcIMS:Metadata:Document"
METADATA_URL = "https://geoportal.example.pt/geoportal/rest/document?id=%7BABC%7D"


@pytest.mark.options(HARVESTER_BACKENDS=["cswudata"])
class CswUdataRemoteUrlTest(PytestOnlyDBTestCase):
    def _source(self):
        return HarvestSourceFactory(backend="cswudata", url=CSW_URL)

    def test_metadata_document_becomes_remote_url_not_a_resource(self):
        source = self._source()
        links = [{"url": METADATA_URL, "scheme": ESRI_METADATA_SCHEME}, _file()]

        harvest(CSWUdataBackend, source, REMOTE_ID, items=_payload(links))

        dataset = harvested_dataset(REMOTE_ID)
        assert dataset.harvest.remote_url == METADATA_URL
        # The metadata document describes the dataset; it is not one of its files.
        assert resource_urls(REMOTE_ID) == [FILE_URL]

    def test_html_protocol_still_becomes_remote_url(self):
        source = self._source()
        landing = {"url": METADATA_URL, "protocol": "WWW:LINK-1.0-http--link"}

        harvest(CSWUdataBackend, source, REMOTE_ID, items=_payload([landing, _file()]))

        assert harvested_dataset(REMOTE_ID).harvest.remote_url == METADATA_URL


@pytest.mark.options(HARVESTER_BACKENDS=["cswudata"])
class CswUdataDatesTest(PytestOnlyDBTestCase):
    """The record's dates land on the harvest metadata, not on a read-only property."""

    def _source(self):
        return HarvestSourceFactory(backend="cswudata", url=CSW_URL)

    def _harvest(self, **dates):
        payload = _payload([_file()]) | dates
        harvest(CSWUdataBackend, self._source(), REMOTE_ID, items=payload)
        return harvested_dataset(REMOTE_ID)

    def test_created_and_modified_land_on_the_harvest_metadata(self):
        # `Dataset.created_at` is a read-only property, so the assignment this
        # replaced raised `AttributeError` and failed the whole item.
        dataset = self._harvest(created="2019-03-04", modified="2024-11-20T10:15:00Z")

        assert dataset.harvest.created_at.date().isoformat() == "2019-03-04"
        assert dataset.harvest.modified_at.date().isoformat() == "2024-11-20"
        # Both are what the public properties read back.
        assert dataset.created_at.date().isoformat() == "2019-03-04"
        assert dataset.last_modified.date().isoformat() == "2024-11-20"

    def test_an_unreadable_date_does_not_fail_the_item(self):
        dataset = self._harvest(created="não disponível", modified=None)

        assert dataset.harvest.created_at is None
        assert dataset.harvest.modified_at is None

    def test_a_future_date_is_refused(self):
        dataset = self._harvest(modified="2999-01-01")

        assert dataset.harvest.modified_at is None


@pytest.mark.options(HARVESTER_BACKENDS=["cswudata"])
class CswUdataLicenseTest(PytestOnlyDBTestCase):
    """The licence comes from `dc:rights`, never from a constant.

    This backend used to stamp `cc-by` on every record, publishing a licence the
    catalogues do not grant -- the complaint that was raised against the DGT
    harvester, on a larger population (LEDG-2518, LEDG-2492).
    """

    def _licenses(self):
        # The test database carries no licences, and LicenseFactory would give
        # each one a random id, so the ones under test are seeded by id.
        LicenseFactory(id="notspecified", title="License Not Specified")
        LicenseFactory(
            id="cc-by",
            title="Creative Commons Attribution 4.0 - CC BY 4.0",
            url="https://creativecommons.org/licenses/by/4.0/",
        )
        LicenseFactory(id="odbl", title="Open Data Commons Open Database License")

    def _harvest(self, rights=None, remote_id=REMOTE_ID):
        source = HarvestSourceFactory(backend="cswudata", url=CSW_URL)
        payload = _payload([_file()]) | {"rights": rights or []}
        harvest(CSWUdataBackend, source, remote_id, items=payload)
        return harvested_dataset(remote_id)

    def test_rights_naming_a_license_resolve_it(self):
        self._licenses()

        dataset = self._harvest(rights=["https://creativecommons.org/licenses/by/4.0/"])

        assert dataset.license.id == "cc-by"
        assert dataset.extras[DERIVED_LICENSE_EXTRA] == "cc-by"

    def test_no_rights_is_notspecified(self):
        self._licenses()

        dataset = self._harvest()

        assert dataset.license.id == "notspecified"
        assert dataset.extras[DERIVED_LICENSE_EXTRA] == "notspecified"

    def test_unresolvable_rights_fall_back_to_the_default(self):
        self._licenses()

        dataset = self._harvest(rights=["Consultar o produtor"])

        assert dataset.license.id == "notspecified"

    def test_manual_license_survives_a_source_without_rights(self):
        self._licenses()
        dataset = self._harvest()
        # A producer corrects it by hand, which clears the derived marker.
        # Deliberately not `cc-by`: that was the value the harvester itself used
        # to stamp, so a test using it would pass against the bug as well.
        dataset.license = License.objects(id="odbl").first()
        dataset.extras.pop(DERIVED_LICENSE_EXTRA, None)
        dataset.save()

        again = self._harvest()

        assert again.license.id == "odbl"

    def test_the_harvesters_own_license_is_revocable(self):
        # The guard that makes the correction above survive must not also make
        # the harvester's own value permanent: a source that stops granting a
        # licence has to be able to take it back.
        self._licenses()
        first = self._harvest(rights=["https://creativecommons.org/licenses/by/4.0/"])
        assert first.license.id == "cc-by"

        again = self._harvest()

        assert again.license.id == "notspecified"


def owslib_bbox(minx, miny, maxx, maxy):
    """The shape owslib hands over for `ows:BoundingBox`."""
    return SimpleNamespace(minx=minx, miny=miny, maxx=maxx, maxy=maxy)


@pytest.mark.options(HARVESTER_BACKENDS=["cswudata"])
class CswUdataSpatialTest(PytestOnlyDBTestCase):
    """The bounding box becomes the coverage, through the shared helper.

    The geometry assertions are written out in full rather than compared with
    `bbox_to_multipolygon`, so they would catch the helper and this backend
    drifting together.
    """

    def _harvest(self, bbox):
        source = HarvestSourceFactory(backend="cswudata", url=CSW_URL)
        harvest(CSWUdataBackend, source, REMOTE_ID, items=_payload([_file()]) | {"bbox": bbox})
        return harvested_dataset(REMOTE_ID)

    def test_bbox_becomes_a_closed_counter_clockwise_ring(self):
        dataset = self._harvest(owslib_bbox("-9.5", "36.9", "-6.2", "42.2"))

        assert dataset.spatial.geom == {
            "type": "MultiPolygon",
            "coordinates": [
                [
                    [
                        [-9.5, 36.9],
                        [-6.2, 36.9],
                        [-6.2, 42.2],
                        [-9.5, 42.2],
                        [-9.5, 36.9],
                    ]
                ]
            ],
        }

    def test_point_bbox_is_widened(self):
        # A zero-area ring is not a polygon, and `SpatialCoverage.geom` only
        # accepts MultiPolygon.
        dataset = self._harvest(owslib_bbox(-8.0, 40.0, -8.0, 40.0))

        ring = dataset.spatial.geom["coordinates"][0][0]
        assert ring[0] == [-8.0001, 39.9999]
        assert ring[2] == [-7.9999, 40.0001]

    def test_swapped_corners_are_reordered(self):
        dataset = self._harvest(owslib_bbox(-6.2, 42.2, -9.5, 36.9))

        assert dataset.spatial.geom["coordinates"][0][0][0] == [-9.5, 36.9]

    def test_unreadable_bbox_costs_the_coverage_not_the_dataset(self):
        dataset = self._harvest(owslib_bbox("oeste", "sul", "este", "norte"))

        assert dataset.spatial is None


@pytest.mark.options(HARVESTER_BACKENDS=["cswudata"])
class CswUdataPaginationTest(PytestOnlyDBTestCase):
    """The record loop has to stop when the server says there is no next record.

    The backend this one absorbs looped instead: it started at 0 and tested
    `startposition <= matches`, so the `nextrecord = 0` of the last page put it
    straight back at the first -- an infinite harvest, latent only because the
    source never returned the shape that triggers it on a run anybody watched.
    """

    def _source(self):
        return HarvestSourceFactory(backend="cswudata", url=CSW_URL)

    def _records(self, first, count=2):
        # Two records per page, not the hundred the server would send: what is
        # under test is which positions get requested, and every extra record
        # is a dataset written to the database for nothing.
        return [csw_record(remote_id=f"{{REC-{n:04d}}}") for n in range(first, first + count)]

    def test_pagination_stops_when_nextrecord_is_zero(self, monkeypatch, rmock):
        pages = [
            (self._records(1), 101),
            (self._records(101), 201),
            (self._records(201), 0),
        ]

        catalogue = run_inner_harvest(monkeypatch, rmock, self._source(), pages, matches=250)

        # The probe (`maxrecords=1`) plus exactly one request per page.
        assert [call["startposition"] for call in catalogue.calls if call["maxrecords"] == 100] == [
            1,
            101,
            201,
        ]

    def test_a_zero_nextrecord_on_the_first_page_does_not_loop(self, monkeypatch, rmock):
        # The shape that made the old backend loop: the server announces many
        # matches but stops after one page.
        pages = [(self._records(1), 0)]

        catalogue = run_inner_harvest(monkeypatch, rmock, self._source(), pages, matches=3936)

        assert len([call for call in catalogue.calls if call["maxrecords"] == 100]) == 1

    def test_a_stale_nextrecord_does_not_loop(self, monkeypatch, rmock):
        # A server that keeps answering with a position at or behind the one
        # already requested would otherwise be followed forever.
        pages = [(self._records(1), 101), (self._records(101), 101)]

        catalogue = run_inner_harvest(monkeypatch, rmock, self._source(), pages, matches=250)

        assert [call["startposition"] for call in catalogue.calls if call["maxrecords"] == 100] == [
            1,
            101,
        ]
