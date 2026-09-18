import os
import re
import xml.etree.ElementTree as ET
from datetime import date, timedelta

import pytest

from udata.core.dataset.constants import UpdateFrequency
from udata.core.dataset.factories import DatasetFactory
from udata.core.dataset.models import HarvestDatasetMetadata
from udata.core.organization.factories import OrganizationFactory
from udata.core.user.factories import UserFactory
from udata.models import Dataset
from udata.tests.api import PytestOnlyDBTestCase

from ..backends.ine import INEBackend, INEDownloadIncomplete
from .factories import HarvestSourceFactory

INE_URL = "https://www.ine.pt/ine/xml_indic.jsp?opc=2&lang=PT"
INE_HVD_URL = "https://www.ine.pt/ine/xml_indic_hvd.jsp?opc=3&lang=PT"

COMPLETE_XML = (
    "<?xml version='1.0' encoding='UTF-8'?>\n"
    "<catalog>\n"
    "<indicator id='0001'><title><![CDATA[Indicador A]]></title></indicator>\n"
    "</catalog>\n"
)

# Same payload but the connection dropped mid-stream: no closing </catalog>.
TRUNCATED_XML = (
    "<?xml version='1.0' encoding='UTF-8'?>\n"
    "<catalog>\n"
    "<indicator id='0001'><title><![CDATA[Indicador A]]></title></indicator>\n"
)


class INEIsCompleteXmlTest(PytestOnlyDBTestCase):
    def _backend(self):
        source = HarvestSourceFactory(backend="ine", url=INE_URL)
        return INEBackend(source)

    def test_complete_file_is_accepted(self, tmp_path):
        path = tmp_path / "ine.xml"
        path.write_text(COMPLETE_XML)
        assert self._backend()._is_complete_xml(str(path)) is True

    def test_truncated_file_is_rejected(self, tmp_path):
        path = tmp_path / "ine.xml"
        path.write_text(TRUNCATED_XML)
        assert self._backend()._is_complete_xml(str(path)) is False

    def test_empty_file_is_rejected(self, tmp_path):
        path = tmp_path / "ine.xml"
        path.write_text("")
        assert self._backend()._is_complete_xml(str(path)) is False

    def test_missing_file_is_rejected(self, tmp_path):
        assert self._backend()._is_complete_xml(str(tmp_path / "nope.xml")) is False


class INEDownloadToFileTest(PytestOnlyDBTestCase):
    def _backend(self, monkeypatch):
        # Avoid real backoff sleeps between retries.
        monkeypatch.setattr("udata.harvest.backends.ine.time.sleep", lambda *a, **k: None)
        source = HarvestSourceFactory(backend="ine", url=INE_URL)
        backend = INEBackend(source)
        backend.MAX_RETRIES = 3
        return backend

    def test_retries_truncated_download_then_succeeds(self, rmock, monkeypatch, tmp_path):
        # First transfer is truncated (connection dropped), second one is complete.
        rmock.get(INE_URL, [{"text": TRUNCATED_XML}, {"text": COMPLETE_XML}])
        dest = tmp_path / "ine.xml"

        self._backend(monkeypatch)._download_to_file(INE_URL, str(dest))

        assert dest.exists()
        content = dest.read_text()
        assert "</catalog>" in content
        assert "Indicador A" in content
        # No leftover .part file
        assert not (tmp_path / "ine.xml.part").exists()

    def test_falls_back_to_cached_valid_file_when_all_attempts_fail(
        self, rmock, monkeypatch, tmp_path
    ):
        rmock.get(INE_URL, text=TRUNCATED_XML)
        dest = tmp_path / "ine.xml"
        dest.write_text(COMPLETE_XML)  # previously cached valid download

        # Should not raise: the last valid file is reused.
        self._backend(monkeypatch)._download_to_file(INE_URL, str(dest))

        assert dest.read_text() == COMPLETE_XML

    def test_raises_when_truncated_and_no_cache(self, rmock, monkeypatch, tmp_path):
        rmock.get(INE_URL, text=TRUNCATED_XML)
        dest = tmp_path / "ine.xml"

        with pytest.raises(INEDownloadIncomplete):
            self._backend(monkeypatch)._download_to_file(INE_URL, str(dest))

        assert not dest.exists()
        assert not (tmp_path / "ine.xml.part").exists()


class INEPrefetchDatasetsTest(PytestOnlyDBTestCase):
    def test_prefetch_finds_existing_and_misses_absent(self):
        source = HarvestSourceFactory(backend="ine", url=INE_URL)
        existing = DatasetFactory(
            harvest=HarvestDatasetMetadata(
                remote_id="0001", source_id=str(source.id), domain=source.domain
            )
        )
        # Same remote_id but another source: must NOT match
        DatasetFactory(
            harvest=HarvestDatasetMetadata(
                remote_id="0002", source_id="other-source", domain="other.example.pt"
            )
        )
        backend = INEBackend(source)

        result = backend._prefetch_datasets(["0001", "0002", "0003"])

        assert set(result) == {"0001"}
        assert result["0001"].id == existing.id

    def test_new_dataset_inherits_source_organization(self):
        org = OrganizationFactory()
        source = HarvestSourceFactory(backend="ine", url=INE_URL, organization=org)
        backend = INEBackend(source)

        dataset = backend._new_dataset()

        assert dataset.id is None
        assert dataset.organization == org


def _catalog_xml(
    ids,
    revision="",
    periodicity=None,
    last_update=None,
    last_period=None,
    geo_lastlevel=None,
    source_description=None,
    update_type=None,
    metainfo_url=None,
):
    """Build a catalogue fixture.

    Every metadata kwarg defaults to `None` meaning "element not emitted", so the fixtures
    of the tests written before the source metadata was read stay byte-for-byte identical.
    """
    metainfo = f"<metainfo_url><![CDATA[{metainfo_url}]]></metainfo_url>" if metainfo_url else ""

    dates = ""
    if last_update or last_period:
        parts = ""
        if last_period:
            parts += f"<last_period_available><![CDATA[{last_period}]]></last_period_available>"
        if last_update:
            parts += f"<last_update><![CDATA[{last_update}]]></last_update>"
        dates = f"\n        <dates>{parts}</dates>"

    extra = dates
    if periodicity is not None:
        extra += f"\n        <periodicity><![CDATA[{periodicity}]]></periodicity>"
    if geo_lastlevel:
        extra += f"\n        <geo_lastlevel><![CDATA[{geo_lastlevel}]]></geo_lastlevel>"
    if source_description:
        extra += f"\n        <source><![CDATA[{source_description}]]></source>"
    if update_type:
        extra += f"\n        <update_type><![CDATA[{update_type}]]></update_type>"

    indicators = "\n".join(
        f"""<indicator id='{i}'>
        <title><![CDATA[Indicador {i}]]></title>
        <description><![CDATA[Descrição {i}{revision}]]></description>
        <html><bdd_url><![CDATA[https://www.ine.pt/xportal/xmain?xpid=INE&xpgid=ine_indicadores&indOcorrCod={i}]]></bdd_url>{metainfo}</html>
        <json>
        <json_dataset><![CDATA[https://www.ine.pt/js/{i}.json]]></json_dataset>
        </json>
        <keywords>INE,<![CDATA[Estatística]]></keywords>{extra}
        </indicator>"""
        for i in ids
    )
    return f"<?xml version='1.0' encoding='UTF-8'?>\n<catalog>\n{indicators}\n</catalog>\n"


@pytest.mark.options(HARVESTER_BACKENDS=["ine"])
class INEInnerHarvestTest(PytestOnlyDBTestCase):
    def _harvest(self, rmock, tmp_path, source):
        rmock.get(INE_URL, text=_catalog_xml(["0001", "0002", "0003"]))
        rmock.get(INE_HVD_URL, text="<indicators/>")
        backend = INEBackend(source)
        backend.LOCAL_FILE_PATH = str(tmp_path / "ine.xml")
        return backend.harvest()

    def test_harvest_creates_datasets_with_job_item_references(self, rmock, tmp_path):
        org = OrganizationFactory()
        source = HarvestSourceFactory(backend="ine", url=INE_URL, organization=org)

        job = self._harvest(rmock, tmp_path, source)

        assert job.status == "done"
        assert len(job.items) == 3
        assert all(item.status == "done" for item in job.items)
        # The flush must happen before the created-ids lookup, otherwise
        # HarvestItems are left without a dataset reference.
        assert all(item.dataset is not None for item in job.items)

        datasets = Dataset.objects(__raw__={"harvest.source_id": str(source.id)})
        assert datasets.count() == 3
        one = datasets.filter(__raw__={"harvest.remote_id": "0001"}).first()
        assert one.title == "Indicador 0001"
        assert one.organization == org
        assert [r.url for r in one.resources] == ["https://www.ine.pt/js/0001.json"]

        # Job items must also be persisted (pushed), not only in memory
        job.reload()
        assert len(job.items) == 3

    def test_second_harvest_skips_unchanged_datasets(self, rmock, tmp_path):
        org = OrganizationFactory()
        source = HarvestSourceFactory(backend="ine", url=INE_URL, organization=org)
        self._harvest(rmock, tmp_path, source)

        job = self._harvest(rmock, tmp_path, source)

        assert job.status == "done"
        assert [item.status for item in job.items] == ["skipped"] * 3
        assert Dataset.objects(__raw__={"harvest.source_id": str(source.id)}).count() == 3


@pytest.mark.options(HARVESTER_BACKENDS=["ine"])
class INEResourceIdentityTest(PytestOnlyDBTestCase):
    """Applying changed metadata must not cost the resources their ids.

    `_has_changed` lets any edited field through to the apply step, which used to
    wipe and rebuild every resource of the dataset — a new id, and therefore a
    dead `/api/1/datasets/r/<id>` permalink, for each of them (LEDG-2251).
    """

    def _harvest(self, rmock, tmp_path, source, revision=""):
        rmock.get(INE_URL, text=_catalog_xml(["0001"], revision=revision))
        rmock.get(INE_HVD_URL, text="<indicators/>")
        backend = INEBackend(source)
        backend.LOCAL_FILE_PATH = str(tmp_path / "ine.xml")
        return backend.harvest()

    def _dataset(self, source):
        return Dataset.objects(
            __raw__={"harvest.source_id": str(source.id), "harvest.remote_id": "0001"}
        ).first()

    def test_changed_description_keeps_the_resource_ids(self, rmock, tmp_path):
        source = HarvestSourceFactory(
            backend="ine", url=INE_URL, organization=OrganizationFactory()
        )
        self._harvest(rmock, tmp_path, source)
        before = [r.id for r in self._dataset(source).resources]
        assert len(before) == 1

        job = self._harvest(rmock, tmp_path, source, revision=" (revista)")

        # The dataset really was reprocessed, not skipped as unchanged.
        assert [item.status for item in job.items] == ["done"]
        dataset = self._dataset(source)
        assert "(revista)" in dataset.description
        assert [r.id for r in dataset.resources] == before


# `CDATA_BASE_URL` so `Owned.page()` resolves to a URL and the conflict message
# names the other owner, as in `test_base_backend.py`; without it `page()` is
# None and the message falls back to a bare id.
@pytest.mark.options(HARVESTER_BACKENDS=["ine"], CDATA_BASE_URL="http://localhost")
class INEUniqueOwnershipTest(PytestOnlyDBTestCase):
    """A second source must not take over records that already have an owner.

    Every other backend reaches an existing record through
    `BaseBackend.get_dataset`, which asks `ensure_unique_ownership` before
    handing it over. This one looks its datasets up in bulk and writes them in
    bulk, so it used to overwrite whatever the `harvest.domain` branch of the
    scoping query happened to match — the whole of another source's catalogue
    at once, for a source claiming the same domain.
    """

    def _harvest(self, rmock, tmp_path, source, ids, revision=""):
        rmock.get(INE_URL, text=_catalog_xml(ids, revision=revision))
        rmock.get(INE_HVD_URL, text="<indicators/>")
        backend = INEBackend(source)
        backend.LOCAL_FILE_PATH = str(tmp_path / f"ine-{source.id}.xml")
        return backend.harvest()

    def _dataset(self, remote_id):
        return Dataset.objects(__raw__={"harvest.remote_id": remote_id}).first()

    @pytest.mark.parametrize(
        "owner_field,owner_factory",
        [
            ("organization", OrganizationFactory),
            ("owner", UserFactory),
        ],
    )
    def test_second_source_cannot_take_over_a_dataset(
        self, rmock, tmp_path, owner_field, owner_factory
    ):
        source1 = HarvestSourceFactory(backend="ine", url=INE_URL, **{owner_field: owner_factory()})
        self._harvest(rmock, tmp_path, source1, ["0001", "0002"])
        original = self._dataset("0001")
        assert original is not None
        original_title = original.title

        # Same URL, so `_prefetch_datasets` matches "0001" on `harvest.domain`
        # exactly as it would for the legitimate source.
        source2 = HarvestSourceFactory(backend="ine", url=INE_URL, **{owner_field: owner_factory()})
        job = self._harvest(rmock, tmp_path, source2, ["0001", "0003"], revision=" (revista)")

        assert job.status == "done-errors"
        by_remote_id = {item.remote_id: item for item in job.items}
        assert by_remote_id["0001"].status == "failed"
        # The record the second source does own is unaffected.
        assert by_remote_id["0003"].status == "done"

        # The failure says who the other owner is, instead of just "failed".
        message = by_remote_id["0001"].errors[0].message
        assert getattr(source1, owner_field).page() in message

        kept = self._dataset("0001")
        assert getattr(kept, owner_field) == getattr(source1, owner_field)
        assert kept.title == original_title
        assert "(revista)" not in kept.description
        assert kept.harvest.source_id == str(source1.id)

    def test_unchanged_record_of_another_owner_is_refused_not_skipped(self, rmock, tmp_path):
        """The guard runs before change detection, not only before the write.

        With identical metadata the record takes the SKIP branch, which writes
        nothing — so a guard placed only on the update path would look just as
        correct as this one. It is not: an unchanged record belonging to someone
        else would then be reported as "skipped" against this source, which
        reads as a record this source legitimately harvested and found current.
        """
        source1 = HarvestSourceFactory(
            backend="ine", url=INE_URL, organization=OrganizationFactory()
        )
        self._harvest(rmock, tmp_path, source1, ["0001"])

        source2 = HarvestSourceFactory(
            backend="ine", url=INE_URL, organization=OrganizationFactory()
        )
        job = self._harvest(rmock, tmp_path, source2, ["0001"])

        assert job.status == "done-errors"
        assert [item.status for item in job.items] == ["failed"]
        assert "another owner" in job.items[0].errors[0].message
        # The failure points at the record it is about, not just at its owner.
        assert job.items[0].dataset == self._dataset("0001").id


@pytest.mark.options(HARVESTER_BACKENDS=["ine"])
class INEPreviewDoesNotWriteTest(PytestOnlyDBTestCase):
    """A preview must not create or replace a single dataset.

    This backend never calls `BaseBackend.process_dataset`, so the dryrun guard
    around `dataset.save()` in `base.py` never applies to it: `inner_harvest`
    writes the datasets itself, in raw pymongo. Both of those writes — the
    upserting `UpdateOne` for a new dataset and the `ReplaceOne` for a changed
    one — go through `_flush_bulk`, which is where the guard lives.
    """

    def _preview(self, rmock, tmp_path, source, ids, revision=""):
        rmock.get(INE_URL, text=_catalog_xml(ids, revision=revision))
        rmock.get(INE_HVD_URL, text="<indicators/>")
        backend = INEBackend(source, dryrun=True)
        backend.LOCAL_FILE_PATH = str(tmp_path / "ine.xml")
        return backend.harvest()

    def test_preview_creates_no_dataset(self, rmock, tmp_path):
        source = HarvestSourceFactory(
            backend="ine", url=INE_URL, organization=OrganizationFactory()
        )

        job = self._preview(rmock, tmp_path, source, ["0001", "0002", "0003"])

        assert job.status == "done"
        assert Dataset.objects(__raw__={"harvest.source_id": str(source.id)}).count() == 0

    def test_preview_does_not_replace_an_existing_dataset(self, rmock, tmp_path):
        source = HarvestSourceFactory(
            backend="ine", url=INE_URL, organization=OrganizationFactory()
        )
        existing = DatasetFactory(
            title="Título anterior",
            description="Descrição anterior",
            harvest=HarvestDatasetMetadata(
                remote_id="0001", source_id=str(source.id), domain=source.domain
            ),
        )

        # The remote catalog carries a different description, so change detection
        # lets this dataset through to the `ReplaceOne` branch.
        job = self._preview(rmock, tmp_path, source, ["0001"], revision=" (revista)")

        assert job.status == "done"
        existing.reload()
        assert existing.title == "Título anterior"
        assert existing.description == "Descrição anterior"


@pytest.mark.options(HARVESTER_BACKENDS=["ine"])
class INEMaxItemsTest(PytestOnlyDBTestCase):
    """`HARVEST_PREVIEW_MAX_ITEMS` has to actually cap an INE preview.

    `actions.preview` passes it as `max_items`, but this backend never read the
    attribute, so a single preview request processed the whole remote catalog.
    """

    def _harvest(self, rmock, tmp_path, source, **kwargs):
        rmock.get(INE_URL, text=_catalog_xml(["0001", "0002", "0003", "0004", "0005"]))
        rmock.get(INE_HVD_URL, text="<indicators/>")
        backend = INEBackend(source, **kwargs)
        backend.LOCAL_FILE_PATH = str(tmp_path / "ine.xml")
        return backend.harvest()

    def test_preview_stops_at_max_items(self, rmock, tmp_path):
        source = HarvestSourceFactory(
            backend="ine", url=INE_URL, organization=OrganizationFactory()
        )

        job = self._harvest(rmock, tmp_path, source, dryrun=True, max_items=2)

        assert len(job.items) == 2
        # Truncation is expected in a preview, so it is not reported as an error.
        assert job.errors == []

    def test_unlimited_harvest_processes_the_whole_catalog(self, rmock, tmp_path):
        source = HarvestSourceFactory(
            backend="ine", url=INE_URL, organization=OrganizationFactory()
        )

        job = self._harvest(rmock, tmp_path, source)

        assert len(job.items) == 5
        assert Dataset.objects(__raw__={"harvest.source_id": str(source.id)}).count() == 5

    def test_truncated_real_harvest_records_an_error(self, rmock, tmp_path):
        source = HarvestSourceFactory(
            backend="ine", url=INE_URL, organization=OrganizationFactory()
        )

        job = self._harvest(rmock, tmp_path, source, max_items=2)

        assert len(job.items) == 2
        assert len(job.errors) == 1
        assert "max items reached" in job.errors[0].message


def _hostile_catalog_xml():
    """A catalog whose title and description carry markup, plus a plain one.

    `0002` has no markup at all: it is there to pin the escaping `bleach` does
    to bare ampersands and angle brackets, which is abundant in a statistics
    catalog and is the bulk of what changes on the first harvest after this fix.
    """
    return (
        "<?xml version='1.0' encoding='UTF-8'?>\n"
        "<catalog>\n"
        "<indicator id='0001'>"
        "<title><![CDATA[Indicador <script>alert(1)</script>]]></title>"
        "<description><![CDATA[Texto <img src=x onerror=alert(1)> final]]></description>"
        "</indicator>\n"
        "<indicator id='0002'>"
        "<title><![CDATA[Investigação e Desenvolvimento (I&D)]]></title>"
        "<description><![CDATA[População com <15 anos]]></description>"
        "</indicator>\n"
        "</catalog>\n"
    )


@pytest.mark.options(HARVESTER_BACKENDS=["ine"])
class INESanitizationTest(PytestOnlyDBTestCase):
    """Titles and descriptions must be sanitized on the raw-pymongo write path.

    `Dataset.pre_save` sanitizes every other write in the portal, but it is a
    mongoengine signal and this backend never calls `.save()`, so remote HTML
    used to be stored verbatim.
    """

    def _harvest(self, rmock, tmp_path, source):
        rmock.get(INE_URL, text=_hostile_catalog_xml())
        rmock.get(INE_HVD_URL, text="<indicators/>")
        backend = INEBackend(source)
        backend.LOCAL_FILE_PATH = str(tmp_path / "ine.xml")
        return backend.harvest()

    def _dataset(self, source, remote_id):
        return Dataset.objects(
            __raw__={"harvest.source_id": str(source.id), "harvest.remote_id": remote_id}
        ).first()

    def test_markup_is_stripped_from_title_and_description(self, rmock, tmp_path):
        source = HarvestSourceFactory(
            backend="ine", url=INE_URL, organization=OrganizationFactory()
        )

        self._harvest(rmock, tmp_path, source)

        dataset = self._dataset(source, "0001")
        # `strip=True` drops the tags and keeps their text, which is the same
        # contract `Dataset.pre_save` applies everywhere else: what must not
        # survive is the markup, not the words.
        assert "<script>" not in dataset.title
        assert "</script>" not in dataset.title
        assert dataset.title == "Indicador alert(1)"
        # The description keeps the markdown allow-list, so `<img>` survives and
        # the event handler on it does not — again the same policy as elsewhere.
        assert "onerror" not in dataset.description
        assert "alert(1)" not in dataset.description

    def test_bare_ampersands_and_brackets_are_escaped(self, rmock, tmp_path):
        # Accepted consequence, not a bug: bleach escapes what it does not strip,
        # which is exactly what `Dataset.pre_save` already does everywhere else.
        source = HarvestSourceFactory(
            backend="ine", url=INE_URL, organization=OrganizationFactory()
        )

        self._harvest(rmock, tmp_path, source)

        dataset = self._dataset(source, "0002")
        assert dataset.title == "Investigação e Desenvolvimento (I&amp;D)"

    def test_sanitization_is_idempotent_across_harvests(self, rmock, tmp_path):
        # If the stored (sanitized) value were compared against a raw one, every
        # one of these datasets would report as changed on every single run.
        source = HarvestSourceFactory(
            backend="ine", url=INE_URL, organization=OrganizationFactory()
        )
        self._harvest(rmock, tmp_path, source)

        job = self._harvest(rmock, tmp_path, source)

        assert [item.status for item in job.items] == ["skipped"] * 2


@pytest.mark.options(HARVESTER_BACKENDS=["ine"])
class INEPreviewReportsItemsTest(PytestOnlyDBTestCase):
    """A preview still has to say what it would have done.

    Contrary to what LEDG-2324 assumed, `_append_job_items` never discarded the
    items in dryrun — it guards only the `$push` to the database and extends
    `job.items` unconditionally. This pins that, because the dryrun guard in
    `_flush_bulk` changed the path around it: the created-ids lookup that runs
    after the flush now finds nothing, so those items come back without a
    dataset reference and must still be reported.
    """

    def _preview(self, rmock, tmp_path, source):
        rmock.get(INE_URL, text=_catalog_xml(["0001", "0002", "0003"]))
        rmock.get(INE_HVD_URL, text="<indicators/>")
        backend = INEBackend(source, dryrun=True)
        backend.LOCAL_FILE_PATH = str(tmp_path / "ine.xml")
        return backend.harvest()

    def test_preview_reports_every_item_it_processed(self, rmock, tmp_path):
        source = HarvestSourceFactory(
            backend="ine", url=INE_URL, organization=OrganizationFactory()
        )

        job = self._preview(rmock, tmp_path, source)

        assert job.status == "done"
        assert len(job.items) == 3
        assert [item.status for item in job.items] == ["done"] * 3
        assert sorted(item.remote_id for item in job.items) == ["0001", "0002", "0003"]
        # No dataset reference, because nothing was written — and nothing was.
        assert all(item.dataset is None for item in job.items)
        assert Dataset.objects(__raw__={"harvest.source_id": str(source.id)}).count() == 0

    def test_preview_persists_no_job(self, rmock, tmp_path):
        source = HarvestSourceFactory(
            backend="ine", url=INE_URL, organization=OrganizationFactory()
        )

        job = self._preview(rmock, tmp_path, source)

        assert job.pk is None


@pytest.mark.options(HARVESTER_BACKENDS=["ine"])
class INELocalFilePathTest(PytestOnlyDBTestCase):
    """A preview must not share the download file with the real harvest.

    `LOCAL_FILE_PATH` is a class attribute, so every INE run in the process used
    the same file: a preview could overwrite the catalog a running harvest was
    reading, and its cleanup deleted the cached file that harvest falls back on.
    """

    def _source(self):
        return HarvestSourceFactory(backend="ine", url=INE_URL, organization=OrganizationFactory())

    def _confine_to(self, monkeypatch, tmp_path):
        """Keep both the shared path and the per-preview one inside tmp_path.

        Patching only the class attribute is not enough: `__init__` overrides it
        for previews, so the download would still land in the real system temp
        directory — and a test that names the real /tmp is a test that collides
        with whatever else is running on the machine.
        """
        monkeypatch.setattr(INEBackend, "LOCAL_FILE_PATH", str(tmp_path / "ine.xml"))
        monkeypatch.setattr("udata.harvest.backends.ine.tempfile.gettempdir", lambda: str(tmp_path))

    def test_previews_get_a_path_of_their_own(self):
        source = self._source()

        first = INEBackend(source, dryrun=True)
        second = INEBackend(source, dryrun=True)

        assert first.LOCAL_FILE_PATH != second.LOCAL_FILE_PATH
        assert first.LOCAL_FILE_PATH != INEBackend.LOCAL_FILE_PATH
        assert second.LOCAL_FILE_PATH != INEBackend.LOCAL_FILE_PATH

    def test_real_harvest_keeps_the_shared_path(self):
        # Deliberate: the shared file is the download cache `_download_to_file`
        # falls back on when every attempt against the slow INE endpoint fails.
        assert INEBackend(self._source()).LOCAL_FILE_PATH == INEBackend.LOCAL_FILE_PATH

    def test_preview_leaves_the_harvest_cache_alone(self, rmock, tmp_path, monkeypatch):
        # Both the shared path and the per-instance one have to land inside
        # tmp_path: other sessions run pytest against this repo at the same time,
        # and the behaviour under test is precisely "does not write the shared
        # path", which would otherwise be the machine's real /tmp/ine.xml.
        self._confine_to(monkeypatch, tmp_path)
        shared = tmp_path / "ine.xml"
        shared.write_text(COMPLETE_XML)
        rmock.get(INE_URL, text=_catalog_xml(["0001", "0002"]))
        rmock.get(INE_HVD_URL, text="<indicators/>")

        backend = INEBackend(self._source(), dryrun=True)
        # The instance really did opt out of the shared path.
        assert backend.LOCAL_FILE_PATH != str(shared)

        backend.harvest()

        assert shared.exists()
        assert shared.read_text() == COMPLETE_XML

    def test_preview_removes_its_own_file(self, rmock, tmp_path, monkeypatch):
        self._confine_to(monkeypatch, tmp_path)
        rmock.get(INE_URL, text=_catalog_xml(["0001"]))
        rmock.get(INE_HVD_URL, text="<indicators/>")
        backend = INEBackend(self._source(), dryrun=True)
        assert backend.LOCAL_FILE_PATH.startswith(str(tmp_path))

        backend.harvest()

        assert not os.path.exists(backend.LOCAL_FILE_PATH)


# Billion laughs, cut short enough to stay a test: each entity expands into ten
# of the one below it. The closing </catalog> matters — without it the download
# integrity check rejects the payload and the parser is never reached.
ENTITY_BOMB_XML = (
    "<?xml version='1.0' encoding='UTF-8'?>\n"
    "<!DOCTYPE catalog [\n"
    "<!ENTITY a 'aaaaaaaaaa'>\n"
    "<!ENTITY b '&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;'>\n"
    "<!ENTITY c '&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;'>\n"
    "]>\n"
    "<catalog>\n"
    "<indicator id='0001'><title><![CDATA[Indicador]]></title>"
    "<description>&c;</description></indicator>\n"
    "</catalog>\n"
)


@pytest.mark.options(HARVESTER_BACKENDS=["ine"])
class INEXmlHardeningTest(PytestOnlyDBTestCase):
    """The catalog body is remote, and through the preview endpoint it is
    caller-supplied. The stdlib parser expands internal general entities, so the
    same request that previews a harvester was also a worker-memory DoS."""

    def _harvest(self, rmock, tmp_path, source, **kwargs):
        rmock.get(INE_URL, text=ENTITY_BOMB_XML)
        rmock.get(INE_HVD_URL, text="<indicators/>")
        backend = INEBackend(source, **kwargs)
        backend.LOCAL_FILE_PATH = str(tmp_path / "ine.xml")
        return backend.harvest()

    def test_entity_expansion_fails_the_harvest_instead_of_expanding(self, rmock, tmp_path):
        source = HarvestSourceFactory(
            backend="ine", url=INE_URL, organization=OrganizationFactory()
        )

        job = self._harvest(rmock, tmp_path, source)

        assert job.status == "failed"
        assert job.errors
        assert Dataset.objects(__raw__={"harvest.source_id": str(source.id)}).count() == 0

    def test_preview_of_a_hostile_catalog_fails_cleanly(self, rmock, tmp_path):
        source = HarvestSourceFactory(
            backend="ine", url=INE_URL, organization=OrganizationFactory()
        )

        job = self._harvest(rmock, tmp_path, source, dryrun=True)

        assert job.status == "failed"
        assert Dataset.objects(__raw__={"harvest.source_id": str(source.id)}).count() == 0


@pytest.mark.options(HARVESTER_BACKENDS=["ine"])
class INETruncatedHarvestDoesNotArchiveTest(PytestOnlyDBTestCase):
    """Capping the parse must not turn a preview into a mass-archive report.

    `BaseBackend.autoarchive` treats every remote_id absent from `job.items` as
    gone from the remote platform, and it runs in dryrun too. Once the parse
    stops at `max_items`, everything past the cut looks missing — so a preview of
    a source whose real harvest has been failing for longer than the grace
    period would report the whole rest of the catalog as archived.
    """

    def _existing_dataset(self, source, remote_id):
        stale = date.today() - timedelta(days=400)
        dataset = DatasetFactory(
            harvest=HarvestDatasetMetadata(
                remote_id=remote_id,
                source_id=str(source.id),
                domain=source.domain,
                last_update=stale,
            )
        )
        return dataset

    def _harvest(self, rmock, tmp_path, source, **kwargs):
        rmock.get(INE_URL, text=_catalog_xml(["0001", "0002", "0003", "0004", "0005"]))
        rmock.get(INE_HVD_URL, text="<indicators/>")
        backend = INEBackend(source, **kwargs)
        backend.LOCAL_FILE_PATH = str(tmp_path / "ine.xml")
        return backend.harvest()

    def test_truncated_preview_archives_nothing(self, rmock, tmp_path):
        source = HarvestSourceFactory(
            backend="ine", url=INE_URL, organization=OrganizationFactory(), autoarchive=True
        )
        # Present in the catalog, but past the cut — and stale enough to qualify.
        stale = self._existing_dataset(source, "0005")

        job = self._harvest(rmock, tmp_path, source, dryrun=True, max_items=2)

        assert [item.status for item in job.items] == ["done"] * 2
        assert not any(item.status == "archived" for item in job.items)
        stale.reload()
        assert stale.harvest.archived_at is None

    def test_untruncated_harvest_still_archives(self, rmock, tmp_path):
        # The guard must be about truncation, not about disabling autoarchive.
        source = HarvestSourceFactory(
            backend="ine", url=INE_URL, organization=OrganizationFactory(), autoarchive=True
        )
        gone = self._existing_dataset(source, "9999")  # not in the catalog at all

        job = self._harvest(rmock, tmp_path, source)

        assert any(item.status == "archived" for item in job.items)
        gone.reload()
        assert gone.harvest.archived_at is not None


@pytest.mark.options(HARVESTER_BACKENDS=["ine"])
class INESlugAndEscapingTest(PytestOnlyDBTestCase):
    def _harvest(self, rmock, tmp_path, source, text):
        rmock.get(INE_URL, text=text)
        rmock.get(INE_HVD_URL, text="<indicators/>")
        backend = INEBackend(source)
        backend.LOCAL_FILE_PATH = str(tmp_path / "ine.xml")
        return backend.harvest()

    def test_slug_does_not_inherit_the_html_escaping(self, rmock, tmp_path):
        # Sanitizing escapes the `&`; slugifying that directly would mint a
        # permalink carrying a spurious "-amp-" segment, forever.
        source = HarvestSourceFactory(
            backend="ine", url=INE_URL, organization=OrganizationFactory()
        )
        catalog = (
            "<?xml version='1.0' encoding='UTF-8'?>\n<catalog>\n"
            "<indicator id='0001'>"
            "<title><![CDATA[Investigação e Desenvolvimento (I&D)]]></title>"
            "</indicator>\n</catalog>\n"
        )

        self._harvest(rmock, tmp_path, source, catalog)

        dataset = Dataset.objects(
            __raw__={"harvest.source_id": str(source.id), "harvest.remote_id": "0001"}
        ).first()
        assert "amp" not in dataset.slug
        assert dataset.slug == "investigacao-e-desenvolvimento-i-d-0001"

    def test_query_string_in_the_remote_url_is_escaped_inside_the_description(
        self, rmock, tmp_path
    ):
        # Accepted, and pinned because it is the reason the first harvest after
        # this change rewrites the whole catalog: the real INE bdd_url is a query
        # string, and sanitizing the description escapes each of its `&`.
        source = HarvestSourceFactory(
            backend="ine", url=INE_URL, organization=OrganizationFactory()
        )

        self._harvest(rmock, tmp_path, source, _catalog_xml(["0001"]))

        dataset = Dataset.objects(
            __raw__={"harvest.source_id": str(source.id), "harvest.remote_id": "0001"}
        ).first()
        assert "xpid=INE&amp;xpgid=" in dataset.description
        # `remote_url` is stored raw — it is a URL, not rendered content.
        assert dataset.harvest.remote_url.startswith("https://www.ine.pt/xportal/xmain?xpid=INE&")


class INEHarvestLogCredentialsTest(PytestOnlyDBTestCase):
    """The INE start line prints the source URL on every harvest (LEDG-2501).

    `INEBackend` also goes through `BaseBackend.harvest`, so a credentialed
    source used to print the password twice per run; the other line is pinned
    in `test_dcat_backend.py`.
    """

    def test_harvest_start_log_line_does_not_carry_the_source_password(self, mocker):
        url = "https://harvestuser:sup3rs3cr3t@www.ine.pt/ine/xml_indic.jsp?opc=2&lang=PT"
        source = HarvestSourceFactory(backend="ine", url=url)
        backend = INEBackend(source)

        # `_log` is an instance attribute, not a module-level logger, so it is
        # patched on the instance. The harvest is cut short right after the
        # line under test.
        backend._log = mocker.Mock()
        mocker.patch.object(INEBackend, "_fetch_hvd_ids", side_effect=RuntimeError("stop here"))

        with pytest.raises(RuntimeError):
            backend._inner_harvest()

        logged = " ".join(str(call) for call in backend._log.info.call_args_list)
        assert "sup3rs3cr3t" not in logged
        assert "harvestuser" not in logged
        assert "https://***@www.ine.pt" in logged


@pytest.mark.options(HARVESTER_BACKENDS=["ine"])
class INESourceMetadataTest(PytestOnlyDBTestCase):
    """Metadata the catalogue publishes and the backend used to hardcode or ignore."""

    def _harvest(self, rmock, tmp_path, source, **kwargs):
        rmock.get(INE_URL, text=_catalog_xml(["0001"], **kwargs))
        rmock.get(INE_HVD_URL, text="<indicators/>")
        backend = INEBackend(source)
        backend.LOCAL_FILE_PATH = str(tmp_path / "ine.xml")
        job = backend.harvest()
        dataset = Dataset.objects(__raw__={"harvest.remote_id": "0001"}).first()
        return job, dataset

    def _source(self):
        return HarvestSourceFactory(backend="ine", url=INE_URL, organization=OrganizationFactory())

    def test_periodicity_becomes_frequency(self, rmock, tmp_path):
        # Leading whitespace on purpose: 13152 of the 13154 published values carry it.
        _job, dataset = self._harvest(rmock, tmp_path, self._source(), periodicity=" Decenal")

        assert dataset.frequency == UpdateFrequency.DECENNIAL
        assert dataset.frequency != UpdateFrequency.UNKNOWN

    def test_sexenal_becomes_other_rather_than_unknown(self, rmock, tmp_path):
        _job, dataset = self._harvest(rmock, tmp_path, self._source(), periodicity="Sexenal")

        assert dataset.frequency == UpdateFrequency.OTHER

    def test_unrecognised_periodicity_stays_unknown_without_failing_the_item(self, rmock, tmp_path):
        job, dataset = self._harvest(
            rmock, tmp_path, self._source(), periodicity="De vez em quando"
        )

        assert dataset.frequency == UpdateFrequency.UNKNOWN
        # Degrades, never fails the item.
        assert [item.status for item in job.items] == ["done"]

    def test_missing_periodicity_stays_unknown(self, rmock, tmp_path):
        _job, dataset = self._harvest(rmock, tmp_path, self._source())

        assert dataset.frequency == UpdateFrequency.UNKNOWN

    def test_uri_is_the_published_bdd_url_and_extras_come_from_the_source(self, rmock, tmp_path):
        _job, dataset = self._harvest(
            rmock,
            tmp_path,
            self._source(),
            periodicity="Mensal",
            last_update="18-09-2026",
            last_period="S3A202608",
            geo_lastlevel="Portugal",
            source_description="INE, Índice de preços",
            update_type="A",
            metainfo_url="https://www.ine.pt/xurl/metax/0001/PT",
        )

        # The landing page the source publishes, not the composed /indicador/<id>.
        assert dataset.harvest.uri == (
            "https://www.ine.pt/xportal/xmain?xpid=INE&xpgid=ine_indicadores&indOcorrCod=0001"
        )
        assert "ine.pt/indicador/" not in dataset.harvest.uri
        assert dataset.extras["geo_lastlevel"] == "Portugal"
        assert dataset.extras["source_description"] == "INE, Índice de preços"
        assert dataset.extras["last_period_available"] == "S3A202608"
        assert dataset.extras["last_update_remote"] == "18-09-2026"
        assert dataset.extras["update_type"] == "A"
        assert dataset.extras["metainfo_url"] == "https://www.ine.pt/xurl/metax/0001/PT"

    def test_optional_update_type_is_absent_when_the_source_omits_it(self, rmock, tmp_path):
        """Published for ~5% of indicators, so its absence is the normal case."""
        _job, dataset = self._harvest(
            rmock, tmp_path, self._source(), periodicity="Anual", geo_lastlevel="Portugal"
        )

        assert "update_type" not in dataset.extras
        assert dataset.extras["geo_lastlevel"] == "Portugal"

    def test_source_tag_is_derived_from_the_source_hostname(self, rmock, tmp_path):
        _job, dataset = self._harvest(rmock, tmp_path, self._source())

        # Derived from the source URL, not a literal: www.ine.pt -> www-ine-pt.
        assert "www-ine-pt" in dataset.tags
        assert "ine-pt" not in dataset.tags

    def test_source_tag_follows_a_source_on_another_host(self, rmock, tmp_path):
        """The tag tracks the configured source, which is what "derived" has to mean."""
        source = HarvestSourceFactory(
            backend="ine",
            url="https://ine.example.test/ine/xml_indic.jsp?opc=2",
            organization=OrganizationFactory(),
        )
        rmock.get("https://ine.example.test/ine/xml_indic.jsp?opc=2", text=_catalog_xml(["0001"]))
        rmock.get(INE_HVD_URL, text="<indicators/>")
        backend = INEBackend(source)
        backend.LOCAL_FILE_PATH = str(tmp_path / "ine.xml")
        backend.harvest()

        dataset = Dataset.objects(__raw__={"harvest.remote_id": "0001"}).first()
        assert "ine-example-test" in dataset.tags

    def test_modified_at_is_the_source_last_update_not_the_harvest_time(self, rmock, tmp_path):
        _job, dataset = self._harvest(
            rmock, tmp_path, self._source(), periodicity="Mensal", last_update="04-02-2026"
        )

        # 4 February, not 2 April: the shared date parser would read this one month-first.
        assert dataset.harvest.modified_at.year == 2026
        assert dataset.harvest.modified_at.month == 2
        assert dataset.harvest.modified_at.day == 4

    def test_modified_at_survives_a_second_harvest_without_source_changes(self, rmock, tmp_path):
        """Criterion 2: the stored date must not drift to "now" on the next run."""
        source = self._source()
        _job, dataset = self._harvest(
            rmock, tmp_path, source, periodicity="Mensal", last_update="04-02-2026"
        )
        first = dataset.harvest.modified_at

        job, dataset = self._harvest(
            rmock, tmp_path, source, periodicity="Mensal", last_update="04-02-2026"
        )

        assert [item.status for item in job.items] == ["skipped"]
        assert dataset.harvest.modified_at == first

    def test_missing_last_update_falls_back_to_the_harvest_time(self, rmock, tmp_path):
        _job, dataset = self._harvest(rmock, tmp_path, self._source(), periodicity="Anual")

        assert dataset.harvest.modified_at is not None

    def test_unparseable_last_update_falls_back_to_the_harvest_time(self, rmock, tmp_path):
        job, dataset = self._harvest(
            rmock, tmp_path, self._source(), periodicity="Anual", last_update="2026/09/18"
        )

        assert dataset.harvest.modified_at is not None
        assert [item.status for item in job.items] == ["done"]
        # The raw text is still kept, so nothing the source said is lost.
        assert dataset.extras["last_update_remote"] == "2026/09/18"


@pytest.mark.options(HARVESTER_BACKENDS=["ine"])
class INEHasChangedTest(PytestOnlyDBTestCase):
    """Change detection has to see the metadata the backend only just started writing.

    `_has_changed` compared title, description, tags and resources. A dataset harvested by
    the previous code matches on all four, so without the new comparisons the ~13k INE
    datasets already stored would be reported unchanged and skipped forever, and the
    enrichment would never reach production.

    These call `_has_changed` directly rather than only asserting on a full harvest: the
    source tag changes in this ticket too, so an end-to-end test would go green through the
    tags branch even if the new comparisons had never been written.
    """

    FIXTURE = dict(
        periodicity="Mensal",
        last_update="04-02-2026",
        last_period="S3A202608",
        geo_lastlevel="Portugal",
        source_description="INE, Índice de preços",
        update_type="A",
        metainfo_url="https://www.ine.pt/xurl/metax/0001/PT",
    )

    def _source(self):
        return HarvestSourceFactory(backend="ine", url=INE_URL, organization=OrganizationFactory())

    def _harvest(self, rmock, tmp_path, source):
        rmock.get(INE_URL, text=_catalog_xml(["0001"], **self.FIXTURE))
        rmock.get(INE_HVD_URL, text="<indicators/>")
        backend = INEBackend(source)
        backend.LOCAL_FILE_PATH = str(tmp_path / "ine.xml")
        return backend.harvest()

    def _backend_and_md(self, source):
        backend = INEBackend(source)
        element = ET.fromstring(_catalog_xml(["0001"], **self.FIXTURE)).find("indicator")
        return backend, backend._extract_metadata(element)

    def _dataset(self, source):
        return Dataset.objects(
            __raw__={"harvest.source_id": str(source.id), "harvest.remote_id": "0001"}
        ).first()

    def _as_the_old_code_left_it(self, source, rmock, tmp_path, **overrides):
        """A stored dataset in the shape the previous implementation produced."""
        self._harvest(rmock, tmp_path, source)
        dataset = self._dataset(source)
        Dataset.objects(id=dataset.id).update(**overrides)
        return self._dataset(source)

    def test_a_dataset_already_carrying_the_source_metadata_is_unchanged(self, rmock, tmp_path):
        """The baseline: without it, the tests below would prove nothing."""
        source = self._source()
        self._harvest(rmock, tmp_path, source)
        backend, md = self._backend_and_md(source)

        assert backend._has_changed(self._dataset(source), md, "0001") is False

    def test_missing_extras_alone_are_detected(self, rmock, tmp_path):
        source = self._source()
        dataset = self._as_the_old_code_left_it(source, rmock, tmp_path, set__extras={})
        backend, md = self._backend_and_md(source)

        assert backend._has_changed(dataset, md, "0001") is True

    def test_stale_frequency_alone_is_detected(self, rmock, tmp_path):
        source = self._source()
        dataset = self._as_the_old_code_left_it(source, rmock, tmp_path, set__frequency="unknown")
        backend, md = self._backend_and_md(source)

        assert backend._has_changed(dataset, md, "0001") is True

    def test_invented_uri_alone_is_detected(self, rmock, tmp_path):
        source = self._source()
        dataset = self._as_the_old_code_left_it(
            source, rmock, tmp_path, set__harvest__uri="https://www.ine.pt/indicador/0001"
        )
        backend, md = self._backend_and_md(source)

        assert backend._has_changed(dataset, md, "0001") is True

    def test_existing_dataset_without_the_new_metadata_is_rewritten_on_the_next_harvest(
        self, rmock, tmp_path
    ):
        """Criterion 4, end to end: detected as changed *and* actually enriched."""
        source = self._source()
        self._as_the_old_code_left_it(
            source,
            rmock,
            tmp_path,
            set__frequency="unknown",
            set__extras={},
            set__harvest__uri="https://www.ine.pt/indicador/0001",
        )

        job = self._harvest(rmock, tmp_path, source)

        assert [item.status for item in job.items] == ["done"]
        dataset = self._dataset(source)
        assert dataset.frequency == UpdateFrequency.MONTHLY
        assert dataset.extras["geo_lastlevel"] == "Portugal"
        assert dataset.extras["metainfo_url"] == "https://www.ine.pt/xurl/metax/0001/PT"
        assert "indicador/0001" not in dataset.harvest.uri

    def test_the_enriching_harvest_keeps_the_resource_ids(self, rmock, tmp_path):
        """Criterion 7: the rewrite that adds the metadata must not move a permalink."""
        source = self._source()
        self._as_the_old_code_left_it(
            source, rmock, tmp_path, set__frequency="unknown", set__extras={}
        )
        before = [r.id for r in self._dataset(source).resources]
        assert before

        job = self._harvest(rmock, tmp_path, source)

        assert [item.status for item in job.items] == ["done"]
        assert [r.id for r in self._dataset(source).resources] == before

    def test_an_indicator_without_bdd_url_settles_instead_of_churning(self, rmock, tmp_path):
        """No landing page published means no URI stored — and no nightly rewrite.

        Every indicator publishes bdd_url today, but if one stopped, a stored URI the feed
        no longer backs would otherwise differ from the extracted dict on every single
        harvest and rewrite the dataset forever.
        """
        source = self._source()
        xml = _catalog_xml(["0001"], **self.FIXTURE)
        xml = re.sub(r"<bdd_url>.*?</bdd_url>", "", xml, flags=re.S)
        rmock.get(INE_URL, text=xml)
        rmock.get(INE_HVD_URL, text="<indicators/>")

        backend = INEBackend(source)
        backend.LOCAL_FILE_PATH = str(tmp_path / "ine.xml")
        backend.harvest()

        rmock.get(INE_URL, text=xml)
        backend = INEBackend(source)
        backend.LOCAL_FILE_PATH = str(tmp_path / "ine.xml")
        job = backend.harvest()

        assert [item.status for item in job.items] == ["skipped"]
