import os

import pytest

from udata.core.dataset.factories import DatasetFactory
from udata.core.dataset.models import HarvestDatasetMetadata
from udata.core.organization.factories import OrganizationFactory
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


def _catalog_xml(ids, revision=""):
    indicators = "\n".join(
        f"""<indicator id='{i}'>
        <title><![CDATA[Indicador {i}]]></title>
        <description><![CDATA[Descrição {i}{revision}]]></description>
        <html><bdd_url><![CDATA[https://www.ine.pt/xurl/indx/{i}/PT]]></bdd_url></html>
        <json>
        <json_dataset><![CDATA[https://www.ine.pt/js/{i}.json]]></json_dataset>
        </json>
        <keywords>INE,<![CDATA[Estatística]]></keywords>
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
        # Never let this touch the real /tmp/ine.xml: other sessions run pytest
        # against this repo at the same time.
        shared = tmp_path / "ine.xml"
        shared.write_text(COMPLETE_XML)
        monkeypatch.setattr(INEBackend, "LOCAL_FILE_PATH", str(shared))
        rmock.get(INE_URL, text=_catalog_xml(["0001", "0002"]))
        rmock.get(INE_HVD_URL, text="<indicators/>")

        INEBackend(self._source(), dryrun=True).harvest()

        assert shared.exists()
        assert shared.read_text() == COMPLETE_XML

    def test_preview_removes_its_own_file(self, rmock, tmp_path, monkeypatch):
        monkeypatch.setattr(INEBackend, "LOCAL_FILE_PATH", str(tmp_path / "ine.xml"))
        rmock.get(INE_URL, text=_catalog_xml(["0001"]))
        rmock.get(INE_HVD_URL, text="<indicators/>")
        backend = INEBackend(self._source(), dryrun=True)

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
