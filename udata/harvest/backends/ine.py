from __future__ import annotations

import glob
import html
import os
import random
import re
import tempfile
import time
import unicodedata
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from datetime import datetime, timezone
from urllib.parse import urlparse
from uuid import uuid4

import defusedxml.ElementTree as DET
import requests
import urllib3
from flask import current_app
from slugify import slugify

from udata.core.dataset.constants import UpdateFrequency
from udata.core.utils.sanitization import sanitize_markdown_html, sanitize_strict
from udata.harvest.backends.base import BaseBackend
from udata.harvest.exceptions import (
    HarvestSourceError,
    HarvestValidationError,
)
from udata.harvest.models import HarvestError, HarvestItem, HarvestJob
from udata.models import Dataset, License
from udata.utils import safe_harvest_datetime, safe_unicode, to_naive_datetime

from ..url_filter import redact_url_credentials
from .tools.harvester_utils import (
    map_ine_periodicity,
    normalize_url_slashes,
    parse_ine_date,
    reset_ine_periodicity_warnings,
    sync_resources,
)

# The HVD subset of the catalogue, published as a separate feed. A fact of the source
# rather than an operator choice, so a module constant and not a per-source extra config.
INE_HVD_FEED_URL = "https://www.ine.pt/ine/xml_indic_hvd.jsp?opc=3&lang=PT"

# Metadata the INE catalogue publishes per indicator and that we store as extras. Kept as
# a tuple so `_has_changed` and `_apply_metadata_to_dataset` iterate the same set: a key
# written by one and ignored by the other is how enrichment silently fails to reach the
# ~13k datasets already in the database.
INE_SOURCE_EXTRAS = (
    "geo_lastlevel",
    "source_description",
    "last_period_available",
    "last_update_remote",
    "update_type",
    "metainfo_url",
)


class INEDownloadIncomplete(HarvestSourceError):
    """Raised when the catalogue stream ended without a complete document.

    The INE endpoint is slow and frequently drops the connection mid-stream.
    This is treated as a retryable error so the whole transfer (request + body)
    can be retried.
    """


# What ends one transfer attempt and is worth another: the connection or the
# body failing, and the body arriving broken (a truncated document, or the error
# page INE appends to a 200 response). Deliberately narrow — a defusedxml refusal
# (`EntitiesForbidden`/`DTDForbidden` are `ValueError`s), a bug in
# `_extract_metadata` or a database error must fail the job at once, not be
# retried five times with backoff as if the source had dropped the connection.
_STREAM_ERRORS = (
    requests.exceptions.ConnectionError,
    requests.exceptions.Timeout,
    requests.exceptions.ChunkedEncodingError,
    urllib3.exceptions.ProtocolError,
    ConnectionResetError,
    ConnectionAbortedError,
    ET.ParseError,
    HarvestSourceError,
)

# Stack-trace text the INE application server appends to a 200 response when it
# gives up midway (`javax.naming.NameNotFoundException: jdbc/... at io.undertow...`).
# Qualified Java names only, which no indicator text carries: a false positive is
# not harmless, since a marker inside a description would cut every run at the
# same byte and leave the job partial forever. So no "Exception", no bare
# newline-tab-"at " frame prefix, and no `<html`/`<!DOCTYPE` (`<html>` is an
# element of every `<indicator>`).
_ERROR_PAGE_MARKERS = (b"javax.naming.", b"at io.undertow.")
_UTF8_BOM = b"\xef\xbb\xbf"
_XML_HEADS = (b"<?xml", b"<catalog")


def _classify_stream_error(exc: Exception | None) -> str:
    """`source` when the body arrived but was wrong, `network` when it did not arrive."""
    return "source" if isinstance(exc, (HarvestSourceError, ET.ParseError)) else "network"


class _ErrorPageScanner:
    """Spot, as the bytes arrive, a response that is not the catalogue.

    The head is checked once: the first bytes past an optional BOM and blank
    lines must open an XML document. Then every chunk is searched for the stack
    trace markers, keeping a short tail so a marker split across two chunks is
    still found. Without this the junk only surfaced as a parse error once the
    source closed the connection, minutes later.
    """

    _TAIL = max(len(m) for m in _ERROR_PAGE_MARKERS) - 1

    def __init__(self):
        self._head = b""
        self._head_checked = False
        self._tail = b""
        self.bytes_seen = 0

    def feed(self, chunk: bytes) -> tuple[int, bytes] | None:
        """Return `(offset, marker)` when an error page starts in `chunk`.

        `offset` is relative to `chunk` and is negative when the marker began in
        the previous chunk. Raises `HarvestSourceError` when the head is not XML.
        """
        if not self._head_checked:
            self._check_head(chunk)
        window = self._tail + chunk
        found = None
        for marker in _ERROR_PAGE_MARKERS:
            index = window.find(marker)
            if index != -1 and (found is None or index < found[0]):
                found = (index, marker)
        self.bytes_seen += len(chunk)
        if found is not None:
            return found[0] - len(self._tail), found[1]
        self._tail = window[-self._TAIL :]
        return None

    def _check_head(self, chunk: bytes) -> None:
        self._head += chunk
        head = self._head
        if len(head) < len(_UTF8_BOM) and _UTF8_BOM.startswith(head):
            return  # a BOM split across chunks
        if head.startswith(_UTF8_BOM):
            head = head[len(_UTF8_BOM) :]
        head = head.lstrip()
        if len(head) < max(len(h) for h in _XML_HEADS) and any(
            h.startswith(head) for h in _XML_HEADS
        ):
            return  # not enough bytes yet to decide
        self._head_checked = True
        self._head = b""
        if not head.startswith(_XML_HEADS):
            raise HarvestSourceError(f"non-XML response body: {head[:60]!r}")


class _INECatalogStream:
    """File-like view over a streamed catalogue response, teeing it to disk.

    `iterparse` only needs `read()`, so the catalogue is parsed while it is still
    arriving and every byte is copied into `part_path` on the way. The copy is
    what becomes the cached catalogue once the document turns out complete; the
    parse is what lets the indicators that did arrive be processed even when the
    source cuts the body halfway.
    """

    def __init__(self, response, part_path: str, chunk_size: int = 8192):
        self._chunks = response.iter_content(chunk_size=chunk_size)
        self._file = open(part_path, "wb")
        self._scanner = _ErrorPageScanner()
        self._pending_error: HarvestSourceError | None = None
        self.bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        # One network chunk per call: `iterparse` accepts short reads, and
        # handing bytes over as soon as they arrive is the whole point.
        if self._pending_error is not None:
            raise self._pending_error
        for chunk in self._chunks:
            if not chunk:
                continue
            found = self._scanner.feed(chunk)
            if found is not None:
                offset, marker = found
                chunk = chunk[: max(offset, 0)]
                # Raised on the *next* read: the bytes before the marker go to
                # the parser first, so the complete indicators sharing a chunk
                # with the error page are still yielded instead of lost.
                self._pending_error = HarvestSourceError(
                    f"error page in the response body ({marker.decode().strip()}) "
                    f"after {self.bytes_read + len(chunk)} bytes"
                )
            self._file.write(chunk)
            self.bytes_read += len(chunk)
            if chunk:
                return chunk
            if self._pending_error is not None:
                raise self._pending_error
        return b""

    def close(self) -> None:
        if not self._file.closed:
            self._file.close()


class INEBackend(BaseBackend):
    """
    INE Harvester - modo FAST (2 fases):
    1) Parse XML -> metadados em memória
    2) Change detection + bulk_write no Mongo (muito mais rápido)

    O catálogo é lido em streaming de self.source.url e processado à medida que chega; a
    última cópia completa fica como snapshot persistente (HARVEST_SNAPSHOT_DIR), usado
    quando nenhuma tentativa entrega um único indicador.

    Robustez:
    - Captura BulkWriteError, extrai bwe.details['writeErrors'] e isola operação falhada
      sem abortar o harvest inteiro. [1](https://www.mongodb.com/docs/languages/python/pymongo-driver/current/crud/bulk-write/)[2](https://pymongo.readthedocs.io/en/4.11/examples/bulk.html)
    - Gera slug a partir do título sanitizado para novos datasets.
    """

    name = "ine"
    display_name = "Instituto nacional de estatística"

    # HTTP retry/backoff/timeout comes from the HARVEST_HTTP_* settings via
    # BaseBackend (http_max_retries, http_retry_*_delay, http_timeout).
    # Only the full-file catalog download keeps a more generous retry budget:
    # the INE endpoint frequently drops the connection mid-stream, so each
    # retry re-transfers the whole (large) body.
    DOWNLOAD_MAX_RETRIES = 5

    # Harvester Configuration
    BULK_SIZE = 500
    LOG_EVERY = 200
    CHECK_CHANGES = True
    # Explicit catalogue path. `None` means the per-source snapshot under
    # `snapshot_dir`; previews set a throwaway path of their own, and tests point
    # it into a temporary directory.
    LOCAL_FILE_PATH: str | None = None

    # Regex patterns
    _KW_SPLIT_RE = re.compile(r"\s*(?:;|,|/|\n|\r|\t|\s+-\s+)\s*")
    _NON_ALNUM_DASH_RE = re.compile(r"[^a-z0-9\-]+")
    _MULTI_DASH_RE = re.compile(r"\-+")

    HVD_INDICATOR_IDS: set[str] = set()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._cc_by_license = None
        self._catalog_truncated = False
        # Set when every transfer attempt was cut after some indicators had
        # already been processed: those stay updated, but the run did not see the
        # whole catalogue, so nothing may be archived from it.
        self._catalog_partial = False
        # remote_ids already processed in this run. Shared by every transfer
        # attempt, so a retry, which re-reads the catalogue from the top, skips
        # what an earlier attempt handled instead of pushing a second HarvestItem.
        self._seen: set[str] = set()
        self._stats = dict.fromkeys(("processed", "changed", "created", "skipped", "failed"), 0)
        self._pending_items: list[HarvestItem] = []
        self._dataset_collection = None
        self._parsed_count = 0
        # Per-phase durations, in seconds, written to the log and to `job.data`.
        # The clock is an instance attribute so a test can drive it without
        # patching `time.monotonic` for the whole process (pymongo reads it too).
        self._clock = time.monotonic
        self._timings: dict[str, float] = {}
        self._download_attempts: list[dict] = []
        # Age in seconds of the snapshot this run fell back on, `None` when the
        # catalogue came from the source.
        self._snapshot_fallback_age: float | None = None
        # Set on a snapshot fallback: datasets harvested after the snapshot was
        # taken are newer than it and left untouched.
        self._snapshot_cutoff: datetime | None = None

        if self.dryrun:
            # Previews must not share the catalogue path with the real harvest:
            # a preview could overwrite the snapshot a running harvest was
            # reading, and its cleanup would delete the snapshot that harvest
            # falls back on when the slow INE endpoint drops the connection on
            # every attempt. A preview's file is throwaway and removed after it.
            self.LOCAL_FILE_PATH = os.path.join(
                tempfile.gettempdir(), f"ine-preview-{uuid4().hex}.xml"
            )

        try:
            self._log = current_app.logger
        except Exception:
            import logging

            self._log = logging.getLogger(__name__)

    # --------------------------
    # Download robusto com validação de integridade
    # --------------------------
    def _is_complete_xml(self, path: str, root_tag: str = "catalog") -> bool:
        """Cheap completeness check: the file must end with the closing root tag.

        A truncated download (connection dropped mid-stream) will not contain the
        closing </catalog> tag, so we can detect it without parsing the whole file.
        """

        try:
            size = os.path.getsize(path)
        except OSError:
            return False
        if size == 0:
            return False
        tail_bytes = min(size, 8192)
        with open(path, "rb") as f:
            f.seek(-tail_bytes, os.SEEK_END)
            tail = f.read().decode("utf-8", errors="ignore")
        return f"</{root_tag}>" in tail

    @staticmethod
    def _safe_remove(path: str) -> None:
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass

    # --------------------------
    # Normalização de tags
    # --------------------------
    def _text(self, node: ET.Element, tag: str) -> str:
        """Text of a child element, stripped.

        Values arrive wrapped in CDATA and 13152 of the 13154 published periodicities
        carry surrounding whitespace, so stripping is not defensive tidying here.
        """
        child = node.find(tag)
        if child is None or not child.text:
            return ""
        return child.text.strip()

    def _source_hostname(self) -> str:
        return urlparse(self.source.url or "").hostname or ""

    def _normalize_tag(self, tag: str) -> str:
        if not tag:
            return ""

        nfd = unicodedata.normalize("NFD", tag)
        tag = "".join(ch for ch in nfd if unicodedata.category(ch) != "Mn")
        tag = tag.lower()
        tag = self._NON_ALNUM_DASH_RE.sub("-", tag)
        tag = self._MULTI_DASH_RE.sub("-", tag).strip("-")
        return tag

    # --------------------------
    # HVD IDs
    # --------------------------
    def _fetch_hvd_ids(self) -> set[str]:
        url = INE_HVD_FEED_URL
        try:
            # Guarded fetch (SSRF check + retry/timeout) via BaseBackend
            resp = self.get(url, timeout=30)
            resp.raise_for_status()
            root = DET.fromstring(resp.content)
            ids = {ind.attrib["id"] for ind in root.findall(".//indicator") if "id" in ind.attrib}
            self._log.info("[INE] HVD IDs carregados: %s", len(ids))
            return ids
        except Exception as e:
            self._log.warning("[INE] Falha ao carregar HVD IDs: %s", e)
            return set()

    # --------------------------
    # Extrai metadados do indicator (já normalizados)
    # --------------------------
    def _extract_metadata(self, elem: ET.Element) -> dict:
        """Read one `<indicator>` into a metadata dict, sanitized.

        Title and description are sanitized *here*, at extraction, and not in
        `_apply_metadata_to_dataset`. This backend writes `dataset.to_mongo()`
        straight to pymongo, so the `Dataset.pre_save` signal that sanitizes
        every other write in the portal never fires for it; the sanitization has
        to be reproduced by hand. It cannot happen in the apply step, though,
        because `_has_changed` compares the *stored* values against this dict
        and runs before it: sanitizing later would compare a sanitized title
        against a raw one, so any indicator carrying markup would report as
        changed on every nightly harvest and be rewritten forever.
        """
        md = {}

        node = elem.find("title")
        if node is not None and node.text:
            md["title"] = sanitize_strict(node.text)

        desc = ""
        remote_url = None
        node = elem.find("description")
        if node is not None and node.text:
            desc = node.text

        metainfo_url = None
        html_node = elem.find("html")
        if html_node is not None:
            bdd_url = html_node.find("bdd_url")
            if bdd_url is not None and bdd_url.text:
                remote_url = bdd_url.text.strip()
                desc = (desc + "\n" + bdd_url.text) if desc else bdd_url.text
            metainfo_node = html_node.find("metainfo_url")
            if metainfo_node is not None and metainfo_node.text:
                metainfo_url = metainfo_node.text.strip()

        if desc:
            md["description"] = sanitize_markdown_html(desc)
        if remote_url:
            # Not sanitized on purpose: this is a URL, not markup, and it is
            # stored in `harvest.remote_url` rather than rendered as content.
            md["remote_url"] = remote_url

        resources = []
        json_node = elem.find("json")
        if json_node is not None:
            jds = json_node.find("json_dataset")
            if jds is not None and jds.text:
                resources.append(
                    {
                        "title": "Dados (JSON)",
                        "description": "Dataset em formato json",
                        "url": normalize_url_slashes(jds.text),
                        "filetype": "remote",
                        "format": "json",
                    }
                )
            jmi = json_node.find("json_metainfo")
            if jmi is not None and jmi.text:
                resources.append(
                    {
                        "title": "Metainfo (JSON)",
                        "description": "Metainfo em formato json",
                        "url": normalize_url_slashes(jmi.text),
                        "filetype": "remote",
                        "format": "json",
                    }
                )

        md["resources"] = resources
        md["resource_urls"] = [r["url"].strip() for r in resources]
        md["resource_sig"] = {
            (r["url"].strip(), r["title"], r["description"], r["format"]) for r in resources
        }

        keywords = set()
        for kn in elem.findall("keywords"):
            text = (kn.text or "").strip()
            if not text:
                continue
            for part in self._KW_SPLIT_RE.split(text):
                part = part.strip().strip(",")
                if part:
                    keywords.add(part)

        for tagname in ("theme", "subtheme"):
            for tn in elem.findall(tagname):
                val = (tn.text or "").strip()
                if val:
                    keywords.add(val)

        tags_norm = {self._normalize_tag(t) for t in keywords if t}
        tags_norm.discard("")
        # Which source a dataset came from, as a tag. Derived from the source URL rather
        # than hardcoded, like `ckanpt` and `odspt` do. Normalized on the way in because
        # `TagListField` slugifies on write while `_has_changed` compares the stored tags
        # against this dict: storing "www.ine.pt" here and "www-ine-pt" in Mongo would
        # report every dataset in the catalogue as changed on every nightly harvest.
        tags_norm.add(self._normalize_tag(self._source_hostname()))
        tags_norm.discard("")
        md["tags_norm"] = sorted(tags_norm)

        md["frequency"] = map_ine_periodicity(self._text(elem, "periodicity"))

        extras = {}
        # Free text rendered by the portal, so sanitized here for the same reason the
        # docstring gives for the title and description.
        geo_lastlevel = self._text(elem, "geo_lastlevel")
        if geo_lastlevel:
            extras["geo_lastlevel"] = sanitize_strict(geo_lastlevel)
        source_description = self._text(elem, "source")
        if source_description:
            extras["source_description"] = sanitize_strict(source_description)

        dates_node = elem.find("dates")
        if dates_node is not None:
            last_period = self._text(dates_node, "last_period_available")
            if last_period:
                extras["last_period_available"] = last_period
            last_update = self._text(dates_node, "last_update")
            if last_update:
                extras["last_update_remote"] = last_update
                md["modified_at"] = safe_harvest_datetime(
                    parse_ine_date(last_update), "INE <last_update>", refuse_future=True
                )

        # Published for ~5% of indicators only, and an opaque code ("A", "N"): stored
        # verbatim, never mapped onto a meaning we would be inventing.
        update_type = self._text(elem, "update_type")
        if update_type:
            extras["update_type"] = update_type

        if metainfo_url:
            extras["metainfo_url"] = metainfo_url

        md["extras"] = extras

        return md

    # --------------------------
    # Prefetch em lote (1 query por chunk em vez de 1 por item)
    # --------------------------
    def _prefetch_datasets(self, remote_ids: list[str]) -> dict[str, Dataset]:
        """Fetch all existing datasets for a chunk in a single query.

        Equivalent to calling `self.get_dataset()` once per item (INE remote
        ids are never URIs, so only the domain/source_id branch applies), but
        with one `$in` query per chunk instead of one round-trip per item.
        """
        found = Dataset.objects(
            __raw__={
                "harvest.remote_id": {"$in": remote_ids},
                "$or": [
                    {"harvest.domain": self.source.domain},
                    {"harvest.source_id": str(self.source.id)},
                ],
            }
        )
        by_remote_id: dict[str, Dataset] = {}
        for dataset in found:
            rid = dataset.harvest.remote_id if dataset.harvest else None
            # Keep the first match per remote_id (mirrors `.first()`)
            if rid and rid not in by_remote_id:
                by_remote_id[rid] = dataset
        return by_remote_id

    def _new_dataset(self) -> Dataset:
        """Build an empty dataset owned like `BaseBackend.get_dataset` does."""
        if self.source.organization:
            return Dataset(organization=self.source.organization)
        elif self.source.owner:
            return Dataset(owner=self.source.owner)
        return Dataset()

    # --------------------------
    # Job items: $push incremental em vez de reescrever o documento
    # --------------------------
    def _append_job_items(self, items: list[HarvestItem]) -> None:
        """Append HarvestItems to the job with a `$push` delta.

        `job.items.extend()` + `job.save()` rewrites (and re-validates) the
        ever-growing items array on every flush; a `push_all` update only
        sends the new items. The local list is kept in sync because
        `BaseBackend.harvest()` inspects `self.job.items` afterwards.
        """
        if not items:
            return
        if not self.dryrun and self.job.pk:
            HarvestJob.objects(pk=self.job.pk).update_one(push_all__items=items)
        self.job.items.extend(items)

    # --------------------------
    # Change detection (barato + deep size check)
    # --------------------------
    def _has_changed(self, dataset, new_md: dict, remote_id: str) -> bool:
        if not getattr(dataset, "id", None):
            return True

        if (dataset.title or "") != (new_md.get("title") or ""):
            return True

        if (dataset.description or "") != (new_md.get("description") or ""):
            return True

        desired = set(new_md.get("tags_norm") or [])
        if remote_id in self.HVD_INDICATOR_IDS:
            desired.update({"estatisticas", "hvd"})

        if set(dataset.tags or []) != desired:
            return True

        current_urls = {r.url for r in dataset.resources}
        if current_urls != set(new_md.get("resource_urls") or []):
            return True

        current_sig = {
            (r.url, r.title or "", r.description or "", r.format or "") for r in dataset.resources
        }
        if current_sig != (new_md.get("resource_sig") or set()):
            return True

        # Everything below is metadata the backend only started writing once it stopped
        # hardcoding it. Without these comparisons the enrichment would never reach the
        # datasets already in the database: they match on title, description, tags and
        # resources, so they would be reported unchanged and skipped forever.
        current_frequency = dataset.frequency or UpdateFrequency.UNKNOWN
        if current_frequency != new_md.get("frequency", UpdateFrequency.UNKNOWN):
            return True

        new_extras = new_md.get("extras") or {}
        for key in INE_SOURCE_EXTRAS:
            if (dataset.extras.get(key) or None) != (new_extras.get(key) or None):
                return True

        current_uri = (dataset.harvest.uri if dataset.harvest else None) or None
        if current_uri != (new_md.get("remote_url") or None):
            return True

        # Fields `_refresh_derived_fields` writes, because the bulk path never runs
        # `Dataset.clean()`. Datasets written before it existed carry the harvest time as
        # `last_update` and an empty or stale `quality_cached`, and match on everything
        # above, so without these they would never heal. Only what follows from the
        # harvested metadata is compared: the rest of `quality_cached` moves with the link
        # checker, and comparing it would rewrite the dataset every night.
        if to_naive_datetime(dataset.last_update) != dataset.compute_last_update():
            return True

        cached = dataset.quality_cached or {}
        if not cached or cached.get("update_frequency") != dataset.has_frequency:
            return True

        return False

    # --------------------------
    # Aplica metadata ao dataset (sem salvar)
    # --------------------------
    def _apply_metadata_to_dataset(self, dataset, remote_id: str, md: dict):
        if self._cc_by_license is None:
            self._cc_by_license = License.guess("cc-by")

        # cc-by is our editorial choice, not something the feed states: the INE catalogue
        # publishes no licence element at all.
        dataset.license = self._cc_by_license
        dataset.frequency = md.get("frequency", UpdateFrequency.UNKNOWN)

        tags = list(md.get("tags_norm") or [])
        if remote_id in self.HVD_INDICATOR_IDS:
            for t in ("estatisticas", "hvd"):
                if t not in tags:
                    tags.append(t)
        source_tag = self._normalize_tag(self._source_hostname())
        if source_tag and source_tag not in tags:
            tags.append(source_tag)
        dataset.tags = tags

        for key in INE_SOURCE_EXTRAS:
            value = (md.get("extras") or {}).get(key)
            if value:
                dataset.extras[key] = value
            else:
                # An indicator that stopped publishing a field must not keep the stale
                # value glued to it.
                dataset.extras.pop(key, None)

        if "title" in md:
            dataset.title = md["title"]
        if "description" in md:
            dataset.description = md["description"]

        # Reconciled, not rebuilt: `_has_changed` lets any single metadata edit
        # reach this point, and recreating the resources there would hand every
        # one of them a new id — a new, broken download permalink (LEDG-2251).
        sync_resources(dataset, md.get("resources") or [])

        if not dataset.harvest:
            dataset.harvest = Dataset.harvest.document_type_obj()

        # Campos obrigatórios
        dataset.harvest.remote_id = str(remote_id)
        dataset.harvest.source_id = str(self.source.id) if self.source.id else None
        dataset.harvest.last_update = datetime.now(timezone.utc)
        dataset.harvest.domain = getattr(self.source, "domain", "") or ""

        # The display name, as `BaseBackend.update_dataset_harvest_info` stamps for every
        # other backend. This one never reaches that method — it bypasses `process_dataset`
        # for the bulk write path — so the field has to be set by hand here; dropping the
        # line would leave it empty rather than let the base class fill it in.
        dataset.harvest.backend = self.display_name

        # The landing page the source publishes, for both fields that hold it. Written
        # unconditionally, `None` included: keeping a URL the source no longer publishes
        # would leave `remote_url` and `uri` disagreeing for good, and would go on feeding
        # `dcat:landingPage` a link the feed has dropped.
        dataset.harvest.remote_url = md.get("remote_url") or None

        # Identificador DCT (Dublin Core Terms)
        dataset.harvest.dct_identifier = f"ine:{remote_id}"

        # Not the `/indicador/<id>` we used to compose. Same unconditional write as
        # `remote_url` above: a stale URI the dict no longer carries would make
        # `_has_changed` fire on every harvest and rewrite the dataset nightly, forever.
        dataset.harvest.uri = md.get("remote_url") or None

        # Data de criação (apenas se for novo)
        if not dataset.harvest.created_at:
            dataset.harvest.created_at = datetime.now(timezone.utc)

        # When the source last updated the indicator — not when we last looked at it.
        # `harvest.last_update` above is the timestamp of this run; conflating the two is
        # what made every INE dataset look freshly modified after every nightly harvest.
        dataset.harvest.modified_at = md.get("modified_at") or datetime.now(timezone.utc)

        # Gera slug a partir do título para novos datasets
        # Adiciona remote_id ao final para garantir unicidade
        if not getattr(dataset, "id", None):
            if not getattr(dataset, "slug", None) and dataset.title:
                # Unescaped first: the title is sanitized, and bleach escapes
                # what it does not strip, so slugifying it directly turns
                # "Investigação e Desenvolvimento (I&D)" into a permalink
                # carrying a spurious "-amp-" segment.
                base_slug = slugify(html.unescape(dataset.title), to_lower=True)
                dataset.slug = f"{base_slug}-{remote_id}" if base_slug else f"ine-{remote_id}"

        # Last on purpose: every field below is derived from the metadata set above.
        self._refresh_derived_fields(dataset)

        return dataset

    def _refresh_derived_fields(self, dataset):
        """Write by hand what `Dataset.clean()` and `save()` would have written.

        The bulk write path hands `to_mongo()` straight to pymongo, so `clean()` never runs
        and these stayed at whatever the document held: `last_update` at the harvest time
        instead of the source date, `quality_cached` empty or stale, so the visible score
        ignored the frequency read from the source, and `last_modified_internal` untouched,
        so `udata search index -f` never saw the rewrite. Same approach as
        `Dataset.add_resource`, which also bypasses `save()`.

        Order matters, as in `clean()`: the quality's `next_update` is computed from
        `last_update`. And it has to run after `license` is assigned: `compute_quality()`
        reads it, and a `License` still lazy from the prefetch would cost one query per
        indicator. Everything else it reads is in memory, resources included.
        """
        dataset.last_update = dataset.compute_last_update()
        dataset.quality_cached = dataset.compute_quality()
        dataset.last_modified_internal = datetime.now(timezone.utc)

    # --------------------------
    # Flush bulk com tratamento de BulkWriteError
    # --------------------------
    def _flush_bulk(self, collection, ops, op_ids):
        """
        Executa bulk_write e trata BulkWriteError:
        - Loga bwe.details['writeErrors'] com o remote_id correspondente (via índice)
        - Reprocessa o batch em modo "divide and conquer" para salvar o máximo possível.
        """
        from pymongo.errors import BulkWriteError

        if not ops:
            return 0, 0, 0  # matched, modified, upserted

        if self.dryrun:
            # A preview must never touch the database. This backend does not go
            # through `BaseBackend.process_dataset`, so the dryrun guard around
            # `dataset.save()` in `base.py` never applies here: `inner_harvest`
            # writes the datasets itself, and every one of those writes — the
            # `ReplaceOne` of a changed dataset and the upserting `UpdateOne` of a
            # new one — funnels through this method. Guarding here therefore
            # closes both call sites (the per-chunk flush and the final one) at
            # once. Logged at WARNING because suppressed writes are an
            # operationally meaningful event; note that, unlike the LEDG-2320
            # backends, nothing on this path installs a `LogCatcher`, so this
            # does not reach the preview response.
            self._log.warning("[INE] Dryrun: discarding %s pending write(s)", len(ops))
            return 0, 0, 0

        t0 = time.time()
        try:
            with self._timed("bulk_write"):
                res = collection.bulk_write(ops, ordered=False)
            dt = time.time() - t0
            upserted = len(getattr(res, "upserted_ids", {}) or {})
            self._log.info(
                "[INE] bulk_write OK: ops=%s em %.2fs | matched=%s modified=%s upserted=%s",
                len(ops),
                dt,
                getattr(res, "matched_count", "?"),
                getattr(res, "modified_count", "?"),
                upserted,
            )
            return (
                getattr(res, "matched_count", 0),
                getattr(res, "modified_count", 0),
                upserted,
            )

        except BulkWriteError as bwe:
            dt = time.time() - t0
            details = getattr(bwe, "details", {}) or {}
            werrors = details.get("writeErrors", []) or []

            self._log.error(
                "[INE] BulkWriteError em %.2fs (ops=%s). writeErrors=%s",
                dt,
                len(ops),
                len(werrors),
            )

            # log detalhado por erro (inclui código/mensagem/índice)
            for err in werrors[:10]:  # limita para não explodir logs
                idx = err.get("index")
                rid = op_ids[idx] if isinstance(idx, int) and idx < len(op_ids) else "?"
                self._log.error(
                    "[INE] writeError remote_id=%s idx=%s code=%s errmsg=%s",
                    rid,
                    idx,
                    err.get("code"),
                    err.get("errmsg"),
                )

            # Estratégia: dividir o batch e tentar salvar a maioria
            if len(ops) == 1:
                # não há como dividir mais; já logamos
                return 0, 0, 0

            mid = len(ops) // 2
            self._flush_bulk(collection, ops[:mid], op_ids[:mid])
            self._flush_bulk(collection, ops[mid:], op_ids[mid:])

            return 0, 0, 0

    # --------------------------
    # inner_harvest (2 fases)
    # --------------------------
    def inner_harvest(self):
        reset_ine_periodicity_warnings()
        try:
            with self._timed("total"):
                self._inner_harvest()
        finally:
            # Failed runs too: knowing how far a failing run got, and how long
            # each attempt took, is what the timings are for.
            self._record_job_data()
            if self.dryrun:
                # A real harvest keeps its catalogue as the snapshot it falls back
                # on; a preview owns a unique throwaway file and would leave it
                # behind for good.
                self._cleanup_local_file()

    def autoarchive(self):
        """Skip archiving when the catalog was only partly read.

        `BaseBackend.autoarchive` treats every remote_id missing from
        `job.items` as gone from the remote platform. That is sound for a run
        that read the whole catalog and false for one that stopped at
        `max_items` — which is every preview, since `actions.preview` always
        passes `HARVEST_PREVIEW_MAX_ITEMS`. Without this, a preview of a source
        whose real harvest has been failing for longer than the grace period
        would report the entire rest of the catalog as archived. A stream the
        source cut midway (`_catalog_partial`) is the same situation, and so is a
        run fed from the snapshot.
        """
        if self._catalog_truncated:
            self._log.warning(
                "[INE] Autoarchive ignorado: o catálogo foi truncado em max_items=%s",
                self.max_items,
            )
            return
        if self._catalog_partial:
            # Same reasoning for a stream the source cut: everything past the cut
            # would look gone from the catalogue.
            self._log.warning(
                "[INE] Autoarchive ignorado: o catálogo só foi lido em parte (%s indicadores)",
                len(self._seen),
            )
            return
        if self._snapshot_fallback_age is not None:
            # An old snapshot proves nothing about what the source removed since.
            self._log.warning(
                "[INE] Autoarchive ignorado: o catálogo veio do snapshot (%.0fs)",
                self._snapshot_fallback_age,
            )
            return
        with self._timed("autoarchive"):
            super().autoarchive()
        self._record_job_data()

    @contextmanager
    def _timed(self, key: str):
        """Add the time spent in the block to `self._timings[key]`."""
        started = self._clock()
        try:
            yield
        finally:
            self._timings[key] = self._timings.get(key, 0.0) + (self._clock() - started)

    def _record_attempt(
        self, attempt: int, started: float, bytes_read: int, error: Exception | None
    ) -> None:
        self._download_attempts.append(
            {
                "attempt": attempt,
                "bytes": bytes_read,
                "seconds": round(self._clock() - started, 3),
                "kind": _classify_stream_error(error) if error is not None else None,
                "error": (
                    redact_url_credentials(safe_unicode(error))[:500] if error is not None else None
                ),
            }
        )

    def _record_job_data(self) -> None:
        """Write the timings and download attempts to the log and `job.data`.

        Merged into `job.data`, never assigned over it: `partial` and `snapshot`
        live there too. `HarvestJob.data` is not exposed by the API, so this is
        an operator's record (read from Mongo), not a contract.
        """
        timings = {key: round(value, 3) for key, value in self._timings.items()}
        attempts = list(self._download_attempts)
        if getattr(self, "job", None) is not None:
            self.job.data.update(
                {
                    "timings": timings,
                    "download": {
                        "attempts": attempts,
                        "bytes": sum(a["bytes"] for a in attempts),
                    },
                }
            )
        self._log.info(
            "[INE] Tempos por fase: %s | tentativas=%s bytes=%s",
            " ".join(f"{key}={value:.1f}s" for key, value in timings.items()),
            len(attempts),
            sum(a["bytes"] for a in attempts),
        )

    @property
    def snapshot_dir(self) -> str:
        """Where real harvests keep their last complete catalogue.

        Defaults under `FS_ROOT`, which deployments mount as a persistent volume
        shared by app and worker (`/dadosgov/fs`), so the snapshot survives a
        worker restart where `/tmp` did not. Not under any registered storage, so
        it is never served by `/s/`.
        """
        configured = current_app.config.get("HARVEST_SNAPSHOT_DIR")
        if configured:
            return configured
        # Same default `flask_storage` gives `FS_ROOT` when it is not configured.
        fs_root = current_app.config.get("FS_ROOT") or os.path.join(current_app.instance_path, "fs")
        return os.path.join(fs_root, "harvest-snapshots")

    def _snapshot_path(self) -> str:
        """The catalogue file of this run, one per source.

        Resolved lazily rather than in `__init__`, so an override of
        `LOCAL_FILE_PATH` set after construction still applies.
        """
        if self.LOCAL_FILE_PATH:
            return self.LOCAL_FILE_PATH
        return os.path.join(self.snapshot_dir, f"ine-{self.source.id}.xml")

    def _cleanup_local_file(self):
        path = self._snapshot_path()
        try:
            if os.path.exists(path):
                os.remove(path)
                self._log.info("[INE] Ficheiro do preview removido: %s", path)
        except Exception as e:
            self._log.warning("[INE] Falha ao remover ficheiro %s: %s", path, e)

    def _inner_harvest(self):
        # Redacted here too: this line runs on every harvest, and an INFO
        # record also becomes a Sentry breadcrumb (LEDG-2501).
        self._log.info(
            "[INE] Iniciando harvester de %s", redact_url_credentials(str(self.source.url))
        )
        self._log.info(
            "[INE] Config: BulkSize=%s, LogEvery=%s, CheckChanges=%s",
            self.BULK_SIZE,
            self.LOG_EVERY,
            self.CHECK_CHANGES,
        )

        start_time = time.time()
        self.HVD_INDICATOR_IDS = self._fetch_hvd_ids()

        if not hasattr(self, "job") or self.job is None:
            self._log.warning(
                "[INE] Atenção: self.job não existe. O progresso não será visível na UI."
            )

        try:
            complete, last_error = self._harvest_live()
            if not complete:
                if self._seen:
                    self._mark_partial(last_error)
                elif self._is_complete_xml(self._snapshot_path()):
                    self._harvest_snapshot(last_error)
                else:
                    self._raise_classified(last_error)
            # Allowed to raise: `harvest()` runs autoarchive right after, from
            # `job.items`, and items that failed to land would read as gone.
            self._flush_pending_items()
        except Exception as e:
            self._log.error(
                "[INE] Erro no download/parsing do XML: %s",
                redact_url_credentials(safe_unicode(e)),
            )
            # Keep the record of what was processed, without hiding `e`.
            self._flush_pending_items(swallow=True)
            raise

        if self._catalog_truncated and not self.dryrun:
            # Expected in a preview, worth an error on a real harvest: with
            # `source.autoarchive` on, everything below the cut would be
            # archived as if it had disappeared from the remote catalog.
            self._log.warning(
                "[INE] max_items=%s atingido: nem todos os indicadores foram retirados",
                self.max_items,
            )
            self.job.errors.append(
                HarvestError(
                    message=(f"{self.max_items} max items reached, not all datasets were retrieved")
                )
            )

        total_time = time.time() - start_time
        stats = self._stats
        self._log.info(
            "[INE] FAST MODE concluído em %ss (%.1f min) | parsed=%s processed=%s changed=%s "
            "created=%s skipped=%s failed=%s",
            round(total_time, 1),
            total_time / 60,
            self._parsed_count,
            stats["processed"],
            stats["changed"],
            stats["created"],
            stats["skipped"],
            stats["failed"],
        )

    def _harvest_live(self) -> tuple[bool, Exception | None]:
        """Stream the catalogue from the source, processing it as it arrives.

        Each attempt re-requests the catalogue from the top: the endpoint
        ignores `Range` and has no paging, so there is nothing to resume from.
        Indicators an earlier attempt already processed are skipped (`_seen`),
        which makes a retry cost the transfer only.

        Returns whether an attempt read the whole catalogue (or stopped at
        `max_items` by design), and the error that ended the last attempt.
        """
        path = self._snapshot_path()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._remove_stale_parts(path)
        delay = self.http_retry_initial_delay
        max_delay = self.http_retry_max_delay
        last_error: Exception | None = None

        for attempt in range(1, self.DOWNLOAD_MAX_RETRIES + 1):
            # Unique per attempt and per process: two runs of the same source
            # must never interleave their writes into one file.
            part = f"{path}.{os.getpid()}-{uuid4().hex[:8]}.part"
            error: Exception | None = None
            started = self._clock()
            bytes_read = 0
            try:
                try:
                    # Guarded fetch (SSRF check, LEDG-1729 / VULN-2084): the
                    # connection-setup retry lives in BaseBackend; this loop
                    # retries the body transfer.
                    with self._timed("download_parse"):
                        response = self.get(self.source.url, stream=True, timeout=self.http_timeout)
                    if response.status_code >= 500:
                        # The source failing to serve, like the error page it
                        # appends to a 200: retried, then the snapshot.
                        response.close()
                        raise HarvestSourceError(f"HTTP {response.status_code} from the source")
                except _STREAM_ERRORS as e:
                    error = e
                else:
                    try:
                        response.raise_for_status()
                        stream = _INECatalogStream(response, part)
                    except BaseException:
                        response.close()
                        raise
                    try:
                        error = self._harvest_indicators(self._iter_indicators(stream))
                    finally:
                        stream.close()
                        response.close()
                        bytes_read = stream.bytes_read

                    if error is None and self._catalog_truncated:
                        self._record_attempt(attempt, started, bytes_read, None)
                        return True, None
                    if error is None and not self._is_complete_xml(part):
                        error = INEDownloadIncomplete("XML truncado: root <catalog> não fechado")
                    if error is None:
                        os.replace(part, path)
                        self._log.info(
                            "[INE] Catálogo completo e validado: %s bytes (tentativa %s)",
                            bytes_read,
                            attempt,
                        )
                        self._record_attempt(attempt, started, bytes_read, None)
                        return True, None
            finally:
                self._safe_remove(part)

            self._record_attempt(attempt, started, bytes_read, error)

            last_error = error
            self._log.warning(
                "[INE] Download falhou/truncado (tentativa %s/%s, %s indicadores processados): %s",
                attempt,
                self.DOWNLOAD_MAX_RETRIES,
                len(self._seen),
                redact_url_credentials(safe_unicode(error)),
            )
            if attempt < self.DOWNLOAD_MAX_RETRIES:
                jitter = random.uniform(0, 0.1 * delay)
                time.sleep(min(delay + jitter, max_delay))
                delay = min(delay * 2, max_delay) if delay else 1

        return False, last_error

    def _remove_stale_parts(self, path: str) -> None:
        """Delete `.part` files a killed worker left next to the snapshot.

        The `finally` of each attempt removes its own file, but not when the
        process dies mid-transfer, and on the persistent volume nothing else
        ever would. A day is far beyond any single run.
        """
        cutoff = time.time() - 24 * 3600
        for leftover in glob.glob(f"{glob.escape(path)}.*.part"):
            try:
                if os.path.getmtime(leftover) < cutoff:
                    os.remove(leftover)
                    self._log.info("[INE] Ficheiro parcial órfão removido: %s", leftover)
            except OSError:
                pass

    def _harvest_snapshot(self, last_error: Exception | None) -> None:
        """Process the last complete catalogue kept on disk.

        Only reached when no attempt delivered a single indicator. Never used to
        complete a partial run: the database already reflects that file, so
        replaying it over a run that did reach the source would at best change
        nothing and at worst roll back what the source just updated.
        """
        path = self._snapshot_path()
        # `os.replace` keeps the mtime of the `.part` file, which is when the
        # download that produced the snapshot finished.
        mtime = os.path.getmtime(path)
        self._snapshot_fallback_age = time.time() - mtime
        taken_at = datetime.fromtimestamp(mtime, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        age_hours = self._snapshot_fallback_age / 3600
        self._log.warning(
            "[INE] Download falhou após %s tentativas (%s); a usar o snapshot de %s (%.1f h): %s",
            self.DOWNLOAD_MAX_RETRIES,
            redact_url_credentials(safe_unicode(last_error)),
            taken_at,
            age_hours,
            path,
        )
        self.job.data["snapshot"] = {
            "used": True,
            "age_seconds": round(self._snapshot_fallback_age, 1),
            "path": path,
        }
        self.job.errors.append(
            HarvestError(
                message=(
                    f"INE {_classify_stream_error(last_error)} error: "
                    f"catalogue download failed after {self.DOWNLOAD_MAX_RETRIES} attempts; "
                    f"using snapshot from {taken_at} ({age_hours:.1f} h old), "
                    f"autoarchive skipped ({safe_unicode(last_error)})"
                )
            )
        )
        # A partial run after the snapshot was taken may have written newer source
        # data; replaying the snapshot over it would roll those datasets back.
        self._snapshot_cutoff = datetime.fromtimestamp(mtime, timezone.utc).replace(tzinfo=None)
        error = self._harvest_indicators(self._iter_indicators(path))
        if error is not None:
            raise error

    def _newer_than_snapshot(self, dataset) -> bool:
        """Whether a fallback run must leave `dataset` alone (see `_harvest_snapshot`)."""
        if self._snapshot_cutoff is None or not dataset.harvest:
            return False
        last_update = dataset.harvest.last_update
        return last_update is not None and to_naive_datetime(last_update) > self._snapshot_cutoff

    def _raise_classified(self, last_error: Exception | None) -> None:
        """Fail the job with an error that says whose fault it was."""
        kind = _classify_stream_error(last_error)
        message = (
            f"INE {kind} error: catalogue download failed after "
            f"{self.DOWNLOAD_MAX_RETRIES} attempts and no snapshot is available "
            f"({redact_url_credentials(safe_unicode(last_error))})"
        )
        if kind == "source":
            raise HarvestSourceError(message) from last_error
        # A `requests` connection error on purpose: `BaseBackend.harvest` logs
        # those as a warning, where any other exception becomes an error report.
        raise requests.exceptions.ConnectionError(message) from last_error

    def _mark_partial(self, last_error: Exception | None) -> None:
        """Record a run whose every attempt was cut after some indicators."""
        self._catalog_partial = True
        self.job.data["partial"] = True
        self._log.warning(
            "[INE] Execução parcial: o catálogo foi cortado após %s indicadores: %s",
            len(self._seen),
            redact_url_credentials(safe_unicode(last_error)),
        )
        self.job.errors.append(
            HarvestError(
                message=(
                    f"INE {_classify_stream_error(last_error)} error: "
                    f"catalogue stream cut after {len(self._seen)} indicators; "
                    "received indicators were updated, autoarchive skipped "
                    f"({safe_unicode(last_error)})"
                )
            )
        )

    def _iter_indicators(self, source):
        """Yield `(remote_id, metadata)` for each complete `<indicator>`.

        `source` is a path or a file-like object (the live stream). Only an
        indicator whose closing tag was parsed is yielded, so whatever the
        source appends after a cut can never become a half-read dataset.
        """
        # Hardened parser: the catalog body is remote and, through the
        # preview endpoint, caller-supplied. defusedxml refuses DTD entity
        # definitions and external references by default, which is what
        # turns a billion-laughs body from a worker-memory DoS into a clean
        # harvest failure. The elements it yields are ordinary stdlib ones,
        # so `elem.clear()` and the `ET.Element` type hints still hold — the
        # stdlib import stays because defusedxml does not re-export Element.
        context = iter(DET.iterparse(source, events=("start", "end")))
        _event, root = next(context)  # Pega o elemento raiz

        for event, elem in context:
            if event == "end" and elem.tag == "indicator":
                self._parsed_count += 1
                md = self._extract_metadata(elem)
                remote_id = elem.get("id")

                # Skip items without title (mandatory field)
                if remote_id and md.get("title"):
                    yield remote_id, md
                elif remote_id:
                    self._log.warning("[INE] Skipping item %s: missing title", remote_id)

                elem.clear()
                root.clear()  # Limpa memoria da arvore XML

    def _harvest_indicators(self, indicators) -> Exception | None:
        """Process indicators in chunks of `BULK_SIZE` as they are parsed.

        Returns the stream error that ended the iteration, or `None` when it
        ran to the end or stopped at `max_items`. Only pulling the next
        indicator is guarded: an error raised while *processing* a chunk is not
        a transfer failure and propagates, so a database problem is never
        retried as if the source had dropped the connection.
        """
        iterator = iter(indicators)
        buffer: list[tuple[str, dict]] = []
        error: Exception | None = None
        while True:
            try:
                # Time spent here is the transfer plus the parse, and nothing
                # else: chunk processing runs outside this block.
                with self._timed("download_parse"):
                    remote_id, md = next(iterator)
            except StopIteration:
                break
            except _STREAM_ERRORS as e:
                error = e
                break
            if remote_id in self._seen:
                continue
            # `max_items` has to be honoured here, while parsing. The convention
            # elsewhere is to call `has_reached_max_items()` per item, but that
            # reads `len(self.job.items)` and this backend only pushes into that
            # list every `BULK_SIZE * 2` items (or at the very end), so for a
            # 20-item preview it would never be true. Checked before processing,
            # not after: a catalog holding exactly `max_items` indicators ends
            # the loop naturally and is not reported as truncated.
            if self.max_items and len(self._seen) >= self.max_items:
                self._catalog_truncated = True
                break
            self._seen.add(remote_id)
            buffer.append((remote_id, md))
            if len(buffer) >= self.BULK_SIZE:
                self._process_chunk(buffer)
                buffer = []

        # The indicators parsed before a cut are complete: process them too.
        if buffer:
            self._process_chunk(buffer)
        return error

    def _process_chunk(self, chunk: list[tuple[str, dict]]) -> None:
        """Change detection + bulk write for one chunk of parsed indicators."""
        from pymongo import ReplaceOne, UpdateOne

        ops = []
        op_ids = []

        # --- Passo A: Pré-buscar datasets (1 query para o chunk inteiro) ---
        with self._timed("prefetch"):
            existing = self._prefetch_datasets([remote_id for remote_id, _ in chunk])
        for remote_id, md in chunk:
            md["__dataset_obj"] = existing.get(remote_id) or self._new_dataset()

        # --- Passo B: Processamento do chunk ---
        # Guarda remote_ids de datasets criados para buscar IDs depois
        created_remote_ids = []

        for remote_id, md in chunk:
            self._stats["processed"] += 1
            item_status = "done"
            dataset = md.pop("__dataset_obj")  # recupera e limpa

            try:
                if self._dataset_collection is None:
                    self._dataset_collection = dataset._get_collection()

                # Verifica se o dataset existe baseado no harvest.remote_id
                # O get_dataset retorna um dataset existente (com id) ou um novo (sem id)
                is_existing = (
                    getattr(dataset, "harvest", None) is not None
                    and getattr(dataset.harvest, "remote_id", None) == remote_id
                    and getattr(dataset, "id", None) is not None
                )

                if is_existing:
                    # Every other backend reaches an existing record through
                    # `BaseBackend.get_dataset`, which asks this right after
                    # the lookup. This one used to as well; the FAST 2-phase
                    # rewrite (4dc13d6eb) took it off that shared path in
                    # favour of a bulk lookup and a bulk write, so when the
                    # guard was later added to `get_dataset` this backend
                    # silently missed it — nothing here ever asked whether
                    # the record it was about to overwrite belongs to
                    # somebody else. Note the guard is blind to records with
                    # no owner at all: an orphan is still adopted, upstream
                    # behaviour shared with `get_dataset`.
                    # It is asked here rather than in the
                    # prefetch because the prefetch has no per-item error
                    # handling — raising there would lose the whole chunk,
                    # whereas the `except` below fails this one item and
                    # carries on, which is what `process_dataset` does.
                    # Asked before `_has_changed` too, for the same reason
                    # the precedent asks before knowing whether anything
                    # changed: an unchanged record owned by someone else
                    # must not be quietly reported as "skipped" against
                    # this source either. The CREATE branch needs no guard,
                    # since it can only be reached with a `_new_dataset()`
                    # already owned by this source.
                    self.ensure_unique_ownership(dataset)

                # ========================================
                # CASO 1: Dataset já existe na base de dados
                # ========================================
                if is_existing:
                    # Verificar se houve alterações nos metadados
                    unchanged = False
                    if self._newer_than_snapshot(dataset):
                        unchanged = True
                    elif self.CHECK_CHANGES:
                        with self._timed("change_detection"):
                            unchanged = not self._has_changed(dataset, md, remote_id)
                    if unchanged:
                        # Sem alterações -> SKIP
                        self._stats["skipped"] += 1
                        item_status = "skipped"
                        self._log.debug("[INE] SKIP: remote_id=%s (sem alterações)", remote_id)
                    else:
                        # Com alterações -> UPDATE
                        with self._timed("serialize"):
                            self._apply_metadata_to_dataset(dataset, remote_id, md)
                            doc = dataset.to_mongo()
                        doc_dict = dict(doc)
                        _id = doc_dict.get("_id", dataset.id)
                        ops.append(ReplaceOne({"_id": _id}, doc_dict, upsert=False))
                        op_ids.append(remote_id)
                        self._stats["changed"] += 1
                        self._log.debug(
                            "[INE] UPDATE: remote_id=%s (metadados alterados)",
                            remote_id,
                        )

                    # HarvestItem para datasets existentes
                    if self.job:
                        h_item = HarvestItem(remote_id=remote_id, status=item_status)
                        h_item.dataset = dataset.id
                        self._pending_items.append(h_item)

                # ========================================
                # CASO 2: Dataset não existe -> CREATE
                # ========================================
                else:
                    with self._timed("serialize"):
                        self._apply_metadata_to_dataset(dataset, remote_id, md)
                        doc = dataset.to_mongo()
                    doc_dict = dict(doc)
                    # Remover _id pois será gerado pelo MongoDB
                    doc_dict.pop("_id", None)
                    ops.append(
                        UpdateOne(
                            {
                                "harvest.remote_id": str(remote_id),
                                "harvest.source_id": (
                                    str(self.source.id) if self.source.id else None
                                ),
                            },
                            {"$setOnInsert": doc_dict},
                            upsert=True,
                        )
                    )
                    op_ids.append(remote_id)
                    self._stats["created"] += 1
                    created_remote_ids.append(remote_id)
                    self._log.debug("[INE] CREATE: remote_id=%s (novo dataset)", remote_id)

            except Exception as e:
                self._stats["failed"] += 1
                item_status = "failed"
                if isinstance(e, HarvestValidationError):
                    # A refusal, not a crash: `process_dataset` logs these at
                    # info too. A rejected catalogue can fail every one of
                    # 13k items, and a full traceback each would bury the
                    # log without adding anything the message does not say.
                    self._log.info("[INE] Recusado na fase 2 para remote_id=%s: %s", remote_id, e)
                else:
                    self._log.exception("[INE] Falha na fase 2 para remote_id=%s", remote_id)
                # The message is carried onto the item, as `process_dataset`
                # does: a job over 13k items reporting `failed` with an empty
                # `errors` list tells the operator nothing about which of
                # them is an ownership conflict, or who the other owner is.
                # Truncated because the items are pushed into one job
                # document: 13k unbounded messages (a mongoengine or pymongo
                # error runs to a kilobyte) would carry the job past the
                # 16 MB BSON limit and lose the whole record of a harvest
                # whose writes already landed.
                if self.job:
                    h_item = HarvestItem(
                        remote_id=remote_id,
                        status=item_status,
                        # Redact before truncating: a cut landing inside the
                        # userinfo would leave a prefix of the password that
                        # the constructor can no longer recognise as one.
                        errors=[
                            HarvestError(message=redact_url_credentials(safe_unicode(e))[:500])
                        ],
                    )
                    # Kept so the job links to the dataset in conflict; the
                    # message names the other owner, not the record.
                    h_item.dataset = getattr(dataset, "id", None)
                    self._pending_items.append(h_item)

        # --- Fim do loop do chunk ---

        # Flush Ops por chunk. Tem de acontecer ANTES do lookup dos IDs
        # criados, senão os upserts ainda não estão na BD e os
        # HarvestItems ficam sem referência ao dataset.
        if ops and self._dataset_collection is not None:
            self._flush_bulk(self._dataset_collection, ops, op_ids)

        # Buscar IDs dos datasets criados (1 query por chunk) e criar HarvestItems
        if self.job and created_remote_ids and self._dataset_collection is not None:
            id_by_rid = {}
            try:
                cursor = self._dataset_collection.find(
                    {
                        "harvest.remote_id": {"$in": [str(r) for r in created_remote_ids]},
                        "harvest.source_id": (str(self.source.id) if self.source.id else None),
                    },
                    {"_id": 1, "harvest.remote_id": 1},
                )
                id_by_rid = {doc["harvest"]["remote_id"]: doc["_id"] for doc in cursor}
            except Exception:
                self._log.warning(
                    "[INE] Não foi possível buscar IDs dos datasets criados neste chunk"
                )
            for rid in created_remote_ids:
                h_item = HarvestItem(remote_id=rid, status="done")
                if str(rid) in id_by_rid:
                    h_item.dataset = id_by_rid[str(rid)]
                self._pending_items.append(h_item)

        if self.job and len(self._pending_items) >= (self.BULK_SIZE * 2):
            added = len(self._pending_items)
            self._append_job_items(self._pending_items)
            self._log.info(
                "[INE] Job items: +%s (total %s)",
                added,
                len(self.job.items),
            )
            self._pending_items = []

        stats = self._stats
        if stats["processed"] % (self.LOG_EVERY * 5) == 0:
            self._log.info(
                "[INE] Fase 2 progresso: processed=%s changed=%s created=%s skipped=%s failed=%s",
                stats["processed"],
                stats["changed"],
                stats["created"],
                stats["skipped"],
                stats["failed"],
            )

    def _flush_pending_items(self, swallow: bool = False) -> None:
        """Push the job items still buffered.

        `swallow` is for the error path only, where raising would hide the
        error already propagating.
        """
        if not (self.job and self._pending_items):
            return
        added = len(self._pending_items)
        try:
            self._append_job_items(self._pending_items)
        except Exception:
            if not swallow:
                raise
            self._log.exception("[INE] Falha ao gravar %s job items", added)
            return
        self._pending_items = []
        self._log.info("[INE] Final job items: +%s (total %s)", added, len(self.job.items))
