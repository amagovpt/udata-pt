# -*- coding: utf-8 -*-
import logging
import random
import re
import time
from urllib.parse import parse_qs, unquote, urlsplit, urlunsplit

import requests

from udata.core.dataset.constants import UpdateFrequency
from udata.models import Resource

log = logging.getLogger(__name__)


def with_http_retry(backend, func, *args, **kwargs):
    """Call `func` retrying connection-level failures, like `BaseBackend.get`.

    For network calls issued by third-party clients (e.g. owslib's
    `CatalogueServiceWeb` / `getrecords2`, which use `requests` internally
    but bypass the guarded `BaseBackend` session). Retries the same
    exception set as `BaseBackend._request_with_retry` — connection errors,
    timeouts and truncated bodies — with exponential backoff and jitter,
    driven by the same `HARVEST_HTTP_*` settings via the backend properties.
    SSL errors, HTTP status errors and OGC ServiceExceptions are never
    retried. The caller remains responsible for `_guard_url` checks.
    """
    delay = backend.http_retry_initial_delay
    max_delay = backend.http_retry_max_delay
    max_retries = backend.http_max_retries

    for attempt in range(1, max_retries + 1):
        try:
            return func(*args, **kwargs)
        except requests.exceptions.SSLError:
            # Certificate errors are not transient: fail immediately.
            raise
        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            requests.exceptions.ChunkedEncodingError,
        ) as e:
            if attempt >= max_retries:
                raise
            log.warning(
                "%s failed (attempt %s/%s), retrying: %s",
                getattr(func, "__name__", repr(func)),
                attempt,
                max_retries,
                e,
            )
            time.sleep(min(delay + random.uniform(0, 0.1 * delay), max_delay))
            delay = min(delay * 2, max_delay) if delay else 1


def normalize_url_slashes(url: str) -> str:
    """
    Replace all backslashes in a URL with forward slashes.
    Remove any accidental multiple slashes after the protocol.
    """
    if not url:
        return url
    # Substitui todos os tipos de backslash por slash
    url = url.replace("\\", "/")
    # Separa protocolo do resto
    parts = url.split("://", 1)
    if len(parts) == 2:
        # Remove múltiplos slashes seguidos no caminho (mas não no protocolo)
        parts[1] = re.sub(r"/+", "/", parts[1])
        return "://".join(parts)
    else:
        return re.sub(r"/+", "/", url)


def _url_key(url: str) -> str:
    """Comparison key for resource URLs: normalized slashes, no outer spaces."""
    return normalize_url_slashes((url or "").strip()).strip()


def sync_resources(dataset, entries: list[dict]) -> None:
    """Reconcile `dataset.resources` with the harvested `entries`, in place.

    Each entry is a dict of `Resource` field values and must carry a `url`. An
    entry matches an existing resource when the two URLs agree once normalized;
    that resource object is then kept — and with it its `id`, hence the
    `/api/1/datasets/r/<id>` permalink users copy and external integrations
    consume — and only its fields are refreshed.

    Harvesters used to do `dataset.resources = []` and rebuild every resource
    from scratch, and since `Resource.id` is an `AutoUUIDField` that mints a new
    UUID on every creation, each nightly run silently broke every permalink of
    the dataset (LEDG-2251). Matching by URL follows the `odspt` backend, which
    already reuses resources through `get_resource()`; dropping the entries that
    vanished upstream follows `ckanpt`.

    Resources absent from `entries` are removed, **except hosted ones**: those
    were uploaded through the portal, never belonged to the harvester, and
    deleting them would both lose the file and orphan it in storage.
    """
    available = list(dataset.resources)
    synced = []
    seen = set()

    for entry in entries:
        fields = dict(entry)
        url = _url_key(fields.pop("url", None))
        # A resource without a URL cannot be stored, and a URL harvested twice
        # describes the same resource: keeping both would leave the duplicate
        # matchless — and therefore with a brand new id — on the next run.
        if not url or url in seen:
            continue
        seen.add(url)
        fields["url"] = url

        resource = next((r for r in available if _url_key(r.url) == url), None)
        if resource is None:
            resource = Resource(**fields)
        else:
            available.remove(resource)
            for name, value in fields.items():
                setattr(resource, name, value)
        synced.append(resource)

    # Files uploaded on the portal are not part of the harvested payload.
    synced.extend(resource for resource in available if resource.filetype == "file")

    # Rebinding the list is not a wipe: these are the very same `Resource`
    # objects, so their ids survive. It also reorders them after the source and
    # drops whatever upstream no longer publishes.
    dataset.resources = synced


def collapse_duplicated_path(url: str) -> str:
    """Drop a path tail that upstream metadata emitted twice in a row.

    Some catalogues publish links whose path was concatenated with itself,
    e.g. `.../geoportaldocs/_Clima/Portal/meta.xlsx_Clima/Portal/meta.xlsx`
    (LEDG-2250). The doubled link 404s while the single one resolves, so the
    repetition is stripped before the URL reaches a resource.

    Only a tail spanning **more than one path segment** is collapsed: a single
    repeated segment (`/reports/reports`) is a plausible real path, whereas a
    multi-segment path repeating itself verbatim at the very end is not. The
    longest such repetition wins. Scheme, host, query and fragment are left
    untouched — the defect only ever affects the path.
    """
    if not url:
        return url
    parts = urlsplit(url)
    path = parts.path
    length = len(path)
    for half in range(length // 2, 0, -1):
        tail = path[length - half :]
        if path[length - 2 * half : length - half] != tail:
            continue
        # Require the repeated tail to cross a segment boundary.
        if "/" not in tail.strip("/"):
            continue
        return urlunsplit(parts._replace(path=path[: length - half]))
    return url


# Query-string service values that identify an OGC endpoint, e.g.
# `...?SERVICE=WMS&REQUEST=GetCapabilities`.
OGC_SERVICE_FORMATS = frozenset({"wms", "wfs", "wcs", "wmts", "csw"})


def guess_url_format(url: str, fallback: str = "remote") -> str:
    """Derive a resource format from `url`, or `fallback` when unknown.

    An OGC `SERVICE=` query parameter wins over the file extension, since
    those endpoints carry no extension at all. Otherwise the extension is read
    from the **last path segment only** — reading it off the whole URL picks up
    dots from the host name and from query strings, which is how `.xlsx`
    documents ended up published as WMS services (LEDG-2250).
    """
    if not url:
        return fallback
    parts = urlsplit(url)
    query = {key.lower(): value for key, value in parse_qs(parts.query).items()}
    service = (query.get("service") or [""])[0].strip().lower()
    if service in OGC_SERVICE_FORMATS:
        return service
    name = unquote(parts.path).rsplit("/", 1)[-1]
    if "." in name:
        extension = name.rsplit(".", 1)[-1].strip().lower()
        # Anything else is upstream noise (`.pdf_Relatorio_2`, truncated paths).
        if extension.isalnum() and len(extension) <= 5:
            return extension
    return fallback


# INE publishes the update frequency of every indicator as free Portuguese text in
# `<periodicity>`. Mapping it onto our controlled vocabulary is shared by the two INE
# backends (`ine`, `inehvd`), which read the same catalogue.
#
# The map is closed over the values actually published: the full catalogue
# (`xml_indic.jsp?opc=2`) was enumerated on 2026-09-18 and carries 15 distinct values over
# 13154 indicators — anual 7158, decenal 1786+1, mensal 1420, não periódica 1025+1,
# trimestral 605, bienal 419, sexenal 414, quinquenal 276, semestral 19, quadrienal 11,
# mensal acumulado 10, trienal 7, semanal 2. Re-run that enumeration before assuming a
# value is absent; anything unmapped degrades to UNKNOWN rather than failing the item.
#
# Two properties of the feed drive the normalisation below, and both are load-bearing:
# 13152 of the 13154 values carry surrounding whitespace (`<![CDATA[ Mensal]]>`), and the
# same value appears in different capitalisations (`Decenal`/`decenal`,
# `Não periódica`/`Não Periódica`).
INE_PERIODICITY: dict[str, UpdateFrequency] = {
    "anual": UpdateFrequency.ANNUAL,
    "mensal": UpdateFrequency.MONTHLY,
    # Accumulated monthly figures are still published monthly.
    "mensal acumulado": UpdateFrequency.MONTHLY,
    "trimestral": UpdateFrequency.QUARTERLY,
    "semestral": UpdateFrequency.SEMIANNUAL,
    "semanal": UpdateFrequency.WEEKLY,
    "bienal": UpdateFrequency.BIENNIAL,
    "trienal": UpdateFrequency.TRIENNIAL,
    "quadrienal": UpdateFrequency.QUADRENNIAL,
    "quinquenal": UpdateFrequency.QUINQUENNIAL,
    "decenal": UpdateFrequency.DECENNIAL,
    "não periódica": UpdateFrequency.IRREGULAR,
    # `UpdateFrequency` has no six-yearly member (it jumps QUINQUENNIAL -> DECENNIAL), so
    # the 414 indicators published as "Sexenal" land on OTHER. Not UNKNOWN: the source does
    # state a frequency, and `Dataset.has_frequency` counts UNKNOWN as "no frequency given".
    "sexenal": UpdateFrequency.OTHER,
    # Not observed in the catalogue on 2026-09-18, kept so the mapping does not regress:
    # "diário" is the one value the previous `inehvd.map_frequency` recognised.
    "diário": UpdateFrequency.DAILY,
    "diario": UpdateFrequency.DAILY,
    "bimestral": UpdateFrequency.BIMONTHLY,
    "ocasional": UpdateFrequency.IRREGULAR,
}

# Warn once per unseen value: a single INE harvest walks ~13k indicators, and an unmapped
# periodicity would otherwise log once per dataset.
_warned_periodicities: set[str] = set()


def map_ine_periodicity(text: str | None) -> UpdateFrequency:
    """Map INE's `<periodicity>` text onto `UpdateFrequency`.

    Returns `UpdateFrequency.UNKNOWN` for empty, missing or unrecognised values and never
    raises: a periodicity we cannot name must not fail the item being harvested.

    Matching is exact on the stripped, case-folded text rather than a substring test. The
    previous per-backend implementation used `"mensal" in text`, which silently swallowed
    "Mensal acumulado" and would misread any future compound value the same way.
    """
    if not text:
        return UpdateFrequency.UNKNOWN

    key = text.strip().casefold()
    if not key:
        return UpdateFrequency.UNKNOWN

    frequency = INE_PERIODICITY.get(key)
    if frequency is None:
        if key not in _warned_periodicities:
            _warned_periodicities.add(key)
            log.warning("Unmapped INE <periodicity> value: %r", text.strip())
        return UpdateFrequency.UNKNOWN

    return frequency
