# -*- coding: utf-8 -*-
import logging
import random
import re
import time
from urllib.parse import parse_qs, unquote, urlsplit, urlunsplit

import requests

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
