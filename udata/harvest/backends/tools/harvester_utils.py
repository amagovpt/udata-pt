# -*- coding: utf-8 -*-
import logging
import random
import re
import time

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
