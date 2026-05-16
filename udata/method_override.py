"""WSGI middleware that honors the ``X-HTTP-Method-Override`` header.

When a client cannot emit ``PUT``/``PATCH``/``DELETE`` directly (e.g. behind a
proxy or WAF that only forwards ``GET``/``POST``), it can send a ``POST`` with
``X-HTTP-Method-Override: <verb>`` and the middleware rewrites
``REQUEST_METHOD`` before Flask routing sees the request.

Only ``POST`` requests carrying an allowlisted override verb are rewritten.
The header is removed from the WSGI environ after consumption so downstream
code observes a clean request.
"""

from typing import Callable, Iterable

WSGIApp = Callable[[dict, Callable], Iterable[bytes]]

ALLOWED_OVERRIDES = frozenset({"PUT", "PATCH", "DELETE"})
HEADER_ENVIRON_KEY = "HTTP_X_HTTP_METHOD_OVERRIDE"


class MethodOverrideMiddleware:
    def __init__(self, app: WSGIApp) -> None:
        self.app = app

    def __call__(self, environ: dict, start_response: Callable) -> Iterable[bytes]:
        if environ.get("REQUEST_METHOD", "").upper() == "POST":
            override = environ.pop(HEADER_ENVIRON_KEY, "").upper()
            if override in ALLOWED_OVERRIDES:
                environ["REQUEST_METHOD"] = override
                # Preserve the original method for downstream consumers
                # (logging, auditing) that need to know the request was tunneled.
                environ["udata.original_method"] = "POST"
        return self.app(environ, start_response)
