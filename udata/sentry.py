import logging
import re
import warnings

from werkzeug.exceptions import HTTPException

from udata.core.storages.api import UploadProgress
from udata.harvest.url_filter import redact_url_credentials, redact_url_credentials_in_url
from udata.utils import get_udata_version

from .app import UDataApp
from .auth import PermissionDenied

log = logging.getLogger(__name__)

RE_DSN = re.compile(
    r"(?P<scheme>https?)://(?P<client_id>[0-9a-f]+)(?::(?P<secret>[0-9a-f]+))?"
    r"@(?P<domain>.+)/(?P<site_id>\d+)"
)

SECRET_DSN_DEPRECATED_MSG = "DSN with secret is deprecated, use a public DSN instead"
ERROR_PARSE_DSN_MSG = "Unable to parse Sentry DSN"

# Controlled exceptions that Sentry should ignore
IGNORED_EXCEPTIONS = HTTPException, PermissionDenied, UploadProgress

# How deep `_redact_in_place` follows an event before giving up. Sentry events
# are shallow (the deepest real nesting is
# `exception.values[].stacktrace.frames[].vars`, which is 6), so this is not a
# tuning knob: it is what makes the walk unable to raise `RecursionError` on a
# pathological payload, which matters because a `before_send` that raises
# drops the event.
_MAX_SCRUB_DEPTH = 20


def _redact_in_place(node, depth: int = 0):
    """Redact URL credentials in every string reachable from `node`."""
    if depth > _MAX_SCRUB_DEPTH:
        return node
    if isinstance(node, str):
        return redact_url_credentials(node)
    if isinstance(node, dict):
        # Rebinding existing keys does not resize the dict, so iterating it
        # while assigning is safe.
        for key, value in node.items():
            node[key] = _redact_in_place(value, depth + 1)
        return node
    if isinstance(node, list):
        for index, value in enumerate(node):
            node[index] = _redact_in_place(value, depth + 1)
        return node
    if isinstance(node, tuple):
        # `logentry.params` is `record.args`, which is a tuple for `%s`-style
        # logging. Tuples are immutable, so this one is rebuilt and handed
        # back to the caller, which rebinds it into its parent.
        return tuple(_redact_in_place(value, depth + 1) for value in node)
    return node


def scrub_url_credentials(event, hint):
    """Strip `user:password@` from every URL in an event before it is sent.

    A harvest source URL may legitimately carry credentials
    (`URLS_ALLOW_CREDENTIALS`), and any `requests` exception raised over one
    embeds it in its message. LEDG-2477 kept that out of the API; this keeps it
    out of Sentry.

    It walks the whole event rather than the handful of keys where the secret
    was first noticed, because enumerating keys is what failed before: the
    obvious four (`logentry.message`, `logentry.params`,
    `exception.values[].value`, `request.url`) leave the password in
    `logentry.formatted` -- the string Sentry actually displays -- and in
    `exception.values[].stacktrace.frames[].vars`, since
    `include_local_variables` defaults to true. `request.data` leaks it too:
    the harvest source create and preview endpoints take the URL in the request
    body, and the body is attached regardless of `send_default_pii`. A walk
    covers those, plus breadcrumbs, `extra` and whatever the SDK adds next.
    `redact_url_credentials` is a no-op on any string without an `@`, so the
    cost is the traversal, not the regex.

    This is not the SDK's `EventScrubber`, which matches *key names*
    (`password`, `secret`) and would see nothing here: the secret is inside the
    value of an ordinarily-named key.

    Scope, decided in LEDG-2501 and recorded in the CHANGELOG: this protects
    Sentry only. The harvest log calls that put the URL in their own message
    redact it at the source, so the on-disk logs are covered there. What stays
    uncovered on disk is the traceback `logging` attaches to `log.exception` --
    redacting that would need a `logging.Filter` on the root logger of every
    process. In Sentry those frames are covered here.
    """
    try:
        request = event.get("request") if isinstance(event, dict) else None
        raw_url = None
        if isinstance(request, dict) and isinstance(request.get("url"), str):
            # Taken out before the walk, not fixed up after it: this value is
            # known to be a whole URL, and the free-text regex has to stop at
            # the RFC 3986 authority alphabet, so it would rewrite a legitimate
            # `/files//report@2026.csv` path. Splitting never reaches past the
            # authority. Once the prose regex has run, that damage cannot be
            # undone.
            raw_url = request.pop("url")

        _redact_in_place(event)

        if raw_url is not None:
            request["url"] = redact_url_credentials_in_url(raw_url)
        return event
    except Exception:
        # Dropping the event is the deliberate choice: losing one report costs
        # visibility, letting one through unredacted costs the credential.
        # `warning` and not `error` on purpose -- LoggingIntegration turns an
        # ERROR into an event, which would come straight back through here.
        log.warning("Dropping a Sentry event: scrubbing its URL credentials failed")
        return None


def public_dsn(dsn: str) -> str | None:
    """Check if DSN is public or raise a warning and turn it into a public one"""
    m = RE_DSN.match(dsn)
    if not m:
        log.error(ERROR_PARSE_DSN_MSG)
        raise ValueError(ERROR_PARSE_DSN_MSG)

    if not m["secret"]:
        return dsn

    log.warning(SECRET_DSN_DEPRECATED_MSG)
    warnings.warn(SECRET_DSN_DEPRECATED_MSG, category=DeprecationWarning)

    public = "{scheme}://{client_id}@{domain}/{site_id}".format(**m.groupdict())
    return public


def init_app(app: UDataApp):
    if app.config["SENTRY_DSN"]:
        try:
            import sentry_sdk
            from sentry_sdk.integrations.celery import CeleryIntegration
            from sentry_sdk.integrations.flask import FlaskIntegration
            from sentry_sdk.integrations.logging import ignore_logger
        except ImportError:
            log.error("sentry-sdk is required to use Sentry")
            return

        app.config["SENTRY_PUBLIC_DSN"] = public_dsn(app.config["SENTRY_DSN"])

        # Do not send HTTPExceptions
        exceptions = set(app.config["SENTRY_IGNORE_EXCEPTIONS"])
        for exception in IGNORED_EXCEPTIONS:
            exceptions.add(exception)

        sentry_sdk.init(
            dsn=app.config["SENTRY_PUBLIC_DSN"],
            integrations=[FlaskIntegration(), CeleryIntegration()],
            ignore_errors=list(exceptions),
            before_send=scrub_url_credentials,
            release=f"udata@{get_udata_version()}",
            environment=app.config.get("SITE_ID", None),
            # Set traces_sample_rate to 1.0 to capture 100%
            # of transactions for performance monitoring.
            # Sentry recommends adjusting this value in production.
            traces_sample_rate=app.config.get("SENTRY_SAMPLE_RATE", None),
            profiles_sample_rate=app.config.get("SENTRY_SAMPLE_RATE", None),
        )

        # The mail dispatch audit logger is a record of what happened, not an
        # alerting channel. Its ERROR line accompanies an exception that is
        # re-raised and reaches Sentry through the Flask/Celery integrations
        # anyway, so leaving LoggingIntegration's defaults in place (event_level
        # ERROR) would raise a second issue for every refused recipient, and
        # turn every successful send into an INFO breadcrumb.
        ignore_logger("udata.mail.audit")

        # Same reasoning for the SAML SSO audit log, and one extra reason that
        # is the sharper one: the line carries `ip=` and `ua=`. This project
        # never sets `send_default_pii`, so it runs with the SDK default of
        # NOT sending them -- and LoggingIntegration hooks `callHandlers` at
        # INFO, which sees records whether or not a handler is attached. Left
        # alone, making that logger emit (LEDG-2371) would have pushed the
        # address and user agent of every sign-in into Sentry through a side
        # door, undoing a deliberate setting. It was moot before only because
        # the logger emitted nothing at all.
        ignore_logger("udata.auth.saml.audit")

        # Set log level
        log_level_name = app.config["SENTRY_LOGGING"]
        if log_level_name:
            log_level = getattr(logging, log_level_name.upper())
            sentry_sdk.set_level(log_level)

        # Set sentry tags
        tags = app.config["SENTRY_TAGS"]
        for tag_key in tags:
            sentry_sdk.set_tag(tag_key, tags[tag_key])

        sentry_sdk.set_tag("udata", get_udata_version())
