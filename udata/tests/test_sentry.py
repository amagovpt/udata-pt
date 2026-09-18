import json
import sys

import pytest
import requests
from sentry_sdk.scrubber import EventScrubber

from udata.sentry import _MAX_SCRUB_DEPTH, init_app, scrub_url_credentials
from udata.tests import PytestOnlyTestCase

# The proof of concept from LEDG-2477: a harvest source whose URL legitimately
# carries credentials, and whose password must not leave this process.
CREDENTIALED_URL = "https://harvestuser:sup3rs3cr3t@www.ine.pt/broken.xml"
PASSWORD = "sup3rs3cr3t"


def raise_requests_error():
    """Raise the real `requests` exception a failing harvest raises.

    Built from a `Response` rather than from the network so the test stays
    offline: `raise_for_status` is what interpolates the URL into the message,
    and it only reads `status_code`, `reason` and `url`.
    """
    response = requests.Response()
    response.status_code = 500
    response.url = CREDENTIALED_URL
    response.raise_for_status()


def _nested_deeper_than_the_walk_follows():
    """An event nested past `_MAX_SCRUB_DEPTH`, with the secret at the bottom."""
    node = CREDENTIALED_URL
    for _ in range(_MAX_SCRUB_DEPTH + 2):
        node = {"nested": node}
    return node


class ScrubURLCredentialsTest:
    """`scrub_url_credentials` is the `before_send` that keeps URL credentials
    out of Sentry (LEDG-2501)."""

    def test_a_real_requests_exception_reaches_sentry_without_the_password(self):
        """The acceptance criterion, asserted over the WHOLE event.

        The event is built by the same SDK function the Flask and Celery
        integrations use, so its shape is the production one and not one this
        test invented. Asserting over the whole serialized event matters: the
        password is in the exception `value` *and* in the local variables of
        two stack frames, because `include_local_variables` defaults to true.
        A narrower assertion would pass while the secret still travelled.
        """
        from sentry_sdk.utils import exceptions_from_error_tuple

        try:
            raise_requests_error()
        except requests.HTTPError:
            values = exceptions_from_error_tuple(sys.exc_info())

        event = {"exception": {"values": values}}
        # Guard the guard: if a future SDK stops putting the password here,
        # this test would pass without proving anything.
        assert PASSWORD in json.dumps(event)

        scrubbed = json.dumps(scrub_url_credentials(event, {}))

        assert PASSWORD not in scrubbed
        assert "harvestuser" not in scrubbed
        assert "https://***@www.ine.pt/broken.xml" in scrubbed

    def test_every_logentry_key_is_redacted(self):
        """`formatted` is the string Sentry displays, and the ticket's list of
        keys did not name it."""
        event = {
            "logentry": {
                "message": "Starting harvesting %s",
                "formatted": f"Starting harvesting {CREDENTIALED_URL}",
                # A list, not a tuple: the SDK serializes every sequence
                # before `before_send`, so this is the shape that arrives.
                "params": [CREDENTIALED_URL],
            }
        }

        result = scrub_url_credentials(event, {})

        assert PASSWORD not in json.dumps(result)
        assert (
            result["logentry"]["formatted"]
            == "Starting harvesting https://***@www.ine.pt/broken.xml"
        )
        assert result["logentry"]["params"] == ["https://***@www.ine.pt/broken.xml"]

    @pytest.mark.parametrize(
        "params",
        [
            (CREDENTIALED_URL,),
            [CREDENTIALED_URL],
            {"url": CREDENTIALED_URL},
        ],
    )
    def test_params_are_redacted_whatever_shape_record_args_took(self, params):
        """`record.args` is a tuple for `%s` and a dict for `%(name)s`. The SDK
        turns the tuple into a list on its way here; the tuple case is kept
        because the walk accepts one and nothing should depend on which
        arrives."""
        result = scrub_url_credentials({"logentry": {"params": params}}, {})

        assert PASSWORD not in json.dumps(result)

    def test_breadcrumbs_and_extra_are_redacted(self):
        """An INFO log line becomes a breadcrumb and rides along with a later
        event from the same harvest."""
        event = {
            "breadcrumbs": {
                "values": [{"message": f"[INE] Iniciando harvester de {CREDENTIALED_URL}"}]
            },
            "extra": {"source_url": CREDENTIALED_URL},
        }

        assert PASSWORD not in json.dumps(scrub_url_credentials(event, {}))

    def test_request_body_is_redacted(self):
        """The harvest source create and preview endpoints take the URL in the
        body, and the body is attached regardless of `send_default_pii`."""
        event = {"request": {"data": {"url": CREDENTIALED_URL, "name": "INE"}}}

        assert PASSWORD not in json.dumps(scrub_url_credentials(event, {}))

    def test_stacktrace_frame_variables_are_redacted(self):
        """The keys the ticket listed would have left the password here."""
        event = {
            "exception": {
                "values": [
                    {
                        "value": "boom",
                        "stacktrace": {"frames": [{"vars": {"url": repr(CREDENTIALED_URL)}}]},
                    }
                ]
            }
        }

        assert PASSWORD not in json.dumps(scrub_url_credentials(event, {}))

    @pytest.mark.parametrize(
        "build_event",
        [
            lambda url: {"request": {"url": url}},
            lambda url: {"request": {"headers": {"Referer": url}}},
            lambda url: {"breadcrumbs": {"values": [{"data": {"url": url}}]}},
            lambda url: {"contexts": {"trace": {"data": {"url": url}}}},
        ],
        ids=["request.url", "request.headers.Referer", "breadcrumb.data.url", "span.data.url"],
    )
    def test_a_url_valued_key_is_split_not_matched_as_prose(self, build_event):
        """A value that is a whole URL is redacted by splitting, wherever it
        sits. The free-text regex has to stop at the RFC 3986 authority
        alphabet, so it would reach past the authority and rewrite a legitimate
        `@` in the path, claiming credentials that were never there
        (LEDG-2500, `d46f5c4d8`)."""
        legitimate = "https://data.gov.pt/files//report@2026.csv"

        scrubbed = json.dumps(scrub_url_credentials(build_event(legitimate), {}))

        assert legitimate in scrubbed
        assert "***" not in scrubbed

    @pytest.mark.parametrize(
        "build_event",
        [
            lambda url: {"request": {"url": url}},
            lambda url: {"request": {"headers": {"Referer": url}}},
            lambda url: {"breadcrumbs": {"values": [{"data": {"url": url}}]}},
            lambda url: {"contexts": {"trace": {"data": {"url": url}}}},
        ],
        ids=["request.url", "request.headers.Referer", "breadcrumb.data.url", "span.data.url"],
    )
    def test_a_credentialed_url_valued_key_is_redacted_wherever_it_sits(self, build_event):
        assert PASSWORD not in json.dumps(scrub_url_credentials(build_event(CREDENTIALED_URL), {}))

    def test_a_url_valued_key_holding_prose_still_gets_redacted(self):
        """`extra` and breadcrumb data are filled by callers, so a key named
        `url` may hold prose after all. Splitting prose finds no `@` in the
        netloc and would return it untouched -- a silent failure to redact."""
        event = {"extra": {"url": f"failed to fetch {CREDENTIALED_URL} twice"}}

        assert PASSWORD not in json.dumps(scrub_url_credentials(event, {}))

    def test_a_credentialed_request_url_is_still_redacted(self):
        event = {"request": {"url": CREDENTIALED_URL}}

        result = scrub_url_credentials(event, {})

        assert result["request"]["url"] == "https://***@www.ine.pt/broken.xml"

    @pytest.mark.parametrize(
        "event",
        [
            {},
            {"logentry": {"message": "no url here"}},
            {"logentry": {"params": [1, None, object()]}},
            {"request": {"url": None}},
            {"exception": {"values": []}},
        ],
    )
    def test_an_event_without_the_expected_shape_survives(self, event):
        """Any key can be missing, and any value can be of an unexpected type.
        A `before_send` that raises drops the event."""
        assert scrub_url_credentials(event, {}) is not None

    @pytest.mark.parametrize(
        "event",
        [
            # Not a mapping: nothing to walk, so nothing was scrubbed.
            ["an event the scrubber does not understand"],
            None,
            # Nested deeper than the walk follows. The SDK caps databag
            # depth far below this, so it is the unreachable case being
            # pinned: the subtree must not travel unscrubbed.
            _nested_deeper_than_the_walk_follows(),
        ],
        ids=["not-a-mapping", "none", "deeper-than-the-walk-follows"],
    )
    def test_an_event_it_cannot_scrub_is_dropped_rather_than_sent(self, event):
        """Losing one report costs visibility; letting one through costs the
        credential."""
        assert scrub_url_credentials(event, {}) is None


class SentryInitAppTest(PytestOnlyTestCase):
    def test_init_app_wires_the_scrubber_into_the_sdk(self, mocker):
        """Defining the scrubber is not enough -- it has to be passed to
        `sentry_sdk.init`. Removing that line must fail a test."""
        init = mocker.patch("sentry_sdk.init")
        # A public DSN, matching this module's RE_DSN.
        self.app.config["SENTRY_DSN"] = "https://abc123@sentry.example.com/1"

        init_app(self.app)

        assert init.call_args.kwargs["before_send"] is scrub_url_credentials
        # `before_send` is never called for transactions, and
        # `traces_sample_rate` means there is one per request and per task.
        assert init.call_args.kwargs["before_send_transaction"] is scrub_url_credentials

    def test_init_app_makes_the_sdk_scrubber_recursive(self, mocker):
        """The SDK builds a scrubber of its own when none is passed, so the
        only thing that separates a covered event from an exposed one is
        `recursive` -- and nothing fails if the argument disappears."""
        init = mocker.patch("sentry_sdk.init")
        self.app.config["SENTRY_DSN"] = "https://abc123@sentry.example.com/1"

        init_app(self.app)

        assert init.call_args.kwargs["event_scrubber"].recursive is True

    def test_a_secret_header_in_a_frame_variable_is_scrubbed(self, mocker):
        """The harvest API key reaches Sentry one level below a frame variable.

        `BaseBackend._request_with_retry` holds the request headers -- with
        `Authorization: <apikey>` for the CKAN family -- as a local of the
        frame that re-raises every connection failure, and Sentry sends frame
        locals. The key the SDK sees at the top is `headers`, which is on
        nobody's denylist; the secret-named key is inside it, so only a
        recursive scrubber reaches it (LEDG-2514).
        """
        init = mocker.patch("sentry_sdk.init")
        self.app.config["SENTRY_DSN"] = "https://abc123@sentry.example.com/1"
        init_app(self.app)
        # The scrubber this app actually hands the SDK, not one built here.
        scrubber = init.call_args.kwargs["event_scrubber"]

        event = {
            "exception": {
                "values": [
                    {
                        "stacktrace": {
                            "frames": [
                                {
                                    "function": "_request_with_retry",
                                    "vars": {
                                        "headers": {
                                            "Authorization": PASSWORD,
                                            "content-type": "application/json",
                                        },
                                        "url": "https://www.ine.pt/api",
                                    },
                                }
                            ]
                        }
                    }
                ]
            }
        }

        scrubber.scrub_event(event)

        frame = event["exception"]["values"][0]["stacktrace"]["frames"][0]
        assert PASSWORD not in json.dumps(frame, default=str)
        # Only the secret goes: the rest of the frame stays readable.
        assert frame["vars"]["headers"]["content-type"] == "application/json"
        assert frame["vars"]["url"] == "https://www.ine.pt/api"

    def test_the_sdk_default_scrubber_would_miss_it(self):
        """Why `recursive=True` is the fix and not a precaution: the scrubber
        the SDK builds when nothing is passed walks the same frames and has
        `authorization` on its denylist, and still leaves the key in place."""
        vars_ = {"headers": {"Authorization": PASSWORD}}
        event = {"exception": {"values": [{"stacktrace": {"frames": [{"vars": vars_}]}}]}}

        EventScrubber().scrub_event(event)

        assert vars_["headers"]["Authorization"] == PASSWORD
