import json
import sys

import pytest
import requests

from udata.sentry import init_app, scrub_url_credentials
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
                "params": (CREDENTIALED_URL,),
            }
        }

        result = scrub_url_credentials(event, {})

        assert PASSWORD not in json.dumps(result)
        assert (
            result["logentry"]["formatted"]
            == "Starting harvesting https://***@www.ine.pt/broken.xml"
        )
        assert result["logentry"]["params"] == ("https://***@www.ine.pt/broken.xml",)

    @pytest.mark.parametrize(
        "params",
        [
            (CREDENTIALED_URL,),
            [CREDENTIALED_URL],
            {"url": CREDENTIALED_URL},
        ],
    )
    def test_params_are_redacted_whatever_shape_record_args_took(self, params):
        """`record.args` is a tuple for `%s`, a dict for `%(name)s`."""
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

    def test_request_url_is_split_not_matched_as_prose(self):
        """`request.url` is known to be a whole URL, so it is redacted by
        splitting. The free-text regex would reach past the authority and
        rewrite a legitimate `@` in the path (LEDG-2500, `d46f5c4d8`)."""
        event = {"request": {"url": "https://data.gov.pt/files//report@2026.csv"}}

        result = scrub_url_credentials(event, {})

        assert result["request"]["url"] == "https://data.gov.pt/files//report@2026.csv"

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

    def test_an_event_it_cannot_scrub_is_dropped_rather_than_sent(self):
        """Losing one report costs visibility; letting one through costs the
        credential."""

        class Exploding(dict):
            def get(self, *args, **kwargs):
                raise RuntimeError("boom")

        assert scrub_url_credentials(Exploding(), {}) is None


class SentryInitAppTest(PytestOnlyTestCase):
    def test_init_app_wires_the_scrubber_into_the_sdk(self, mocker):
        """Defining the scrubber is not enough -- it has to be passed to
        `sentry_sdk.init`. Removing that line must fail a test."""
        init = mocker.patch("sentry_sdk.init")
        # A public DSN, matching this module's RE_DSN.
        self.app.config["SENTRY_DSN"] = "https://abc123@sentry.example.com/1"

        init_app(self.app)

        assert init.call_args.kwargs["before_send"] is scrub_url_credentials
