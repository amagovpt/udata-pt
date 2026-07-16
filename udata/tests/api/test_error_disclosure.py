"""Regression tests for VULN-2091 (LEDG-2136): error responses must stay
generic — no stack trace / internal detail and no Flask-RestX "did you mean
<route>" hints that would disclose valid route prefixes.
"""

from flask import url_for

from udata.api import API, api
from udata.tests.api import APITestCase

ns = api.namespace("fake_err", "Error-disclosure regression namespace")


class ErrorDisclosureTest(APITestCase):
    def test_404_has_no_route_hints_or_traceback(self):
        """A 404 must return a plain, generic message: no 'did you mean' route
        hints and no traceback."""
        response = self.get("/api/1/definitely-not-a-real-endpoint/")
        assert response.status_code == 404

        body = response.get_data(as_text=True)
        assert "did you mean" not in body.lower()
        assert "Traceback" not in body
        # No enumeration of valid route prefixes.
        assert "/api/1/reuses/" not in body
        assert "/api/1/users/" not in body

    def test_500_does_not_leak_traceback_or_internal_detail(self):
        """An unhandled server error must not expose the traceback or the
        internal exception message in the response body."""

        @ns.route("/boom", endpoint="boom")
        class BoomAPI(API):
            def get(self):
                raise RuntimeError("internal detail that must not leak")

        response = self.get(url_for("api.boom"))
        assert response.status_code == 500

        body = response.get_data(as_text=True)
        assert "Traceback" not in body
        assert "internal detail that must not leak" not in body
