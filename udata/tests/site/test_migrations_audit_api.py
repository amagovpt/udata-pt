"""
LEDG-2655: the migration audit, served to administrators and to nobody else.

The payload names the schema's internals and carries the tracebacks of failed
migrations, so the protection is not a formality -- and the one case a
half-done protection lets through is an authenticated user with no role, which
is why that is the first test here and the anonymous one comes after.
"""

from flask import url_for

from udata.core.user.factories import AdminFactory, UserFactory
from udata.db import migration_audit
from udata.tests.api import APITestCase


class SiteMigrationsAPITest(APITestCase):
    def test_an_administrator_gets_the_audit(self):
        self.login(AdminFactory())

        response = self.get(url_for("api.site_migrations"))

        self.assert200(response)
        assert "migrations" in response.json
        assert isinstance(response.json["clean"], bool)

    def test_the_counts_name_every_state_even_at_zero(self):
        """A consumer should not have to guess which keys exist.

        The page draws a breakdown from these; a state missing because it
        happened to be zero would read as a state that does not exist.
        """
        self.login(AdminFactory())

        response = self.get(url_for("api.site_migrations"))

        assert set(response.json["counts"]) == set(migration_audit.ALL_STATES)

    def test_a_signed_in_user_without_the_role_is_refused(self):
        """🚩 The case a weak check lets through.

        Anonymous requests are stopped by almost anything; an ordinary
        authenticated account is what gets through a protection that tests
        only for "logged in".
        """
        self.login(UserFactory())

        response = self.get(url_for("api.site_migrations"))

        self.assert403(response)

    def test_an_anonymous_request_is_refused(self):
        response = self.get(url_for("api.site_migrations"))

        self.assert401(response)

    def test_the_payload_never_carries_migration_source(self):
        """add_record stores inspect.getsource() on every operation.

        Without the projection that drops it, this endpoint would ship the
        source of every migration, several times over, to a browser that has
        no use for any of it -- slowly, and without ever erroring.
        """
        self.login(AdminFactory())

        response = self.get(url_for("api.site_migrations"))

        for entry in response.json["migrations"]:
            assert "script" not in entry

    def test_writing_is_not_offered(self):
        """Read-only by requirement: no verb but GET is defined."""
        self.login(AdminFactory())
        url = url_for("api.site_migrations")

        assert self.post(url, {}).status_code == 405
        assert self.delete(url).status_code == 405
