from urllib.parse import quote_plus

from flask import current_app, url_for
from flask_security.utils import hash_data

from udata.core.user.factories import AdminFactory, UserFactory
from udata.tests.api import APITestCase
from udata.tests.helpers import capture_mails


class AuthTest(APITestCase):
    def test_change_mail(self):
        user = self.login(AdminFactory())

        new_email = "test@test.com"

        security = current_app.extensions["security"]

        data = [str(user.fs_uniquifier), hash_data(user.email), new_email]
        token = security.confirm_serializer.dumps(data)
        confirmation_link = url_for("security.confirm_change_email", token=token)

        resp = self.get(confirmation_link)
        assert resp.status_code == 302

        user.reload()
        assert user.email == new_email

    def test_change_mail_already_taken(self):
        """Should not allow changing email to one already taken by another user"""
        user = self.login(AdminFactory())
        original_email = user.email

        # Create another user with the target email
        existing_user = UserFactory(email="taken@example.com")
        new_email = existing_user.email

        security = current_app.extensions["security"]

        data = [str(user.fs_uniquifier), hash_data(user.email), new_email]
        token = security.confirm_serializer.dumps(data)
        confirmation_link = url_for("security.confirm_change_email", token=token)

        resp = self.get(confirmation_link)
        assert resp.status_code == 302
        assert "change_email_already_taken" in resp.location

        # Email should not have changed
        user.reload()
        assert user.email == original_email

    def test_change_mail_after_password_change(self):
        """Changing password rotates fs_uniquifier and invalidates email change token"""
        user = UserFactory(password="Password123!@#")
        self.login(user)
        old_uniquifier = user.fs_uniquifier

        new_email = "new@example.com"

        security = current_app.extensions["security"]

        data = [str(user.fs_uniquifier), hash_data(user.email), new_email]
        token = security.confirm_serializer.dumps(data)
        confirmation_link = url_for("security.confirm_change_email", token=token)

        # Change password via API
        resp = self.post(
            url_for("security.change_password"),
            {
                "password": "Password123!@#",
                "new_password": "NewPassword456!@#",
                "new_password_confirm": "NewPassword456!@#",
                "submit": True,
            },
        )
        assert resp.status_code == 200, f"Password change failed: {resp.data}"

        user.reload()
        assert user.fs_uniquifier != old_uniquifier, "fs_uniquifier should have changed"

        # Now try to use the email change link - should fail
        resp = self.get(confirmation_link)
        assert resp.status_code == 302
        assert "change_email_invalid" in resp.location

    def test_change_mail_from_placeholder_saml_user(self):
        """A password-less CMD/SAML account with a placeholder email can
        complete registration through the change-email flow: submit a real
        email, receive the confirmation link, and have the email replaced."""
        user = UserFactory(email="saml-abcdef01@autenticacao.gov.pt", password=None)
        self.login(user)
        assert user.has_placeholder_email

        new_email = "real.email@example.com"

        with capture_mails() as mails:
            resp = self.post(
                url_for("security.change_email"),
                {
                    "new_email": new_email,
                    "new_email_confirm": new_email,
                    "submit": True,
                },
            )
        assert resp.status_code == 200
        assert len(mails) == 1
        assert mails[0].recipients == [new_email]

        # Extract the confirmation link from the mail and follow it.
        security = current_app.extensions["security"]
        data = [str(user.fs_uniquifier), hash_data(user.email), new_email]
        token = security.confirm_serializer.dumps(data)
        confirmation_link = url_for("security.confirm_change_email", token=token)

        resp = self.get(confirmation_link)
        assert resp.status_code == 302
        assert "change_email_confirmed" in resp.location

        user.reload()
        assert user.email == new_email
        assert not user.has_placeholder_email

    def _submit_change_email(self, address):
        # Form-encoded POST: this is the shape the frontend proxy sends, and
        # the only one whose failure path used to render the error back.
        return self.post(
            url_for("security.change_email"),
            {"new_email": address, "new_email_confirm": address, "submit": True},
            json=False,
        )

    def test_change_mail_taken_address_warns_the_owner_at_submit(self):
        """The collision is still handled at submit time, not only after the
        confirmation link is clicked.

        What changed is who is told: the owner of the address, by mail, and not
        whoever submitted it. The previous version of this test asserted the
        opposite -- 200 with "already registered" in the body -- which is the
        disclosure this replaces.
        """
        user = self.login(UserFactory(email="saml-deadbeef@autenticacao.gov.pt", password=None))
        owner = UserFactory(email="taken@example.com")

        with capture_mails() as mails:
            resp = self._submit_change_email("taken@example.com")

        # Exactly one mail, to the mailbox that already holds the address.
        # Never to the requester, who must learn nothing.
        assert len(mails) == 1
        assert mails[0].recipients == [owner.email]

        # No confirmation link was issued for an address this session has
        # proved nothing about.
        assert "confirm-change-email" not in mails[0].body

        # Neither account moves. This is the assertion that stops an account
        # being claimed by naming its address, and it is the one the previous
        # version of this test got right.
        user.reload()
        assert user.email == "saml-deadbeef@autenticacao.gov.pt"
        owner.reload()
        assert owner.email == "taken@example.com"

        # Answered in the success shape; pinned against a free address below.
        assert resp.status_code == 302

    def test_change_mail_taken_address_answers_like_a_free_one(self):
        """The taken and free branches must be indistinguishable to the caller.

        If they differ in any observable way, one account is enough to test
        any address, which is the enumeration oracle this flow must not be.
        """
        self.login(UserFactory(email="saml-deadbeef@autenticacao.gov.pt", password=None))
        UserFactory(email="taken@example.com")

        taken = self._submit_change_email("taken@example.com")
        free = self._submit_change_email("free@example.com")

        assert taken.status_code == free.status_code

        # The redirect echoes the submitted address, which discloses nothing
        # because the caller chose it -- so normalise it out and require
        # everything else to match byte for byte.
        #
        # Both encodings are normalised: homepage_url goes through cdata_url
        # (urlencode, so "@" becomes %40) when CDATA_BASE_URL is set, and falls
        # back to url_for otherwise, which leaves "@" literal. Normalising only
        # one of them silently turns this into a no-op comparison.
        def normalise(location, address):
            return location.replace(quote_plus(address), "ADDR").replace(address, "ADDR")

        assert normalise(taken.location, "taken@example.com") == normalise(
            free.location, "free@example.com"
        )

    def test_change_mail_same_address_error_is_translated(self):
        """The form's own error must not reach a Portuguese user in English.

        The language comes from the signed-in user: i18n.get_locale reads
        `default_lang`, which is `prefered_language` before it is the configured
        default -- and this suite's default is fr (settings.Testing), not pt.
        The security views are not locale-prefixed, so passing lang_code to
        url_for only appends a query parameter and changes nothing.
        """
        user = self.login(
            UserFactory(email="mine@example.com", password=None, prefered_language="pt")
        )

        resp = self.post(
            url_for("security.change_email"),
            {
                "new_email": user.email,
                "new_email_confirm": user.email,
                "submit": True,
            },
            json=False,
        )

        assert resp.status_code == 200
        body = resp.data.decode()
        assert "must be different than your previous email" not in body
        assert "tem de ser diferente do anterior" in body
