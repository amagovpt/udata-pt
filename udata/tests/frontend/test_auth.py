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
        user = UserFactory(password="Password123")
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
                "password": "Password123",
                "new_password": "NewPassword456",
                "new_password_confirm": "NewPassword456",
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

    def test_change_mail_rejects_already_registered_email_at_submit(self):
        """The collision must surface at submit time, not only after the
        confirmation link is clicked."""
        user = self.login(UserFactory(email="saml-deadbeef@autenticacao.gov.pt", password=None))
        UserFactory(email="taken@example.com")

        with capture_mails() as mails:
            # Form-encoded POST: validation errors only surface in the HTML
            # render (the JSON branch returns a bare csrf_token payload).
            resp = self.post(
                url_for("security.change_email"),
                {
                    "new_email": "taken@example.com",
                    "new_email_confirm": "taken@example.com",
                    "submit": True,
                },
                json=False,
            )
        # Validation failure: no confirmation mail is sent and the email
        # is left untouched.
        assert len(mails) == 0
        user.reload()
        assert user.email == "saml-deadbeef@autenticacao.gov.pt"
        assert resp.status_code == 200
        assert b"already registered" in resp.data
