import logging
import smtplib
from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from flask import url_for
from flask_security.recoverable import generate_reset_password_token

from udata import settings
from udata.auth import AuditMailUtil
from udata.commands.fixtures import UserFactory
from udata.i18n import lazy_gettext as _
from udata.mail import mail
from udata.tests.api import PytestOnlyAPITestCase
from udata.tests.helpers import capture_mails


class SecurityAPITest(PytestOnlyAPITestCase):
    @pytest.mark.options(CAPTCHETAT_BASE_URL=None)
    def test_register(self):
        # We cannot test for mail sending since they are sent with Flask
        # directly and not with our system but if the sending is working
        # we test the rendering of the mail.

        response = self.post(
            url_for("security.register"),
            {
                "first_name": "Jane",
                "last_name": "Doe",
                "accept_conditions": True,
                "email": "jane@example.org",
                "password": "Password123!@#",
                "password_confirm": "Password123!@#",
                "submit": True,
            },
        )
        self.assertStatus(response, 200)

    @pytest.mark.options(CAPTCHETAT_BASE_URL=None, SECURITY_RETURN_GENERIC_RESPONSES=True)
    def test_register_existing(self):
        # We cannot test for mail sending since they are sent with Flask
        # directly and not with our system but if the sending is working
        # we test the rendering of the mail.

        UserFactory(email="jane@example.org", confirmed_at=datetime.now())
        response = self.post(
            url_for("security.register"),
            {
                "first_name": "Jane",
                "last_name": "Doe",
                "accept_conditions": True,
                "email": "jane@example.org",
                "password": "Password123!@#",
                "password_confirm": "Password123!@#",
                "submit": True,
            },
        )
        self.assertStatus(response, 200)

    @pytest.mark.options(CAPTCHETAT_BASE_URL=None, GOOGLE_RECAPTCHA_SECRET_KEY=None)
    def test_ask_for_reset(self):
        # We cannot test for mail sending since they are sent with Flask
        # directly and not with our system but if the sending is working
        # we test the rendering of the mail.

        UserFactory(email="jane@example.org", confirmed_at=datetime.now())

        response = self.post(
            url_for("security.forgot_password"), {"email": "jane@example.org", "submit": True}
        )
        self.assertStatus(response, 200)

    @pytest.mark.options(CAPTCHETAT_BASE_URL=None)
    def test_change_notice_mail(self):
        # We cannot test for mail sending since they are sent with Flask
        # directly and not with our system but if the sending is working
        # we test the rendering of the mail.

        user = UserFactory(
            email="jane@example.org", password="password", confirmed_at=datetime.now()
        )
        self.login(user)

        response = self.post(
            url_for("security.change_password"),
            {
                "password": "password",
                "new_password": "New_password123",
                "new_password_confirm": "New_password123",
                "submit": True,
            },
        )
        self.assertStatus(response, 200)

    @pytest.mark.options(CAPTCHETAT_BASE_URL=None)
    def test_change_email_confirmation(self):
        user = UserFactory(email="jane@example.org", confirmed_at=datetime.now())
        self.login(user)

        with capture_mails() as mails:
            response = self.post(
                url_for("security.change_email"),
                {
                    "new_email": "jane2@example.org",
                    "new_email_confirm": "jane2@example.org",
                    "submit": True,
                },
            )
            self.assertStatus(response, 200)

        assert len(mails) == 1
        assert len(mails[0].recipients) == 1
        assert mails[0].recipients[0] == "jane2@example.org"
        assert mails[0].subject == _("Confirm your email address")


class TwoFactorSecurityAPITest(PytestOnlyAPITestCase):
    """Test 2FA requirement enforcement."""

    def test_2fa_routes_requires_authentication(self):
        """Test that 2FA setup, validation and rescue require user to be logged in."""
        response = self.get(url_for("security.two_factor_setup"))
        assert response.status_code == 302
        assert response.location == url_for("security.login")

        response = self.get(url_for("security.two_factor_rescue"))
        assert response.status_code == 302
        assert response.location == url_for("security.login")

        response = self.get(url_for("security.two_factor_token_validation"))
        assert response.status_code == 302
        assert response.location == url_for("security.login")

    @pytest.mark.options(SECURITY_TWO_FACTOR_REQUIRED=False)
    def test_2fa_disabled_by_default(self):
        today = datetime.now(UTC)
        user = UserFactory(password="password123", confirmed_at=today)

        # Should be able to login without 2FA
        response = self.post(
            url_for("security.login"), {"email": user.email, "password": "password123"}
        )
        self.assertStatus(response, 200)
        assert "tf_required" not in response.json["response"]
        assert "tf_state" not in response.json["response"]

        # Should be None by default (2FA not set up)
        assert user.tf_primary_method is None
        assert user.tf_totp_secret is None

    @pytest.mark.options(SECURITY_TWO_FACTOR_REQUIRED=True)
    def test_2fa_required_by_default(self):
        today = datetime.now(UTC)
        user = UserFactory(password="password123", confirmed_at=today)

        # Should require 2FA setup
        response = self.post(
            url_for("security.login"), {"email": user.email, "password": "password123"}
        )
        self.assertStatus(response, 200)
        assert response.json["response"]["tf_required"] is True
        assert response.json["response"]["tf_state"] == "setup_from_login"

    def test_user_with_2fa_fields_need_to_validate_token(self):
        today = datetime.now(UTC)
        user = UserFactory(
            password="password123",
            confirmed_at=today,
            tf_primary_method="authenticator",
            tf_totp_secret="test_secret",
        )

        # Should require 2FA token validation
        response = self.post(
            url_for("security.login"), {"email": user.email, "password": "password123"}
        )
        assert response.json["response"]["tf_required"] is True
        assert response.json["response"]["tf_state"] == "ready"
        assert response.json["response"]["tf_primary_method"] == "authenticator"

    @pytest.mark.options(CAPTCHETAT_BASE_URL=None, SECURITY_RETURN_GENERIC_RESPONSES=True)
    def test_reset_password(self):
        user = UserFactory(email="jane@example.org", confirmed_at=datetime.now())
        token = generate_reset_password_token(user)

        response = self.post(
            url_for("security.reset_password", token=token),
            {
                "password": "Password123!@#",
                "password_confirm": "Password123!@#",
                "submit": True,
            },
        )
        self.assertStatus(response, 200)


class SecurityMailAuditLogTest(PytestOnlyAPITestCase):
    """Tests that Flask-Security's own mails reach the dispatch audit log.

    The tests above state in their comments that they "cannot test for mail
    sending since they are sent with Flask directly and not with our system",
    and settle for asserting the rendering. That gap is exactly what the
    AuditMailUtil closes, so it is tested here.

    ``SEND_MAIL`` has to be set through ``get_settings`` rather than
    ``config.update``: ``mail_util_cls`` is chosen while the app is being
    built (``udata.auth.init_app``), so flipping the flag at runtime would
    leave the NoopMailUtil wired and prove nothing.
    """

    AUDIT_LOGGER = "udata.mail.audit"

    def get_settings(self, request):
        class SendMailSettings(settings.Testing):
            SEND_MAIL = True

        return SendMailSettings

    @pytest.fixture(autouse=True)
    def _inject_caplog(self, caplog):
        self.caplog = caplog

    def test_password_reset_mail_is_audited(self):
        UserFactory(email="jane.doe@example.org", confirmed_at=datetime.now())

        with self.caplog.at_level(logging.INFO, logger=self.AUDIT_LOGGER):
            with mail.record_messages() as outbox:
                response = self.post(
                    url_for("security.forgot_password"),
                    {"email": "jane.doe@example.org", "submit": True},
                )

        self.assertStatus(response, 200)
        assert len(outbox) == 1
        # The bare template name is the identifier Flask-Security hands over;
        # the security/email/ prefix only exists while resolving the file.
        assert 'mail_dispatch kind="reset_instructions"' in self.caplog.text
        assert "recipient=j***@example.org" in self.caplog.text
        assert "result=sent" in self.caplog.text
        assert "jane.doe@example.org" not in self.caplog.text

    def test_account_confirmation_mail_is_audited(self):
        with self.caplog.at_level(logging.INFO, logger=self.AUDIT_LOGGER):
            with mail.record_messages() as outbox:
                response = self.post(
                    url_for("security.register"),
                    {
                        "first_name": "Jane",
                        "last_name": "Doe",
                        "accept_conditions": True,
                        "email": "jane.doe@example.org",
                        "password": "Password123!@#",
                        "password_confirm": "Password123!@#",
                        "submit": True,
                    },
                )

        self.assertStatus(response, 200)
        assert len(outbox) == 1
        assert 'mail_dispatch kind="welcome"' in self.caplog.text
        assert "recipient=j***@example.org" in self.caplog.text
        assert "result=sent" in self.caplog.text
        assert "jane.doe@example.org" not in self.caplog.text

    def test_failed_security_mail_is_audited_and_still_raises(self):
        refusal = smtplib.SMTPRecipientsRefused(
            {"jane.doe@example.org": (550, b"No such user here")}
        )

        # Patched on Connection, not on Mail: app.extensions["mail"] is a
        # flask_mail _MailState, so patching Mail.send leaves it untouched and
        # the send would quietly succeed.
        with self.caplog.at_level(logging.INFO, logger=self.AUDIT_LOGGER):
            with patch("flask_mail.Connection.send", side_effect=refusal):
                with pytest.raises(smtplib.SMTPRecipientsRefused):
                    AuditMailUtil(self.app).send_mail(
                        "reset_instructions",
                        "Password reset",
                        "jane.doe@example.org",
                        "noreply@example.org",
                        "body",
                        "<p>body</p>",
                    )

        assert 'mail_dispatch kind="reset_instructions"' in self.caplog.text
        assert "result=error" in self.caplog.text
        assert "SMTPRecipientsRefused" in self.caplog.text
        assert "jane.doe@example.org" not in self.caplog.text

    def test_audit_mail_util_is_the_one_wired_when_sending_is_enabled(self):
        """Guards the wiring itself, which no assertion above would catch."""
        assert isinstance(self.app.extensions["security"].mail_util, AuditMailUtil)
