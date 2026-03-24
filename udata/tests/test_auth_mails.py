import pytest

from udata.auth.mails import (
    change_notice,
    confirmation_instructions,
    render_mail_template,
    reset_instructions,
    reset_notice,
    welcome,
    welcome_existing,
)
from udata.core.user.factories import UserFactory
from udata.tests.api import APITestCase


class AuthMailRenderingTest(APITestCase):
    """Test auth/security email rendering via render_mail_template."""

    # --- welcome (account creation confirmation) ---

    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_welcome_mail_txt(self):
        user = UserFactory()
        result = render_mail_template(
            "security/email/welcome.txt",
            user=user,
            confirmation_link="https://example.com/confirm/abc123",
        )
        assert result is not None
        assert "Confirm your email" in result or "confirm" in result.lower()
        assert "https://example.com/confirm/abc123" in result

    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_welcome_mail_html(self):
        user = UserFactory()
        result = render_mail_template(
            "security/email/welcome.html",
            user=user,
            confirmation_link="https://example.com/confirm/abc123",
        )
        assert result is not None
        assert "https://example.com/confirm/abc123" in result
        assert "<" in result

    # --- welcome_existing (registration with existing email) ---

    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_welcome_existing_mail_txt(self):
        user = UserFactory()
        result = render_mail_template(
            "security/email/welcome_existing.txt",
            user=user,
            recovery_link="https://example.com/reset/abc123",
        )
        assert result is not None
        assert "https://example.com/reset/abc123" in result

    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_welcome_existing_mail_html(self):
        user = UserFactory()
        result = render_mail_template(
            "security/email/welcome_existing.html",
            user=user,
            recovery_link="https://example.com/reset/abc123",
        )
        assert result is not None
        assert "https://example.com/reset/abc123" in result
        assert "<" in result

    # --- confirmation_instructions (email confirmation reminder) ---

    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_confirmation_instructions_mail_txt(self):
        user = UserFactory()
        result = render_mail_template(
            "security/email/confirmation_instructions.txt",
            user=user,
            confirmation_link="https://example.com/confirm/abc123",
        )
        assert result is not None
        assert "https://example.com/confirm/abc123" in result

    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_confirmation_instructions_mail_html(self):
        user = UserFactory()
        result = render_mail_template(
            "security/email/confirmation_instructions.html",
            user=user,
            confirmation_link="https://example.com/confirm/abc123",
        )
        assert result is not None
        assert "https://example.com/confirm/abc123" in result
        assert "<" in result

    # --- reset_instructions (password reset request) ---

    @pytest.mark.options(DEFAULT_LANGUAGE="en", CDATA_BASE_URL="https://example.com")
    def test_reset_instructions_mail_txt(self):
        user = UserFactory()
        result = render_mail_template(
            "security/email/reset_instructions.txt",
            user=user,
            reset_token="abc123token",
        )
        assert result is not None
        assert "https://example.com/reset/abc123token" in result

    @pytest.mark.options(DEFAULT_LANGUAGE="en", CDATA_BASE_URL="https://example.com")
    def test_reset_instructions_mail_html(self):
        user = UserFactory()
        result = render_mail_template(
            "security/email/reset_instructions.html",
            user=user,
            reset_token="abc123token",
        )
        assert result is not None
        assert "https://example.com/reset/abc123token" in result
        assert "<" in result

    # --- reset_notice (password was reset) ---

    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_reset_notice_mail_txt(self):
        user = UserFactory()
        result = render_mail_template(
            "security/email/reset_notice.txt",
            user=user,
        )
        assert result is not None
        assert "reset" in result.lower()

    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_reset_notice_mail_html(self):
        user = UserFactory()
        result = render_mail_template(
            "security/email/reset_notice.html",
            user=user,
        )
        assert result is not None
        assert "reset" in result.lower()
        assert "<" in result

    # --- change_notice (password was changed) ---

    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_change_notice_mail_txt(self):
        user = UserFactory()
        result = render_mail_template(
            "security/email/change_notice.txt",
            user=user,
        )
        assert result is not None
        assert "changed" in result.lower() or "password" in result.lower()

    @pytest.mark.options(DEFAULT_LANGUAGE="en", CDATA_BASE_URL="https://example.com")
    def test_change_notice_mail_html(self):
        user = UserFactory()
        result = render_mail_template(
            "security/email/change_notice.html",
            user=user,
        )
        assert result is not None
        assert "password" in result.lower()
        assert "<" in result

    # --- error handling ---

    def test_unknown_template_raises(self):
        with pytest.raises(Exception, match="Unknown mail message template"):
            render_mail_template(
                "security/email/unknown_template.txt",
                user=UserFactory(),
            )

    def test_non_security_template_returns_none(self):
        result = render_mail_template("other/template.txt")
        assert result is None

    def test_non_string_template_returns_none(self):
        result = render_mail_template(["security/email/welcome.txt"])
        assert result is None

    def test_unsupported_format_returns_none(self):
        """Non .txt/.html format is filtered out early and returns None."""
        result = render_mail_template(
            "security/email/welcome.pdf",
            user=UserFactory(),
            confirmation_link="https://example.com",
        )
        assert result is None


class AuthMailMessageBuilderTest(APITestCase):
    """Test MailMessage objects returned by each builder function."""

    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_welcome_subject_and_cta(self):
        """Welcome email should have correct subject and confirmation CTA."""
        msg = welcome(confirmation_link="https://example.com/confirm/token123")
        assert "confirm" in str(msg.subject).lower()
        cta = next((p for p in msg.paragraphs if hasattr(p, "link")), None)
        assert cta is not None
        assert cta.link == "https://example.com/confirm/token123"

    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_welcome_existing_subject_and_cta(self):
        """Welcome existing email should have recovery link CTA."""
        msg = welcome_existing(recovery_link="https://example.com/reset/token456")
        assert "account" in str(msg.subject).lower() or "information" in str(msg.subject).lower()
        cta = next((p for p in msg.paragraphs if hasattr(p, "link")), None)
        assert cta is not None
        assert cta.link == "https://example.com/reset/token456"

    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_confirmation_instructions_subject_and_cta(self):
        """Confirmation instructions email should have confirmation CTA."""
        msg = confirmation_instructions(
            confirmation_link="https://example.com/confirm/token789"
        )
        assert "confirm" in str(msg.subject).lower()
        cta = next((p for p in msg.paragraphs if hasattr(p, "link")), None)
        assert cta is not None
        assert cta.link == "https://example.com/confirm/token789"

    @pytest.mark.options(DEFAULT_LANGUAGE="en", CDATA_BASE_URL="https://example.com")
    def test_reset_instructions_subject_and_cta(self):
        """Reset instructions email should have reset link with token."""
        msg = reset_instructions(reset_token="resettoken123")
        assert "reset" in str(msg.subject).lower()
        cta = next((p for p in msg.paragraphs if hasattr(p, "link")), None)
        assert cta is not None
        assert "resettoken123" in cta.link

    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_reset_notice_subject(self):
        """Reset notice email should confirm password was reset."""
        msg = reset_notice()
        assert "reset" in str(msg.subject).lower()
        assert len(msg.paragraphs) >= 1

    @pytest.mark.options(DEFAULT_LANGUAGE="en", CDATA_BASE_URL="https://example.com")
    def test_change_notice_subject_and_cta(self):
        """Change notice email should confirm password was changed and offer reset link."""
        msg = change_notice()
        assert "changed" in str(msg.subject).lower()
        cta = next((p for p in msg.paragraphs if hasattr(p, "link")), None)
        assert cta is not None
        assert "/reset" in cta.link
