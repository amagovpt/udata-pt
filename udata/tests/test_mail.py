import logging
import smtplib
from unittest.mock import patch

import pytest
from flask_babel import LazyString

from udata.core.organization.factories import OrganizationFactory
from udata.core.user.factories import UserFactory
from udata.i18n import lazy_gettext as _
from udata.mail import (
    LabelledContent,
    MailMessage,
    ParagraphWithLinks,
    mail,
    mail_kind,
    scrub_addresses,
    send_mail,
)
from udata.tests.api import APITestCase
from udata.tests.helpers import capture_mails


class MailGenerationTest(APITestCase):
    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_simple_mail(self):
        with capture_mails() as mails:
            send_mail(
                UserFactory(email="jane@example.org"),
                MailMessage(_("Unknown"), paragraphs=[_("Some text")]),
            )

        assert len(mails) == 1
        assert len(mails[0].recipients) == 1
        assert mails[0].recipients[0] == "jane@example.org"
        assert mails[0].subject == "Unknown"
        assert "Some text" in mails[0].body
        assert "Some text" in mails[0].html

    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_allow_none_in_paragraphs(self):
        with capture_mails() as mails:
            send_mail(
                UserFactory(email="jane@example.org"),
                MailMessage(_("Unknown"), paragraphs=[_("Some text"), None]),
            )

        assert len(mails) == 1

    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_multiple_recipients(self):
        with capture_mails() as mails:
            send_mail(
                [
                    UserFactory(email="jane@example.org"),
                    UserFactory(email="john@example.org", prefered_language="fr"),
                ],
                MailMessage(_("Unknown"), paragraphs=[_("Some text")]),
            )

        assert len(mails) == 2
        assert len(mails[0].recipients) == 1
        assert mails[0].recipients[0] == "jane@example.org"
        assert mails[0].subject == "Unknown"
        assert len(mails[1].recipients) == 1
        assert mails[1].recipients[0] == "john@example.org"
        assert mails[1].subject == "Inconnu"

    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_use_user_language(self):
        with capture_mails() as mails:
            send_mail(
                UserFactory(email="jane@example.org", prefered_language="fr"),
                MailMessage(_("Unknown"), paragraphs=[_("Some text")]),
            )

        assert len(mails) == 1
        assert mails[0].subject == "Inconnu"

    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_use_objects_in_translations(self):
        org = OrganizationFactory(name="My Org")

        with capture_mails() as mails:
            send_mail(
                UserFactory(email="jane@example.org", prefered_language="fr"),
                MailMessage(
                    _("Unknown"),
                    paragraphs=[ParagraphWithLinks(_("Some text %(org)s", org=org))],
                ),
            )

        assert len(mails) == 1
        assert "My Org" in mails[0].body
        assert org.url_for() not in mails[0].body
        assert "My Org" in mails[0].html
        assert "<a" in mails[0].html
        assert org.url_for() in mails[0].html

    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_labelled_bloc(self):
        with capture_mails() as mails:
            send_mail(
                UserFactory(email="jane@example.org", prefered_language="fr"),
                MailMessage(
                    _("Unknown"),
                    paragraphs=[LabelledContent(_("Some text:"), "Some content", inline=True)],
                ),
            )

        assert len(mails) == 1
        assert "<strong>Du texte :</strong> Some content" in mails[0].html
        assert "Du texte : Some content" in mails[0].body

    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_labelled_bloc_truncation(self):
        with capture_mails() as mails:
            send_mail(
                UserFactory(email="jane@example.org", prefered_language="fr"),
                MailMessage(
                    _("Unknown"),
                    paragraphs=[
                        LabelledContent(
                            _("Some text:"),
                            """
                                Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book.
                            """,
                        )
                    ],
                ),
            )

        assert len(mails) == 1
        assert "a type specimen book." not in mails[0].html
        assert "a type specimen book." not in mails[0].body

    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_escape_user_content_in_content(self):
        with capture_mails() as mails:
            send_mail(
                UserFactory(email="jane@example.org", prefered_language="fr"),
                MailMessage(
                    _("Unknown"),
                    paragraphs=[
                        LabelledContent(
                            _("Some text:"), "<script>Some content</script>", inline=True
                        )
                    ],
                ),
            )

        assert len(mails) == 1
        assert "<script>" not in mails[0].html

    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_escape_user_content_in_object_label(self):
        org = OrganizationFactory(name="<script>My Org</script>")

        with capture_mails() as mails:
            send_mail(
                UserFactory(email="jane@example.org", prefered_language="fr"),
                MailMessage(
                    _("Unknown"),
                    paragraphs=[ParagraphWithLinks(_("Some text %(org)s", org=org))],
                ),
            )

        assert len(mails) == 1
        assert "<script>" not in mails[0].html


class MailDispatchAuditLogTest(APITestCase):
    """Tests the audit line emitted for every real mail dispatch attempt.

    ``MailGenerationTest`` above runs under the test default ``SEND_MAIL=False``
    and asserts through the ``mail_sent`` signal, so it never enters the
    transport branch of ``send_mail`` — the only branch used in deployed
    environments, and the one the audit line lives in. Here ``SEND_MAIL=True``
    is forced as in ``SiteContactEnvironmentMailTest``; ``MAIL_SUPPRESS_SEND``
    follows ``TESTING``, so the dispatch path runs without opening SMTP.

    Note the assertions never compare translated text: ``pytest.mark.options``
    is not consumed anywhere, so ``DEFAULT_LANGUAGE`` stays at its default
    regardless of the marker. Only msgids (English by construction) and the
    fields of the audit line are asserted.
    """

    AUDIT_LOGGER = "udata.mail.audit"

    @pytest.fixture(autouse=True)
    def _inject_caplog(self, caplog):
        self.caplog = caplog

    def _enable_sending(self):
        self.app.config.update(SEND_MAIL=True)

    def _message(self):
        return MailMessage(_("Unknown"), paragraphs=[_("Some text")])

    def test_successful_dispatch_is_logged_with_masked_recipient(self):
        self._enable_sending()
        user = UserFactory(email="jane.doe@example.org")

        with self.caplog.at_level(logging.INFO, logger=self.AUDIT_LOGGER):
            with mail.record_messages() as outbox:
                send_mail(user, self._message())

        assert len(outbox) == 1
        assert 'mail_dispatch kind="Unknown"' in self.caplog.text
        assert "recipient=j***@example.org" in self.caplog.text
        assert "result=sent" in self.caplog.text
        # The whole point of masking: the address must not reach the log file.
        assert "jane.doe@example.org" not in self.caplog.text

    def test_failed_dispatch_is_logged_and_still_raises(self):
        self._enable_sending()
        user = UserFactory(email="jane.doe@example.org")
        # SMTPRecipientsRefused is the failure the ticket names ("destinatário
        # rejeitado") and the one that quotes the address back at us: str() of
        # it is the {address: (code, response)} dict itself. A generic
        # SMTPException would not exercise the scrubbing at all.
        refusal = smtplib.SMTPRecipientsRefused(
            {"jane.doe@example.org": (550, b"No such user here")}
        )

        with self.caplog.at_level(logging.INFO, logger=self.AUDIT_LOGGER):
            with patch("flask_mail.Connection.send", side_effect=refusal):
                with pytest.raises(smtplib.SMTPRecipientsRefused):
                    send_mail(user, self._message())

        assert "result=error" in self.caplog.text
        assert "SMTPRecipientsRefused" in self.caplog.text
        # The refused address is quoted inside the exception message, so this
        # is where masking is easiest to lose.
        assert "jane.doe@example.org" not in self.caplog.text
        assert "j***@example.org" in self.caplog.text

    def test_connection_failure_is_logged_and_still_raises(self):
        """A refused connection is an OSError, not an SMTPException."""
        self._enable_sending()
        user = UserFactory(email="jane.doe@example.org")

        with self.caplog.at_level(logging.INFO, logger=self.AUDIT_LOGGER):
            with patch(
                "flask_mail.Connection.send",
                side_effect=ConnectionRefusedError(111, "Connection refused"),
            ):
                with pytest.raises(ConnectionRefusedError):
                    send_mail(user, self._message())

        assert "result=error" in self.caplog.text
        assert "ConnectionRefusedError" in self.caplog.text

    def test_audit_logger_level_survives_a_production_like_parent(self):
        """Regression guard for the whole feature being a silent no-op.

        ``init_logging`` sets the ``udata`` logger to WARNING when not in
        debug, which a child with no level of its own inherits — dropping
        every INFO line before it reaches a handler. ``mail.init_app`` pins
        the child's level precisely to stop that.
        """
        logging.getLogger("udata").setLevel(logging.WARNING)

        assert logging.getLogger(self.AUDIT_LOGGER).getEffectiveLevel() == logging.INFO


class MailKindTest(APITestCase):
    def test_lazy_subject_yields_the_untranslated_msgid(self):
        message = MailMessage(_("New membership request"), paragraphs=[])

        assert mail_kind(message) == "New membership request"

    def test_eagerly_formatted_subject_falls_back_to_the_resolved_string(self):
        # `_("...").format(...)` resolves the LazyString through its
        # __getattr__ and hands back a plain str, so there is no msgid left to
        # read. udata/core/user/mails.py builds one subject this way, and its
        # kind is therefore the *translated* subject — asserted here without
        # pinning a locale, since the resolved string is whatever the active
        # language produces.
        subject = _("Inactivity of your {site} account").format(site="x")
        message = MailMessage(subject, paragraphs=[])

        assert not isinstance(subject, LazyString)
        assert mail_kind(message) == str(subject)
        assert "x" in mail_kind(message)


class ScrubAddressesTest:
    def test_masks_a_bare_address(self):
        assert scrub_addresses("jane.doe@example.org refused") == "j***@example.org refused"

    def test_masks_an_address_inside_an_smtp_error_repr(self):
        error = smtplib.SMTPRecipientsRefused({"jane.doe@example.org": (550, b"No such user")})

        scrubbed = scrub_addresses(str(error))

        assert "jane.doe@example.org" not in scrubbed
        assert "j***@example.org" in scrubbed
        # The domain and the SMTP code survive: that is what makes the line
        # useful to whoever reads it.
        assert "550" in scrubbed

    def test_masks_every_address_when_several_are_refused(self):
        error = smtplib.SMTPRecipientsRefused(
            {"jane@example.org": (550, b"nope"), "john@other.example": (551, b"nope")}
        )

        scrubbed = scrub_addresses(str(error))

        assert "jane@example.org" not in scrubbed
        assert "john@other.example" not in scrubbed
        assert "j***@example.org" in scrubbed
        assert "j***@other.example" in scrubbed

    def test_text_without_an_address_is_untouched(self):
        assert scrub_addresses("Connection refused") == "Connection refused"
