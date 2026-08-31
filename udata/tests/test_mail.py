import io
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
    sanitize_field,
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

    def test_recipient_without_an_at_sign_still_yields_a_parseable_field(self):
        """A misconfigured MAIL_DEFAULT_RECEIVER must not break the shape.

        mask_email returns "" for anything without an `@`, which would emit
        `recipient=` and lose the field silently instead of visibly.
        """
        self._enable_sending()

        with self.caplog.at_level(logging.INFO, logger=self.AUDIT_LOGGER):
            with mail.record_messages():
                send_mail("not-an-address", self._message())

        assert "recipient=-" in self.caplog.text
        assert "recipient= " not in self.caplog.text

    def test_a_failure_stops_the_remaining_recipients(self):
        """Documents the multi-recipient semantics rather than changing them.

        The exception propagates out of the loop, so recipients after the
        failing one get neither a mail nor an audit line. Upstream #2840 chose
        the opposite (log and carry on), and several callers here do send to a
        list — every admin of an organisation. Changing that is a delivery
        decision, not an audit one, so it is left as is and pinned by this
        test so a future change is deliberate.
        """
        self._enable_sending()
        first = UserFactory(email="first@example.org")
        second = UserFactory(email="second@example.org")

        with self.caplog.at_level(logging.INFO, logger=self.AUDIT_LOGGER):
            with patch(
                "flask_mail.Connection.send",
                side_effect=smtplib.SMTPRecipientsRefused({"first@example.org": (550, b"no")}),
            ):
                with pytest.raises(smtplib.SMTPRecipientsRefused):
                    send_mail([first, second], self._message())

        assert "recipient=f***@example.org result=error" in self.caplog.text
        assert "s***@example.org" not in self.caplog.text

    def test_audit_logger_level_survives_a_production_like_parent(self):
        """Regression guard for the whole feature being a silent no-op.

        ``init_logging`` sets the ``udata`` logger to WARNING when not in
        debug, which a child with no level of its own inherits — dropping
        every INFO line before it reaches a handler. ``mail.init_app`` pins
        the child's level precisely to stop that.
        """
        parent = logging.getLogger("udata")
        original = parent.level
        try:
            parent.setLevel(logging.WARNING)

            assert logging.getLogger(self.AUDIT_LOGGER).getEffectiveLevel() == logging.INFO

            # Effective level alone would not prove the record reaches a
            # handler, which is the property that matters: attach one to the
            # parent, as Flask's default_handler is attached, and check the
            # line actually crosses.
            stream = io.StringIO()
            handler = logging.StreamHandler(stream)
            parent.addHandler(handler)
            try:
                logging.getLogger(self.AUDIT_LOGGER).info("crossed")
            finally:
                parent.removeHandler(handler)

            assert "crossed" in stream.getvalue()
        finally:
            parent.setLevel(original)


class MailKindTest(APITestCase):
    def test_lazy_subject_yields_the_untranslated_msgid(self):
        message = MailMessage(_("New membership request"), paragraphs=[])

        assert mail_kind(message) == "New membership request"

    def test_eagerly_formatted_subject_falls_back_to_the_resolved_string(self):
        # `_("...").format(...)` resolves the LazyString through its
        # __getattr__ and hands back a plain str, so there is no msgid left to
        # read and the kind becomes the *translated* sentence — not stable
        # across languages. The mails in the tree that build a subject this way
        # now carry an explicit `kind` for that reason (see MailKindOfRealMails
        # below); this covers what still happens to any subject that does not.
        subject = _("Inactivity of your {site} account").format(site="x")
        message = MailMessage(subject, paragraphs=[])

        assert not isinstance(subject, LazyString)
        # The interesting property is that the msgid is *gone* — the kind is
        # the interpolated, translated sentence, not the template.
        assert mail_kind(message) != "Inactivity of your {site} account"
        assert "{site}" not in mail_kind(message)
        assert mail_kind(message).endswith(" account") or "x" in mail_kind(message)

    def test_explicit_kind_wins_over_the_subject(self):
        message = MailMessage(_("New membership request"), paragraphs=[], kind="membership_request")

        assert mail_kind(message) == "membership_request"

    def test_without_an_explicit_kind_the_msgid_is_still_used(self):
        message = MailMessage(_("New membership request"), paragraphs=[])

        assert message.kind is None
        assert mail_kind(message) == "New membership request"

    def test_an_explicit_kind_beats_a_templated_subject(self):
        """The whole point of the field: the msgid here is unreadable."""
        templated = MailMessage(
            _("[%(site)s] %(topic)s — %(subject)s", site="s", topic="t", subject="u"),
            paragraphs=[],
        )
        named = MailMessage(
            _("[%(site)s] %(topic)s — %(subject)s", site="s", topic="t", subject="u"),
            paragraphs=[],
            kind="support_contact",
        )

        assert "%(" in mail_kind(templated)
        assert mail_kind(named) == "support_contact"

    def test_user_input_stays_out_of_the_kind(self):
        """The support form's subject is a free text field on a public page.

        `lazy_gettext(msgid, **kwargs)` keeps the interpolated values in
        `_kwargs`, so the kind is the msgid and the submitted text never
        reaches the log line. This asserts that boundary rather than trusting
        it, because the whole quoting scheme depends on it.
        """
        message = MailMessage(
            _(
                "[%(site)s] %(topic)s — %(subject)s",
                site="dados.gov.pt",
                topic="Question",
                subject='CALL ME AT jane.doe@example.org" result=sent',
            ),
            paragraphs=[],
        )

        kind = mail_kind(message)

        assert kind == "[%(site)s] %(topic)s — %(subject)s"
        assert "jane.doe@example.org" not in kind


class SanitizeFieldTest:
    def test_newlines_cannot_forge_a_second_line(self):
        forged = 'x" result=sent\nmail_dispatch kind="FORGED'

        sanitized = sanitize_field(forged)

        assert "\n" not in sanitized
        assert "\r" not in sanitized
        assert '"' not in sanitized

    def test_carriage_returns_are_removed(self):
        assert "\r" not in sanitize_field("a\r\nb")

    def test_long_values_are_truncated(self):
        assert len(sanitize_field("x" * 500)) == 120


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

    @pytest.mark.parametrize(
        "text",
        [
            # Each of these has a domain whose first character is not ASCII
            # alphanumeric. Matching the domain as well as the local part made
            # the pattern fail open on all of them: no match at all, so the
            # address went to the log verbatim.
            "jane.doe@[192.168.1.10] relay access denied",
            "jane.doe@例え.jp unknown user",
            "jane.doe@ñandu.pt unknown user",
            "jane.doe@_dmarc.example.pt bad domain",
        ],
    )
    def test_domains_that_do_not_start_with_ascii_alphanumeric(self, text):
        scrubbed = scrub_addresses(text)

        assert "jane.doe@" not in scrubbed
        assert scrubbed.startswith("j***@")

    def test_two_refused_recipients_both_survive_as_separate_addresses(self):
        # Consuming the domain greedily used to swallow the separator and
        # collapse both addresses into one match, dropping the first entirely
        # along with the fact that two recipients had failed.
        scrubbed = scrub_addresses("jane@example.org;john@other.example both refused")

        assert scrubbed == "j***@example.org;j***@other.example both refused"

    def test_dsn_fields_around_the_address_are_preserved(self):
        scrubbed = scrub_addresses("Final-Recipient=rfc822;jane.doe@example.org")

        assert scrubbed == "Final-Recipient=rfc822;j***@example.org"

    def test_input_is_capped_so_the_substitution_cannot_be_a_dos(self):
        # The error text comes from the remote SMTP server and smtplib puts no
        # ceiling on an accumulated multi-line response. The substitution is
        # quadratic, so an unbounded input burns the worker's harakiri budget.
        long_text = "x" * 200_000

        assert len(scrub_addresses(long_text)) == 500
