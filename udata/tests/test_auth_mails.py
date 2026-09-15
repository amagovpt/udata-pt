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
        assert "https://example.com/reset-password/abc123token" in result

    @pytest.mark.options(DEFAULT_LANGUAGE="en", CDATA_BASE_URL="https://example.com")
    def test_reset_instructions_mail_html(self):
        user = UserFactory()
        result = render_mail_template(
            "security/email/reset_instructions.html",
            user=user,
            reset_token="abc123token",
        )
        assert result is not None
        assert "https://example.com/reset-password/abc123token" in result
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
        assert "redefinid" in result.lower()

    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_reset_notice_mail_html(self):
        user = UserFactory()
        result = render_mail_template(
            "security/email/reset_notice.html",
            user=user,
        )
        assert result is not None
        assert "redefinid" in result.lower()
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
        msg = confirmation_instructions(confirmation_link="https://example.com/confirm/token789")
        assert "confirm" in str(msg.subject).lower()
        cta = next((p for p in msg.paragraphs if hasattr(p, "link")), None)
        assert cta is not None
        assert cta.link == "https://example.com/confirm/token789"

    @pytest.mark.options(DEFAULT_LANGUAGE="en", CDATA_BASE_URL="https://example.com")
    def test_reset_instructions_subject_and_cta(self):
        """Reset instructions email should have reset link with token."""
        msg = reset_instructions(reset_token="resettoken123")
        assert "redefinição" in str(msg.subject).lower()
        cta = next((p for p in msg.paragraphs if hasattr(p, "link")), None)
        assert cta is not None
        assert "resettoken123" in cta.link

    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_reset_notice_subject(self):
        """Reset notice email should confirm password was reset."""
        msg = reset_notice()
        assert "redefinid" in str(msg.subject).lower()
        assert len(msg.paragraphs) >= 1

    @pytest.mark.options(DEFAULT_LANGUAGE="en", CDATA_BASE_URL="https://example.com")
    def test_change_notice_subject_and_cta(self):
        """Change notice email should confirm password was changed and offer reset link."""
        msg = change_notice()
        assert "changed" in str(msg.subject).lower()
        cta = next((p for p in msg.paragraphs if hasattr(p, "link")), None)
        assert cta is not None
        assert "/reset" in cta.link


class AuthMailPortugueseTranslationTest(APITestCase):
    """Every auth string a Portuguese reader can be shown must be translated.

    The account-linking mail went out entirely in English -- subject included --
    because its strings were wrapped in gettext but had no pt catalogue entry.
    That fails silently: gettext returns the msgid, so the mail renders and
    looks fine to anyone reading English.

    Listing the msgids is deliberate. Re-extracting them with pybabel at test
    time would also cover strings added later, but it would not know which of
    them a pt reader can actually see -- seven strings in the SAML plugin are
    already written in Portuguese as their msgid, and would show up as missing
    forever. This pins the set that was actually broken.
    """

    # Spelled exactly as Python concatenates them in the source. An implicit
    # concatenation whose line breaks fall elsewhere is a DIFFERENT msgid, and
    # the lookup then silently returns the English -- which is the whole failure
    # mode being guarded here, so it must not be reintroduced by the guard.
    PT_REQUIRED = (
        # udata/auth/forms.py
        "Your new email must be different than your previous email",
        "reCAPTCHA token",
        "reCAPTCHA validation required",
        "Invalid reCAPTCHA",
        # udata/auth/mails.py -- address-taken notice
        "Your %(site)s account already exists",
        (
            "You received this email because someone tried to use your email "
            "address on %(site)s. It already belongs to an account, so nothing "
            "was created and nothing changed."
        ),
        # Still pinned although address_taken_notice stopped using it: the
        # SAML wizard's sibling notice still does, and there the advice is
        # sound -- that reader is not held on a screen and the next paragraph
        # tells them what to do.
        (
            "If it was you, sign in to that account the way you normally "
            "do, or use the account recovery if you cannot."
        ),
        (
            "If it was you, nothing further is needed to keep the account. "
            "If you cannot access it, contact support."
        ),
        "If it was not you, no action is needed. Your account is untouched.",
        # udata/auth/mails.py -- the confirm-email mail (LEDG-2350 copy)
        "Confirm your email on dados.gov.pt",
        "This email address was provided for a dados.gov.pt account.",
        ("To confirm this address and link it to your account, select the button below."),
        "Confirm email address",
        "If you did not provide this email address, you can ignore this message.",
        "Need help? See the %(help_link)s page on dados.gov.pt.",
        "Help and contacts",
        # udata/auth/mails.py -- registration-association refusal.
        #
        # Absent from this list until 2026-09-15, and that absence is why the
        # mail shipped untranslated for a week: the notice was added AFTER the
        # commit that translated its siblings and extended this guard, so
        # nothing ever asked whether it had a translation. A list that pins
        # "the set that was actually broken" only stays useful if it grows
        # with the set.
        "Your %(site)s account could not be linked",
        (
            "You received this email because someone signing in to %(site)s with a "
            "digital identity asked to link it to the account that uses this address."
        ),
        (
            "It was not linked. The temporary account created for that sign-in "
            "already holds content of its own, and linking would have discarded it. "
            "Nothing was changed on either account."
        ),
        (
            "If it was you, contact support so the two accounts can be sorted out "
            "together. If it was not you, no action is needed: your account is "
            "untouched and nobody gained access to it."
        ),
        # SAML plugin -- the account-linking mail the user received in English
        "Confirm linking a digital identity to your account",
        (
            "Someone signed in with the digital identity of %(name)s and asked to link "
            "it to your %(site)s account."
        ),
        "an unnamed identity",
        "Open the link below to complete the linking and sign in.",
        "Confirm linking",
        "The link is valid for 30 minutes and can only be used once.",
        (
            "If it was not you who started this, do NOT open the link and ignore this "
            "email. Your account will not be changed."
        ),
        # SAML plugin -- its own address-taken notice
        (
            "Someone signing in with a digital identity tried to use this "
            "address to create a new %(site)s account. It already belongs "
            "to an account, so nothing was created and nothing changed."
        ),
        (
            "To link that account to your digital identity, start the "
            "sign-in again and follow the account association steps."
        ),
    )

    @pytest.mark.options(DEFAULT_LANGUAGE="pt")
    def test_auth_strings_have_a_portuguese_translation(self):
        from udata.i18n import gettext

        missing = [s for s in self.PT_REQUIRED if gettext(s) == s]
        assert not missing, (
            "These auth strings fall back to English for a pt reader, which "
            "means they have no msgid in udata/translations/pt. Add them to the "
            "catalogue and recompile the .mo:\n" + "\n".join(f"  - {s!r}" for s in missing)
        )

    @pytest.mark.options(DEFAULT_LANGUAGE="pt")
    def test_address_taken_notice_renders_fully_in_portuguese(self):
        """Structural check on the notice added with this flow.

        The list above pins known msgids; this one pins the message, so a
        paragraph added to it later without a translation is caught even though
        nobody remembered to extend the list.
        """
        from udata.auth.mails import address_taken_notice

        msg = address_taken_notice()
        rendered = [str(msg.subject)] + [str(p) for p in msg.paragraphs]
        english = [t for t in rendered if " the " in t or "account already exists" in t]
        assert not english, f"untranslated fragments in the notice: {english}"

    @pytest.mark.options(DEFAULT_LANGUAGE="pt")
    def test_confirmation_instructions_renders_the_approved_copy_in_portuguese(self):
        """The mail every citizen completing a sign-in receives.

        Three things it must not do, and each has a reason that is invisible
        from the outside:

        - **No greeting, no sign-off.** The mail frame supplies both for every
          message on the platform. A paragraph repeating them prints them
          twice, and nothing else in the test suite would notice.
        - **Not "to finish registering".** The same mail serves an email
          change from the profile, where that phrasing is false.
        - **The site name written out.** SITE_TITLE in production is the
          platform's full descriptive title; interpolating it would make the
          subject line unreadable.
        """
        from udata.auth.mails import confirmation_instructions

        msg = confirmation_instructions(confirmation_link="https://example.org/c/tok")
        subject = str(msg.subject)
        paragraphs = [str(p) for p in msg.paragraphs]
        body = " ".join(paragraphs)

        assert subject == "Confirme o seu e-mail no dados.gov.pt"
        assert "registo" not in body, body
        assert "Bom dia" not in body, body
        assert "equipa" not in body.lower(), body

        cta = [p for p in msg.paragraphs if getattr(p, "link", None)]
        assert len(cta) == 1
        assert cta[0].link == "https://example.org/c/tok"
        assert str(cta[0].label) == "Confirmar endereço de e-mail"

        english = [p for p in paragraphs if " the " in p]
        assert not english, f"untranslated fragments: {english}"

    def test_address_taken_notice_prescribes_no_sign_in(self):
        """The notice must not tell its reader to sign in.

        It used to: "sign in to that account the way you normally do". That is
        impossible advice for the reader most likely to get this mail --
        somebody held on the registration completion screen, who cannot sign
        in anywhere until that screen lets them through. The account may also
        be a SAML one with no usable password at all.

        Asserted on the English source rather than the translation, so the
        check survives a retranslation, and paired with the no-link assertion
        because both are properties the docstring argues for and neither is
        visible from the outside.
        """
        from udata.auth.mails import address_taken_notice

        msg = address_taken_notice()
        rendered = " ".join(str(p) for p in msg.paragraphs)
        assert "sign in" not in rendered.lower(), rendered
        assert not [p for p in msg.paragraphs if getattr(p, "link", None)]

    @pytest.mark.options(DEFAULT_LANGUAGE="pt")
    def test_registration_association_refused_notice_renders_fully_in_portuguese(self):
        """The same structural check, for the notice that had none.

        This mail shipped in English for a week and nothing said so: gettext
        returns the msgid when a catalogue has no entry, so it rendered
        cleanly and read fine to anyone who reads English. Nobody reading it
        in production did.

        Also asserts what the notice must NOT have. It carries no link by
        design -- there is nothing a link could do, because the refusal is
        about content on the other account that only a person can resolve --
        and a paragraph with a link would be the first sign that somebody
        "helpfully" added an action here.
        """
        from udata.auth.mails import registration_association_refused_notice

        msg = registration_association_refused_notice()
        rendered = [str(msg.subject)] + [str(p) for p in msg.paragraphs]
        english = [t for t in rendered if " the " in t or "could not be linked" in t]
        assert not english, f"untranslated fragments in the refusal: {english}"

        assert not [p for p in msg.paragraphs if getattr(p, "link", None)]
