import copy
import logging
import re
from dataclasses import dataclass
from html import escape

from blinker import signal
from flask import current_app, render_template
from flask_babel import LazyString
from flask_mail import Mail, Message

from udata import i18n
from udata.utils import mask_email

log = logging.getLogger(__name__)

# Dedicated audit logger: one line per mail dispatch attempt, so "did this
# user ever get the mail?" can be answered from the backoffice log page
# instead of guessed. It lives under `udata.*` on purpose — the records
# propagate to the handlers of the `udata` logger (`app.logger`), whose
# stderr uwsgi writes to the file that page reads. Its level is pinned in
# `init_app` because `udata` is set to WARNING in production, which a child
# with no level of its own would inherit, silently dropping every line.
audit_logger = logging.getLogger("udata.mail.audit")

mail = Mail()

mail_sent = signal("mail-sent")

# Matches the local part of anything shaped like an address, by looking ahead
# for the `@` without consuming the domain. Matching the domain too — the
# obvious way to write this — fails open on every domain whose first character
# is not ASCII alphanumeric: an address literal (`jane@[192.168.1.10]`, which
# MTAs do quote in bounces), an IDN (`jane@exemplo.pt` is fine, `jane@例え.jp`
# is not) or a leading underscore would then match nothing at all and the
# whole address, local part included, would reach the log in the clear.
# Leaving the domain out also stops the match from eating the text around it:
# consuming greedily across a separator turned `a@x.pt;b@y.pt` into a single
# match, dropping the first address and the fact that two recipients failed.
ADDRESS_LOCAL_RE = re.compile(r"[^\s<>,:;=\"'()\[\]]+(?=@)")

# The error text comes from the remote SMTP server, and smtplib accumulates
# multi-line responses with no overall ceiling. The substitution below is
# quadratic in the length of the text, so an unbounded input is a way to burn
# the worker's whole harakiri budget on a regex. No diagnostic survives past a
# few hundred characters anyway.
MAX_ERROR_CHARS = 500

# Ceiling for the quoted `kind` field, which is a subject msgid.
MAX_KIND_CHARS = 120


def sanitize_field(value: str) -> str:
    """Make ``value`` safe to sit inside a quoted key=value field.

    Today every subject is `lazy_gettext(msgid, **kwargs)`, so `mail_kind`
    returns a msgid and user input stays in the LazyString's `_kwargs`,
    out of reach. That is an unwritten invariant, not a guarantee: one
    subject in the tree is already built with `.format()`, and a future
    subject interpolating user input the same way would carry newlines and
    quotes straight into the line — enough to forge a second audit record.
    Cheap to close here rather than to rely on nobody doing it.
    """
    return str(value).replace("\r", " ").replace("\n", " ").replace('"', "'")[:MAX_KIND_CHARS]


def scrub_addresses(text: str) -> str:
    """Mask the local part of every address in ``text``.

    SMTP failures name the address they refused: ``str(SMTPRecipientsRefused)``
    is the ``{address: (code, response)}`` dict itself, and SMTPSenderRefused
    carries the sender. Logging such a message verbatim would write the very
    address the audit line takes care to mask, so the message is scrubbed
    before it reaches the log. The domain survives, which is what makes the
    line diagnostic: a whole domain refusing mail is a real signal.
    """
    return ADDRESS_LOCAL_RE.sub(lambda match: f"{match.group(0)[0]}***", text[:MAX_ERROR_CHARS])


def mail_kind(message: "MailMessage") -> str:
    """Return a stable identifier for the kind of mail being sent.

    An explicit ``kind`` on the message wins, and is how the mails whose
    subject is a template say what they are: deriving from the subject gives
    them the msgid with its placeholders unfilled — `[%(site)s] %(topic)s —
    %(subject)s` tells a reader nothing — and, when the subject was built with
    ``.format()``, gives a *translated* string, which is not stable at all.

    Otherwise the msgid is used, which is the right identifier for the
    subjects that are plain sentences: the translated subject would log
    differently per recipient language, and lazy_gettext keeps the msgid in
    ``_args[0]``. Reading that internal is the same coupling
    `ParagraphWithLinks.html` already has on ``_kwargs``.
    """
    if message.kind:
        return message.kind

    subject = message.subject
    try:
        if isinstance(subject, LazyString) and subject._args:
            return str(subject._args[0])
        return str(subject)
    except Exception:  # noqa: BLE001 - an audit line must never break a send
        return "?"


def log_mail_dispatch(kind: str, recipient: str, result: str, error: Exception | None = None):
    """Emit one key=value audit line per mail dispatch attempt.

    Mirrors the shape of the SAML audit line (`_audit_saml`): a single line
    per terminal outcome, never raising — an audit failure must not turn a
    working send into a 500. ``kind`` is quoted because msgids contain
    spaces and interpolation placeholders, which would otherwise break the
    key=value shape.
    """
    try:
        # `or "-"`, not `if recipient`: mask_email returns "" for anything
        # without an `@`, and a misconfigured MAIL_DEFAULT_RECEIVER would
        # then emit `recipient=` — breaking the key=value shape and losing
        # the field silently rather than visibly.
        masked = mask_email(recipient) or "-"
        detail = "-"
        if error is not None:
            detail = f"{type(error).__name__}: {scrub_addresses(str(error))}"
        line = (
            f'mail_dispatch kind="{sanitize_field(kind)}" recipient={masked} '
            f"result={result} error={detail}"
        )
        if result == "sent":
            audit_logger.info(line)
        else:
            # exc_info stays off: this is a one-line audit record, and the
            # traceback (which quotes the raw address) is still logged by the
            # normal error handling downstream, where it already was.
            audit_logger.error(line)
    except Exception:  # noqa: BLE001 - see docstring
        log.exception("Failed to emit mail dispatch audit line")


@dataclass
class MailCTA:
    label: LazyString
    link: str | None


@dataclass
class LabelledContent:
    label: LazyString
    content: str
    inline: bool = False
    truncated_at: int = 200

    @property
    def truncated_content(self) -> str:
        return (
            self.content[: self.truncated_at] + "…"
            if len(self.content) > self.truncated_at
            else self.content
        )


@dataclass
class Link:
    """Simple linkable object for use in ParagraphWithLinks"""

    label: str
    url: str

    def __str__(self):
        return str(self.label)

    def url_for(self, **kwargs):
        return self.url


@dataclass
class ParagraphWithLinks:
    paragraph: LazyString

    def __str__(self):
        return str(self.paragraph)

    @property
    def html(self):
        new_paragraph = copy.deepcopy(self.paragraph)

        for key, value in new_paragraph._kwargs.items():
            if hasattr(value, "url_for"):
                new_paragraph._kwargs[key] = (
                    f'<a href="{value.url_for(_mailCampaign=True)}" style="color: #000000; text-decoration: underline;">{escape(str(value))}</a>'
                )

        return str(new_paragraph)


@dataclass
class MailMessage:
    subject: LazyString
    paragraphs: list[LazyString | MailCTA | ParagraphWithLinks | LabelledContent | None]
    # Short, stable name for the dispatch audit line, for the mails whose
    # subject makes a poor label. Optional: derived from the subject's msgid
    # when left unset, which is fine for the subjects that are plain
    # sentences. Last, because the two fields above have no default.
    kind: str | None = None

    def __post_init__(self):
        self.paragraphs = [p for p in self.paragraphs if p is not None]

    def text(self, recipient) -> str:
        return render_template(
            "mail/message.txt",
            message=self,
            recipient=recipient,
        )

    def html(self, recipient) -> str:
        return render_template(
            "mail/message.html",
            message=self,
            recipient=recipient,
        )

    def send(self, recipients, reply_to: str | None = None):
        send_mail(recipients, self, reply_to=reply_to)


def init_app(app):
    mail.init_app(app)
    # See `audit_logger`: without its own level it would inherit the WARNING
    # that `init_logging` sets on the `udata` logger in production, and every
    # successful-dispatch line would be dropped before reaching the log file.
    audit_logger.setLevel(logging.INFO)


def send_mail(
    recipients: object | list,
    message: MailMessage,
    reply_to: str | None = None,
):
    # Security mails are sent via the Flask-Security package and not
    # from this function. Disabling mail sending logic is duplicated
    # in :DisableMail.
    # Flask-Security templates are rendered in `render_mail_template`.
    debug = current_app.config.get("DEBUG", False)
    send_mail = current_app.config.get("SEND_MAIL", not debug)

    if not isinstance(recipients, list):
        recipients = [recipients]

    # Derived once: the kind belongs to the message, not to the recipient.
    kind = mail_kind(message)

    for recipient in recipients:
        lang = i18n._default_lang(recipient)
        to = recipient if isinstance(recipient, str) else recipient.email
        with i18n.language(lang):
            msg = Message(
                subject=str(message.subject),
                body=message.text(recipient),
                html=message.html(recipient),
                recipients=[to],
                reply_to=reply_to,
            )

        if send_mail:
            try:
                with mail.connect() as conn:
                    conn.send(msg)
            except Exception as e:
                # A failed send used to leave no trace at all. Upstream #2840
                # once logged one here, but inside the loop and without
                # re-raising, so a single refused recipient did not stop the
                # rest; that guard is gone and this is NOT a restoration of it
                # — the exception is re-raised, matching what this branch has
                # done since. Swallowing it would make a failed send look
                # successful, and changing the multi-recipient semantics is
                # more than an audit trail should decide.
                log_mail_dispatch(kind, to, "error", error=e)
                raise
            log_mail_dispatch(kind, to, "sent")
        else:
            log.debug(f"Sending mail {message.subject} to {to}")
            log.debug(msg.body)
            log.debug(msg.html)
            mail_sent.send(msg)


def get_mail_campaign_dict() -> dict:
    """Return a dict with the `mtm_campaign` key set if there is a `MAIL_CAMPAIGN` configured in udata.cfg."""
    extras = {}
    mail_campaign = current_app.config.get("MAIL_CAMPAIGN")
    if mail_campaign:
        extras["mtm_campaign"] = mail_campaign
    return extras
