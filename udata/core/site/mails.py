from udata.i18n import lazy_gettext as _
from udata.mail import LabelledContent, MailMessage

# Maps the topic submitted by the support form to a human-readable subject prefix.
# Keep keys in sync with the frontend SupportPage toggles (question / bug / feedback).
SUPPORT_TOPIC_LABELS = {
    "question": _("Question"),
    "bug": _("Problem"),
    "feedback": _("Feedback"),
}


def support_contact(
    topic: str,
    sender_email: str,
    subject: str,
    message: str,
) -> MailMessage:
    """Mail composed when a portal visitor submits the support form."""
    topic_label = SUPPORT_TOPIC_LABELS.get(topic, _("Support"))
    return MailMessage(
        subject=_("[%(site)s] %(topic)s — %(subject)s", site="dados.gov.pt", topic=topic_label, subject=subject),
        paragraphs=[
            _("A portal visitor submitted the support form."),
            LabelledContent(_("Topic:"), str(topic_label), inline=True),
            LabelledContent(_("From:"), sender_email, inline=True),
            LabelledContent(_("Subject:"), subject, inline=True),
            LabelledContent(_("Message:"), message),
        ],
    )
