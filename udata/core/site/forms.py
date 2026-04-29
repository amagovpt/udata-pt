from udata.forms import Form, fields, validators
from udata.i18n import lazy_gettext as _

__all__ = ("SupportContactForm",)

SUPPORT_TOPIC_CHOICES = ("question", "bug", "feedback")
SUPPORT_SUBJECT_MAX = 200
SUPPORT_MESSAGE_MAX = 5000


class SupportContactForm(Form):
    """Validate the public support form payload before sending it as email.

    The form is anonymous: anyone can submit it, so we validate strictly to
    avoid abuse. Topic must be one of the three frontend toggles. Subject and
    message lengths are bounded to keep the resulting email a sensible size.
    """

    topic = fields.SelectField(
        _("Topic"),
        choices=[(c, c) for c in SUPPORT_TOPIC_CHOICES],
        validators=[validators.DataRequired()],
    )
    email = fields.StringField(
        _("Email"),
        validators=[validators.DataRequired(), validators.Email()],
    )
    subject = fields.StringField(
        _("Subject"),
        validators=[
            validators.DataRequired(),
            validators.Length(max=SUPPORT_SUBJECT_MAX),
        ],
    )
    message = fields.StringField(
        _("Message"),
        validators=[
            validators.DataRequired(),
            validators.Length(max=SUPPORT_MESSAGE_MAX),
        ],
    )
