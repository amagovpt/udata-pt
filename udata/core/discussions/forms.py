import bleach

from udata.forms import Form, ModelForm, fields, validators
from udata.i18n import lazy_gettext as _

from .constants import COMMENT_SIZE_LIMIT
from .models import Discussion

__all__ = ("DiscussionCreateForm", "DiscussionCommentForm")


def _sanitize_html(value):
    """Strip all HTML tags from a string to prevent XSS."""
    if value:
        return bleach.clean(value, tags=[], strip=True)
    return value


class DiscussionCreateForm(ModelForm):
    model_class = Discussion

    organization = fields.PublishAsField(_("Publish as"), owner_field=None)
    title = fields.StringField(_("Title"), [validators.DataRequired()])
    comment = fields.StringField(
        _("Comment"), [validators.DataRequired(), validators.Length(max=COMMENT_SIZE_LIMIT)]
    )
    subject = fields.ModelField(_("Subject"), [validators.DataRequired()])
    extras = fields.ExtrasField()

    def validate(self, **kwargs):
        self.title.data = _sanitize_html(self.title.data)
        self.comment.data = _sanitize_html(self.comment.data)
        return super().validate(**kwargs)


class DiscussionEditForm(ModelForm):
    model_class = Discussion

    title = fields.StringField(_("Title"), [validators.DataRequired()])

    def validate(self, **kwargs):
        self.title.data = _sanitize_html(self.title.data)
        return super().validate(**kwargs)


class DiscussionCommentForm(Form):
    organization = fields.PublishAsField(_("Publish as"), owner_field=None)

    comment = fields.StringField(_("Comment"), [validators.Length(max=COMMENT_SIZE_LIMIT)])
    close = fields.BooleanField(default=False)

    def validate(self, **kwargs):
        self.comment.data = _sanitize_html(self.comment.data)
        return super().validate(**kwargs)


class DiscussionEditCommentForm(Form):
    comment = fields.StringField(
        _("Comment"), [validators.DataRequired(), validators.Length(max=COMMENT_SIZE_LIMIT)]
    )

    def validate(self, **kwargs):
        self.comment.data = _sanitize_html(self.comment.data)
        return super().validate(**kwargs)
