from udata.forms import Form, fields, validators
from udata.harvest.backends import get_backend, get_enabled_backends
from udata.i18n import lazy_gettext as _
from udata.utils import safe_unicode

from .models import VALIDATION_REFUSED, VALIDATION_STATES
from .url_filter import HarvestURLForbidden, check_harvest_url

__all__ = "HarvestSourceForm", "HarvestSourceValidationForm"


class HarvestURLField(fields.URLField):
    """`URLField` that gates the hostname against the harvest deny/allow list
    BEFORE the parent `pre_validate` triggers DNS resolution.

    Prevents the out-of-band DNS leak from VULN-2084 — a denied hostname
    never reaches `socket.getaddrinfo`.
    """

    def pre_validate(self, form):
        if self.data:
            try:
                check_harvest_url(self.data)
            except HarvestURLForbidden as e:
                raise validators.ValidationError(str(e))
        return super().pre_validate(form)


class HarvestConfigField(fields.DictField):
    """
    A DictField with extras validations on known configurations
    """

    def get_filter_specs(self, backend, key):
        candidates = (f for f in backend.filters if f.key == key)
        return next(candidates, None)

    def get_feature_specs(self, backend, key):
        candidates = (f for f in backend.features if f.key == key)
        return next(candidates, None)

    def get_extra_configs_specs(self, backend, key):
        candidates = (f for f in backend.extra_configs if f.key == key)
        return next(candidates, None)

    def pre_validate(self, form):
        if self.data:
            backend = get_backend(form.backend.data)
            if backend is None:
                return  # Should have been catch by the enum check for `form.backend`

            # Validate filters
            for f in self.data.get("filters") or []:
                if not ("key" in f and "value" in f):
                    msg = "A field should have both key and value properties"
                    raise validators.ValidationError(msg)
                specs = self.get_filter_specs(backend, f["key"])
                if not specs:
                    msg = 'Unknown filter key "{0}" for "{1}" backend'
                    msg = msg.format(f["key"], backend.name)
                    raise validators.ValidationError(msg)

                if isinstance(f["value"], str):
                    f["value"] = safe_unicode(f["value"])  # Fix encoding error

                if not isinstance(f["value"], specs.type):
                    msg = '"{0}" filter should of type "{1}"'
                    msg = msg.format(specs.key, specs.type.__name__)
                    raise validators.ValidationError(msg)

            # Validate extras configs
            for f in self.data.get("extra_configs") or []:
                if not ("key" in f and "value" in f):
                    msg = "A field should have both key and value properties"
                    raise validators.ValidationError(msg)
                specs = self.get_extra_configs_specs(backend, f["key"])
                if not specs:
                    msg = 'Unknown extra config key "{0}" for "{1}" backend'
                    msg = msg.format(f["key"], backend.name)
                    raise validators.ValidationError(msg)
                if not isinstance(f["value"], specs.type):
                    msg = '"{0}" extra config should be of type "{1}"'
                    msg = msg.format(specs.key, specs.type.__name__)
                    raise validators.ValidationError(msg)

            # Validate features
            for key, value in (self.data.get("features") or {}).items():
                if not isinstance(value, bool):
                    msg = "A feature should be a boolean"
                    raise validators.ValidationError(msg)
                if not self.get_feature_specs(backend, key):
                    msg = 'Unknown feature "{0}" for "{1}" backend'
                    msg = msg.format(key, backend.name)
                    raise validators.ValidationError(msg)


class HarvestSourceForm(Form):
    name = fields.StringField(_("Name"), [validators.DataRequired()])
    description = fields.MarkdownField(
        _("Description"), description=_("Some optional details about this harvester")
    )
    url = HarvestURLField(_("URL"), [validators.DataRequired()])
    backend = fields.SelectField(
        _("Backend"),
        choices=lambda: [(b.name, b.display_name) for b in get_enabled_backends().values()],
    )
    owner = fields.CurrentUserField()
    organization = fields.PublishAsField(_("Publish as"))
    active = fields.BooleanField()
    autoarchive = fields.BooleanField()

    config = HarvestConfigField()


class HarvestSourceValidationForm(Form):
    state = fields.SelectField(choices=list(VALIDATION_STATES.items()))
    comment = fields.StringField(
        _("Comment"), [validators.RequiredIfVal("state", VALIDATION_REFUSED)]
    )
