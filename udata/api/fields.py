import datetime
import inspect
import logging
from datetime import UTC

from dateutil.parser import parse
from flask import request, url_for

# Explicitly import all of flask_restx fields so they're available throughout the codebase as api.fields
from flask_restx.fields import Arbitrary as Arbitrary
from flask_restx.fields import Boolean as Boolean
from flask_restx.fields import ClassName as ClassName
from flask_restx.fields import Date as Date
from flask_restx.fields import DateTime as DateTime
from flask_restx.fields import Fixed as Fixed
from flask_restx.fields import Float as Float
from flask_restx.fields import FormattedString as FormattedString
from flask_restx.fields import Integer as Integer
from flask_restx.fields import List as List
from flask_restx.fields import MarshallingError as MarshallingError
from flask_restx.fields import MinMaxMixin as MinMaxMixin
from flask_restx.fields import Nested as Nested
from flask_restx.fields import NumberMixin as NumberMixin
from flask_restx.fields import Polymorph as Polymorph
from flask_restx.fields import Raw as Raw
from flask_restx.fields import String as String
from flask_restx.fields import StringMixin as StringMixin
from flask_restx.fields import Url as Url
from flask_restx.fields import Wildcard as Wildcard
from flask_restx.fields import get_value as get_value
from mongoengine.errors import DoesNotExist

from udata.utils import multi_to_dict

log = logging.getLogger(__name__)

# Extract Flask's url_for() reserved arguments dynamically to filter from user-provided query params
URL_FOR_RESERVED_ARGS = {
    name
    for name, param in inspect.signature(url_for).parameters.items()
    if param.kind in (inspect.Parameter.KEYWORD_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    and name != "values"
}


class ISODateTime(String):
    __schema_format__ = "date-time"

    def format(self, value):
        if isinstance(value, str):
            value = parse(value)
        if (
            isinstance(value, datetime.date)
            and not isinstance(value, datetime.datetime)
            or (isinstance(value, datetime.datetime) and value.tzinfo)
        ):
            return value.isoformat()
        # If naive datetime, localize it to UTC
        if isinstance(value, datetime.datetime) and not value.tzinfo:
            return value.replace(tzinfo=UTC).isoformat()
        return value.isoformat()


class Markdown(String):
    __schema_format__ = "markdown"


class Permission(Boolean):
    def __init__(self, mapper=None, **kwargs):
        super(Permission, self).__init__(**kwargs)

    def format(self, field):
        return field.can()


class TolerantNested(Nested):
    """A `Nested` that serves a dangling reference as null instead of failing.

    A `ReferenceField` whose target was removed from the database raises
    `DoesNotExist` the moment it is dereferenced, and marshalling dereferences
    it: one such document takes down the whole response — the listing it
    belongs to, not just its own entry — with a 500 carrying no body, which a
    proxy in front reports as a 502.

    It has to override `output` rather than `format`, because the failure
    happens while the value is being resolved: `Nested.output` goes through
    `get_value` -> `_get_value_for_key` -> `obj[key]`, and the `except` around
    that only swallows `IndexError`, `TypeError` and `KeyError`, so mongoengine's
    lazy-dereference error escapes long before `format` could see it.

    Only the resolution is guarded, deliberately. Wrapping the whole of
    `super().output()` would also swallow a `DoesNotExist` raised from inside
    the nested model — `QuerySet.get()` raises the same class — and turn a real
    bug in one endpoint into a silent `null` that matches nothing anywhere else.

    Same trade as `udata.core.activity.api`, which filters dangling references
    out of the activity feed: answer with what is readable and log the rest for
    Sentry, rather than fail whole. The difference is granularity — there the
    item is dropped, here only the field is nulled, because the document around
    it is intact and has to stay in the listing.
    """

    def __init__(self, model, **kwargs):
        if not kwargs.get("allow_null"):
            raise ValueError(
                "TolerantNested serves null when a reference does not resolve, so it has to "
                "be declared allow_null=True — otherwise its own schema promises an object "
                "it will sometimes refuse to produce, and every client generated from that "
                "schema is wrong about it."
            )
        super(TolerantNested, self).__init__(model, **kwargs)

    def output(self, key, obj, **kwargs):
        try:
            get_value(key if self.attribute is None else self.attribute, obj)
        except DoesNotExist as e:
            # Named, because the bare mongoengine message carries only the id of
            # the document that is *gone*. Whoever reads this has to find the one
            # that is still here and still pointing at it.
            log.error(
                "Dangling reference at %s.%s on %s: %s",
                type(obj).__name__,
                key,
                getattr(obj, "id", None),
                e,
                exc_info=True,
            )
            return None
        return super(TolerantNested, self).output(key, obj, **kwargs)


class NextPageUrl(String):
    def output(self, key, obj, **kwargs):
        if not getattr(obj, "has_next", None):
            return None
        args = multi_to_dict(request.args)
        args.update(request.view_args)
        args["page"] = obj.page + 1
        for reserved in URL_FOR_RESERVED_ARGS:
            args.pop(reserved, None)
        return url_for(request.endpoint, _external=True, **args)


class PreviousPageUrl(String):
    def output(self, key, obj, **kwargs):
        if not getattr(obj, "has_prev", None):
            return None
        args = multi_to_dict(request.args)
        args.update(request.view_args)
        args["page"] = obj.page - 1
        for reserved in URL_FOR_RESERVED_ARGS:
            args.pop(reserved, None)
        return url_for(request.endpoint, _external=True, **args)


class ImageField(String):
    def __init__(self, size=None, original=False, **kwargs):
        super(ImageField, self).__init__(**kwargs)
        self.original = original
        self.size = size

    def format(self, field):
        if not field:
            return
        elif self.original:
            return field.fs.url(field.original, external=True)
        elif self.size:
            return field(self.size, external=True)
        else:
            # This will respect max_size if defined
            return field.fs.url(field.filename, external=True)


def pager(page_fields):
    pager_fields = {
        "data": List(Nested(page_fields), attribute="objects", description="The page data"),
        "page": Integer(description="The current page", required=True, min=1),
        "page_size": Integer(description="The page size used for pagination", required=True, min=0),
        "total": Integer(description="The total paginated items", required=True, min=0),
        "next_page": NextPageUrl(description="The next page URL if exists"),
        "previous_page": PreviousPageUrl(description="The previous page URL if exists"),
    }
    return pager_fields


def search_pager(page_fields):
    """Pager with facets for search endpoints."""
    pager_fields = pager(page_fields)
    pager_fields["facets"] = Raw(
        description="Facets/aggregations for filtering", attribute="facets"
    )
    return pager_fields
