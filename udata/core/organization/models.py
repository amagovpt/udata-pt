from datetime import UTC, datetime
from itertools import chain

from blinker import Signal
from flask import url_for
from flask_babel import LazyString
from flask_storage.mongo import ImageField
from mongoengine import EmbeddedDocument
from mongoengine.errors import ValidationError
from mongoengine.fields import (
    DateTimeField,
    EmbeddedDocumentField,
    GenericEmbeddedDocumentField,
    GenericReferenceField,
    ListField,
    MapField,
    ReferenceField,
    StringField,
)
from mongoengine.signals import post_save, pre_save
from werkzeug.utils import cached_property

from udata.api_fields import field, generate_fields
from udata.core.activity.models import Auditable
from udata.core.badges.models import Badge, BadgeMixin, BadgesList
from udata.core.linkable import Linkable
from udata.core.metrics.helpers import get_stock_metrics
from udata.core.metrics.models import WithMetrics
from udata.core.storages import avatars, default_image_basename
from udata.core.utils.sanitization import sanitize_markdown_html
from udata.frontend.markdown import mdstrip
from udata.i18n import lazy_gettext as _
from udata.mongo.datetime_fields import Datetimed
from udata.mongo.document import UDataDocument as Document
from udata.mongo.extras_fields import OrganizationExtrasField
from udata.mongo.queryset import UDataQuerySet
from udata.mongo.slug_fields import SlugField
from udata.mongo.url_field import URLField
from udata.mongo.uuid_fields import AutoUUIDField
from udata.uris import cdata_url

from .constants import (
    ASSIGNABLE_OBJECT_TYPES,
    ASSOCIATION,
    BIGGEST_LOGO_SIZE,
    CERTIFIED,
    COMPANY,
    DEFAULT_ROLE,
    LOCAL_AUTHORITY,
    LOGO_MAX_SIZE,
    LOGO_SIZES,
    MEMBERSHIP_STATUS,
    ORG_BID_SIZE_LIMIT,
    ORG_ROLES,
    PUBLIC_SERVICE,
    REQUEST_TYPES,
)

__all__ = ("Organization", "Team", "Member", "MembershipRequest")

BADGES: dict[str, LazyString] = {
    PUBLIC_SERVICE: _("Public Service"),
    CERTIFIED: _("Certified"),
    ASSOCIATION: _("Association"),
    COMPANY: _("Company"),
    LOCAL_AUTHORITY: _("Local authority"),
}


@generate_fields()
class Team(EmbeddedDocument):
    name = StringField(required=True)
    slug = SlugField(max_length=255, required=True, populate_from="name", update=True, unique=False)
    description = StringField()

    members = ListField(ReferenceField("User"))


@generate_fields()
class Member(EmbeddedDocument):
    user = ReferenceField("User")
    role = StringField(choices=list(ORG_ROLES), default=DEFAULT_ROLE)
    since = DateTimeField(default=lambda: datetime.now(UTC), required=True)

    @property
    def label(self):
        return ORG_ROLES[self.role]


@generate_fields()
class MembershipRequest(EmbeddedDocument):
    """
    Pending organization membership requests or invitations.

    For requests (user asks to join):
        - kind = "request"
        - user = the requesting user
        - created_by = None

    For invitations (org invites user):
        - kind = "invitation"
        - user = the invited user (or None if email invitation)
        - email = email for non-registered users
        - created_by = admin who created the invitation
    """

    id = AutoUUIDField()
    user = ReferenceField("User")
    status = StringField(choices=list(MEMBERSHIP_STATUS), default="pending")

    created = DateTimeField(default=lambda: datetime.now(UTC), required=True)

    handled_on = DateTimeField()
    handled_by = ReferenceField("User")

    comment = StringField()
    refusal_comment = StringField()

    # New fields for invitation support
    kind = StringField(choices=list(REQUEST_TYPES), default="request")
    email = StringField()  # For inviting non-registered users by email
    created_by = ReferenceField("User")  # Admin who created the invitation
    role = StringField(choices=list(ORG_ROLES), default=DEFAULT_ROLE)
    assignments = ListField(GenericReferenceField(choices=ASSIGNABLE_OBJECT_TYPES))

    after_create = Signal()
    after_handle = Signal()

    @property
    def status_label(self):
        return MEMBERSHIP_STATUS[self.status]


class OrganizationQuerySet(UDataQuerySet):
    def visible(self):
        return self(deleted=None)

    def hidden(self):
        return self(deleted__ne=None)

    def get_by_id_or_slug(self, id_or_slug):
        return self(slug=id_or_slug).first() or self(id=id_or_slug).first()

    def with_badge(self, kind):
        return self(badges__kind=kind)


# Uses __badges__ (not available_badges) so that existing badges in DB
# remain valid even if they are hidden via settings.
# Uses a standalone function (not a model method) because OrganizationBadge is
# defined before Organization in the file — Organization is resolved lazily at call time.
def validate_badge(value):
    if value not in Organization.__badges__.keys():
        raise ValidationError("Unknown badge type")


class OrganizationBadge(Badge):
    kind = StringField(required=True, validation=validate_badge)


class OrganizationBadgeMixin(BadgeMixin):
    badges = field(
        BadgesList(OrganizationBadge), show_as_ref=True, **BadgeMixin.default_badges_list_params
    )
    __badges__ = BADGES


@generate_fields()
class Organization(
    Auditable,
    WithMetrics,
    OrganizationBadgeMixin,
    Linkable,
    Datetimed,
    Document[OrganizationQuerySet],
):
    name = field(StringField(required=True), show_as_ref=True)
    acronym = field(StringField(max_length=128), show_as_ref=True)
    slug = field(
        SlugField(max_length=255, required=True, populate_from="name", update=True, follow=True),
        auditable=False,
        show_as_ref=True,
    )
    description = field(
        StringField(required=True),
        markdown=True,
    )
    url = field(URLField())
    image_url = field(StringField())
    logo = field(
        ImageField(
            fs=avatars,
            basename=default_image_basename,
            max_size=LOGO_MAX_SIZE,
            thumbnails=LOGO_SIZES,
        ),
        show_as_ref=True,
        thumbnail_info={
            "size": BIGGEST_LOGO_SIZE,
        },
    )
    business_number_id = field(StringField(max_length=ORG_BID_SIZE_LIMIT))

    members = field(ListField(EmbeddedDocumentField(Member)))
    teams = field(ListField(EmbeddedDocumentField(Team)))
    requests = field(ListField(EmbeddedDocumentField(MembershipRequest)))

    ext = field(MapField(GenericEmbeddedDocumentField()))
    zone = field(StringField())
    extras = field(OrganizationExtrasField(), auditable=False)

    deleted = field(DateTimeField())

    meta = {
        "indexes": [
            {"fields": ["$name", "$description", "$acronym"]},
            "created_at",
            "slug",
            "metrics.reuses",
            "metrics.datasets",
            "metrics.followers",
            "metrics.views",
            "last_modified",
        ],
        "ordering": ["-created_at"],
        "queryset_class": OrganizationQuerySet,
        "auto_create_index_on_save": True,
    }

    verbose_name = _("organization")

    def __str__(self):
        return self.name or ""

    @property
    def permissions(self):
        from .permissions import EditOrganizationPermission, OrganizationPrivatePermission

        return {
            "edit": EditOrganizationPermission(self),
            "delete": EditOrganizationPermission(self),
            "members": EditOrganizationPermission(self),
            "harvest": EditOrganizationPermission(self),
            "private": OrganizationPrivatePermission(self),
        }

    __metrics_keys__ = [
        "dataservices",
        "dataservices_by_months",
        "datasets",
        "datasets_by_months",
        "datasets_followers_by_months",
        "datasets_reuses_by_months",
        "discussions",
        "discussions_open",
        "members",
        "reuses",
        "reuses_by_months",
        "reuses_followers_by_months",
        "followers",
        "views",
        "resource_downloads",
        "reuse_views",
        "dataservice_views",
    ]

    before_save = Signal()
    after_save = Signal()
    on_create = Signal()
    on_update = Signal()
    before_delete = Signal()
    after_delete = Signal()
    on_delete = Signal()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.compute_aggregate_metrics = True

    @classmethod
    def pre_save(cls, sender, document, **kwargs):
        # VULN-2075: defense-in-depth sanitization for any write path
        # (forms, api_fields.patch, direct ORM writes, harvesters).
        if document.description:
            document.description = sanitize_markdown_html(document.description)
        cls.before_save.send(document)

    def self_web_url(self, **kwargs):
        return cdata_url(f"/organizations/{self._link_id(**kwargs)}", **kwargs)

    def self_api_url(self, **kwargs):
        return url_for(
            "api.organization", org=self._link_id(**kwargs), **self._self_api_url_kwargs(**kwargs)
        )

    @property
    def pending_requests(self):
        return [r for r in self.requests if r.status == "pending"]

    @property
    def refused_requests(self):
        return [r for r in self.requests if r.status == "refused"]

    @property
    def accepted_requests(self):
        return [r for r in self.requests if r.status == "accepted"]

    @property
    def certified(self):
        return any(b.kind == CERTIFIED for b in self.badges)

    @property
    def public_service(self):
        is_public_service = any(b.kind == PUBLIC_SERVICE for b in self.badges)
        return self.certified and is_public_service

    @property
    def company(self):
        return any(b.kind == COMPANY for b in self.badges)

    @property
    def association(self):
        return any(b.kind == ASSOCIATION for b in self.badges)

    @property
    def local_authority(self):
        return any(b.kind == LOCAL_AUTHORITY for b in self.badges)

    def set_badges(self, kinds):
        """Replace badges with the given kinds (site-admin API use)."""
        from udata.auth import current_user

        seen = set()
        ordered_kinds = []
        for kind in kinds:
            if kind not in seen:
                if kind not in self.available_badges():
                    msg = "Unknown badge type for {model}: {kind}"
                    raise ValidationError(msg.format(model=self.__class__.__name__, kind=kind))
                seen.add(kind)
                ordered_kinds.append(kind)

        existing_by_kind = {badge.kind: badge for badge in self.badges}
        new_badges = []
        for kind in ordered_kinds:
            if kind in existing_by_kind:
                new_badges.append(existing_by_kind[kind])
                continue
            badge = self._fields["badges"].field.document_type(kind=kind)
            if current_user and current_user.is_authenticated:
                badge.created_by = current_user.id
            new_badges.append(badge)

        self.badges = new_badges
        self.save()

    def member(self, user):
        for member in self.members:
            if member.user == user:
                return member
        return None

    def is_member(self, user):
        return self.member(user) is not None

    def is_admin(self, user):
        member = self.member(user)
        return member is not None and member.role == "admin"

    def is_last_admin(self, user):
        """True when `user` is the only member holding the admin role.

        An organisation without an administrator is stuck: nobody can manage
        members, accept transfers or edit it, and -- the part that makes it
        expensive -- it cannot promote anyone from the inside, so recovering
        needs a sysadmin.

        Lives on the model rather than in the API because it is a question
        about the organisation, not about one request: the account-deletion
        paths orphan organisations too, and when their behaviour is decided
        they have to ask the same question rather than restate the rule.

        Deliberately false for an organisation that already has no admin at
        all: refusing there would freeze an organisation that is already
        stuck, over an operation that cannot make it worse.
        """
        return self.is_admin(user) and not any(
            member.user != user and member.role == "admin" for member in self.members
        )

    def pending_request(self, user):
        for request in self.requests:
            if (
                request.user == user
                and request.status == "pending"
                and request.kind != "invitation"
            ):
                return request
        return None

    @field(description="Link to the API endpoint for this organization", show_as_ref=True)
    def uri(self, *args, **kwargs):
        return self.self_api_url(*args, **kwargs)

    @field(description="Link to the udata web page for this organization", show_as_ref=True)
    def page(self, *args, **kwargs):
        return self.self_web_url(*args, **kwargs)

    @classmethod
    def get(cls, id_or_slug):
        obj = cls.objects(slug=id_or_slug).first()
        return obj or cls.objects.get_or_404(id=id_or_slug)

    def by_role(self, role):
        return filter(lambda m: m.role == role, self.members)

    def check_availability(self):
        from udata.models import Dataset  # Circular imports.

        # Performances: only check the first 20 datasets for now.
        return chain(
            *[
                dataset.check_availability()
                for dataset in Dataset.objects(organization=self).visible()[:20]
            ]
        )

    @cached_property
    def json_ld(self):
        type_ = "GovernmentOrganization" if self.public_service else "Organization"

        result = {
            "@context": "http://schema.org",
            "@type": type_,
            "@id": str(self.id),
            "alternateName": self.slug,
            "url": self.url_for(),
            "name": self.name,
            "dateCreated": self.created_at.isoformat(),
            "dateModified": self.last_modified.isoformat(),
        }

        if self.description:
            result["description"] = mdstrip(self.description)

        logo = self.logo(external=True)
        if logo:
            result["logo"] = logo

        return result

    @property
    def views_count(self):
        return self.metrics.get("views", 0)

    def add_membership_request(self, membership_request):
        self.requests.append(membership_request)
        self.save()
        MembershipRequest.after_create.send(membership_request, org=self)

    def _save_metrics(self, **values):
        """Persist the named metrics, and nothing else.

        These counts are recomputed whenever a dataset, reuse, dataservice,
        follower, discussion or member of this organisation changes — none of
        which is someone editing the organisation. They used to be persisted
        with `save()`, which runs the `Datetimed` pre_save hook; that hook
        stamps `last_modified` unless the field is already marked as changed,
        so every recount moved the date the organisation's card shows and the
        listing sorts by. The date tracked activity around the organisation
        rather than changes to it.

        Writing the counters directly keeps `last_modified` out of the update
        entirely, so the hook never runs and the date cannot be rewritten from
        this instance either.

        Assigned one key at a time, and that is load-bearing twice over. The
        write must be per key because these recounts run from instances that may
        have been loaded long before — the DCAT harvester collects organisations
        for the length of a crawl and counts them at the end — and a wholesale
        write would roll back counters another process set meanwhile, or drop
        keys this instance never loaded. And the *assignment* must be per key
        too: `dict.update` marks the whole `metrics` field as changed, so a later
        `save()` on this same instance would write the dict in one piece and lose
        those counters anyway — the same defect, moved one step later. Assigning
        the key marks `metrics.<key>`, which is what `save()` did before this
        method existed. Same shape as `udata.core.metrics.tasks`, which writes
        `set__metrics__<key>` for the view and download counters.

        Unlike `save()`, this does not emit `post_save`, so it does not queue a
        search reindex. That matches `udata.core.metrics.tasks`, whose counter
        writes never reindexed either: counts in the search index now refresh
        on a real edit or a full reindex, not on every recount.
        """
        for key, value in values.items():
            self.metrics[key] = value
        Organization.objects(id=self.id).update(
            **{f"set__metrics__{key}": value for key, value in values.items()}
        )

    def count_members(self):
        self._save_metrics(members=len(self.members))

    def count_datasets(self):
        from udata.models import Dataset, Follow, Reuse

        values = {"datasets": Dataset.objects(organization=self).visible().count()}
        if self.compute_aggregate_metrics:
            values["datasets_by_months"] = get_stock_metrics(
                Dataset.objects(organization=self).visible(), date_label="created_at_internal"
            )
            values["datasets_followers_by_months"] = get_stock_metrics(
                Follow.objects(following__in=Dataset.objects(organization=self)), date_label="since"
            )
            values["datasets_reuses_by_months"] = get_stock_metrics(
                Reuse.objects(datasets__in=Dataset.objects(organization=self)).visible()
            )

        self._save_metrics(**values)

    def count_reuses(self):
        from udata.models import Follow, Reuse

        self._save_metrics(
            reuses=Reuse.objects(organization=self).visible().count(),
            reuses_by_months=get_stock_metrics(Reuse.objects(organization=self).visible()),
            reuses_followers_by_months=get_stock_metrics(
                Follow.objects(following__in=Reuse.objects(organization=self)), date_label="since"
            ),
        )

    def count_dataservices(self):
        from udata.models import Dataservice

        self._save_metrics(
            dataservices=Dataservice.objects(organization=self).visible().count(),
            dataservices_by_months=get_stock_metrics(
                Dataservice.objects(organization=self).visible(), date_label="created_at"
            ),
        )

    def count_followers(self):
        from udata.models import Follow

        self._save_metrics(followers=Follow.objects(until=None).followers(self).count())

    def count_discussions(self):
        from udata.models import Discussion

        self._save_metrics(
            discussions=Discussion.objects(subject=self).count(),
            discussions_open=Discussion.objects(subject=self, closed=None).count(),
        )


pre_save.connect(Organization.pre_save, sender=Organization)
post_save.connect(Organization.post_save, sender=Organization)
