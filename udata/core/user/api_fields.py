from flask import session

from udata.api import api, base_reference, fields
from udata.auth import current_user
from udata.auth.helpers import current_user_is_admin_or_self

from .constants import BIGGEST_AVATAR_SIZE


def _get_saml_login():
    """Return True if the current session was authenticated via SAML."""
    return session.get("saml_login", False)


def _get_asserted_email():
    """Return the address the SAML assertion carried, if this session has one.

    Only set while the caller still holds a placeholder email, and only by CMD
    -- the eIDAS Minimum Data Set has no email attribute, so an eIDAS session
    reaches the completion screen with nothing to offer.
    """
    return session.get("saml_asserted_email")


def _get_migration_invite(user) -> bool:
    """Whether this account is being offered the optional CMD/eIDAS link.

    The whole decision lives in the SAML plugin, next to the flags and the
    predicate it shares with the wizard, and is merely surfaced here. A second
    copy of the condition in the serializer is how the notice and the flow it
    starts end up disagreeing about who is invited.

    Imported inside the function because udata.auth.saml imports back into the
    user package, and this module is imported at API registration time.
    """
    from udata.auth.saml.saml_plugin.saml_govpt import _invite_offered_to

    return _invite_offered_to(user)


def _get_migration_link_available(user) -> bool:
    """Whether this account may still reach the linking flow at all.

    The sibling of _get_migration_invite, and the difference is one condition:
    this one ignores a dismissal. "Not now" must never mean "never let me", so
    the permanent way in stays while the notice is hidden -- otherwise the
    notice would have closed the door behind itself.
    """
    from udata.auth.saml.saml_plugin.saml_govpt import _link_available_to

    return _link_available_to(user)


def _is_current_user(user) -> bool:
    """True when the serialized user is the authenticated caller.

    Session-derived flags (like saml_login) only make sense for the caller's
    own account: on any other user they would leak the *viewer's* session
    state, which is meaningless and misleading.
    """
    return current_user.is_authenticated and current_user.id == user.id


def _count_user_datasets(user) -> int:
    """Live count of all non-deleted, non-archived datasets owned by the user.

    Includes drafts (private=True) so that admin users see the full count of
    all active datasets regardless of publication state.
    """
    from udata.models import Dataset  # avoid circular imports

    return Dataset.objects(owner=user, deleted=None, archived=None).count()


def _count_user_reuses(user) -> int:
    """Live count of a user's non-private, non-archived, non-deleted reuses.

    Computed directly from MongoDB on every request so that the admin user
    listing is always accurate, regardless of whether the pre-computed
    metrics dict has been refreshed by the signal pipeline.
    """
    from udata.models import Reuse  # avoid circular imports

    return Reuse.objects(owner=user, private__ne=True, archived=None, deleted=None).count()


user_ref_fields = api.inherit(
    "UserReference",
    base_reference,
    {
        "first_name": fields.String(description="The user first name", readonly=True),
        "last_name": fields.String(description="The user larst name", readonly=True),
        "slug": fields.String(description="The user permalink string", readonly=True),
        "uri": fields.String(
            attribute=lambda u: u.self_api_url(),
            description="The API URI for this user",
            readonly=True,
        ),
        "page": fields.String(
            attribute=lambda u: u.self_web_url(),
            description="The user web page URL",
            readonly=True,
        ),
        "avatar": fields.ImageField(original=True, description="The user avatar URL"),
        "avatar_thumbnail": fields.ImageField(
            attribute="avatar",
            size=BIGGEST_AVATAR_SIZE,
            description="The user avatar thumbnail URL. This is the square "
            "({0}x{0}) and cropped version.".format(BIGGEST_AVATAR_SIZE),
        ),
    },
)

from udata.core.organization.api_fields import member_email_with_visibility_check, org_ref_fields  # noqa

user_fields = api.model(
    "User",
    {
        "id": fields.String(description="The user identifier", readonly=True),
        "slug": fields.String(description="The user permalink string", readonly=True),
        "first_name": fields.String(description="The user first name", required=True),
        "last_name": fields.String(description="The user last name", required=True),
        "email": fields.Raw(
            attribute=lambda o: o.email if current_user_is_admin_or_self() else None,
            description="The user email",
            readonly=True,
        ),
        # In user_fields (not the unused me_fields) because GET /api/1/me/
        # marshals user_fields; only meaningful for the caller's own session,
        # so it is null on any other user.
        "saml_login": fields.Raw(
            attribute=lambda o: _get_saml_login() if _is_current_user(o) else None,
            description="Whether the current session was authenticated via SAML "
            "(only present on the caller's own user, e.g. /me)",
            readonly=True,
        ),
        # In user_fields (not the unused me_fields) because GET /api/1/me/
        # marshals user_fields; guarded like email so public user listings
        # never disclose which accounts still hold a placeholder email.
        "pending_registration": fields.Raw(
            attribute=lambda o: (
                o.has_placeholder_email if current_user_is_admin_or_self() else None
            ),
            description="True while the account still has a minted saml-* placeholder "
            "email; the user must provide a real email to complete registration "
            "(only present for global admins and on /me)",
            readonly=True,
        ),
        # Guarded by _is_current_user and NOT by current_user_is_admin_or_self,
        # which the sibling pending_registration above uses. The difference
        # matters because this value comes from the *session*, not from the
        # document: under the admin guard, an admin listing users would see
        # their own session's address stamped onto every row they may see.
        # Nulled once the placeholder is gone, so it cannot outlive the screen
        # it exists for -- an association leaves the session key behind, and
        # this is what stops it being served afterwards.
        "pending_registration_email": fields.Raw(
            attribute=lambda o: (
                _get_asserted_email() if _is_current_user(o) and o.has_placeholder_email else None
            ),
            description="The email address the CMD assertion carried, offered as a "
            "prefill on the registration completion screen. Null for eIDAS (the "
            "Minimum Data Set has no email attribute), for a CMD assertion that "
            "carried none, and on any user other than the caller",
            readonly=True,
        ),
        # The optional CMD/eIDAS linking invite, decided here and never in the
        # browser. That is not a style preference: the frontend reading a
        # migration flag is what removed the sign-in form from production
        # (LEDG-2432), and nothing observable in a rendered page distinguishes
        # "the backend said so" from "we guessed from configuration".
        #
        # It rides /me rather than /saml/migration/check because that
        # endpoint's `needs_migration` means MANDATORY, and the frontend logs
        # the user out when it is true -- which would sign people out of a
        # notice they are allowed to dismiss.
        #
        # Guarded by _is_current_user like saml_login, not by the admin guard:
        # whether somebody has linked an identity is not a listing column.
        "migration_invite": fields.Raw(
            attribute=lambda o: _get_migration_invite(o) if _is_current_user(o) else None,
            description="True when this account is being invited (optionally) to link a "
            "CMD/eIDAS identity: the invite is enabled, linking is not mandatory, the "
            "account signs in with a password and holds no identity yet, and the invite "
            "has not been dismissed recently. Only present on the caller's own user",
            readonly=True,
        ),
        # The permanent way in, as opposed to the notice above. Same guard,
        # same reason; the difference is that this one survives a dismissal,
        # because dismissing is "not now" and never "never let me".
        "migration_link_available": fields.Raw(
            attribute=lambda o: _get_migration_link_available(o) if _is_current_user(o) else None,
            description="True when this account can still link a CMD/eIDAS identity: the "
            "invite is enabled, linking is not mandatory, and the account signs in with a "
            "password and holds no identity yet. Unlike migration_invite this stays true "
            "after the notice has been dismissed, so the entry point in the profile does "
            "not disappear with it. Only present on the caller's own user",
            readonly=True,
        ),
        "avatar": fields.ImageField(original=True, description="The user avatar URL"),
        "avatar_thumbnail": fields.ImageField(
            attribute="avatar",
            size=BIGGEST_AVATAR_SIZE,
            description="The user avatar thumbnail URL. This is the square "
            "({0}x{0}) and cropped version.".format(BIGGEST_AVATAR_SIZE),
        ),
        "website": fields.String(description="The user website"),
        "about": fields.Markdown(description="The user self description"),
        "roles": fields.List(
            fields.String,
            attribute=lambda o: [r.name for r in (o.roles or [])],
            description="Site wide user roles",
        ),
        "active": fields.Boolean(),
        "organizations": fields.List(
            fields.Nested(org_ref_fields), description="The organization the user belongs to"
        ),
        "since": fields.ISODateTime(
            attribute="created_at", description="The registeration date", required=True
        ),
        "last_login_at": fields.Raw(
            attribute=lambda o: o.current_login_at if current_user_is_admin_or_self() else None,
            description="The user last connection date (only present for global admins and on /me)",
            readonly=True,
        ),
        "uri": fields.String(
            attribute=lambda u: u.self_api_url(),
            description="The API URI for this user",
            readonly=True,
        ),
        "page": fields.String(
            attribute=lambda u: u.self_web_url(),
            description="The user web page URL",
            readonly=True,
        ),
        "metrics": fields.Raw(
            attribute=lambda o: o.get_metrics(), description="The user metrics", readonly=True
        ),
        # Flat counts consumed by the admin user listing column renderers in the
        # frontend (LEDG-1763). Computed live from MongoDB so the values are
        # always accurate regardless of whether the pre-computed metrics dict
        # has been refreshed.
        "datasets_count": fields.Integer(
            attribute=lambda o: _count_user_datasets(o),
            description="Number of visible datasets owned by the user (live count).",
            readonly=True,
        ),
        "reuses_count": fields.Integer(
            attribute=lambda o: _count_user_reuses(o),
            description="Number of reuses owned by the user (live count).",
            readonly=True,
        ),
    },
)

# NOTE: currently unused — GET /api/1/me/ marshals user_fields, so anything
# meant to appear on /me must live there (guarded). Kept only for the swagger
# model; marshalling this on GET would also expose apikey on every /me poll.
me_fields = api.inherit(
    "Me",
    user_fields,
    {
        "apikey": fields.String(description="The user API Key", readonly=True),
    },
)

me_metrics_fields = api.model(
    "MyMetrics",
    {
        "id": fields.String(description="The user identifier", required=True),
        "resources_availability": fields.Float(
            description="The user's resources availability percentage", readonly=True
        ),
        "datasets_org_count": fields.Integer(
            description="The user's orgs datasets number", readonly=True
        ),
        "followers_org_count": fields.Integer(
            description="The user's orgs followers number", readonly=True
        ),
        "datasets_count": fields.Integer(description="The user's datasets number", readonly=True),
        "followers_count": fields.Integer(description="The user's followers number", readonly=True),
    },
)

apikey_fields = api.model(
    "ApiKey",
    {
        "apikey": fields.String(description="The user API Key", readonly=True),
    },
)

user_page_fields = api.model("UserPage", fields.pager(user_fields))

user_suggestion_fields = api.model(
    "UserSuggestion",
    {
        "id": fields.String(description="The user identifier", readonly=True),
        "first_name": fields.String(description="The user first name", readonly=True),
        "last_name": fields.String(description="The user last name", readonly=True),
        "avatar_url": fields.ImageField(
            size=BIGGEST_AVATAR_SIZE, description="The user avatar URL", readonly=True
        ),
        "email": fields.Raw(
            attribute=lambda o: member_email_with_visibility_check(o["email"]),
            description="The user email (only the domain for non-admin user)",
            readonly=True,
        ),
        "slug": fields.String(description="The user permalink string", readonly=True),
    },
)

notifications_fields = api.model(
    "Notification",
    {
        "type": fields.String(description="The notification type", readonly=True),
        "created_on": fields.ISODateTime(
            description="The notification creation datetime", readonly=True
        ),
        "details": fields.Raw(
            description="Key-Value details depending on notification type", readonly=True
        ),
    },
)


user_role_fields = api.model(
    "UserRole",
    {
        "name": fields.String(description="The role name", readonly=True),
    },
)
