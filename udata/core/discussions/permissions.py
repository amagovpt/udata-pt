from udata.auth import Permission, UserNeed
from udata.core.dataset.permissions import OwnablePermission
from udata.core.organization.models import Organization
from udata.core.organization.permissions import (
    OrganizationAdminNeed,
    OrganizationEditorNeed,
)

from .models import Discussion, Message


def SubjectOwnerPermission(subject):
    """Who owns the thing a discussion is about.

    `OwnablePermission` answers this for every subject that carries an owner or an
    organization, which is every subject but one: an organization is the subject of the
    discussions held on its own page, and it has neither field -- it does not even derive
    from `Owned`. Reaching for `getattr(subject, "organization", None)` there would not
    degrade gracefully: `Permission` prepends `RoleNeed("admin")`, so a permission built
    with no needs at all is not "everyone", it is "sysadmins only", and the admins of the
    organization would quietly lose the right to moderate discussions on their own page.

    An organization owns itself, so it gets the needs `OwnablePermission` would compute
    for an asset it owns -- admin and editor, the editors included so they can moderate
    an organization's discussions exactly as they moderate its datasets'.
    """
    if isinstance(subject, Organization):
        return Permission(OrganizationAdminNeed(subject.id), OrganizationEditorNeed(subject.id))
    return OwnablePermission(subject)


# This is a hack to because double inheritance doesn't work really well with permissions.
# I simulate a class constructor with a function to keep the same API than other permissions
# but use the `.union()` of two permission under the hood.
def DiscussionAuthorOrSubjectOwnerPermission(discussion: Discussion):
    return SubjectOwnerPermission(discussion.subject).union(DiscussionAuthorPermission(discussion))


class DiscussionAuthorPermission(Permission):
    def __init__(self, discussion: Discussion):
        needs = []

        if discussion.organization:
            needs.append(OrganizationAdminNeed(discussion.organization.id))
            needs.append(OrganizationEditorNeed(discussion.organization.id))
        else:
            needs.append(UserNeed(discussion.user.fs_uniquifier))

        super(DiscussionAuthorPermission, self).__init__(*needs)


class DiscussionMessagePermission(Permission):
    def __init__(self, message: Message):
        needs = []

        if message.posted_by_organization:
            needs.append(OrganizationAdminNeed(message.posted_by_organization.id))
            needs.append(OrganizationEditorNeed(message.posted_by_organization.id))
        else:
            needs.append(UserNeed(message.posted_by.fs_uniquifier))

        super(DiscussionMessagePermission, self).__init__(*needs)
