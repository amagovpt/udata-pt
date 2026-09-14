import pytest

from udata.core.dataset.factories import DatasetFactory
from udata.core.discussions.factories import DiscussionFactory, MessageDiscussionFactory
from udata.core.discussions.models import Discussion
from udata.core.followers.models import Follow
from udata.core.organization.factories import OrganizationFactory
from udata.core.user.factories import UserFactory
from udata.core.user.models import User, find_user_by_email_ci
from udata.tests.api import APITestCase


class UserModelTest(APITestCase):
    def test_mark_as_deleted(self):
        user = UserFactory()
        other_user = UserFactory()
        org = OrganizationFactory(editors=[user])
        discussion = DiscussionFactory(
            user=user,
            subject=org,
            discussion=[
                MessageDiscussionFactory(posted_by=user),
                MessageDiscussionFactory(posted_by=user),
            ],
        )
        user_follow_org = Follow.objects.create(follower=user, following=org)
        user_followed = Follow.objects.create(follower=other_user, following=user)

        user.mark_as_deleted()

        org.reload()
        assert len(org.members) == 0

        # discussions are kept by default
        discussion.reload()
        assert len(discussion.discussion) == 2
        assert discussion.discussion[1].content != "DELETED"

        assert Follow.objects(id=user_follow_org.id).first() is None
        assert Follow.objects(id=user_followed.id).first() is None

        assert user.slug == f"deleted-{user.id}"

    def test_mark_as_deleted_with_comments_deletion(self):
        user = UserFactory()
        other_user = UserFactory()
        dataset = DatasetFactory(owner=user)
        discussion_only_user = DiscussionFactory(
            user=user,
            subject=dataset,
            discussion=[
                MessageDiscussionFactory(posted_by=user),
                MessageDiscussionFactory(posted_by=user),
            ],
        )
        discussion_with_other = DiscussionFactory(
            user=other_user,
            discussion=[
                MessageDiscussionFactory(posted_by=other_user),
                MessageDiscussionFactory(posted_by=user),
            ],
        )

        user.mark_as_deleted(delete_comments=True)

        assert Discussion.objects(id=discussion_only_user.id).first() is None
        discussion_with_other.reload()
        assert discussion_with_other.discussion[1].content == "DELETED"

    def test_mark_as_deleted_slug_multiple(self):
        user = UserFactory()
        other_user = UserFactory()

        user.mark_as_deleted()
        other_user.mark_as_deleted()

        assert user.slug == f"deleted-{user.id}"
        assert other_user.slug == f"deleted-{other_user.id}"

    def test_delete_safeguard(self):
        user = UserFactory()
        with pytest.raises(NotImplementedError):
            user.delete()
        user._delete()
        assert User.objects.filter(id=user.id).count() == 0


class FindUserByEmailCiTest(APITestCase):
    """The lookup every "does this address exist" check now goes through.

    Its whole reason to exist is the preference for the exact row: the unique
    index on User.email is case-sensitive, so two rows can answer to one
    address, and User orders by -created_at. A bare .first() would hand back
    whichever was created last -- which is what flask_security's own
    find_user(case_insensitive=True) still does.
    """

    def test_finds_a_row_whose_casing_differs(self):
        user = UserFactory(email="Maria@example.pt")
        assert find_user_by_email_ci("maria@example.pt") == user
        assert find_user_by_email_ci("MARIA@EXAMPLE.PT") == user

    def test_prefers_the_exact_row_over_the_newest(self):
        older = UserFactory(email="maria@example.pt")
        newer = UserFactory(email="Maria@example.pt")
        # Newest-first ordering means a bare .first() would return `newer`
        # for both spellings. Each caller gets the row they actually typed.
        assert find_user_by_email_ci("maria@example.pt") == older
        assert find_user_by_email_ci("Maria@example.pt") == newer

    def test_falls_back_to_the_newest_when_no_spelling_matches_exactly(self):
        UserFactory(email="maria@example.pt")
        newer = UserFactory(email="Maria@example.pt")
        # A third spelling matches neither exactly; the answer has to be
        # deterministic rather than arbitrary, and -created_at makes it so.
        assert find_user_by_email_ci("MARIA@example.pt") == newer

    def test_returns_none_for_an_unknown_or_empty_address(self):
        UserFactory(email="maria@example.pt")
        assert find_user_by_email_ci("someone.else@example.pt") is None
        assert find_user_by_email_ci("") is None
        assert find_user_by_email_ci(None) is None
