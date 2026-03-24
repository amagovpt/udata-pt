import pytest

from udata.core.organization.factories import OrganizationFactory
from udata.core.organization.models import Member, MembershipRequest
from udata.core.organization.tasks import (
    notify_membership_request,
    notify_membership_response,
    notify_new_member,
)
from udata.core.user.factories import UserFactory
from udata.tests.api import APITestCase
from udata.tests.helpers import capture_mails


class OrganizationMembershipMailTest(APITestCase):
    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_membership_request_mail_sent_to_admins(self):
        """Membership request should send mail to all org admins."""
        admin1 = UserFactory()
        admin2 = UserFactory()
        editor = UserFactory()
        requester = UserFactory()
        org = OrganizationFactory(
            members=[
                Member(user=admin1, role="admin"),
                Member(user=admin2, role="admin"),
                Member(user=editor, role="editor"),
            ]
        )
        request = MembershipRequest(user=requester, comment="Please let me join")
        org.requests.append(request)
        org.save()

        with capture_mails() as mails:
            notify_membership_request(str(org.id), str(request.id))

        assert len(mails) == 2
        recipients = {m.recipients[0] for m in mails}
        assert admin1.email in recipients
        assert admin2.email in recipients
        assert editor.email not in recipients

    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_membership_request_mail_content(self):
        """Membership request mail should contain the request comment."""
        admin = UserFactory()
        requester = UserFactory()
        org = OrganizationFactory(members=[Member(user=admin, role="admin")])
        request = MembershipRequest(user=requester, comment="I would like to contribute data")
        org.requests.append(request)
        org.save()

        with capture_mails() as mails:
            notify_membership_request(str(org.id), str(request.id))

        assert len(mails) == 1
        assert "membership" in mails[0].subject.lower()
        assert "I would like to contribute data" in mails[0].body

    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_membership_request_not_found(self):
        """Should handle gracefully when request is not found."""
        admin = UserFactory()
        org = OrganizationFactory(members=[Member(user=admin, role="admin")])

        with capture_mails() as mails:
            notify_membership_request(str(org.id), "nonexistent-id")

        assert len(mails) == 0

    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_membership_accepted_mail(self):
        """Accepted membership should send mail to requester."""
        admin = UserFactory()
        requester = UserFactory()
        org = OrganizationFactory(members=[Member(user=admin, role="admin")])
        request = MembershipRequest(user=requester, comment="join", status="accepted")
        org.requests.append(request)
        org.save()

        with capture_mails() as mails:
            notify_membership_response(str(org.id), str(request.id))

        assert len(mails) == 1
        assert mails[0].recipients[0] == requester.email
        assert "accepted" in mails[0].subject.lower()

    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_membership_refused_mail(self):
        """Refused membership should send mail to requester."""
        admin = UserFactory()
        requester = UserFactory()
        org = OrganizationFactory(members=[Member(user=admin, role="admin")])
        request = MembershipRequest(user=requester, comment="join", status="refused")
        org.requests.append(request)
        org.save()

        with capture_mails() as mails:
            notify_membership_response(str(org.id), str(request.id))

        assert len(mails) == 1
        assert mails[0].recipients[0] == requester.email
        assert "refused" in mails[0].subject.lower()

    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_new_member_mail(self):
        """Adding a member should send them a notification mail."""
        admin = UserFactory()
        new_user = UserFactory()
        org = OrganizationFactory(
            members=[
                Member(user=admin, role="admin"),
                Member(user=new_user, role="editor"),
            ]
        )

        with capture_mails() as mails:
            notify_new_member(str(org.id), new_user.email)

        assert len(mails) == 1
        assert mails[0].recipients[0] == new_user.email
        assert "member" in mails[0].subject.lower()
        assert org.name in mails[0].html

    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_new_member_not_found(self):
        """Should handle gracefully when member is not found."""
        admin = UserFactory()
        org = OrganizationFactory(members=[Member(user=admin, role="admin")])

        with capture_mails() as mails:
            notify_new_member(str(org.id), "nonexistent@example.org")

        assert len(mails) == 0
