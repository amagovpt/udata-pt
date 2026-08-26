import logging
from unittest import mock

import pytest

from udata.core.organization.constants import (
    ASSOCIATION,
    CERTIFIED,
    COMPANY,
    LOCAL_AUTHORITY,
    PUBLIC_SERVICE,
)
from udata.core.organization.factories import OrganizationFactory
from udata.core.organization.models import Member
from udata.core.user.factories import UserFactory
from udata.features.notifications.models import Notification
from udata.tests.api import PytestOnlyAPITestCase
from udata.tests.helpers import capture_mails


class NotifyBadgeTest(PytestOnlyAPITestCase):
    @pytest.mark.parametrize(
        "badge_type", [CERTIFIED, PUBLIC_SERVICE, LOCAL_AUTHORITY, COMPANY, ASSOCIATION]
    )
    def test_notify_badge_creates_notifications(self, badge_type):
        """
        Test that notify_badge_* creates in-app notifications for organization members
        """
        # Create users and organization
        user1 = UserFactory()
        user2 = UserFactory()

        # Create organization with members
        organization = OrganizationFactory(
            members=[Member(user=user1, role="admin"), Member(user=user2, role="editor")]
        )
        org_mails = [user1.email, user2.email]

        with capture_mails() as mails:
            # Add badge to organization
            organization.add_badge(badge_type)
            assert len(mails) == 2
            assert mails[0].recipients[0] in org_mails
            assert mails[1].recipients[0] in org_mails

        # Verify that notifications were created for each member
        notifications = Notification.objects(user__in=[user1, user2])
        assert len(notifications) == 2

        # Verify that notifications are for the correct organization and badge kind
        for notification in notifications:
            assert notification.details.organization.id == organization.id
            assert notification.details.organization.name == organization.name
            assert notification.details.kind == badge_type

    @pytest.mark.parametrize(
        "badge_type", [CERTIFIED, PUBLIC_SERVICE, LOCAL_AUTHORITY, COMPANY, ASSOCIATION]
    )
    def test_notify_badge_notification_details(self, badge_type):
        """
        Test that notifications have correct details for organization badge
        """
        # Create users and organization
        user = UserFactory()
        organization = OrganizationFactory(members=[Member(user=user, role="admin")])

        with capture_mails():
            # Add badge to organization
            organization.add_badge(badge_type)

        # Get the notification
        notification = Notification.objects.first()

        # Verify notification details
        assert notification is not None
        assert notification.details.organization.id == organization.id
        assert notification.details.organization.name == organization.name
        assert notification.details.kind == badge_type
        assert notification.user == user

    def test_badge_notification_failure_logs_traceback(self, caplog):
        """
        Test that a notification that fails to save logs its traceback
        """
        user = UserFactory()
        organization = OrganizationFactory(members=[Member(user=user, role="admin")])

        with (
            mock.patch.object(Notification, "save", side_effect=ValueError("cannot save")),
            capture_mails(),
            caplog.at_level(logging.ERROR, logger="udata.core.organization.tasks"),
        ):
            organization.add_badge(CERTIFIED)

        failures = [
            record
            for record in caplog.records
            if "Failed to create new badge notification" in record.getMessage()
        ]
        assert failures, [record.getMessage() for record in caplog.records]

        # The error must carry its traceback: swallowing it is what hid this bug
        # in production for the whole time the details class was unregistered.
        assert failures[0].exc_info is not None
        assert Notification.objects.count() == 0
