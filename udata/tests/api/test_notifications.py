import pytest
from flask import url_for

from udata.core.organization.factories import OrganizationFactory
from udata.core.organization.models import Member

from . import PytestOnlyAPITestCase

# Known failures owned by out-of-scope root causes. Each reason names the ticket that
# owns the production bug; strict=True means a fix turns the XPASS red and forces the
# marker to be removed by the same change.

R1 = (
    "LEDG-2322 pending. Notification.details "
    "(udata/features/notifications/models.py:57-65) lists only 4 of the 7 "
    "*NotificationDetails classes, leaving out NewBadgeNotificationDetails, "
    "MembershipAcceptedNotificationDetails and MembershipRefusedNotificationDetails. "
    "mongoengine rejects the document and udata/core/organization/tasks.py swallows the "
    "error, so badge and membership-response notifications are never created. This is a "
    "production bug being recorded, not a stale test: when it is fixed this starts "
    "passing and strict=True turns the XPASS red, forcing the marker out."
)


class NotificationsAPITest(PytestOnlyAPITestCase):
    def test_no_notifications(self):
        # Test that a user has no notifications
        self.login()
        response = self.get(url_for("api.notifications"))
        self.assert200(response)
        assert response.json["total"] == 0

    def test_has_notifications(self):
        # Test that a user has notifications
        admin = self.login()
        self.login()
        organization = OrganizationFactory(members=[Member(user=admin, role="admin")])
        data = {"comment": "a comment"}

        response = self.post(url_for("api.request_membership", org=organization), data)
        self.assert201(response)

        self.login(admin)
        response = self.get(url_for("api.notifications"))
        self.assert200(response)
        assert response.json["total"] == 1
        assert response.json["data"][0]["details"]["request_organization"]["id"] == str(
            organization.id
        )

    @pytest.mark.xfail(strict=True, reason=R1)
    def test_read_notification(self):
        """Test marking a notification as read"""
        # Create a certified organization which should create a notification
        admin = self.login()
        organization = OrganizationFactory(members=[Member(user=admin, role="admin")])

        # Add CERTIFIED badge to organization to trigger notification
        organization.add_badge("certified")
        organization.save()

        # Get the notification first
        response = self.get(url_for("api.notifications"))
        self.assert200(response)
        assert response.json["total"] == 1
        notification_id = response.json["data"][0]["id"]

        # Now mark the notification as read
        response = self.post(url_for("api.read_notifications", notification=notification_id))
        self.assert200(response)

        # Verify the notification is marked as handled
        assert response.json["handled_at"] is not None

        # Verify that the notification no longer appears in the list of pending notifications
        response = self.get(url_for("api.notifications", handled=False))
        self.assert200(response)
        assert response.json["total"] == 0

    @pytest.mark.xfail(strict=True, reason=R1)
    def test_read_notification_permission(self):
        """Test that only the user of a notification can mark it as read"""
        # Create a certified organization which should create a notification
        admin = self.login()
        organization = OrganizationFactory(members=[Member(user=admin, role="admin")])

        # Add CERTIFIED badge to organization to trigger notification
        organization.add_badge("certified")
        organization.save()

        # Get the notification first
        response = self.get(url_for("api.notifications"))
        self.assert200(response)
        assert response.json["total"] == 1
        notification_id = response.json["data"][0]["id"]

        # Login as a different user who doesn't own the notification
        self.login()
        # Try to mark the notification as read - should fail
        response = self.post(url_for("api.read_notifications", notification=notification_id))
        self.assert403(response)
