import pytest

from udata.core.dataset.factories import DatasetFactory
from udata.core.discussions.factories import DiscussionFactory, MessageDiscussionFactory
from udata.core.discussions.notifications import DiscussionNotificationDetails, DiscussionStatus
from udata.core.user.factories import AdminFactory, UserFactory
from udata.features.notifications.models import Notification
from udata.features.transfer.factories import TransferFactory
from udata.harvest.notifications import ValidateHarvesterNotificationDetails
from udata.harvest.tests.factories import HarvestSourceFactory
from udata.tests.api import PytestOnlyDBTestCase

# Known failures owned by out-of-scope root causes. Each reason names the ticket that
# owns the production bug; strict=True means a fix turns the XPASS red and forces the
# marker to be removed by the same change.

R3 = (
    "LEDG-2328 pending. Notification.message_id is a StringField where upstream has a "
    "UUIDField (udata/core/discussions/notifications.py:32-36), and the cleanup receivers "
    "for on_discussion_deleted and on_discussion_message_deleted are missing entirely, so "
    "deleting a discussion or a message leaves orphaned notifications. This is a "
    "production bug being recorded, not a stale test: when it is fixed this starts "
    "passing and strict=True turns the XPASS red, forcing the marker out."
)


class NotificationIntegrityTest(PytestOnlyDBTestCase):
    """Test notification cleanup when referenced documents are deleted."""

    @pytest.mark.xfail(strict=True, reason=R3)
    def test_discussion_notification_cleanup_on_discussion_delete(self):
        """Test that notifications are cleaned up when a discussion is deleted."""
        # Create a user and discussion with messages
        user = UserFactory()
        dataset = DatasetFactory()
        from udata.core.discussions.factories import MessageDiscussionFactory

        message = MessageDiscussionFactory(posted_by=user)
        discussion = DiscussionFactory(user=user, subject=dataset, discussion=[message])

        # Create a notification for this discussion
        notification = Notification(
            user=user,
            details=DiscussionNotificationDetails(
                discussion=discussion,
                status=DiscussionStatus.NEW_DISCUSSION,
                message_id=discussion.discussion[0].id,
            ),
        )
        notification.save()

        # Verify notification exists
        assert Notification.objects.count() == 1
        assert Notification.objects.first().details.discussion == discussion

        # Delete the discussion
        discussion.delete()

        # Verify notification is cleaned up
        assert Notification.objects.count() == 0

    def test_transfer_notification_cleanup_on_transfer_delete(self):
        """Test that notifications are cleaned up when a transfer is deleted."""
        # Create users and organization
        owner = UserFactory()
        recipient = UserFactory()
        dataset = DatasetFactory(owner=owner)

        # Create a transfer (this automatically creates a notification via signal)
        transfer = TransferFactory(
            user=owner, owner=owner, recipient=recipient, subject=dataset, status="pending"
        )

        # Verify notification exists (automatically created by factory)
        assert Notification.objects.count() == 1
        notification = Notification.objects.first()
        assert notification.user == recipient

        # Delete the transfer
        transfer.delete()

        # Verify notification is cleaned up
        assert Notification.objects.count() == 0

    def test_harvest_source_notification_cleanup_on_source_delete(self):
        """Test that notifications are cleaned up when a harvest source is deleted."""
        # Create admin user and harvest source
        admin = AdminFactory()
        source = HarvestSourceFactory()

        # Create a notification for this harvest source
        notification = Notification(
            user=admin,
            details=ValidateHarvesterNotificationDetails(source=source, status="pending"),
        )
        notification.save()

        # Verify notification exists
        assert Notification.objects.count() == 1

        # Delete the harvest source
        from udata.harvest.actions import delete_source

        delete_source(source)

        # Verify notification is cleaned up (via signal)
        assert Notification.objects.count() == 0

    def test_harvest_source_notification_cleanup_on_source_purge(self):
        """Test that notifications are cleaned up when a harvest source is purged."""
        # Create admin user and harvest source
        from udata.core.user.factories import AdminFactory

        admin = AdminFactory()
        source = HarvestSourceFactory()

        # Create a notification for this harvest source
        notification = Notification(
            user=admin,
            details=ValidateHarvesterNotificationDetails(source=source, status="pending"),
        )
        notification.save()

        # Verify notification exists
        assert Notification.objects.count() == 1

        # Mark source as deleted and purge it
        from udata.harvest.actions import delete_source, purge_sources

        delete_source(source)
        purge_sources()

        # Verify notification is cleaned up (via purge function)
        assert Notification.objects.count() == 0

    @pytest.mark.xfail(strict=True, reason=R3)
    def test_multiple_notifications_cleanup(self):
        """Test that multiple notifications are cleaned up correctly."""
        # Create users and discussions
        user1 = UserFactory()
        user2 = UserFactory()
        dataset = DatasetFactory()
        message1 = MessageDiscussionFactory(posted_by=user1)
        message2 = MessageDiscussionFactory(posted_by=user2)
        discussion1 = DiscussionFactory(user=user1, subject=dataset, discussion=[message1])
        discussion2 = DiscussionFactory(user=user2, subject=dataset, discussion=[message2])

        # Create notifications for both discussions
        notification1 = Notification(
            user=user1,
            details=DiscussionNotificationDetails(
                discussion=discussion1,
                status=DiscussionStatus.NEW_DISCUSSION,
                message_id=discussion1.discussion[0].id,
            ),
        )
        notification1.save()

        notification2 = Notification(
            user=user2,
            details=DiscussionNotificationDetails(
                discussion=discussion2,
                status=DiscussionStatus.NEW_DISCUSSION,
                message_id=discussion2.discussion[0].id,
            ),
        )
        notification2.save()

        # Verify both notifications exist
        assert Notification.objects.count() == 2

        # Delete one discussion
        discussion1.delete()

        # Verify only one notification is cleaned up
        assert Notification.objects.count() == 1
        assert Notification.objects.first().details.discussion == discussion2

        # Delete the second discussion
        discussion2.delete()

        # Verify all notifications are cleaned up
        assert Notification.objects.count() == 0

    @pytest.mark.xfail(strict=True, reason=R3)
    def test_discussion_notification_survives_message_delete(self):
        """Test that notifications are not broken when referenced messages are deleted."""
        user = UserFactory()
        dataset = DatasetFactory()
        message1 = MessageDiscussionFactory(posted_by=user)
        message2 = MessageDiscussionFactory(posted_by=user)
        discussion = DiscussionFactory(user=user, subject=dataset, discussion=[message1, message2])

        notification = Notification(
            user=user,
            details=DiscussionNotificationDetails(
                discussion=discussion,
                status=DiscussionStatus.NEW_COMMENT,
                message_id=discussion.discussion[1].id,
            ),
        )
        notification.save()

        assert Notification.objects.count() == 1
        assert Notification.objects.first().details.discussion == discussion

        discussion.remove_message(1)

        assert Notification.objects.count() == 0
