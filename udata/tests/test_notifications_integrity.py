import logging
from datetime import UTC, datetime
from unittest import mock

from udata.core.dataset.factories import DatasetFactory
from udata.core.discussions.factories import DiscussionFactory, MessageDiscussionFactory
from udata.core.discussions.models import Discussion
from udata.core.discussions.notifications import DiscussionNotificationDetails, DiscussionStatus
from udata.core.organization.constants import CERTIFIED
from udata.core.organization.factories import OrganizationFactory
from udata.core.organization.notifications import (
    MembershipRequestNotificationDetails,
    NewBadgeNotificationDetails,
)
from udata.core.user.factories import AdminFactory, UserFactory
from udata.features.notifications.models import Notification, NotificationQuerySet
from udata.features.transfer.factories import TransferFactory
from udata.harvest.notifications import ValidateHarvesterNotificationDetails
from udata.harvest.tests.factories import HarvestSourceFactory
from udata.tests.api import PytestOnlyDBTestCase


class NotificationIntegrityTest(PytestOnlyDBTestCase):
    """Test notification cleanup when referenced documents are deleted."""

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

    def test_organization_notification_cleanup_on_organization_purge(self):
        """Test that notifications are cleaned up when an organization is purged."""
        from udata.core.organization import tasks

        user = UserFactory()
        org = OrganizationFactory(deleted=datetime.now(UTC))

        # One notification per branch of with_organization_in_details: badge details
        # keep the organization in `details.organization`, a membership request keeps
        # it in `details.request_organization`.
        Notification(
            user=user,
            details=NewBadgeNotificationDetails(organization=org, kind=CERTIFIED),
        ).save()
        Notification(
            user=user,
            details=MembershipRequestNotificationDetails(
                request_organization=org, request_user=user
            ),
        ).save()

        # Verify notifications exist
        assert Notification.objects.count() == 2

        # Purge the deleted organization
        tasks.purge_organizations()

        # Verify notifications are cleaned up (via purge function)
        assert Notification.objects.count() == 0

    def test_delete_discussions_for_subject_cleans_notifications(self):
        """Test that the shared helper cleans up the notifications it deletes discussions for."""
        from udata.core.discussions.actions import delete_discussions_for_subject

        user = UserFactory()
        dataset = DatasetFactory()
        other_dataset = DatasetFactory()
        discussions = [
            DiscussionFactory(
                user=user, subject=subject, discussion=[MessageDiscussionFactory(posted_by=user)]
            )
            for subject in (dataset, dataset, other_dataset)
        ]
        for discussion in discussions:
            Notification(
                user=user,
                details=DiscussionNotificationDetails(
                    discussion=discussion,
                    status=DiscussionStatus.NEW_DISCUSSION,
                    message_id=discussion.discussion[0].id,
                ),
            ).save()

        assert Notification.objects.count() == 3

        delete_discussions_for_subject(dataset)

        # Only the discussion hanging off the untouched subject survives, with its notification.
        assert Discussion.objects(subject=dataset).count() == 0
        assert Notification.objects.count() == 1
        assert Notification.objects.first().details.discussion == discussions[2]

    def test_discussion_notification_cleanup_on_dataset_purge(self):
        """Test that purging a dataset leaves none of its discussions' notifications."""
        from udata.core.dataset import tasks

        user = UserFactory()
        dataset = DatasetFactory(deleted=datetime.now(UTC))
        kept_dataset = DatasetFactory()
        discussion = DiscussionFactory(
            user=user,
            subject=dataset,
            discussion=[
                MessageDiscussionFactory(posted_by=user),
                MessageDiscussionFactory(posted_by=user),
            ],
        )
        kept_discussion = DiscussionFactory(
            user=user,
            subject=kept_dataset,
            discussion=[MessageDiscussionFactory(posted_by=user)],
        )

        # Both kinds of detail referencing the purged discussion: the discussion
        # itself, and a comment carrying a `message_id`.
        Notification(
            user=user,
            details=DiscussionNotificationDetails(
                discussion=discussion,
                status=DiscussionStatus.NEW_DISCUSSION,
                message_id=discussion.discussion[0].id,
            ),
        ).save()
        Notification(
            user=user,
            details=DiscussionNotificationDetails(
                discussion=discussion,
                status=DiscussionStatus.NEW_COMMENT,
                message_id=discussion.discussion[1].id,
            ),
        ).save()
        Notification(
            user=user,
            details=DiscussionNotificationDetails(
                discussion=kept_discussion,
                status=DiscussionStatus.NEW_DISCUSSION,
                message_id=kept_discussion.discussion[0].id,
            ),
        ).save()

        assert Notification.objects.count() == 3

        tasks.purge_datasets()

        assert Discussion.objects(subject=dataset).count() == 0
        assert Notification.objects.count() == 1
        assert Notification.objects.first().details.discussion == kept_discussion

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

    def test_discussion_cleanup_failure_logs_traceback(self, caplog):
        """Test that a cleanup that fails to delete logs its traceback"""
        user = UserFactory()
        dataset = DatasetFactory()
        message = MessageDiscussionFactory(posted_by=user)
        discussion = DiscussionFactory(user=user, subject=dataset, discussion=[message])

        notification = Notification(
            user=user,
            details=DiscussionNotificationDetails(
                discussion=discussion,
                status=DiscussionStatus.NEW_DISCUSSION,
                message_id=discussion.discussion[0].id,
            ),
        )
        notification.save()

        # Patch the notification queryset only: patching QuerySet.delete outright would also
        # hit the super().delete() that runs before the signal is sent.
        with (
            mock.patch.object(
                NotificationQuerySet, "delete", side_effect=ValueError("cannot delete")
            ),
            caplog.at_level(logging.ERROR, logger="udata.core.discussions.notifications"),
        ):
            discussion.delete()

        failures = [
            record
            for record in caplog.records
            if "Error cleaning up notifications for discussion" in record.getMessage()
        ]
        assert failures, [record.getMessage() for record in caplog.records]

        # The error must carry its traceback: a swallowed one is what kept the missing
        # receivers invisible in production.
        assert failures[0].exc_info is not None
