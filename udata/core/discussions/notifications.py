import enum
import logging

from udata.api_fields import field, generate_fields
from udata.features.notifications.actions import notifier
from udata.models import db

from .actions import discussions_for
from .models import Message
from .signals import on_discussion_deleted, on_discussion_message_deleted

log = logging.getLogger(__name__)


class DiscussionStatus(str, enum.Enum):
    NEW_DISCUSSION = "new_discussion"
    NEW_COMMENT = "new_comment"
    CLOSED = "closed"


@generate_fields()
class DiscussionNotificationDetails(db.EmbeddedDocument):
    discussion = field(
        db.ReferenceField("Discussion"),
        readonly=True,
        auditable=False,
        allow_null=True,
        filterable={},
    )
    status = field(
        db.StringField(choices=[s.value for s in DiscussionStatus]),
        readonly=True,
        auditable=False,
    )
    message_id = field(
        # binary=False on purpose: upstream's plain UUIDField() would store BSON Binary,
        # which no notification written so far matches -- every one was saved as str(uuid).
        db.UUIDField(binary=False),
        readonly=True,
        auditable=False,
    )


@notifier("discussion")
def discussions_notifications(user):
    """Notify user about open discussions"""
    notifications = []

    # Only fetch required fields for notification serialization
    # Greatly improve performances and memory usage
    qs = discussions_for(user).only("id", "created", "title", "subject")

    # Do not dereference subject (so it's a DBRef)
    # Also improve performances and memory usage
    for discussion in qs.no_dereference():
        notifications.append(
            (
                discussion.created,
                {
                    "id": discussion.id,
                    "title": discussion.title,
                    "subject": {
                        "id": discussion.subject["_ref"].id,
                        "type": discussion.subject["_cls"].lower(),
                    },
                },
            )
        )

    return notifications


@on_discussion_deleted.connect
def cleanup_discussion_notifications(discussion, **kwargs):
    """Clean up notifications when a discussion is deleted"""
    from udata.features.notifications.models import Notification

    try:
        Notification.objects(details__discussion=discussion).delete()
    except Exception:
        # The signal is sent after the discussion is already gone, so raising here would
        # turn a completed DELETE into a 500. log.exception rather than upstream's
        # log.error: a swallowed traceback is what kept this broken in production.
        log.exception("Error cleaning up notifications for discussion %s", discussion.id)


@on_discussion_message_deleted.connect
def cleanup_message_notifications(discussion, message=None, **kwargs):
    """Clean up notifications when a message is deleted from a discussion"""
    from udata.features.notifications.models import Notification

    try:
        if message and isinstance(message, Message):
            Notification.objects(
                details__discussion=discussion, details__message_id=message.id
            ).delete()
    except Exception:
        log.exception(
            "Error cleaning up message notification for discussion %s, message %s",
            discussion.id,
            getattr(message, "id", None),
        )
