import enum
import logging

from udata.api_fields import field, generate_fields
from udata.features.notifications.actions import notifier
from udata.models import db

from .actions import discussions_for

log = logging.getLogger(__name__)


class DiscussionStatus(str, enum.Enum):
    NEW_DISCUSSION = "new_discussion"
    NEW_COMMENT = "new_comment"


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
        db.StringField(),
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
