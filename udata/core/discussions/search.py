from datetime import UTC, datetime

from udata.core.dataset.constants import LAST_UPDATE_RANGES
from udata.core.discussions.models import Discussion
from udata.search import BoolFilter, Filter, ModelSearchAdapter, register


@register
class DiscussionSearch(ModelSearchAdapter):
    model = Discussion
    search_url = "discussions/"

    sorts = {
        "created": "created_at",
        "closed": "closed_at",
    }

    filters = {
        "closed": BoolFilter(),
        "last_update_range": Filter(choices=["last_30_days", "last_12_months", "last_3_years"]),
    }

    @classmethod
    def is_indexable(cls, discussion):
        return True

    @classmethod
    def mongo_search(cls, args):
        """Fallback search implementation when search service is not available"""
        discussions = Discussion.objects()
        if args.get("last_update_range"):
            # A discussion is the one model here with no `last_modified`: it carries
            # `created` and `closed`, and neither is a last update. What it does have is
            # messages, and its last update is its last message — so the window matches a
            # discussion when *any* of its messages falls inside it, which is what
            # "discussions active in the last 30 days" means.
            #
            # The window reaches back from midnight today, not from this instant: the
            # search service rounds its own boundary down to the day (`now-30d/d`), and
            # the two sides have to select the same documents.
            today = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
            since = today - LAST_UPDATE_RANGES[args["last_update_range"]]
            discussions = discussions.filter(discussion__posted_on__gte=since)
        # `.paginate()` is what the search framework needs: it reads `.total` off the
        # result, and a bare queryset does not carry one. Without it this endpoint
        # answered 500 to every request, filter or no filter (LEDG-2713).
        return discussions.order_by("-created").paginate(args["page"], args["page_size"])

    @classmethod
    def serialize(cls, discussion):
        """Transform a Discussion object into a flat dictionary for indexing."""
        # Concatenate all message contents
        messages_content = []
        for message in discussion.discussion:
            if message.content:
                messages_content.append(message.content)

        subject_class = None
        subject_id = None
        if discussion.subject:
            subject_class = discussion.subject.__class__.__name__
            subject_id = str(discussion.subject.id)

        return {
            "id": str(discussion.id),
            "title": discussion.title,
            "content": " ".join(messages_content),
            "created_at": discussion.created.isoformat() if discussion.created else None,
            "closed_at": discussion.closed.isoformat() if discussion.closed else None,
            "closed": discussion.closed is not None,
            "subject_class": subject_class,
            "subject_id": subject_id,
        }
