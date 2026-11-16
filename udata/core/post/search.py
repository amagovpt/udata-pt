from datetime import UTC, datetime

from udata.core.dataset.constants import LAST_UPDATE_RANGES
from udata.core.post.models import Post
from udata.search import Filter, ListFilter, ModelSearchAdapter, register


@register
class PostSearch(ModelSearchAdapter):
    model = Post
    search_url = "posts/"

    sorts = {
        "created": "created_at",
        "last_modified": "last_modified",
        "published": "published",
    }

    filters = {
        "tag": ListFilter(),
        "last_update_range": Filter(choices=["last_30_days", "last_12_months", "last_3_years"]),
    }

    @classmethod
    def is_indexable(cls, post):
        return True

    @classmethod
    def mongo_search(cls, args):
        """Fallback search implementation when search service is not available"""
        posts = Post.objects()
        if args.get("last_update_range"):
            # `last_modified`, from the `Datetimed` mixin — not `published`, which is the
            # publication date. The filter is named after the last update, and a post
            # edited today was last updated today whenever it first went out.
            #
            # The window reaches back from midnight today, not from this instant: the
            # search service rounds its own boundary down to the day (`now-30d/d`), and
            # the two sides have to select the same documents.
            today = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
            since = today - LAST_UPDATE_RANGES[args["last_update_range"]]
            posts = posts.filter(last_modified__gte=since)
        # `.paginate()` is what the search framework needs: it reads `.total` off the
        # result, and a bare queryset does not carry one. Without it this endpoint
        # answered 500 to every request, filter or no filter (LEDG-2713).
        return posts.order_by("-created_at").paginate(args["page"], args["page_size"])

    @classmethod
    def serialize(cls, post):
        """Transform a Post object into a flat dictionary for indexing."""
        return {
            "id": str(post.id),
            "name": post.name,
            "headline": post.headline or "",
            "content": post.content,
            "tags": post.tags or [],
            "created_at": post.created_at.isoformat() if post.created_at else None,
            "last_modified": post.last_modified.isoformat() if post.last_modified else None,
            "published": post.published.isoformat() if post.published else None,
        }
