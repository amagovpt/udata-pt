from datetime import UTC, datetime

from dateutil.relativedelta import relativedelta

from udata.core.post.factories import PostFactory
from udata.models import Post
from udata.tests.api import APITestCase


class PostSearchAPIV2Test(APITestCase):
    def test_search_post_last_update_range(self):
        """The three windows must select three different sets, not everything.

        `last_update_range` was advertised by the search adapter — an unknown value is
        already rejected with 400 — while `mongo_search` never read `args` at all, so all
        three windows answered with the whole collection (LEDG-2713, following LEDG-2686
        which fixed the same defect for datasets). The dates below sit far from every
        boundary, so the counts do not drift with the day the suite runs.
        """
        now = datetime.now(UTC).replace(tzinfo=None)
        for post, age in (
            (PostFactory(), relativedelta(days=10)),
            (PostFactory(), relativedelta(months=6)),
            (PostFactory(), relativedelta(years=2)),
            (PostFactory(), relativedelta(years=10)),
        ):
            Post.objects(id=post.id).update(set__last_modified=now - age)

        expected = {"last_30_days": 1, "last_12_months": 2, "last_3_years": 3}
        for window, count in expected.items():
            response = self.get(f"/api/2/posts/search/?last_update_range={window}")
            self.assert200(response)
            assert response.json["total"] == count, window
