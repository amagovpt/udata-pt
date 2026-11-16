from datetime import UTC, datetime

from dateutil.relativedelta import relativedelta

from udata.core.dataset.factories import DatasetFactory
from udata.core.discussions.factories import DiscussionFactory, MessageDiscussionFactory
from udata.core.user.factories import UserFactory
from udata.models import Discussion
from udata.tests.api import APITestCase


class DiscussionSearchAPIV2Test(APITestCase):
    def test_search_discussion_last_update_range(self):
        """The three windows must select three different sets, not everything.

        Two defects met here. `mongo_search` never read `args`, so the advertised
        `last_update_range` was accepted, validated and ignored; and it returned a bare
        queryset, so the endpoint answered 500 to every request (LEDG-2713).

        A discussion has no `last_modified` — it carries `created` and `closed`, and
        neither is a last update. Its last update is its last message, so the window
        matches when any message falls inside it. The dates below sit far from every
        boundary, so the counts do not drift with the day the suite runs.
        """
        user = UserFactory()
        now = datetime.now(UTC).replace(tzinfo=None)
        for age in (
            relativedelta(days=10),
            relativedelta(months=6),
            relativedelta(years=2),
            relativedelta(years=10),
        ):
            # A subject is required: the serializer builds the discussion's web URL
            # from it, and has nothing to build from without one.
            discussion = DiscussionFactory(
                user=user,
                subject=DatasetFactory(),
                discussion=[MessageDiscussionFactory(posted_by=user)],
            )
            Discussion.objects(id=discussion.id).update(set__discussion__0__posted_on=now - age)

        expected = {"last_30_days": 1, "last_12_months": 2, "last_3_years": 3}
        for window, count in expected.items():
            response = self.get(f"/api/2/discussions/search/?last_update_range={window}")
            self.assert200(response)
            assert response.json["total"] == count, window
