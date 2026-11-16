from datetime import UTC, datetime

from dateutil.relativedelta import relativedelta

from udata.core.reuse.factories import ReuseFactory, VisibleReuseFactory
from udata.models import Reuse
from udata.tests.api import APITestCase


class ReuseSearchAPIV2Test(APITestCase):
    def test_reuse_search_with_model_query_param(self):
        """Searching reuses with 'model' as query param should not crash."""
        ReuseFactory.create_batch(3)

        response = self.get("/api/2/reuses/search/?model=malicious")
        self.assert200(response)

    def test_search_reuse_last_update_range(self):
        """The three windows must select three different sets, not everything.

        `last_update_range` was advertised by the search adapter — an unknown value is
        already rejected with 400 — while the Mongo path never applied it, so all three
        windows answered with the whole collection (LEDG-2713, following LEDG-2686 which
        fixed the same defect for datasets). The dates below sit far from every boundary,
        so the counts do not drift with the day the suite runs.
        """
        now = datetime.now(UTC).replace(tzinfo=None)
        # `VisibleReuseFactory`, not `ReuseFactory`: the search runs on
        # `Reuse.objects.visible()`, which requires at least one attached dataset.
        for reuse, age in (
            (VisibleReuseFactory(), relativedelta(days=10)),
            (VisibleReuseFactory(), relativedelta(months=6)),
            (VisibleReuseFactory(), relativedelta(years=2)),
            (VisibleReuseFactory(), relativedelta(years=10)),
        ):
            Reuse.objects(id=reuse.id).update(set__last_modified=now - age)

        expected = {"last_30_days": 1, "last_12_months": 2, "last_3_years": 3}
        for window, count in expected.items():
            response = self.get(f"/api/2/reuses/search/?last_update_range={window}")
            self.assert200(response)
            assert response.json["total"] == count, window
