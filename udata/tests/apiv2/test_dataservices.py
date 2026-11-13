from datetime import UTC, datetime

from dateutil.relativedelta import relativedelta

from udata.core.dataservices.factories import DataserviceFactory
from udata.models import Dataservice
from udata.tests.api import APITestCase


class DataserviceSearchAPIV2Test(APITestCase):
    def test_dataservice_search_with_model_query_param(self):
        """Searching dataservices with 'model' as query param should not crash.

        Regression test for: TypeError: query() got multiple values for argument 'model'
        """
        DataserviceFactory.create_batch(3)

        response = self.get("/api/2/dataservices/search/?model=malicious")
        self.assert200(response)

    def test_search_dataservice_last_update_range(self):
        """The three windows must select three different sets, not everything.

        `last_update_range` was advertised by the search adapter — an unknown value is
        already rejected with 400 — while the Mongo path never applied it, so all three
        windows answered with the whole collection (LEDG-2713, following LEDG-2686 which
        fixed the same defect for datasets). The dates below sit far from every boundary,
        so the counts do not drift with the day the suite runs.
        """
        now = datetime.now(UTC).replace(tzinfo=None)
        for dataservice, age in (
            (DataserviceFactory(), relativedelta(days=10)),
            (DataserviceFactory(), relativedelta(months=6)),
            (DataserviceFactory(), relativedelta(years=2)),
            (DataserviceFactory(), relativedelta(years=10)),
        ):
            Dataservice.objects(id=dataservice.id).update(set__metadata_modified_at=now - age)

        expected = {"last_30_days": 1, "last_12_months": 2, "last_3_years": 3}
        for window, count in expected.items():
            response = self.get(f"/api/2/dataservices/search/?last_update_range={window}")
            self.assert200(response)
            assert response.json["total"] == count, window
