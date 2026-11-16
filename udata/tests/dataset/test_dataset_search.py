from datetime import UTC, datetime

from udata.core.dataset.factories import DatasetFactory
from udata.core.dataset.models import HarvestDatasetMetadata
from udata.core.dataset.search import DatasetSearch
from udata.tests.api import APITestCase


class DatasetSearchSerializeTest(APITestCase):
    def test_serialize_created_at_matches_the_sorted_field(self):
        """The index must receive the field the sort mapping names.

        `sorts["created"]` points at `created_at_internal`, because Mongo cannot order by
        a Python property. `serialize()` used to feed the index from `Dataset.created_at`,
        which is a property resolving to the harvest issued date when there is one — so
        the two paths named one sort key and ordered it by two different dates
        (LEDG-2714).

        The harvest date here sits years away from the stored one, far enough that a
        serializer reading the property cannot pass by accident.
        """
        dataset = DatasetFactory(
            created_at_internal=datetime(2024, 3, 1, tzinfo=UTC),
            harvest=HarvestDatasetMetadata(
                backend="DCAT",
                issued_at=datetime(2015, 7, 9, tzinfo=UTC),
                source_id="source_id",
                remote_id="remote_id",
            ),
        )

        # The property still answers the harvest date — this is not being changed, and
        # the API keeps showing it.
        assert dataset.created_at.year == 2015

        indexed = DatasetSearch.serialize(dataset)
        assert indexed["created_at"].startswith("2024-03-01"), indexed["created_at"]
        assert DatasetSearch.sorts["created"] == "created_at_internal"
