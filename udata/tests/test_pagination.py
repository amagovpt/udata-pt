"""The paginated `total` must be counted, not estimated.

`Pagination.total` is what every paginated API response reports as `total`, and
what `pages`, `next_page` and `previous_page` are derived from. It was computed
with `QuerySet.count()`, which mongoengine routes to
`estimated_document_count()` when the queryset carries **no filter** -- and that
reads collection metadata rather than counting.

A filtered listing was never affected (it already went through
`count_documents()`), but an unfiltered one is reachable in production:
`udata/core/reports/api.py` paginates a bare `Report.objects`.
"""

from udata.core.dataset.factories import DatasetFactory
from udata.core.dataset.models import Dataset
from udata.tests.api import PytestOnlyDBTestCase


class PaginationTotalTest(PytestOnlyDBTestCase):
    def test_total_is_exact_for_an_unfiltered_queryset(self):
        """The case that was estimated: a queryset with no filter at all."""
        DatasetFactory.create_batch(7)

        page = Dataset.objects.paginate(1, 3)

        assert page.total == 7
        assert page.page_size == 3
        assert len(list(page)) == 3

    def test_total_is_exact_for_a_filtered_queryset(self):
        """The case that was always exact, pinned so the fix cannot regress it."""
        DatasetFactory.create_batch(4, archived=None)
        DatasetFactory.create_batch(3, archived="2026-01-01")

        page = Dataset.objects(archived=None).paginate(1, 10)

        assert page.total == 4

    def test_total_counts_documents_the_page_does_not_show(self):
        """`total` is the size of the whole result set, not of the page."""
        DatasetFactory.create_batch(5)

        first = Dataset.objects.paginate(1, 2)
        second = Dataset.objects.paginate(2, 2)

        assert first.total == 5
        assert second.total == 5
        assert len(list(first)) == 2
        assert len(list(second)) == 2
