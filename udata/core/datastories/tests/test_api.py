from flask import url_for

from udata.core.datastories.models import DatastoryMetrics
from udata.core.metrics.events import MetricEvent
from udata.core.metrics.tasks import update_metrics_from_internal
from udata.tests.api import PytestOnlyAPITestCase


class DatastoryAPITest(PytestOnlyAPITestCase):
    def test_get_unknown_datastory_has_no_views(self):
        response = self.get(url_for("api.datastory", slug="unknown-story"))

        self.assert200(response)
        assert response.json == {"slug": "unknown-story", "metrics": {"views": 0}}
        # Reading must neither count nor create anything.
        assert len(list(DatastoryMetrics.objects)) == 0
        assert len(list(MetricEvent.objects)) == 0

    def test_get_returns_stored_views(self):
        DatastoryMetrics(slug="my-story", metrics={"views": 42}).save()

        response = self.get(url_for("api.datastory", slug="my-story"))

        self.assert200(response)
        assert response.json["metrics"]["views"] == 42

    def test_post_records_a_view_event(self):
        DatastoryMetrics(slug="my-story", metrics={"views": 3}).save()

        response = self.post(url_for("api.datastory_views", slug="my-story"))

        self.assert201(response)
        # The total is the DAG's to compute: the event does not change it here.
        assert response.json == {"slug": "my-story", "metrics": {"views": 3}}
        event = MetricEvent.objects.get()
        assert event.event_type == "view"
        assert event.object_type == "datastory"
        assert event.object_id == "my-story"
        assert DatastoryMetrics.objects.get(slug="my-story").metrics["views"] == 3

    def test_post_records_the_user(self):
        user = self.login()

        self.assert201(self.post(url_for("api.datastory_views", slug="my-story")))

        assert MetricEvent.objects.get().user_id == str(user.id)

    def test_slug_with_slashes(self):
        slug = "ambiente/qualidade-do-ar"

        self.assert201(self.post(url_for("api.datastory_views", slug=slug)))
        response = self.get(url_for("api.datastory", slug=slug))

        self.assert200(response)
        assert response.json["slug"] == slug
        assert MetricEvent.objects.get().object_id == slug

    def test_paths_without_trailing_slash(self):
        # The frontend proxy strips the trailing slash before forwarding to Flask, and both
        # routes take a `path` slug, so `<slug>/views` must still reach the POST route rather
        # than read as a GET of the slug `<slug>/views`.
        DatastoryMetrics(slug="ambiente/ar", metrics={"views": 7}).save()

        response = self.post("/api/1/datastories/ambiente/ar/views")

        self.assert201(response)
        assert response.json["slug"] == "ambiente/ar"
        assert MetricEvent.objects.get().object_id == "ambiente/ar"
        response = self.get("/api/1/datastories/ambiente/ar")
        self.assert200(response)
        assert response.json["metrics"]["views"] == 7

    def test_invalid_slug_is_rejected(self):
        for slug in ["with space", "dots..", "quote'", "x" * 256]:
            self.assert400(self.post(url_for("api.datastory_views", slug=slug)))
            self.assert400(self.get(url_for("api.datastory", slug=slug)))

        assert len(list(MetricEvent.objects)) == 0
        assert len(list(DatastoryMetrics.objects)) == 0

    def test_generic_tracking_accepts_datastory(self):
        response = self.post(
            url_for("api.tracking"),
            {"event_type": "view", "object_type": "datastory", "object_id": "my-story"},
        )

        self.assert201(response)
        assert MetricEvent.objects.get().object_type == "datastory"


class DatastoriesListAPITest(PytestOnlyAPITestCase):
    def test_views_in_the_order_asked_with_zero_for_unknown(self):
        DatastoryMetrics(slug="ambiente/ar", metrics={"views": 7}).save()
        DatastoryMetrics(slug="orcamento", metrics={"views": 3}).save()

        response = self.get(url_for("api.datastories", slugs="orcamento,unknown,ambiente/ar"))

        self.assert200(response)
        assert response.json == {
            "data": [
                {"slug": "orcamento", "metrics": {"views": 3}},
                {"slug": "unknown", "metrics": {"views": 0}},
                {"slug": "ambiente/ar", "metrics": {"views": 7}},
            ]
        }
        # Reading must not create documents for the unknown slug.
        assert len(list(DatastoryMetrics.objects)) == 2

    def test_duplicates_and_empty_items_are_dropped(self):
        response = self.get(url_for("api.datastories", slugs="a,,b,a,"))

        self.assert200(response)
        assert [row["slug"] for row in response.json["data"]] == ["a", "b"]

    def test_no_slugs_returns_an_empty_list(self):
        for url in [url_for("api.datastories"), url_for("api.datastories", slugs="")]:
            response = self.get(url)
            self.assert200(response)
            assert response.json == {"data": []}

    def test_too_many_slugs_is_rejected(self):
        slugs = ",".join(f"story-{i}" for i in range(101))

        self.assert400(self.get(url_for("api.datastories", slugs=slugs)))

    def test_one_invalid_slug_rejects_the_request(self):
        self.assert400(self.get(url_for("api.datastories", slugs="good,bad slug")))


class DatastoryInternalMetricsTest(PytestOnlyAPITestCase):
    def test_update_metrics_from_internal_upserts_datastory_views(self):
        DatastoryMetrics(slug="known-story", metrics={"views": 1}).save()
        for slug in ["known-story", "known-story", "new-story"]:
            MetricEvent.create_event(event_type="view", object_type="datastory", object_id=slug)

        update_metrics_from_internal()

        assert DatastoryMetrics.objects.get(slug="known-story").metrics["views"] == 2
        assert DatastoryMetrics.objects.get(slug="new-story").metrics["views"] == 1
        assert len(list(DatastoryMetrics.objects)) == 2
