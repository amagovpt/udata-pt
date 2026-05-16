from datetime import UTC, datetime

import pytest
from flask import url_for

from udata.core.dataset.factories import DatasetFactory
from udata.core.dataset.models import Dataset
from udata.method_override import (
    ALLOWED_OVERRIDES,
    HEADER_ENVIRON_KEY,
    MethodOverrideMiddleware,
)
from udata.tests.api import APITestCase


def _make_environ(method: str, override: str | None = None) -> dict:
    environ = {"REQUEST_METHOD": method}
    if override is not None:
        environ[HEADER_ENVIRON_KEY] = override
    return environ


def _capture_app():
    captured: dict = {}

    def app(environ, start_response):
        captured["method"] = environ.get("REQUEST_METHOD")
        captured["original"] = environ.get("udata.original_method")
        captured["header_remaining"] = environ.get(HEADER_ENVIRON_KEY)
        return [b""]

    return app, captured


class MethodOverrideMiddlewareTest:
    """Pure WSGI tests for the middleware — no Flask app needed."""

    @pytest.mark.parametrize("verb", sorted(ALLOWED_OVERRIDES))
    def test_post_with_allowed_override_rewrites_method(self, verb):
        app, captured = _capture_app()
        middleware = MethodOverrideMiddleware(app)

        middleware(_make_environ("POST", verb), lambda *a, **kw: None)

        assert captured["method"] == verb
        assert captured["original"] == "POST"
        # The header must be stripped from the environ after consumption.
        assert captured["header_remaining"] is None

    def test_post_with_lowercase_override_is_normalized(self):
        app, captured = _capture_app()
        middleware = MethodOverrideMiddleware(app)

        middleware(_make_environ("POST", "delete"), lambda *a, **kw: None)

        assert captured["method"] == "DELETE"

    def test_post_with_unsupported_override_is_ignored(self):
        app, captured = _capture_app()
        middleware = MethodOverrideMiddleware(app)

        middleware(_make_environ("POST", "GET"), lambda *a, **kw: None)

        assert captured["method"] == "POST"
        assert captured["original"] is None

    def test_post_without_override_is_unchanged(self):
        app, captured = _capture_app()
        middleware = MethodOverrideMiddleware(app)

        middleware(_make_environ("POST"), lambda *a, **kw: None)

        assert captured["method"] == "POST"
        assert captured["original"] is None

    @pytest.mark.parametrize("verb", ["GET", "PUT", "DELETE", "PATCH", "OPTIONS"])
    def test_non_post_methods_never_override(self, verb):
        """Only POST may carry an override — prevents GET→DELETE smuggling."""
        app, captured = _capture_app()
        middleware = MethodOverrideMiddleware(app)

        middleware(_make_environ(verb, "DELETE"), lambda *a, **kw: None)

        assert captured["method"] == verb
        assert captured["original"] is None


class MethodOverrideIntegrationTest(APITestCase):
    """Verify the middleware reaches Flask routing through the real WSGI stack."""

    def test_post_with_override_delete_deletes_dataset(self):
        user = self.login()
        dataset = DatasetFactory(owner=user, nb_resources=1)

        response = self.post(
            url_for("api.dataset", dataset=dataset),
            headers={"X-HTTP-Method-Override": "DELETE"},
        )

        self.assertStatus(response, 204)
        dataset.reload()
        assert dataset.deleted is not None

    def test_post_with_override_put_updates_dataset(self):
        user = self.login()
        dataset = DatasetFactory(owner=user, title="Old", nb_resources=1)
        payload = dataset.to_dict()
        payload["title"] = "New"

        # Address by id to avoid slug-change 308 redirects after the update.
        response = self.post(
            url_for("api.dataset", dataset=dataset.id),
            data=payload,
            headers={"X-HTTP-Method-Override": "PUT"},
        )

        self.assert200(response)
        dataset.reload()
        assert dataset.title == "New"

    def test_post_without_override_stays_post(self):
        """Sanity: a real POST with no header still hits the POST handler."""
        user = self.login()
        dataset = DatasetFactory(owner=user, deleted=datetime.now(UTC))

        # POST to the dataset detail URL is not allowed — confirms the
        # request is *not* being silently rewritten by the middleware.
        response = self.post(url_for("api.dataset", dataset=dataset))

        assert response.status_code in (404, 405, 410)
        assert Dataset.objects(id=dataset.id).first().deleted is not None
