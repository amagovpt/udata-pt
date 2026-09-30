"""The unauthenticated identicon endpoint is gone and must stay gone.

`GET /api/1/avatars/<identifier>/<size>/` rendered a pydenticon from a hash of the
identifier. It never read the database, so it leaked nothing -- but `size` had no
ceiling and the image was drawn before any validation, so a single anonymous request
could burn tens of seconds of CPU and gigabytes of RSS. Nothing in this fork consumed
it: uploaded avatars are served as files by the storage, and the serialization returns
`None` rather than falling back to an identicon.

The three assertions below cover the three separate ways a route can still exist --
HTTP dispatch, the internal url map, and the published Swagger contract. None of them
subsumes the others.
"""

import json

from flask import current_app, url_for

from udata.tests.api import PytestOnlyAPITestCase
from udata.tests.helpers import assert200, assert404

REMOVED_ENDPOINT = "api.avatar"
REMOVED_PATH_PREFIX = "/avatars/"


class AvatarEndpointRemovedTest(PytestOnlyAPITestCase):
    def test_avatar_route_returns_404(self):
        # `url_map.strict_slashes` is False app-wide, so both spellings used to answer
        # 200 and production exposed both. Close both.
        for path in ("/api/1/avatars/anything/150/", "/api/1/avatars/anything/150"):
            assert404(self.get(path))

    def test_avatar_endpoint_not_in_url_map(self):
        # Deliberately not `pytest.raises(BuildError)`: `url_for` also raises that when
        # the endpoint exists but the arguments do not match, so it would not tell a
        # removed name apart from a name re-registered with another signature.
        endpoints = {rule.endpoint for rule in current_app.url_map.iter_rules()}
        assert REMOVED_ENDPOINT not in endpoints

    def test_avatar_namespace_absent_from_swagger(self):
        response = self.get(url_for("api.specs"))
        assert200(response)
        swagger = json.loads(response.data)

        # Anchored on the path prefix, not on the substring "avatar": the live upload
        # endpoints `/me/avatar/` and `/users/{user}/avatar/` are still in the spec.
        assert not [p for p in swagger["paths"] if p.startswith(REMOVED_PATH_PREFIX)]
        assert not [t for t in swagger.get("tags", []) if t["name"] == "avatars"]
