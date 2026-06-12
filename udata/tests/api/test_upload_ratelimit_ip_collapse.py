"""Regression suite for the public file-UPLOAD rate limits.

Third companion to the public-search (PR #89) and download/export/feed (PR #90)
IP-collapse fixes. Several authenticated upload endpoints carried NO explicit
per-endpoint limit, so they fell under the IP-keyed ``RATELIMIT_DEFAULT``
("200 per hour"). Behind the F5/WAF every client reaches the backend from one
origin IP (docs/infra-adc-waf-impact-ppr-prd.md §4.2), so that 200/hour became a
SHARED site-wide ceiling: once aggregate uploads cross it, every editor's upload
returns 429. Worse, the limit is IP-keyed (not user-keyed), so a single user can
exhaust the shared bucket for everyone.

The endpoints that were lifted out of the default (this fix):

* ``POST /datasets/<d>/resources/<rid>/upload/`` — replace an existing
  resource's file (as frequent as creating one) -> UPLOAD_LIMIT (10/min);
* ``POST /datasets/community_resources/<crid>/upload/`` — re-upload a community
  resource file -> CONTENT_CREATE_LIMIT (5/min, public content);
* ``POST /users/<user>/avatar/`` -> UPLOAD_LIMIT (10/min);
* ``POST /reuses/<reuse>/image/`` -> UPLOAD_LIMIT (10/min);
* ``POST /posts/<post>/image/`` (and the PUT resize) -> UPLOAD_LIMIT (10/min).

All limits are keyed by ``user_or_ip`` and method-scoped, matching the already
protected ``/datasets/<d>/upload/``, ``/datasets/<d>/upload/community/``,
``/organizations/<org>/logo/`` and ``/me/avatar/`` endpoints.

Method: fire requests ANONYMOUSLY. The limiter decorator wraps the view and runs
BEFORE ``@api.secure``, so each anonymous POST consumes a limiter slot (keyed by
IP via the user_or_ip fallback) and returns 401 until the per-endpoint ceiling
is crossed, then 429. The signature of the fix is a 429 at the *per-endpoint*
threshold (11th / 6th request) — NOT at ~200, which is what the collapsing
IP-keyed default would have allowed.

Run:
    uv run pytest udata/tests/api/test_upload_ratelimit_ip_collapse.py -v
"""

from uuid import uuid4

import pytest
from flask import url_for

from udata.app import limiter
from udata.core.dataset.factories import CommunityResourceFactory, DatasetFactory
from udata.core.post.factories import PostFactory
from udata.core.reuse.factories import ReuseFactory
from udata.core.user.factories import UserFactory
from udata.tests.api import PytestOnlyAPITestCase

RATELIMIT_OPTIONS = dict(RATELIMIT_ENABLED=True)

# Mirrored from udata/api/limits.py.
UPLOAD_PER_MIN = 10  # UPLOAD_LIMIT = "10 per minute; 100 per hour; 500 per day"
CONTENT_CREATE_PER_MIN = 5  # CONTENT_CREATE_LIMIT = "5 per minute; ..."

BLOCK_STATUSES = (429, 403)


def _statuses(responses):
    return [r.status_code for r in responses]


@pytest.fixture(autouse=True)
def _reset_limiter():
    """Clear the shared rate-limit windows around every test so counters from
    one test never leak spurious 429s into the next."""
    limiter.reset()
    yield
    limiter.reset()


def _assert_throttled_at(statuses, threshold, endpoint):
    """Assert the per-endpoint limit engaged at ``threshold`` (and not earlier),
    proving the endpoint carries its own limit rather than the 200/h default."""
    blocked_before = [s for s in statuses[:threshold] if s in BLOCK_STATUSES]
    blocked_after = [s for s in statuses[threshold:] if s in BLOCK_STATUSES]
    assert not blocked_before, (
        f"{endpoint}: blocked within the first {threshold} requests "
        f"(limit tighter than expected, or a leaked window). statuses={statuses}"
    )
    assert blocked_after, (
        f"{endpoint}: {len(statuses)} rapid uploads from one IP never produced a "
        f"429 past request #{threshold}. The endpoint is either unlimited or back "
        f"under the collapsing 200/h IP default. statuses={statuses}"
    )


class ResourceReuploadLiftedAboveIpDefaultTest(PytestOnlyAPITestCase):
    """Replacing an existing resource's file must carry UPLOAD_LIMIT (10/min),
    not the IP-keyed 200/h default that collapses site-wide behind the F5/WAF."""

    @pytest.mark.options(**RATELIMIT_OPTIONS)
    def test_resource_reupload_throttles_at_upload_limit(self):
        dataset = DatasetFactory()
        url = url_for("api.upload_dataset_resource", dataset=dataset, rid=uuid4())
        statuses = _statuses(self.post(url) for _ in range(UPLOAD_PER_MIN + 3))
        _assert_throttled_at(statuses, UPLOAD_PER_MIN, "upload_dataset_resource")


class CommunityResourceReuploadLiftedAboveIpDefaultTest(PytestOnlyAPITestCase):
    """Re-uploading a community resource file must carry CONTENT_CREATE_LIMIT
    (5/min, tighter — public content), not the 200/h default."""

    @pytest.mark.options(**RATELIMIT_OPTIONS)
    def test_community_resource_reupload_throttles_at_content_create_limit(self):
        community = CommunityResourceFactory()
        url = url_for("api.upload_community_resource", community=community)
        statuses = _statuses(self.post(url) for _ in range(CONTENT_CREATE_PER_MIN + 3))
        _assert_throttled_at(statuses, CONTENT_CREATE_PER_MIN, "upload_community_resource")


class UserAvatarUploadLiftedAboveIpDefaultTest(PytestOnlyAPITestCase):
    """Admin avatar upload for a user must carry UPLOAD_LIMIT (10/min)."""

    @pytest.mark.options(**RATELIMIT_OPTIONS)
    def test_user_avatar_upload_throttles_at_upload_limit(self):
        user = UserFactory()
        url = url_for("api.user_avatar", user=user)
        statuses = _statuses(self.post(url) for _ in range(UPLOAD_PER_MIN + 3))
        _assert_throttled_at(statuses, UPLOAD_PER_MIN, "user_avatar")


class ReuseImageUploadLiftedAboveIpDefaultTest(PytestOnlyAPITestCase):
    """Reuse image upload must carry UPLOAD_LIMIT (10/min)."""

    @pytest.mark.options(**RATELIMIT_OPTIONS)
    def test_reuse_image_upload_throttles_at_upload_limit(self):
        reuse = ReuseFactory()
        url = url_for("api.reuse_image", reuse=reuse)
        statuses = _statuses(self.post(url) for _ in range(UPLOAD_PER_MIN + 3))
        _assert_throttled_at(statuses, UPLOAD_PER_MIN, "reuse_image")


class PostImageUploadLiftedAboveIpDefaultTest(PytestOnlyAPITestCase):
    """Post image upload must carry UPLOAD_LIMIT (10/min)."""

    @pytest.mark.options(**RATELIMIT_OPTIONS)
    def test_post_image_upload_throttles_at_upload_limit(self):
        post = PostFactory()
        url = url_for("api.post_image", post=post)
        statuses = _statuses(self.post(url) for _ in range(UPLOAD_PER_MIN + 3))
        _assert_throttled_at(statuses, UPLOAD_PER_MIN, "post_image")
