import pytest
from flask import url_for

from udata.core.dataservices.factories import (
    DataserviceFactory,  # noqa: F401 - registers Dataservice model
)
from udata.core.dataset.factories import DatasetFactory, LicenseFactory
from udata.core.organization.factories import OrganizationFactory
from udata.core.pages.factories import PageFactory
from udata.core.reuse.factories import ReuseFactory
from udata.core.site.models import Site
from udata.core.user.factories import AdminFactory, UserFactory
from udata.tests.api import APITestCase
from udata.tests.helpers import capture_mails


class SiteAPITest(APITestCase):
    def test_get_site(self):
        response = self.get(url_for("api.site"))
        self.assert200(response)

        site = Site.objects.get(id=self.app.config["SITE_ID"])

        self.assertEqual(site.title, response.json["title"])
        self.assertIsNotNone(response.json["version"])

    def test_set_site(self):
        response = self.get(url_for("api.site"))
        self.assert200(response)

        site = Site.objects.get(id=self.app.config["SITE_ID"])
        ids = [p.id for p in PageFactory.create_batch(3)]
        self.login(AdminFactory())

        response = self.patch(
            url_for("api.site"),
            {
                "datasets_page": ids[0],
                "reuses_page": ids[1],
                "dataservices_page": ids[2],
            },
        )

        self.assert200(response)
        self.assertEqual(response.json["title"], site.title)

        site = Site.objects.get(id=self.app.config["SITE_ID"])

        self.assertEqual(site.datasets_page.id, ids[0])
        self.assertEqual(site.reuses_page.id, ids[1])
        self.assertEqual(site.dataservices_page.id, ids[2])


class SiteContactAPITest(APITestCase):
    @pytest.mark.options(MAIL_DEFAULT_RECEIVER="support@example.org", DEFAULT_LANGUAGE="en")
    def test_post_contact_question_sends_email(self):
        with capture_mails() as mails:
            response = self.post(
                url_for("api.site_contact"),
                {
                    "topic": "question",
                    "email": "user@example.org",
                    "subject": "How do I publish?",
                    "message": "I would like to publish a dataset.",
                },
            )

        self.assertStatus(response, 204)
        assert len(mails) == 1
        sent = mails[0]
        assert sent.recipients == ["support@example.org"]
        assert sent.reply_to == "user@example.org"
        assert "Question" in sent.subject
        assert "How do I publish?" in sent.subject
        assert "user@example.org" in sent.body
        assert "I would like to publish a dataset." in sent.body

    @pytest.mark.options(MAIL_DEFAULT_RECEIVER="support@example.org", DEFAULT_LANGUAGE="en")
    def test_post_contact_each_topic_emits_distinct_subject_prefix(self):
        prefixes = {}
        for topic, expected in (
            ("question", "Question"),
            ("bug", "Problem"),
            ("feedback", "Feedback"),
        ):
            with capture_mails() as mails:
                response = self.post(
                    url_for("api.site_contact"),
                    {
                        "topic": topic,
                        "email": "user@example.org",
                        "subject": "S",
                        "message": "M",
                    },
                )
            self.assertStatus(response, 204)
            assert len(mails) == 1
            prefixes[topic] = mails[0].subject

        for topic, expected in (
            ("question", "Question"),
            ("bug", "Problem"),
            ("feedback", "Feedback"),
        ):
            assert expected in prefixes[topic]

    @pytest.mark.options(MAIL_DEFAULT_RECEIVER="support@example.org")
    def test_post_contact_rejects_unknown_topic(self):
        with capture_mails() as mails:
            response = self.post(
                url_for("api.site_contact"),
                {
                    "topic": "spam",
                    "email": "user@example.org",
                    "subject": "S",
                    "message": "M",
                },
            )
        self.assert400(response)
        assert mails == []

    @pytest.mark.options(MAIL_DEFAULT_RECEIVER="support@example.org")
    def test_post_contact_rejects_invalid_email(self):
        with capture_mails() as mails:
            response = self.post(
                url_for("api.site_contact"),
                {
                    "topic": "question",
                    "email": "not-an-email",
                    "subject": "S",
                    "message": "M",
                },
            )
        self.assert400(response)
        assert mails == []

    @pytest.mark.options(MAIL_DEFAULT_RECEIVER="support@example.org")
    def test_post_contact_rejects_missing_fields(self):
        with capture_mails() as mails:
            response = self.post(
                url_for("api.site_contact"),
                {"topic": "question", "email": "user@example.org"},
            )
        self.assert400(response)
        assert mails == []

    @pytest.mark.options(MAIL_DEFAULT_RECEIVER=None, CONTACT_EMAIL=None)
    def test_post_contact_returns_503_when_recipient_unconfigured(self):
        with capture_mails() as mails:
            response = self.post(
                url_for("api.site_contact"),
                {
                    "topic": "question",
                    "email": "user@example.org",
                    "subject": "S",
                    "message": "M",
                },
            )
        self.assertStatus(response, 503)
        assert mails == []

    @pytest.mark.options(MAIL_DEFAULT_RECEIVER=None, CONTACT_EMAIL="fallback@example.org")
    def test_post_contact_falls_back_to_contact_email(self):
        with capture_mails() as mails:
            response = self.post(
                url_for("api.site_contact"),
                {
                    "topic": "question",
                    "email": "user@example.org",
                    "subject": "S",
                    "message": "M",
                },
            )
        self.assertStatus(response, 204)
        assert len(mails) == 1
        assert mails[0].recipients == ["fallback@example.org"]


class SiteDatasetsListingAPITest(APITestCase):
    """LEDG-1836: aggregated endpoint that replaces 14 parallel calls with 1."""

    def test_get_returns_aggregated_payload(self):
        org = OrganizationFactory()
        license = LicenseFactory()
        DatasetFactory.create_batch(3, organization=org, license=license)
        DatasetFactory(tags=["hvd"], organization=org)

        response = self.get(url_for("api.site_datasets_listing"))
        self.assert200(response)

        payload = response.json
        assert set(payload.keys()) == {
            "listing",
            "filter_counts",
            "organizations",
            "licenses",
            "frequencies",
            "granularities",
        }

        listing = payload["listing"]
        assert {"data", "page", "page_size", "total", "next_page", "previous_page"} <= set(
            listing.keys()
        )
        assert listing["total"] >= 4

        counts = payload["filter_counts"]
        for key in (
            "formato_all",
            "formato_tabular",
            "formato_structured",
            "formato_geographic",
            "formato_documents",
            "atualizacao_all",
            "atualizacao_30_days",
            "atualizacao_12_months",
            "atualizacao_3_years",
            "rotulo_all",
            "rotulo_high_value",
        ):
            assert key in counts, f"missing filter count: {key}"
        assert counts["formato_all"] == counts["atualizacao_all"] == counts["rotulo_all"]
        assert counts["rotulo_high_value"] >= 1
        assert counts["atualizacao_all"] >= 4

        assert any(o["id"] == str(org.id) for o in payload["organizations"])
        assert any(lic["id"] == license.id for lic in payload["licenses"])
        assert payload["frequencies"]
        assert payload["granularities"]

    def test_get_respects_query_filter(self):
        org = OrganizationFactory()
        DatasetFactory.create_batch(2, organization=org, title="alpha needle")
        DatasetFactory(organization=org, title="beta haystack")

        response = self.get(url_for("api.site_datasets_listing", q="needle"))
        self.assert200(response)

        listing = response.json["listing"]
        assert listing["total"] == 2
        for ds in listing["data"]:
            assert "needle" in ds["title"]


class SiteReusesListingAPITest(APITestCase):
    """LEDG-1836: aggregated endpoint that replaces 6 parallel calls with 1."""

    def test_get_returns_aggregated_payload(self):
        org = OrganizationFactory()
        ReuseFactory.create_batch(4, organization=org)

        response = self.get(url_for("api.site_reuses_listing"))
        self.assert200(response)

        payload = response.json
        assert set(payload.keys()) == {"listing", "filter_counts", "organizations"}

        listing = payload["listing"]
        assert {"data", "page", "page_size", "total", "next_page", "previous_page"} <= set(
            listing.keys()
        )
        assert listing["total"] >= 4

        counts = payload["filter_counts"]
        for key in (
            "atualizacao_all",
            "atualizacao_30_days",
            "atualizacao_12_months",
            "atualizacao_3_years",
        ):
            assert key in counts, f"missing filter count: {key}"
        assert counts["atualizacao_all"] >= 4

        assert any(o["id"] == str(org.id) for o in payload["organizations"])


class SiteOrganizationsListingAPITest(APITestCase):
    """LEDG-1836: aggregated endpoint that replaces 3+N parallel calls with 1."""

    def test_get_returns_aggregated_payload(self):
        OrganizationFactory.create_batch(3)
        certified = OrganizationFactory()
        certified.add_badge("certified")
        public_service = OrganizationFactory()
        public_service.add_badge("public-service")

        response = self.get(url_for("api.site_organizations_listing"))
        self.assert200(response)

        payload = response.json
        assert set(payload.keys()) == {"listing", "badges", "badge_counts", "organizations"}

        listing = payload["listing"]
        assert {"data", "page", "page_size", "total", "next_page", "previous_page"} <= set(
            listing.keys()
        )
        assert listing["total"] >= 5

        assert "certified" in payload["badges"]
        assert "public-service" in payload["badges"]
        assert payload["badge_counts"]["certified"] >= 1
        assert payload["badge_counts"]["public-service"] >= 1
        assert payload["organizations"]


class SiteHomeCacheInvalidationTest(APITestCase):
    """LEDG-1860: setting featured datasets/reuses must invalidate /site/home/.

    Each test follows the same pattern that proves cache invalidation:
      1. set initial featured = [first]
      2. GET /site/home/  -> warms the @cache.cached payload with "first"
      3. PUT new featured = [second]  (must call cache.delete("site_home"))
      4. GET /site/home/  -> must surface "second", not the cached "first"

    Without the fix, step 4 would return the warm "first" payload because the
    Flask-Caching key is unchanged.
    """

    def _set_featured(self, endpoint, ids):
        return self.put(url_for(endpoint), ids)

    def test_put_featured_datasets_invalidates_home_cache(self):
        first = DatasetFactory(title="cached-first dataset")
        second = DatasetFactory(title="post-update dataset")
        self.login(AdminFactory())

        # 1 + 2: prime the cache with `first` featured.
        self.assert200(self._set_featured("api.site_home_datasets", [str(first.id)]))
        warm = self.get(url_for("api.site_home"))
        self.assert200(warm)
        warm_titles = [d["title"] for d in warm.json["latest_datasets"]]
        assert "cached-first dataset" in warm_titles
        assert "post-update dataset" not in warm_titles

        # 3: switch featured to `second`.
        self.assert200(self._set_featured("api.site_home_datasets", [str(second.id)]))

        # 4: the very next /site/home/ must reflect the change, not the warm payload.
        fresh = self.get(url_for("api.site_home"))
        self.assert200(fresh)
        fresh_titles = [d["title"] for d in fresh.json["latest_datasets"]]
        assert "post-update dataset" in fresh_titles
        assert "cached-first dataset" not in fresh_titles

    def test_put_featured_reuses_invalidates_home_cache(self):
        org = OrganizationFactory()
        first = ReuseFactory(organization=org, title="cached-first reuse")
        second = ReuseFactory(organization=org, title="post-update reuse")
        self.login(AdminFactory())

        # 1 + 2: prime the cache with `first` featured.
        self.assert200(self._set_featured("api.site_home_reuses", [str(first.id)]))
        warm = self.get(url_for("api.site_home"))
        self.assert200(warm)
        # 3: switch featured to `second`.
        self.assert200(self._set_featured("api.site_home_reuses", [str(second.id)]))
        # 4: confirm /site/home/ payload re-runs and the change is visible.
        fresh = self.get(url_for("api.site_home"))
        self.assert200(fresh)
        fresh_titles = [r["title"] for r in fresh.json["latest_reuses"]]
        assert "post-update reuse" in fresh_titles
        assert "cached-first reuse" not in fresh_titles


class SiteHomeOwnerSerializationTest(APITestCase):
    """LEDG-1861: /site/home/ must expose dataset.owner so user-authored
    datasets can be attributed (and linked to /pages/users/<slug>) on the
    homepage card instead of falling back to "Sem Organização"."""

    def test_dataset_owner_present_when_no_organization(self):
        author = UserFactory(first_name="Ana", last_name="Carvalho")
        target = DatasetFactory(
            title="user-authored dataset",
            owner=author,
            organization=None,
        )
        self.login(AdminFactory())
        self.assert200(self.put(url_for("api.site_home_datasets"), [str(target.id)]))

        response = self.get(url_for("api.site_home"))
        self.assert200(response)

        items = response.json["latest_datasets"]
        match = next((d for d in items if d["title"] == "user-authored dataset"), None)
        assert match is not None
        assert match["organization"] is None
        owner = match["owner"]
        assert owner is not None
        assert owner["slug"] == author.slug
        assert owner["first_name"] == "Ana"
        assert owner["last_name"] == "Carvalho"
        assert "avatar_thumbnail" in owner

    def test_dataset_owner_none_when_organization_present(self):
        org = OrganizationFactory()
        target = DatasetFactory(
            title="org-authored dataset",
            owner=UserFactory(),
            organization=org,
        )
        self.login(AdminFactory())
        self.assert200(self.put(url_for("api.site_home_datasets"), [str(target.id)]))

        response = self.get(url_for("api.site_home"))
        self.assert200(response)
        match = next(
            (d for d in response.json["latest_datasets"] if d["title"] == "org-authored dataset"),
            None,
        )
        assert match is not None
        # When an organization is set the card uses it, but `owner` is still
        # serialised so consumers can choose attribution logic on the client.
        assert match["organization"]["name"] == org.name
        assert match["owner"] is not None
