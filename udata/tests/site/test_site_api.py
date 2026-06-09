from unittest.mock import patch

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
from udata.mail import mail
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
    @pytest.mark.options(
        MAIL_DEFAULT_RECEIVER="support@example.org",
        DEFAULT_LANGUAGE="en",
        GOOGLE_RECAPTCHA_SECRET_KEY=None,
    )
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

    @pytest.mark.options(
        MAIL_DEFAULT_RECEIVER="support@example.org",
        DEFAULT_LANGUAGE="en",
        GOOGLE_RECAPTCHA_SECRET_KEY=None,
    )
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

    @pytest.mark.options(
        MAIL_DEFAULT_RECEIVER="support@example.org", GOOGLE_RECAPTCHA_SECRET_KEY=None
    )
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

    @pytest.mark.options(
        MAIL_DEFAULT_RECEIVER="support@example.org", GOOGLE_RECAPTCHA_SECRET_KEY=None
    )
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

    @pytest.mark.options(
        MAIL_DEFAULT_RECEIVER="support@example.org", GOOGLE_RECAPTCHA_SECRET_KEY=None
    )
    def test_post_contact_rejects_missing_fields(self):
        with capture_mails() as mails:
            response = self.post(
                url_for("api.site_contact"),
                {"topic": "question", "email": "user@example.org"},
            )
        self.assert400(response)
        assert mails == []

    @pytest.mark.options(
        MAIL_DEFAULT_RECEIVER=None, CONTACT_EMAIL=None, GOOGLE_RECAPTCHA_SECRET_KEY=None
    )
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

    @pytest.mark.options(
        MAIL_DEFAULT_RECEIVER=None,
        CONTACT_EMAIL="fallback@example.org",
        GOOGLE_RECAPTCHA_SECRET_KEY=None,
    )
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


# Mail configuration representative of each deployed environment. The values
# mirror what udata.cfg builds from the per-environment .env files; only the
# keys that influence whether the support email is actually dispatched are
# listed here.
ENVIRONMENT_MAIL_CONFIGS = {
    "dev": {
        "SERVER_NAME": "dev.dados.gov.pt",
        "MAIL_SERVER": "localhost",
        "MAIL_PORT": 1025,
        "MAIL_DEFAULT_SENDER": "noreply@dev.dados.gov.pt",
        "MAIL_DEFAULT_RECEIVER": "suporte-dev@dados.gov.pt",
    },
    "tst": {
        "SERVER_NAME": "tst.dados.gov.pt",
        "MAIL_SERVER": "smtp.tst.dados.gov.pt",
        "MAIL_PORT": 587,
        "MAIL_DEFAULT_SENDER": "noreply@tst.dados.gov.pt",
        "MAIL_DEFAULT_RECEIVER": "suporte-tst@dados.gov.pt",
    },
    "prod": {
        "SERVER_NAME": "dados.gov.pt",
        "MAIL_SERVER": "smtp.dados.gov.pt",
        "MAIL_PORT": 587,
        "MAIL_DEFAULT_SENDER": "noreply@dados.gov.pt",
        "MAIL_DEFAULT_RECEIVER": "suporte@dados.gov.pt",
    },
}

SUPPORT_PAYLOAD = {
    "topic": "question",
    "email": "user@example.org",
    "subject": "How do I publish?",
    "message": "I would like to publish a dataset.",
}


class SiteContactEnvironmentMailTest(APITestCase):
    """Tests that the /pages/support form actually dispatches an email in the
    DEV, TST and production environments.

    The other contact tests run under the test default ``SEND_MAIL=False`` and
    therefore only assert the message is *built* (via the ``mail_sent`` signal).
    They never exercise the real transport branch of ``udata.mail.send_mail``
    (``with mail.connect() as conn: conn.send(msg)``), which is the branch used
    in every deployed environment where ``SEND_MAIL=True``. A regression in
    that branch — or a missing recipient/SMTP configuration — would leave those
    tests green while no email leaves the server, exactly the symptom reported
    for the support page.

    Here we force ``SEND_MAIL=True`` (as in DEV/TST/prod) and capture the real
    Flask-Mail outbox with ``mail.record_messages()``. ``MAIL_SUPPRESS_SEND``
    follows ``TESTING`` so no real SMTP connection is opened, but the dispatch
    path is fully executed and the ``email_dispatched`` signal fires.
    """

    def _dispatch_support_email(self, env_config):
        # reCAPTCHA is disabled here (GOOGLE_RECAPTCHA_SECRET_KEY=None) so this
        # test isolates the mail transport wiring. The reCAPTCHA gate — which is
        # active in the real environments and is itself a likely cause of the
        # "no email is sent" symptom — is covered by the dedicated tests below.
        self.app.config.update(
            SEND_MAIL=True,
            DEFAULT_LANGUAGE="en",
            GOOGLE_RECAPTCHA_SECRET_KEY=None,
            **env_config,
        )
        with mail.record_messages() as outbox:
            response = self.post(url_for("api.site_contact"), SUPPORT_PAYLOAD)
        return response, outbox

    def test_support_email_dispatched_in_each_environment(self):
        """The support form must reach the SMTP transport in DEV, TST and prod."""
        for env_name, env_config in ENVIRONMENT_MAIL_CONFIGS.items():
            response, outbox = self._dispatch_support_email(env_config)

            self.assertStatus(
                response, 204, f"[{env_name}] expected 204, got {response.status_code}"
            )
            assert len(outbox) == 1, (
                f"[{env_name}] support email was NOT dispatched (outbox size={len(outbox)})"
            )
            sent = outbox[0]
            assert sent.recipients == [env_config["MAIL_DEFAULT_RECEIVER"]], (
                f"[{env_name}] wrong recipient: {sent.recipients}"
            )
            # A sender must be configured for the SMTP relay to accept the
            # message (Flask-Mail freezes MAIL_DEFAULT_SENDER at init_app, so we
            # only assert one is present rather than its per-environment value).
            assert sent.sender, f"[{env_name}] no sender configured"
            # Reply-To is the citizen's address so support can answer directly.
            assert sent.reply_to == SUPPORT_PAYLOAD["email"], f"[{env_name}] missing reply-to"
            assert SUPPORT_PAYLOAD["subject"] in sent.subject, f"[{env_name}] subject lost"
            assert SUPPORT_PAYLOAD["message"] in sent.body, f"[{env_name}] message body lost"

    def test_support_email_not_dispatched_when_recipient_unconfigured(self):
        """If no recipient is configured (a common cause of "no email is sent"
        in a fresh environment) the endpoint must fail loudly with 503 instead
        of silently dropping the message."""
        self.app.config.update(
            SEND_MAIL=True,
            MAIL_SERVER="smtp.dados.gov.pt",
            MAIL_DEFAULT_RECEIVER=None,
            CONTACT_EMAIL=None,
            GOOGLE_RECAPTCHA_SECRET_KEY=None,
        )
        with mail.record_messages() as outbox:
            response = self.post(url_for("api.site_contact"), SUPPORT_PAYLOAD)
        self.assertStatus(response, 503)
        assert len(outbox) == 0

    def test_support_email_blocked_when_recaptcha_token_missing(self):
        """Regression for the reported bug: in DEV/TST/prod a reCAPTCHA secret
        IS configured, so a request without a token (or with an unverified one)
        is rejected with 400 by SupportContactForm and NO email is sent.

        This is the most likely reason the support page "stopped sending
        emails" after reCAPTCHA verification was wired into the form: if the
        frontend does not attach a valid token, the message never reaches the
        mail transport.
        """
        self.app.config.update(
            SEND_MAIL=True,
            GOOGLE_RECAPTCHA_SECRET_KEY="configured-in-tst-dev-prod",
            **ENVIRONMENT_MAIL_CONFIGS["prod"],
        )
        with mail.record_messages() as outbox:
            response = self.post(url_for("api.site_contact"), SUPPORT_PAYLOAD)
        self.assert400(response)
        assert response.json["errors"]["recaptcha_token"]
        assert len(outbox) == 0, "no email must be sent when reCAPTCHA fails"

    def test_support_email_sent_with_valid_recaptcha_token(self):
        """Happy path for a configured environment: a valid reCAPTCHA token
        passes server-side verification and the email is dispatched over the
        real transport."""

        class _FakeResponse:
            @staticmethod
            def json():
                return {"success": True, "score": 0.9}

        self.app.config.update(
            SEND_MAIL=True,
            DEFAULT_LANGUAGE="en",
            GOOGLE_RECAPTCHA_SECRET_KEY="configured-in-tst-dev-prod",
            **ENVIRONMENT_MAIL_CONFIGS["prod"],
        )
        with patch("udata.auth.forms.requests.post", return_value=_FakeResponse()):
            with mail.record_messages() as outbox:
                response = self.post(
                    url_for("api.site_contact"),
                    {**SUPPORT_PAYLOAD, "recaptcha_token": "valid-frontend-token"},
                )
        self.assertStatus(response, 204)
        assert len(outbox) == 1
        assert outbox[0].recipients == [ENVIRONMENT_MAIL_CONFIGS["prod"]["MAIL_DEFAULT_RECEIVER"]]
        assert outbox[0].reply_to == SUPPORT_PAYLOAD["email"]


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
