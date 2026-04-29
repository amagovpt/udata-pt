import pytest
from flask import url_for

from udata.core.pages.factories import PageFactory
from udata.core.site.models import Site
from udata.core.user.factories import AdminFactory
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
