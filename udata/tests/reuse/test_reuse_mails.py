import pytest
from flask import url_for

from udata.core.dataset.factories import DatasetFactory
from udata.core.organization.factories import OrganizationFactory
from udata.core.organization.models import Member
from udata.core.reuse.factories import ReuseFactory
from udata.core.reuse.tasks import notify_new_reuse
from udata.core.user.factories import UserFactory
from udata.tests.api import APITestCase
from udata.tests.helpers import capture_mails


class ReuseNotificationMailTest(APITestCase):
    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_notify_new_reuse_to_dataset_owner(self):
        """Notify dataset owner when a reuse references their dataset."""
        owner = UserFactory()
        dataset = DatasetFactory(owner=owner)
        reuse = ReuseFactory(datasets=[dataset], owner=UserFactory())

        with capture_mails() as mails:
            notify_new_reuse(str(reuse.id))

        assert len(mails) == 1
        assert mails[0].recipients[0] == owner.email
        assert "reuse" in mails[0].subject.lower()

    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_notify_new_reuse_to_org_members(self):
        """Notify all org members when a reuse references an org dataset."""
        admin = UserFactory()
        editor = UserFactory()
        org = OrganizationFactory(
            members=[
                Member(user=admin, role="admin"),
                Member(user=editor, role="editor"),
            ]
        )
        dataset = DatasetFactory(organization=org)
        reuse = ReuseFactory(datasets=[dataset], owner=UserFactory())

        with capture_mails() as mails:
            notify_new_reuse(str(reuse.id))

        assert len(mails) == 2
        recipients = {m.recipients[0] for m in mails}
        assert admin.email in recipients
        assert editor.email in recipients

    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_notify_new_reuse_multiple_datasets(self):
        """Notify owners of each dataset referenced by the reuse."""
        owner1 = UserFactory()
        owner2 = UserFactory()
        dataset1 = DatasetFactory(owner=owner1)
        dataset2 = DatasetFactory(owner=owner2)
        reuse = ReuseFactory(datasets=[dataset1, dataset2], owner=UserFactory())

        with capture_mails() as mails:
            notify_new_reuse(str(reuse.id))

        assert len(mails) == 2
        recipients = {m.recipients[0] for m in mails}
        assert owner1.email in recipients
        assert owner2.email in recipients

    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_no_notification_when_dataset_has_no_owner(self):
        """No mail sent if dataset has neither owner nor organization."""
        dataset = DatasetFactory(owner=None, organization=None)
        reuse = ReuseFactory(datasets=[dataset], owner=UserFactory())

        with capture_mails() as mails:
            notify_new_reuse(str(reuse.id))

        assert len(mails) == 0

    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_reuse_mail_contains_reuse_title(self):
        """Mail body should contain the reuse title."""
        owner = UserFactory()
        dataset = DatasetFactory(owner=owner)
        reuse = ReuseFactory(title="My Amazing Reuse", datasets=[dataset], owner=UserFactory())

        with capture_mails() as mails:
            notify_new_reuse(str(reuse.id))

        assert len(mails) == 1
        assert "My Amazing Reuse" in mails[0].body
        assert "My Amazing Reuse" in mails[0].html


class ReuseAPIMailTest(APITestCase):
    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_create_reuse_with_dataset_triggers_notification(self):
        """Creating a reuse via the API with datasets should trigger notification."""
        self.login()
        dataset = DatasetFactory(owner=UserFactory())

        response = self.post(
            url_for("api.reuses"),
            {
                "title": "Test Reuse",
                "description": "A test reuse",
                "url": "https://example.com/reuse",
                "type": "application",
                "topic": "housing_and_development",
                "datasets": [{"id": str(dataset.id)}],
            },
        )
        self.assert201(response)

    @pytest.mark.options(DEFAULT_LANGUAGE="en")
    def test_create_reuse_without_dataset_no_notification(self):
        """Creating a reuse via the API without datasets should not trigger notification."""
        self.login()

        with capture_mails() as mails:
            response = self.post(
                url_for("api.reuses"),
                {
                    "title": "Test Reuse",
                    "description": "A test reuse",
                    "url": "https://example.com/reuse",
                    "type": "application",
                    "topic": "housing_and_development",
                },
            )
        self.assert201(response)
        assert len(mails) == 0
