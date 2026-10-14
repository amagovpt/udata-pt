from flask import url_for

from udata.api.oauth2 import OAuth2Client
from udata.core import storages
from udata.core.dataset.factories import DatasetFactory, ResourceFactory
from udata.core.discussions.models import Discussion, Message
from udata.core.organization import tasks
from udata.core.user.factories import AdminFactory, UserFactory
from udata.models import ContactPoint, Dataset, Member, Organization, Transfer
from udata.tests.api import APITestCase
from udata.tests.helpers import create_test_image


class OrganizationTasksTest(APITestCase):
    def test_purge_organizations(self):
        self.login()
        member = Member(user=self.user, role="admin")
        org = Organization.objects.create(name="delete me", description="XXX", members=[member])
        data = {
            "email": "mooneywayne@cobb-cochran.com",
            "name": "Martin Schultz",
            "organization": str(org.id),
            "role": "contact",
        }
        response = self.post(url_for("api.contact_points"), data)
        self.assert201(response)

        # `len(list(...))` rather than `.count()`: mongoengine routes an *unfiltered*
        # count to `estimated_document_count()`, which reads collection metadata and
        # can be wrong in either direction -- including reporting zero while a document
        # that should have been removed is still there.
        self.assertEqual(len(list(ContactPoint.objects())), 1)

        resources = [ResourceFactory() for _ in range(2)]
        dataset = DatasetFactory(resources=resources, organization=org)

        # Upload organization's logo
        file = create_test_image()
        user = AdminFactory()
        self.login(user)
        response = self.post(
            url_for("api.organization_logo", org=org), {"file": (file, "test.png")}, json=False
        )
        self.assert200(response)

        transfer_to_org = Transfer.objects.create(
            owner=user,
            recipient=org,
            subject=dataset,
            comment="comment",
        )
        transfer_from_org = Transfer.objects.create(
            owner=org,
            recipient=user,
            subject=dataset,
            comment="comment",
        )

        oauth_client = OAuth2Client.objects.create(
            name="test-client",
            owner=user,
            organization=org,
            redirect_uris=["https://test.org/callback"],
        )

        # Delete organization
        response = self.delete(url_for("api.organization", org=org))
        self.assert204(response)

        tasks.purge_organizations()

        oauth_client.reload()
        assert oauth_client.organization is None

        assert Transfer.objects.filter(id=transfer_from_org.id).count() == 0
        assert Transfer.objects.filter(id=transfer_to_org.id).count() == 0

        # Check organization's logo is deleted
        self.assertEqual(list(storages.avatars.list_files()), [])

        # Check organization's contact points are deleted
        self.assertEqual(ContactPoint.objects(organization=org).count(), 0)
        self.assertEqual(len(list(ContactPoint.objects())), 0)

        dataset = Dataset.objects(id=dataset.id).first()
        self.assertIsNone(dataset.organization)

        organization = Organization.objects(name="delete me").first()
        self.assertIsNone(organization)

    def test_purge_organizations_deletes_discussions(self):
        """Discussions held on the organization itself go with it."""
        self.login()
        org = Organization.objects.create(
            name="delete me", description="XXX", members=[Member(user=self.user, role="admin")]
        )
        user = UserFactory()
        Discussion.objects.create(
            subject=org,
            user=user,
            title="discussion about the organization",
            discussion=[Message(content="bla bla", posted_by=user)],
        )
        self.assertEqual(Discussion.objects(subject=org).count(), 1)

        response = self.delete(url_for("api.organization", org=org))
        self.assert204(response)

        tasks.purge_organizations()

        self.assertEqual(Discussion.objects(subject=org).count(), 0)
        self.assertEqual(len(list(Discussion.objects())), 0)
