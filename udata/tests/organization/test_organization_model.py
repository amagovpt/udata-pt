from datetime import UTC, datetime

import pytest
from mongoengine.errors import ValidationError

import udata.core.organization.constants as org_constants
from udata.core.dataservices.factories import DataserviceFactory
from udata.core.dataservices.models import Dataservice
from udata.core.dataset.factories import DatasetFactory, HiddenDatasetFactory
from udata.core.discussions.factories import DiscussionFactory
from udata.core.followers.signals import on_follow, on_unfollow
from udata.core.organization.factories import OrganizationFactory
from udata.core.organization.models import Organization, OrganizationBadge
from udata.core.reuse.factories import ReuseFactory, VisibleReuseFactory
from udata.core.user.factories import UserFactory
from udata.models import Dataset, Follow, Member, Reuse
from udata.tests.api import DBTestCase
from udata.tests.helpers import assert_emit


class OrganizationModelTest(DBTestCase):
    # Load metrics
    import udata.core.organization.metrics  # noqa
    import udata.core.discussions.metrics  # noqa
    import udata.core.followers.metrics  # noqa

    def test_metrics_recount_preserves_last_modified(self):
        """Recounting metrics must not move the date the organisation's card shows.

        None of these recounts is someone editing the organisation: a dataset was
        published, a reuse was created, somebody followed it, a discussion was
        opened, a member was counted. Persisting them with `save()` ran the
        `Datetimed` pre_save hook and stamped `last_modified`, so the card — and
        the listing's default ordering — tracked activity instead of edits.

        Each recount runs from its own instance, loaded before the others wrote.
        That is what production looks like — the DCAT harvester holds organisations
        for a whole crawl and counts them at the end — and it is what makes the
        metric assertions mean something: with a single shared instance they would
        pass even if each write clobbered the previous one.
        """
        pinned = datetime(2020, 1, 1)
        org = OrganizationFactory(members=[Member(user=UserFactory(), role="admin")])
        # Queryset write: it does not go through pre_save, so it pins the date
        # without the hook rewriting it on the way in.
        Organization.objects(id=org.id).update(set__last_modified=pinned)

        DatasetFactory(organization=org)
        VisibleReuseFactory(organization=org)
        DataserviceFactory(organization=org)
        Follow.objects.create(following=org, follower=UserFactory(), since=datetime.now(UTC))
        DiscussionFactory(subject=org, user=UserFactory())

        # Discussions and members recount through their own method rather than a
        # signal: the discussion receiver drags in notification senders that need
        # the API blueprint, and members are only ever counted from the API. Each
        # gets a freshly loaded instance, so neither can carry the other's writes.
        Organization.objects(id=org.id).first().count_discussions()
        Organization.objects(id=org.id).first().count_members()

        stored = Organization.objects(id=org.id).first()
        assert stored.get_metrics()["datasets"] == 1
        assert stored.get_metrics()["reuses"] == 1
        assert stored.get_metrics()["dataservices"] == 1
        assert stored.get_metrics()["followers"] == 1
        assert stored.get_metrics()["discussions"] == 1
        assert stored.get_metrics()["members"] == 1
        assert stored.last_modified == pinned

    def test_metrics_recount_does_not_clobber_other_counters(self):
        """A recount writes its own counters and leaves everyone else's alone.

        These run from instances loaded long before they are used, so persisting
        the whole `metrics` dict would roll back whatever another process wrote in
        between — the view and download counters are written that way by their own
        task — or drop keys the stale instance never loaded.
        """
        org = OrganizationFactory()
        stale = Organization.objects(id=org.id).first()

        Organization.objects(id=org.id).update(set__metrics__views=99)
        stale.count_followers()

        stored = Organization.objects(id=org.id).first()
        assert stored.get_metrics()["views"] == 99
        assert stored.get_metrics()["followers"] == 0

    def test_real_edit_stamps_last_modified(self):
        """The other half of the rule: editing the organisation still moves the date."""
        pinned = datetime(2020, 1, 1)
        org = OrganizationFactory()
        Organization.objects(id=org.id).update(set__last_modified=pinned)
        org.reload()

        org.description = "A new description"
        org.save()

        org.reload()
        assert org.last_modified > pinned

    def test_organization_metrics(self):
        # Members count update are in API calls, thus being tested in API dedicated tests

        member = Member(user=UserFactory(), role="admin")
        org = OrganizationFactory(members=[member])

        with assert_emit(Reuse.on_create):
            reuse = VisibleReuseFactory(organization=org)
            ReuseFactory(organization=org)
        with assert_emit(Dataservice.on_create):
            dataservice = DataserviceFactory(organization=org)
        with assert_emit(Dataset.on_create):
            dataset = DatasetFactory(organization=org)
            HiddenDatasetFactory(organization=org)
        with assert_emit(on_follow):
            follow = Follow.objects.create(
                following=org, follower=UserFactory(), since=datetime.now(UTC)
            )

        assert org.get_metrics()["datasets"] == 1
        assert org.get_metrics()["reuses"] == 1
        assert org.get_metrics()["dataservices"] == 1
        assert org.get_metrics()["followers"] == 1

        with assert_emit(Reuse.on_delete):
            reuse.deleted = datetime.now(UTC)
            reuse.save()
        with assert_emit(Dataservice.on_delete):
            dataservice.deleted_at = datetime.now(UTC)
            dataservice.save()
        with assert_emit(Dataset.on_delete):
            dataset.deleted = datetime.now(UTC)
            dataset.save()
        with assert_emit(on_unfollow):
            follow.until = datetime.now(UTC)
            follow.save()

        assert org.get_metrics()["datasets"] == 0
        assert org.get_metrics()["reuses"] == 0
        assert org.get_metrics()["dataservices"] == 0
        assert org.get_metrics()["followers"] == 0

    def test_organization_queryset_with_badge(self):
        org_public_service = OrganizationFactory()
        org_public_service.add_badge(org_constants.PUBLIC_SERVICE)
        org_certified_association = OrganizationFactory()
        org_certified_association.add_badge(org_constants.CERTIFIED)
        org_certified_association.add_badge(org_constants.ASSOCIATION)

        public_services = list(Organization.objects.with_badge(org_constants.PUBLIC_SERVICE))
        assert len(public_services) == 1
        assert org_public_service in public_services

        certified = list(Organization.objects.with_badge(org_constants.CERTIFIED))
        assert len(certified) == 1
        assert org_certified_association in certified

        associations = list(Organization.objects.with_badge(org_constants.ASSOCIATION))
        assert len(associations) == 1
        assert org_certified_association in associations

    def test_organization__url(self):
        with pytest.raises(ValidationError):
            OrganizationFactory(url="not-an-url")


class OrganizationBadgeTest(DBTestCase):
    # Model badges can be extended in plugins, for example in our previous plugin udata-front
    # for french only badges.
    Organization.__badges__["new"] = "new"

    def test_validation(self):
        """It should validate default badges as well as extended ones"""
        badge = OrganizationBadge(kind="public-service")
        badge.validate()

        badge = OrganizationBadge(kind="new")
        badge.validate()

        with self.assertRaises(ValidationError):
            badge = OrganizationBadge(kind="doesnotexist")
            badge.validate()
