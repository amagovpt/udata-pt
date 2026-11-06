from datetime import UTC, datetime

import pytest
from flask import current_app
from mongoengine.errors import ValidationError

from udata.core import metrics
from udata.core.dataset.factories import DatasetFactory
from udata.core.discussions.factories import DiscussionFactory
from udata.core.organization.factories import OrganizationFactory
from udata.core.reuse.factories import ReuseFactory, VisibleReuseFactory
from udata.core.reuse.models import Reuse, ReuseBadge
from udata.core.user.factories import UserFactory
from udata.i18n import gettext as _
from udata.tests.api import DBTestCase
from udata.tests.helpers import assert_emit


class ReuseModelTest(DBTestCase):
    def test_owned_by_user(self):
        user = UserFactory()
        reuse = ReuseFactory(owner=user)
        ReuseFactory(owner=UserFactory())

        result = Reuse.objects.owned_by(user)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], reuse)

    def test_owned_by_org(self):
        org = OrganizationFactory()
        reuse = ReuseFactory(organization=org)
        ReuseFactory(organization=OrganizationFactory())

        result = Reuse.objects.owned_by(org)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], reuse)

    def test_owned_by_org_or_user(self):
        user = UserFactory()
        org = OrganizationFactory()
        reuses = [ReuseFactory(owner=user), ReuseFactory(organization=org)]
        excluded = [
            ReuseFactory(owner=UserFactory()),
            ReuseFactory(organization=OrganizationFactory()),
        ]

        result = Reuse.objects.owned_by(org, user)

        self.assertEqual(len(result), 2)
        for reuse in result:
            self.assertIn(reuse, reuses)

        for reuse in excluded:
            self.assertNotIn(reuse, result)

    def test_tags_normalized(self):
        user = UserFactory()
        tags = [" one another!", " one another!", 'This IS a "tag"…']
        reuse = ReuseFactory(owner=user, tags=tags)
        self.assertEqual(len(reuse.tags), 2)
        self.assertEqual(reuse.tags[1], "this-is-a-tag")

    def test_send_on_delete(self):
        reuse = ReuseFactory()
        with assert_emit(Reuse.on_delete):
            reuse.deleted = datetime.now(UTC)
            reuse.save()

    def test_reuse_metrics(self):
        # We need to init metrics module
        metrics.init_app(current_app)

        dataset = DatasetFactory()
        reuse = VisibleReuseFactory()
        DiscussionFactory(subject=reuse)

        reuse.count_datasets()
        reuse.count_discussions()

        assert reuse.get_metrics()["datasets"] == 1
        assert reuse.get_metrics()["discussions"] == 1

        with assert_emit(Reuse.on_update):
            reuse.datasets.append(dataset)
            reuse.save()

        assert reuse.get_metrics()["datasets"] == 2

        dataset.reload()
        assert dataset.get_metrics()["reuses"] == 1

        with assert_emit(Reuse.on_update):
            reuse.datasets.remove(dataset)
            reuse.save()

        dataset.reload()
        assert dataset.get_metrics()["reuses"] == 0

    def test_metrics_recount_preserves_last_modified(self):
        """Recounting metrics must not move the date the reuse's card shows.

        None of these is someone editing the reuse: a dataset is attached, a
        discussion is opened, somebody follows it. Persisting them with `save()`
        ran the `Datetimed` pre_save hook and stamped `last_modified`, so the card
        — and the listing's default ordering — tracked activity instead of edits.

        Order matters. The reuse is created with its dataset already attached,
        because that list lives on the reuse document: attaching one after pinning
        the date would need a `save()`, which stamps, and the test would fail for a
        reason it is not testing.

        Each recount runs from its own instance, because the follower receiver
        recounts on the very object it was handed. With one shared instance the
        metric assertions would hold even if each write clobbered the last.
        """
        from udata.models import Follow

        pinned = datetime(2020, 1, 1)
        reuse = VisibleReuseFactory()
        # Queryset write: it does not go through pre_save, so it pins the date
        # without the hook rewriting it on the way in.
        Reuse.objects(id=reuse.id).update(set__last_modified=pinned)

        Follow.objects.create(following=reuse, follower=UserFactory(), since=datetime.now(UTC))
        DiscussionFactory(subject=reuse, user=UserFactory())

        # Called directly rather than through their signals: the discussion
        # receiver drags in notification senders that need the API blueprint, and
        # a fresh instance each time is what makes the assertions mean something.
        Reuse.objects(id=reuse.id).first().count_datasets()
        Reuse.objects(id=reuse.id).first().count_discussions()
        Reuse.objects(id=reuse.id).first().count_followers()

        stored = Reuse.objects(id=reuse.id).first()
        assert stored.get_metrics()["datasets"] == 1
        assert stored.get_metrics()["discussions"] == 1
        assert stored.get_metrics()["followers"] == 1
        assert stored.last_modified == pinned

    def test_metrics_recount_does_not_clobber_other_counters(self):
        """A recount writes its own counters and leaves everyone else's alone.

        `metrics.views` is written key-by-key by the counter tasks, so persisting
        the whole `metrics` dict from an instance loaded earlier would roll it back.
        """
        reuse = ReuseFactory()
        stale = Reuse.objects(id=reuse.id).first()

        Reuse.objects(id=reuse.id).update(set__metrics__views=99)
        stale.count_followers()

        stored = Reuse.objects(id=reuse.id).first()
        assert stored.get_metrics()["views"] == 99
        assert stored.get_metrics()["followers"] == 0

    def test_real_edit_stamps_last_modified(self):
        """The other half of the rule: editing the reuse still moves the date."""
        pinned = datetime(2020, 1, 1)
        reuse = ReuseFactory()
        Reuse.objects(id=reuse.id).update(set__last_modified=pinned)
        reuse.reload()

        reuse.description = "A new description"
        reuse.save()

        reuse.reload()
        assert reuse.last_modified > pinned

    def test_reuse_type(self):
        reuse = ReuseFactory(type="api")
        self.assertEqual(reuse.type, "api")
        self.assertEqual(reuse.type_label, "API")

    def test_reuse_topic(self):
        reuse = ReuseFactory(topic="health")
        self.assertEqual(reuse.topic, "health")
        self.assertEqual(reuse.topic_label, _("Health"))

    def test_reuse_archived(self):
        reuse = ReuseFactory(archived=datetime.now(UTC))
        reuse.save()
        self.assertLess(reuse.archived, datetime.now(UTC))

        reuse.archived = None
        reuse.save()
        self.assertIsNone(reuse.archived)

    def test_reuse_without_private(self):
        reuse = ReuseFactory()
        self.assertEqual(reuse.private, False)

        reuse.private = None
        reuse.save()
        self.assertEqual(reuse.private, False)

        reuse.private = True
        reuse.save()
        self.assertEqual(reuse.private, True)

    def test_reuse_url(self):
        with pytest.raises(ValidationError):
            ReuseFactory(url="not-an-url")


class ReuseBadgeTest(DBTestCase):
    # Model badges can be extended in plugins, for example in our previous plugin udata-front
    # for french only badges.
    Reuse.__badges__["new"] = "new"

    def test_validation(self):
        """It should validate default badges as well as extended ones"""
        badge = ReuseBadge(kind="new")
        badge.validate()

        with self.assertRaises(ValidationError):
            badge = ReuseBadge(kind="doesnotexist")
            badge.validate()
