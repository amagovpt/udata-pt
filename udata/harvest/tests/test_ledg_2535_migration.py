"""The harvest sources lose their references to users that no longer exist (LEDG-2535).

What the migration has to prove: a dangling reference is unset and nothing
around it is lost -- the validation keeps its state and its date, so the record
of *that it was validated* survives losing the record of *by whom* -- a live
reference is left alone, and running twice changes nothing.

`owner` is covered here too, and only here: it is dereferenced by the permission
checks behind the `url` and `config` attributes, so no tolerant field reaches it
and repairing the data is the whole fix.
"""

import pytest
from mongoengine.connection import get_db

from udata.core.organization.factories import OrganizationFactory
from udata.core.user.factories import UserFactory
from udata.tests.api import PytestOnlyDBTestCase

from ..models import VALIDATION_ACCEPTED, HarvestSourceValidation
from .factories import HarvestSourceFactory
from .test_ckanpt_migrations import load_migration

MIGRATION = "2026-09-22-harvest-sources-user-integrity.py"


@pytest.mark.usefixtures("app")
class HarvestSourcesUserIntegrityMigrationTest(PytestOnlyDBTestCase):
    def _migrate(self):
        load_migration(MIGRATION).migrate(None)

    def _validated_source(self, **kwargs):
        user = UserFactory()
        source = HarvestSourceFactory(
            validation=HarvestSourceValidation(state=VALIDATION_ACCEPTED, by=user), **kwargs
        )
        return source, user

    def _drop_user(self, user):
        """Remove the user the way the incidents did: straight in the database.

        `User._delete()` would fire the `reverse_delete_rule`s registered
        against it, which is exactly what did *not* happen to the documents this
        migration repairs -- and for `owner`, whose rule is NULLIFY, it would
        leave nothing dangling at all.
        """
        get_db().user.delete_one({"_id": user.id})

    def test_dangling_validator_is_unset(self):
        source, user = self._validated_source()
        validated_on = source.validation.on
        self._drop_user(user)

        self._migrate()

        source.reload()
        assert source.validation.by is None
        # The validation itself survives losing its author.
        assert source.validation.state == VALIDATION_ACCEPTED
        assert source.validation.on == validated_on

    def test_dangling_owner_is_unset(self):
        owner = UserFactory()
        source = HarvestSourceFactory(owner=owner)
        self._drop_user(owner)

        self._migrate()

        source.reload()
        assert source.owner is None

    def test_dangling_organization_is_unset(self):
        # Not a user reference, and not what the incident was about — but the
        # same corridor: the permission checks read `organization` before any
        # field is serialized, so the tolerant field never reaches it and only
        # this migration repairs it.
        organization = OrganizationFactory()
        source = HarvestSourceFactory(organization=organization)
        get_db().organization.delete_one({"_id": organization.id})

        self._migrate()

        source.reload()
        assert source.organization is None

    def test_both_dangling_references_on_one_source_are_unset(self):
        # The realistic worst case, and the one that pins the two passes
        # together: they touch the same document, so neither may leave it in a
        # state the other cannot read.
        owner = UserFactory()
        source, validator = self._validated_source(owner=owner)
        self._drop_user(validator)
        self._drop_user(owner)

        self._migrate()

        source.reload()
        assert source.validation.by is None
        assert source.owner is None
        assert source.validation.state == VALIDATION_ACCEPTED

    def test_live_references_are_kept(self):
        # Two sources, because `Owned` treats `owner` and `organization` as
        # mutually exclusive and nulls one when the other is set.
        owner = UserFactory()
        owned, validator = self._validated_source(owner=owner)
        organization = OrganizationFactory()
        run_by_org = HarvestSourceFactory(organization=organization)

        self._migrate()

        owned.reload()
        run_by_org.reload()
        assert owned.validation.by == validator
        assert owned.owner == owner
        assert run_by_org.organization == organization

    def test_is_idempotent(self):
        source, user = self._validated_source()
        self._drop_user(user)

        self._migrate()
        self._migrate()

        source.reload()
        assert source.validation.by is None
        assert source.validation.state == VALIDATION_ACCEPTED
