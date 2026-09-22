"""A harvest source whose validator was removed from the database (LEDG-2535).

`HarvestSourceValidation.by` is a plain `ReferenceField`: mongoengine refuses
`reverse_delete_rule` on an EmbeddedDocument field, the official deletion path
keeps the user document rather than removing it, and there is no user purge —
so the reference goes dangling only through a direct write to the database, and
nothing in the application is on that path to clean it up.

Marshalling dereferences it, so one such source used to answer 500 with an empty
body for the *whole* sources listing — every other source went down with it, and
nginx reported the empty 500 as a 502.
"""

import pytest
from flask import url_for

from udata.api import fields
from udata.core.user.api_fields import user_ref_fields
from udata.core.user.factories import UserFactory
from udata.tests.api import PytestOnlyAPITestCase
from udata.tests.helpers import assert200

from ..models import VALIDATION_ACCEPTED, HarvestSourceValidation
from .factories import HarvestSourceFactory, MockBackendsMixin


class OrphanUserRefsInHarvestApiTest(MockBackendsMixin, PytestOnlyAPITestCase):
    def orphan_validator_source(self):
        """A source validated by a user that no longer exists in the database.

        `HarvestSourceFactory` does not populate `validation`, so it is built
        here. The user is removed with `_delete()` — the door the model itself
        offers, `delete()` being a `NotImplementedError` — which fires the
        `reverse_delete_rule`s registered against `User`. None of them covers
        `validation.by`, which is precisely why it is left dangling.
        """
        user = UserFactory()
        source = HarvestSourceFactory(
            validation=HarvestSourceValidation(state=VALIDATION_ACCEPTED, by=user)
        )
        user._delete()
        return source

    def test_orphan_validator_does_not_break_the_listing(self):
        orphan = self.orphan_validator_source()
        healthy_user = UserFactory()
        healthy = HarvestSourceFactory(
            validation=HarvestSourceValidation(state=VALIDATION_ACCEPTED, by=healthy_user)
        )

        response = self.get(url_for("api.harvest_sources"))

        assert200(response)
        by_id = {source["id"]: source for source in response.json["data"]}
        assert set(by_id) == {str(orphan.id), str(healthy.id)}

        # The dangling reference is nulled, and nothing else about the source is
        # lost: it stays in the listing with the rest of its validation intact.
        assert by_id[str(orphan.id)]["validation"]["by"] is None
        assert by_id[str(orphan.id)]["validation"]["state"] == VALIDATION_ACCEPTED

        # A neighbour with a live validator is untouched — the tolerance is per
        # field, not a blanket null.
        assert by_id[str(healthy.id)]["validation"]["by"]["id"] == str(healthy_user.id)

    def test_tolerant_nested_refuses_to_promise_what_it_may_not_deliver(self):
        # The field answers null on a dangling reference, so a declaration that
        # forbids null describes an endpoint that does not exist. Caught at
        # import time rather than by a client that trusted the schema.
        with pytest.raises(ValueError):
            fields.TolerantNested(user_ref_fields)

    def test_orphan_validator_does_not_break_the_detail(self):
        orphan = self.orphan_validator_source()

        response = self.get(url_for("api.harvest_source", source=str(orphan.id)))

        assert200(response)
        assert response.json["validation"]["by"] is None
        assert response.json["validation"]["state"] == VALIDATION_ACCEPTED
