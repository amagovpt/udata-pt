import logging
from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from flask import url_for
from pytest_mock import MockerFixture

from udata.core.dataservices.factories import DataserviceFactory
from udata.core.dataset.factories import DatasetFactory
from udata.core.organization.factories import OrganizationFactory
from udata.core.user.factories import AdminFactory, UserFactory
from udata.harvest.backends import get_enabled_backends
from udata.i18n import gettext
from udata.models import Member, PeriodicTask
from udata.tests.api import PytestOnlyAPITestCase
from udata.tests.helpers import assert200, assert201, assert204, assert400, assert403, assert404
from udata.utils import faker

from .. import actions
from ..models import (
    VALIDATION_ACCEPTED,
    VALIDATION_PENDING,
    VALIDATION_REFUSED,
    HarvestError,
    HarvestItem,
    HarvestLog,
    HarvestSource,
    HarvestSourceValidation,
)
from .factories import (
    HarvestJobFactory,
    HarvestSourceFactory,
    MockBackendsMixin,
    mock_initialize,
)

log = logging.getLogger(__name__)


class HarvestAPITest(MockBackendsMixin, PytestOnlyAPITestCase):
    def test_list_backends(self):
        """It should fetch the harvest backends list from the API"""
        response = self.get(url_for("api.harvest_backends"))
        assert200(response)
        assert len(response.json) == len(get_enabled_backends())
        for data in response.json:
            assert "id" in data
            assert "label" in data
            assert "filters" in data
            assert isinstance(data["filters"], (list, tuple))
            assert "extra_configs" in data

    def test_list_sources(self):
        sources = HarvestSourceFactory.create_batch(3)

        response = self.get(url_for("api.harvest_sources"))
        assert200(response)
        assert len(response.json["data"]) == len(sources)

    def test_list_sources_exclude_deleted(self):
        sources = HarvestSourceFactory.create_batch(3)
        HarvestSourceFactory.create_batch(2, deleted=datetime.now(UTC))

        response = self.get(url_for("api.harvest_sources"))
        assert200(response)
        assert len(response.json["data"]) == len(sources)

    def test_list_sources_include_deleted(self):
        sources = HarvestSourceFactory.create_batch(3)
        sources.extend(HarvestSourceFactory.create_batch(2, deleted=datetime.now(UTC)))

        response = self.get(url_for("api.harvest_sources", deleted=True))
        assert200(response)
        assert len(response.json["data"]) == len(sources)

    def test_list_sources_for_owner(self):
        owner = UserFactory()
        sources = HarvestSourceFactory.create_batch(3, owner=owner)
        HarvestSourceFactory()

        url = url_for("api.harvest_sources", owner=str(owner.id))
        response = self.get(url)
        assert200(response)

        assert len(response.json["data"]) == len(sources)

    def test_list_sources_for_org(self):
        org = OrganizationFactory()
        sources = HarvestSourceFactory.create_batch(3, organization=org)
        HarvestSourceFactory()

        response = self.get(url_for("api.harvest_sources", owner=str(org.id)))
        assert200(response)

        assert len(response.json["data"]) == len(sources)

    def test_list_sources_search(self):
        HarvestSourceFactory.create_batch(3)
        source = HarvestSourceFactory(name="Moissonneur GeoNetwork de la ville de Rennes")

        url = url_for("api.harvest_sources", q="geonetwork rennes")
        response = self.get(url)
        assert200(response)

        assert len(response.json["data"]) == 1
        assert response.json["data"][0]["id"] == str(source.id)

    def test_list_sources_search_does_not_match_url(self):
        """Searching must not confirm a credential stored in a source URL.

        The text index used to cover `$url`, so `?q=<password>` on this public
        route returned the source carrying it: not a disclosure, but a way for
        someone who had guessed a credential to confirm it (LEDG-2502).
        """
        source = HarvestSourceFactory(
            name="Fonte legada",
            url="https://harvestuser:sup3rs3cr3t@www.ine.pt/broken.xml",
        )

        response = self.get(url_for("api.harvest_sources", q="sup3rs3cr3t"))
        assert200(response)
        assert response.json["data"] == []

        response = self.get(url_for("api.harvest_sources", q="ine.pt"))
        assert200(response)
        assert response.json["data"] == []

        # Searching by name still works -- the index is kept, minus the URL.
        response = self.get(url_for("api.harvest_sources", q="legada"))
        assert200(response)
        assert [s["id"] for s in response.json["data"]] == [str(source.id)]

    def test_list_sources_paginate(self):
        total = 25
        page_size = 20
        HarvestSourceFactory.create_batch(total)

        url = url_for("api.harvest_sources", page=1, page_size=page_size)
        response = self.get(url)
        assert200(response)
        assert len(response.json["data"]) == page_size
        assert response.json["total"] == total

        url = url_for("api.harvest_sources", page=2, page_size=page_size)
        response = self.get(url)
        assert200(response)
        assert len(response.json["data"]) == total - page_size
        assert response.json["total"] == total

        url = url_for("api.harvest_sources", page=3, page_size=page_size)
        response = self.get(url)
        assert404(response)

    def test_create_source_with_owner(self):
        """It should create and attach a new source to an owner"""
        user = self.login()
        data = {"name": faker.word(), "url": faker.url(), "backend": "factory"}
        response = self.post(url_for("api.harvest_sources"), data)

        assert201(response)

        source = response.json
        assert source["validation"]["state"] == VALIDATION_PENDING
        assert source["owner"]["id"] == str(user.id)
        assert source["organization"] is None

    def test_create_source_with_org(self):
        """It should create and attach a new source to an organization"""
        user = self.login()
        member = Member(user=user, role="admin")
        org = OrganizationFactory(members=[member])
        data = {
            "name": faker.word(),
            "url": faker.url(),
            "backend": "factory",
            "organization": str(org.id),
        }
        response = self.post(url_for("api.harvest_sources"), data)

        assert201(response)

        source = response.json
        assert source["validation"]["state"] == VALIDATION_PENDING
        assert source["owner"] is None
        assert source["organization"]["id"] == str(org.id)

    def test_create_source_with_org_not_member(self):
        """It should create and attach a new source to an organization"""
        user = self.login()
        member = Member(user=user, role="editor")
        org = OrganizationFactory(members=[member])
        data = {
            "name": faker.word(),
            "url": faker.url(),
            "backend": "factory",
            "organization": str(org.id),
        }
        response = self.post(url_for("api.harvest_sources"), data)

        assert403(response)

    def test_create_source_with_config(self):
        """It should create a new source with configuration"""
        self.login()
        data = {
            "name": faker.word(),
            "url": faker.url(),
            "backend": "factory",
            "config": {
                "filters": [
                    {"key": "test", "value": 1},
                    {"key": "test", "value": 42},
                    {"key": "tag", "value": "my-tag"},
                ],
                "features": {
                    "test": True,
                    "toggled": True,
                },
                "extra_configs": [
                    {"key": "test_int", "value": 1},
                    {"key": "test_str", "value": "test"},
                ],
            },
        }
        response = self.post(url_for("api.harvest_sources"), data)

        assert201(response)

        source = response.json
        assert source["config"] == {
            "filters": [
                {"key": "test", "value": 1},
                {"key": "test", "value": 42},
                {"key": "tag", "value": "my-tag"},
            ],
            "features": {
                "test": True,
                "toggled": True,
            },
            "extra_configs": [
                {"key": "test_int", "value": 1},
                {"key": "test_str", "value": "test"},
            ],
        }

    def test_create_source_with_unknown_filter(self):
        """Can only use known filters in config"""
        self.login()
        data = {
            "name": faker.word(),
            "url": faker.url(),
            "backend": "factory",
            "config": {
                "filters": [
                    {"key": "unknown", "value": "any"},
                ]
            },
        }
        response = self.post(url_for("api.harvest_sources"), data)

        assert400(response)

    def test_create_source_with_bad_filter_type(self):
        """Can only use the xpected filter type"""
        self.login()
        data = {
            "name": faker.word(),
            "url": faker.url(),
            "backend": "factory",
            "config": {
                "filters": [
                    {"key": "test", "value": "not-an-integer"},
                ]
            },
        }
        response = self.post(url_for("api.harvest_sources"), data)

        assert400(response)

    def test_create_source_with_bad_filter_format(self):
        """Filters should have the right format"""
        self.login()
        data = {
            "name": faker.word(),
            "url": faker.url(),
            "backend": "factory",
            "config": {
                "filters": [
                    {"key": "unknown", "notvalue": "any"},
                ]
            },
        }
        response = self.post(url_for("api.harvest_sources"), data)

        assert400(response)

    def test_create_source_with_unknown_extra_config(self):
        """Can only use known extra config in config"""
        self.login()
        data = {
            "name": faker.word(),
            "url": faker.url(),
            "backend": "factory",
            "config": {
                "extra_configs": [
                    {"key": "unknown", "value": "any"},
                ]
            },
        }
        response = self.post(url_for("api.harvest_sources"), data)

        assert400(response)

    def test_create_source_with_bad_extra_config_type(self):
        """Can only use the expected extra config type"""
        self.login()
        data = {
            "name": faker.word(),
            "url": faker.url(),
            "backend": "factory",
            "config": {
                "extra_configs": [
                    {"key": "test_int", "value": "not-an-integer"},
                ]
            },
        }
        response = self.post(url_for("api.harvest_sources"), data)

        assert400(response)

    def test_create_source_with_bad_extra_config_format(self):
        """Extra config should have the right format"""
        self.login()
        data = {
            "name": faker.word(),
            "url": faker.url(),
            "backend": "factory",
            "config": {
                "extra_configs": [
                    {"key": "unknown", "notvalue": "any"},
                ]
            },
        }
        response = self.post(url_for("api.harvest_sources"), data)

        assert400(response)

    def test_create_source_with_unknown_feature(self):
        """Can only use known features in config"""
        self.login()
        data = {
            "name": faker.word(),
            "url": faker.url(),
            "backend": "factory",
            "config": {
                "features": {"unknown": True},
            },
        }
        response = self.post(url_for("api.harvest_sources"), data)

        assert400(response)

    def test_create_source_with_false_feature(self):
        """It should handled negative values"""
        self.login()
        data = {
            "name": faker.word(),
            "url": faker.url(),
            "backend": "factory",
            "config": {
                "features": {
                    "test": False,
                    "toggled": False,
                }
            },
        }
        response = self.post(url_for("api.harvest_sources"), data)

        assert201(response)

        source = response.json
        assert source["config"] == {
            "features": {
                "test": False,
                "toggled": False,
            }
        }

    def test_create_source_with_not_boolean_feature(self):
        """It should handled negative values"""
        self.login()
        data = {
            "name": faker.word(),
            "url": faker.url(),
            "backend": "factory",
            "config": {
                "features": {
                    "test": "not a boolean",
                }
            },
        }
        response = self.post(url_for("api.harvest_sources"), data)

        assert400(response)

    def test_create_source_with_config_with_custom_key(self):
        self.login()
        data = {
            "name": faker.word(),
            "url": faker.url(),
            "backend": "factory",
            "config": {"custom": "value"},
        }
        response = self.post(url_for("api.harvest_sources"), data)

        assert201(response)

        source = response.json
        assert source["config"] == {"custom": "value"}

    def test_create_source_rejects_url_credentials(self):
        """A source URL may no longer carry `user:password@` (LEDG-2502).

        LEDG-2477 redacted the userinfo everywhere it reached a reader, but the
        portal kept accepting it, so every new serialization path reopened the
        problem. An inventory of production found no source using basic auth in
        its URL, so the field rejects it instead.
        """
        self.login()
        data = {
            "name": faker.word(),
            "url": "https://harvestuser:sup3rs3cr3t@www.ine.pt/broken.xml",
            "backend": "factory",
        }

        response = self.post(url_for("api.harvest_sources"), data)

        assert400(response)
        # Asserted through `gettext` rather than against English: the suite
        # runs in the default locale, and the message is deliberately the msgid
        # `udata.uris` already uses, which is translated for pt and fr.
        with self.app.test_request_context():
            expected = str(gettext("Credentials in URL are not allowed"))
        assert response.json["errors"]["url"] == [expected]
        # The rejection must not repeat the secret back to the caller, which is
        # why this is not `uris.validate(url, credentials=False)`: that one
        # composes `Invalid URL "{url}": {reason}`.
        assert "sup3rs3cr3t" not in str(response.json)
        assert HarvestSource.objects(url__contains="sup3rs3cr3t").count() == 0

    def test_update_source_rejects_url_credentials_until_removed(self):
        """A source stored before the rejection cannot be saved as it is.

        This is the migration path for legacy sources: the PUT revalidates the
        URL, so editing one forces its credentials out. Harvesting it keeps
        working until someone does — the fetch guard is deliberately unchanged,
        because rejecting there would break a live harvest in silence.
        """
        user = self.login()
        source = HarvestSourceFactory(
            owner=user, url="https://harvestuser:sup3rs3cr3t@www.ine.pt/broken.xml"
        )
        api_url = url_for("api.harvest_source", source=source)

        data = {
            "name": source.name,
            "description": source.description,
            "url": "https://harvestuser:sup3rs3cr3t@www.ine.pt/feed.xml",
            "backend": "factory",
        }
        response = self.put(api_url, data)
        assert400(response)
        assert "sup3rs3cr3t" not in str(response.json)

        data["url"] = "https://www.ine.pt/feed.xml"
        response = self.put(api_url, data)
        assert200(response)
        source.reload()
        assert source.url == "https://www.ine.pt/feed.xml"

    def test_create_source_rejects_credentials_split_by_a_fragment(self):
        """A password holding `#`, `?` or `/` must be refused like any other.

        `urlsplit` cuts the fragment, the query and the path off before the
        netloc, so it sees no `@` in these at all -- but `udata.uris.URL_REGEX`
        accepts them as credentials, so the source was stored. Every redaction
        downstream shares `urlsplit`'s reading, so the password was then served
        in full to anonymous callers instead of being masked.
        """
        self.login()
        for url in (
            "https://harvestuser:sup3r#s3cr3t@www.ine.pt/broken.xml",
            "https://harvestuser:sup3r?s3cr3t@www.ine.pt/broken.xml",
            "https://harvestuser:sup3r/s3cr3t@www.ine.pt/broken.xml",
        ):
            data = {"name": faker.word(), "url": url, "backend": "factory"}

            response = self.post(url_for("api.harvest_sources"), data)

            assert400(response)
            assert "sup3r" not in str(response.json)
        assert HarvestSource.objects(url__contains="s3cr3t").count() == 0

    def test_update_source_rejects_credentials_it_was_not_asked_to_change(self):
        """A payload that omits `url` is still refused for a legacy source.

        This is what makes the rejection a migration path rather than a rule
        for new sources only: `api.validate(HarvestSourceForm, source)` seeds
        the field from the stored object, so the credentials are revalidated
        even by an edit that never mentions them -- deactivating the source,
        say. Without this the legacy row would quietly stay as it is.
        """
        user = self.login()
        source = HarvestSourceFactory(
            owner=user, url="https://harvestuser:sup3rs3cr3t@www.ine.pt/broken.xml"
        )

        response = self.put(
            url_for("api.harvest_source", source=source),
            {"name": source.name, "description": source.description, "backend": "factory"},
        )

        assert400(response)
        assert "sup3rs3cr3t" not in str(response.json)

    def test_create_source_accepts_a_url_with_no_userinfo(self):
        """The guard must not refuse an ordinary source URL, port and all."""
        self.login()
        data = {
            "name": faker.word(),
            "url": "https://www.ine.pt:8443/feed.xml",
            "backend": "factory",
        }

        response = self.post(url_for("api.harvest_sources"), data)

        assert201(response)

    def test_preview_source_rejects_url_credentials(self):
        """The preview route validates the same form, so it rejects too.

        It is the route the backoffice calls before saving, so a payload that
        the create would refuse must not be previewable either.
        """
        user = self.login()
        member = Member(user=user, role="admin")
        org = OrganizationFactory(members=[member])
        data = {
            "name": faker.word(),
            "url": "https://harvestuser:sup3rs3cr3t@www.ine.pt/broken.xml",
            "backend": "factory",
            "organization": str(org.id),
        }

        response = self.post(url_for("api.preview_harvest_source_config"), data)

        assert400(response)
        assert "sup3rs3cr3t" not in str(response.json)

    def test_update_source(self):
        """It should update a source if owner or orga admin"""
        user = self.login()
        source = HarvestSourceFactory(owner=user)
        new_url = faker.url()
        data = {
            "name": source.name,
            "description": source.description,
            "url": new_url,
            "backend": "factory",
        }
        api_url = url_for("api.harvest_source", source=source)
        response = self.put(api_url, data)
        assert200(response)
        assert response.json["url"] == new_url

        # Source is now owned by orga, with user as admin
        source.organization = OrganizationFactory(members=[Member(user=user, role="admin")])
        source.save()
        api_url = url_for("api.harvest_source", source=source)
        response = self.put(api_url, data)
        assert200(response)

    def test_update_source_require_permission(self):
        """It should not update a source if not the owner"""
        self.login()
        source = HarvestSourceFactory()
        new_url: str = faker.url()
        data = {
            "name": source.name,
            "description": source.description,
            "url": new_url,
            "backend": "factory",
        }
        api_url: str = url_for("api.harvest_source", source=source)
        response = self.put(api_url, data)

        assert403(response)

    def test_validate_source(self):
        """It should allow to validate a source if admin"""
        user = self.login(AdminFactory())
        source = HarvestSourceFactory()

        data = {"state": VALIDATION_ACCEPTED}
        url = url_for("api.validate_harvest_source", source=source)
        response = self.post(url, data)
        assert200(response)

        source.reload()
        assert source.validation.state == VALIDATION_ACCEPTED
        assert source.validation.by == user

    def test_reject_source(self):
        """It should allow to reject a source if admin"""
        user = self.login(AdminFactory())
        source = HarvestSourceFactory()

        data = {"state": VALIDATION_REFUSED, "comment": "Not valid"}
        url = url_for("api.validate_harvest_source", source=source)
        response = self.post(url, data)
        assert200(response)

        source.reload()
        assert source.validation.state == VALIDATION_REFUSED
        assert source.validation.comment == "Not valid"
        assert source.validation.by == user

    def test_validate_source_is_admin_only(self):
        """It should allow to validate a source if admin"""
        self.login()
        source = HarvestSourceFactory()

        data = {"validate": True}
        url = url_for("api.validate_harvest_source", source=source)
        response = self.post(url, data)
        assert403(response)

    def test_get_source(self):
        source = HarvestSourceFactory()

        url = url_for("api.harvest_source", source=source)
        response = self.get(url)
        assert200(response)

    def test_get_missing_source(self):
        url = url_for("api.harvest_source", source="685bb38b9cb9284b93fd9e72")
        response = self.get(url)
        assert404(response)

    def test_source_preview(self):
        user = self.login()
        source = HarvestSourceFactory(backend="factory", owner=user)

        url = url_for("api.preview_harvest_source", source=source)
        response = self.get(url)
        assert200(response)

    @pytest.mark.options(HARVEST_ENABLE_MANUAL_RUN=True)
    def test_run_source(self, mocker: MockerFixture):
        launch = mocker.patch.object(actions.harvest, "delay")
        user = self.login()

        source = HarvestSourceFactory(
            backend="factory",
            owner=user,
            validation=HarvestSourceValidation(state=VALIDATION_ACCEPTED),
        )

        url = url_for("api.run_harvest_source", source=source)
        response = self.post(url)
        assert200(response)

        launch.assert_called()

    @pytest.mark.options(HARVEST_ENABLE_MANUAL_RUN=False)
    def test_cannot_run_source_if_disabled(self, mocker: MockerFixture):
        launch = mocker.patch.object(actions.harvest, "delay")
        user = self.login()

        source = HarvestSourceFactory(
            backend="factory",
            owner=user,
            validation=HarvestSourceValidation(state=VALIDATION_ACCEPTED),
        )

        url = url_for("api.run_harvest_source", source=source)
        response = self.post(url)
        assert400(response)

        launch.assert_not_called()

    @pytest.mark.options(HARVEST_ENABLE_MANUAL_RUN=True)
    def test_cannot_run_source_if_not_owned(self, mocker: MockerFixture):
        launch = mocker.patch.object(actions.harvest, "delay")
        other_user = UserFactory()
        self.login()

        source = HarvestSourceFactory(
            backend="factory",
            owner=other_user,
            validation=HarvestSourceValidation(state=VALIDATION_ACCEPTED),
        )

        url = url_for("api.run_harvest_source", source=source)
        response = self.post(url)
        assert403(response)

        launch.assert_not_called()

    @pytest.mark.options(HARVEST_ENABLE_MANUAL_RUN=True)
    def test_cannot_run_source_if_not_validated(self, mocker: MockerFixture):
        launch = mocker.patch.object(actions.harvest, "delay")
        user = self.login()

        source = HarvestSourceFactory(
            backend="factory",
            owner=user,
            validation=HarvestSourceValidation(state=VALIDATION_PENDING),
        )

        url = url_for("api.run_harvest_source", source=source)
        response = self.post(url)
        assert400(response)

        launch.assert_not_called()

    def test_source_from_config(self):
        """It should preview a config for an organization the user may harvest for"""
        user = self.login()
        member = Member(user=user, role="admin")
        org = OrganizationFactory(members=[member])
        data = {
            "name": faker.word(),
            "url": faker.url(),
            "backend": "factory",
            "organization": str(org.id),
        }
        response = self.post(url_for("api.preview_harvest_source_config"), data)
        assert200(response)

    def test_source_from_config_without_org_requires_admin(self):
        """It should refuse a config preview that names no organization

        This is the route that makes the server run a harvest backend against a
        URL the caller chose, and a payload with no organization leaves nothing
        to weigh that against. Being logged in used to be the whole test.
        """
        self.login()
        data = {"name": faker.word(), "url": faker.url(), "backend": "factory"}
        response = self.post(url_for("api.preview_harvest_source_config"), data)
        assert403(response)

    def test_source_from_config_without_org_as_admin(self):
        """It should preview a config with no organization for a sysadmin"""
        self.login(AdminFactory())
        data = {"name": faker.word(), "url": faker.url(), "backend": "factory"}
        response = self.post(url_for("api.preview_harvest_source_config"), data)
        assert200(response)

    def test_source_from_config_refuses_before_resolving_the_url(self):
        """It should authorize before the form resolves the submitted hostname

        Validating the form resolves the URL's hostname, so authorizing after it
        still hands any authenticated account an out-of-band DNS probe against
        any host outside the denylist — the VULN-2084 pattern. The refusal has to
        come first.
        """
        self.login()
        data = {"name": faker.word(), "url": "http://probe.example.org", "backend": "factory"}

        with patch(
            "udata.uris.resolve_hostname",
            side_effect=AssertionError("DNS leak: the URL was resolved before authorization"),
        ):
            response = self.post(url_for("api.preview_harvest_source_config"), data)

        assert403(response)

    def test_source_from_config_with_org_not_member(self):
        """It should refuse a config preview for an organization the user only edits

        `Organization.permissions["harvest"]` is `EditOrganizationPermission`,
        which admits org admins and not editors — the same line `POST
        /harvest/sources/` already draws.
        """
        user = self.login()
        member = Member(user=user, role="editor")
        org = OrganizationFactory(members=[member])
        data = {
            "name": faker.word(),
            "url": faker.url(),
            "backend": "factory",
            "organization": str(org.id),
        }
        response = self.post(url_for("api.preview_harvest_source_config"), data)
        assert403(response)

    def test_delete_source(self):
        user = self.login()
        source = HarvestSourceFactory(owner=user)

        url = url_for("api.harvest_source", source=source)
        response = self.delete(url)
        assert204(response)

        deleted_sources = HarvestSource.objects(deleted__exists=True)
        assert len(deleted_sources) == 1

    def test_delete_source_require_permission(self):
        """It should not delete a source if not the owner"""
        self.login()
        source = HarvestSourceFactory()

        url = url_for("api.harvest_source", source=source)
        response = self.delete(url)

        assert403(response)

    def test_schedule_source(self):
        """It should allow to schedule a source if admin"""
        self.login(AdminFactory())
        source = HarvestSourceFactory()

        data = "0 0 * * *"
        url = url_for("api.schedule_harvest_source", source=source)
        response = self.post(url, data)
        assert200(response)

        assert response.json["schedule"] == "0 0 * * *"

        source.reload()
        assert source.periodic_task is not None
        periodic_task = source.periodic_task
        assert periodic_task.crontab.hour == "0"
        assert periodic_task.crontab.minute == "0"
        assert periodic_task.crontab.day_of_week == "*"
        assert periodic_task.crontab.day_of_month == "*"
        assert periodic_task.crontab.month_of_year == "*"
        assert periodic_task.enabled

    def test_schedule_source_is_admin_only(self):
        """It should only allow admins to schedule a source"""
        self.login()
        source = HarvestSourceFactory()

        data = "0 0 * * *"
        url = url_for("api.schedule_harvest_source", source=source)
        response = self.post(url, data)
        assert403(response)

        source.reload()
        assert source.periodic_task is None

    def test_unschedule_source(self):
        """It should allow to unschedule a source if admin"""
        self.login(AdminFactory())
        periodic_task = PeriodicTask.objects.create(
            task="harvest",
            name=faker.name(),
            description=faker.sentence(),
            enabled=True,
            crontab=PeriodicTask.Crontab(),
        )
        source = HarvestSourceFactory(periodic_task=periodic_task)

        url = url_for("api.schedule_harvest_source", source=source)
        response = self.delete(url)
        assert204(response)

        source.reload()
        assert source.periodic_task is None

    def test_unschedule_source_is_admin_only(self):
        """It should only allow admins to unschedule a source"""
        self.login()
        periodic_task = PeriodicTask.objects.create(
            task="harvest",
            name=faker.name(),
            description=faker.sentence(),
            enabled=True,
            crontab=PeriodicTask.Crontab(),
        )
        source = HarvestSourceFactory(periodic_task=periodic_task)

        url = url_for("api.schedule_harvest_source", source=source)
        response = self.delete(url)
        assert403(response)

        source.reload()
        assert source.periodic_task is not None

    def test_list_items(self):
        """It should fetch the harvest items list from the API for a specific job"""
        job = HarvestJobFactory(
            items=[
                HarvestItem(dataset=DatasetFactory()),
                HarvestItem(dataservice=DataserviceFactory()),
                HarvestItem(dataset=DatasetFactory(), remote_url="https://my.remote.example.com"),
            ],
        )
        response = self.get(url_for("api.harvest_job", ident=str(job.id)))
        assert200(response)
        assert len(response.json["items"]) == 3
        assert set(response.json["items"][0].keys()) == set(
            [
                "created",
                "started",
                "ended",
                "dataset",
                "dataservice",
                "remote_url",
                "remote_id",
                "args",
                "errors",
                "kwargs",
                "logs",
                "status",
            ]
        )
        # Make sure appropriate dataset or dataservice is set
        assert response.json["items"][0]["dataset"] is not None
        assert response.json["items"][0]["dataservice"] is None
        assert response.json["items"][1]["dataset"] is None
        assert response.json["items"][1]["dataservice"] is not None
        # Make sure remote_url is exposed if exists
        assert response.json["items"][1]["remote_url"] is None
        assert response.json["items"][2]["remote_url"] == "https://my.remote.example.com"

    def test_list_jobs_lightweight(self):
        """The jobs list returns per-status counts and only failed items, never the full array"""
        source = HarvestSourceFactory()
        failed_ds = DatasetFactory()
        HarvestJobFactory(
            source=source,
            items=[
                HarvestItem(remote_id="1", status="done", dataset=DatasetFactory()),
                HarvestItem(remote_id="2", status="skipped"),
                HarvestItem(remote_id="3", status="done"),
                HarvestItem(
                    remote_id="4",
                    status="failed",
                    dataset=failed_ds,
                    errors=[HarvestError(message="boom")],
                ),
            ],
        )

        response = self.get(url_for("api.harvest_jobs", source=source))
        assert200(response)
        assert response.json["total"] == 1

        job = response.json["data"][0]
        # The heavy full items array must not be serialized in the list
        assert "items" not in job
        assert job["item_counts"]["done"] == 2
        assert job["item_counts"]["skipped"] == 1
        assert job["item_counts"]["failed"] == 1
        assert job["item_counts"]["total"] == 4
        # Only the item that actually has errors is returned
        assert len(job["error_items"]) == 1
        error_item = job["error_items"][0]
        assert error_item["remote_id"] == "4"
        assert error_item["errors"][0]["message"] == "boom"
        assert error_item["dataset"]["id"] == str(failed_ds.id)

    def test_list_jobs_anonymous_hides_url_credentials(self):
        """The jobs list builds its dicts by hand, so it needs its own redaction.

        `JobsAPI.get` projects the documents in an aggregation instead of
        marshalling them, so it never passes through `error_fields` -- and it
        is the endpoint that serves what the INE backend writes with a
        queryset update (LEDG-2477).
        """
        source = HarvestSourceFactory()
        HarvestJobFactory(
            source=source,
            items=[
                HarvestItem(
                    remote_id="1",
                    status="failed",
                    errors=[
                        HarvestError(
                            message=(
                                "500 Server Error: None for url: "
                                "https://harvestuser:sup3rs3cr3t@www.ine.pt/broken.xml"
                            )
                        )
                    ],
                )
            ],
        )

        response = self.get(url_for("api.harvest_jobs", source=source))
        assert200(response)

        message = response.json["data"][0]["error_items"][0]["errors"][0]["message"]
        assert "sup3rs3cr3t" not in message
        assert "https://***@www.ine.pt/broken.xml" in message

    def test_get_job_anonymous_hides_url_credentials_in_logs(self):
        """The captured log lines carry the same exception text as the errors."""
        job = HarvestJobFactory(
            items=[
                HarvestItem(
                    remote_id="1",
                    status="failed",
                    logs=[
                        HarvestLog(
                            level="ERROR",
                            message=(
                                "Error while processing 1 : 401 Client Error: "
                                "Unauthorized for url: "
                                "https://harvestuser:sup3rs3cr3t@www.ine.pt/broken.xml"
                            ),
                        )
                    ],
                )
            ]
        )

        response = self.get(url_for("api.harvest_job", ident=str(job.id)))
        assert200(response)

        message = response.json["items"][0]["logs"][0]["message"]
        assert "sup3rs3cr3t" not in message
        assert "https://***@www.ine.pt/broken.xml" in message

    def test_get_source_anonymous_redacts_url_credentials(self):
        """Neither source route may hand the URL password to a reader.

        Both are open to anonymous callers and `source_fields` serialized the
        URL verbatim, so the credentials of a basic-auth source were public
        without a failed harvest and without knowing any id (LEDG-2477).
        """
        source = HarvestSourceFactory(url="https://harvestuser:sup3rs3cr3t@www.ine.pt/broken.xml")
        redacted = "https://***@www.ine.pt/broken.xml"

        response = self.get(url_for("api.harvest_source", source=source))
        assert200(response)
        assert response.json["url"] == redacted

        response = self.get(url_for("api.harvest_sources"))
        assert200(response)
        listed = next(s for s in response.json["data"] if s["id"] == str(source.id))
        assert listed["url"] == redacted

    def test_get_source_owner_sees_full_url(self):
        """Whoever may rewrite the URL still needs to read it whole."""
        user = self.login()
        url = "https://harvestuser:sup3rs3cr3t@www.ine.pt/broken.xml"
        source = HarvestSourceFactory(url=url, owner=user)

        response = self.get(url_for("api.harvest_source", source=source))
        assert200(response)
        assert response.json["url"] == url

    def test_get_source_anonymous_hides_config(self):
        """Neither source route may hand the source config to a reader.

        `config` is free-form -- `HarvestConfigField.pre_validate` only checks
        `filters`, `extra_configs` and `features` -- and the CKAN family reads
        `config["apikey"]` into an `Authorization` header, so serializing it
        raw published the API key of every authenticated source to anyone
        (LEDG-2514).
        """
        source = HarvestSourceFactory(
            backend="ckan", config={"apikey": "sup3rs3cr3t", "filters": []}
        )

        response = self.get(url_for("api.harvest_source", source=source))
        assert200(response)
        assert response.json["config"] == {}
        assert b"sup3rs3cr3t" not in response.data

        response = self.get(url_for("api.harvest_sources"))
        assert200(response)
        listed = next(s for s in response.json["data"] if s["id"] == str(source.id))
        assert listed["config"] == {}
        assert b"sup3rs3cr3t" not in response.data

    def test_get_source_owner_sees_full_config(self):
        """Whoever may rewrite the config still needs to read it whole.

        The admin harvester screen merges the form values onto the stored
        config precisely because it holds keys no screen models, so an owner
        who got `{}` back would wipe them on the next save.
        """
        user = self.login()
        config = {"apikey": "sup3rs3cr3t", "filters": []}
        source = HarvestSourceFactory(backend="ckan", config=config, owner=user)

        response = self.get(url_for("api.harvest_source", source=source))
        assert200(response)
        assert response.json["config"] == config

    def test_get_job_anonymous_hides_url_credentials(self):
        """Reading a job without a session must not disclose the source password.

        The job endpoint has no `@api.secure` and `details` is the only field
        gated behind the admin permission, so `message` used to hand the
        credentials of the source URL to any anonymous caller (LEDG-2477).
        """
        job = HarvestJobFactory(
            errors=[
                HarvestError(
                    message=(
                        "500 Server Error: None for url: "
                        "https://harvestuser:sup3rs3cr3t@www.ine.pt/broken.xml"
                    )
                )
            ]
        )

        response = self.get(url_for("api.harvest_job", ident=str(job.id)))
        assert200(response)

        message = response.json["errors"][0]["message"]
        assert "sup3rs3cr3t" not in message
        assert "harvestuser" not in message
        assert message == ("500 Server Error: None for url: https://***@www.ine.pt/broken.xml")

    def test_preview_error_hides_url_credentials(self):
        """The preview never saves, so only the serialization can redact it.

        `save_job()`/`end_job()` are no-ops when `dryrun` is set, so
        `HarvestError.clean()` never runs on this path -- yet the preview
        models are clones of the job models and serialize the same errors, to
        an audience that includes organization editors.
        """
        user = self.login()
        source = HarvestSourceFactory(
            backend="factory",
            owner=user,
            url="https://harvestuser:sup3rs3cr3t@www.ine.pt/broken.xml",
        )

        def init(self):
            raise ValueError(
                "500 Server Error: None for url: "
                "https://harvestuser:sup3rs3cr3t@www.ine.pt/broken.xml"
            )

        with mock_initialize.connected_to(init):
            response = self.get(url_for("api.preview_harvest_source", source=source))

        assert200(response)
        assert response.json["status"] == "failed"
        message = response.json["errors"][0]["message"]
        assert "sup3rs3cr3t" not in message
        assert "https://***@www.ine.pt/broken.xml" in message

    def test_get_source_permissions_as_anonymous(self):
        """It should return all permissions as False for anonymous users"""
        source = HarvestSourceFactory()

        url = url_for("api.harvest_source", source=source)
        response = self.get(url)
        assert200(response)

        assert "permissions" in response.json
        permissions = response.json["permissions"]
        assert permissions["edit"] is False
        assert permissions["delete"] is False
        assert permissions["run"] is False
        assert permissions["preview"] is False
        assert permissions["validate"] is False
        assert permissions["schedule"] is False

    def test_get_source_permissions_as_owner(self):
        """It should return owner permissions as True for source owner"""
        user = self.login()
        source = HarvestSourceFactory(owner=user)

        url = url_for("api.harvest_source", source=source)
        response = self.get(url)
        assert200(response)

        permissions = response.json["permissions"]
        assert permissions["edit"] is True
        assert permissions["delete"] is True
        assert permissions["run"] is True
        assert permissions["preview"] is True
        assert permissions["validate"] is False
        assert permissions["schedule"] is False

    def test_get_source_permissions_as_org_admin(self):
        """It should return owner permissions as True for org admins"""
        user = self.login()
        member = Member(user=user, role="admin")
        org = OrganizationFactory(members=[member])
        source = HarvestSourceFactory(organization=org)

        url = url_for("api.harvest_source", source=source)
        response = self.get(url)
        assert200(response)

        permissions = response.json["permissions"]
        assert permissions["edit"] is True
        assert permissions["delete"] is True
        assert permissions["run"] is True
        assert permissions["preview"] is True
        assert permissions["validate"] is False
        assert permissions["schedule"] is False

    def test_get_source_permissions_as_org_editor(self):
        """It should return only preview permission as True for org editors"""
        user = self.login()
        member = Member(user=user, role="editor")
        org = OrganizationFactory(members=[member])
        source = HarvestSourceFactory(organization=org)

        url = url_for("api.harvest_source", source=source)
        response = self.get(url)
        assert200(response)

        permissions = response.json["permissions"]
        assert permissions["edit"] is False
        assert permissions["delete"] is False
        assert permissions["run"] is False
        assert permissions["preview"] is True
        assert permissions["validate"] is False
        assert permissions["schedule"] is False

    def test_get_source_permissions_as_superadmin(self):
        """It should return all permissions as True for admin users"""
        self.login(AdminFactory())
        source = HarvestSourceFactory()

        url = url_for("api.harvest_source", source=source)
        response = self.get(url)
        assert200(response)

        permissions = response.json["permissions"]
        assert permissions["edit"] is True
        assert permissions["delete"] is True
        assert permissions["run"] is True
        assert permissions["preview"] is True
        assert permissions["validate"] is True
        assert permissions["schedule"] is True

    def test_get_source_permissions_as_other_user(self):
        """It should return all permissions as False for non-owner users"""
        self.login()
        source = HarvestSourceFactory()  # owned by another user

        url = url_for("api.harvest_source", source=source)
        response = self.get(url)
        assert200(response)

        permissions = response.json["permissions"]
        assert permissions["edit"] is False
        assert permissions["delete"] is False
        assert permissions["run"] is False
        assert permissions["preview"] is False
        assert permissions["validate"] is False
        assert permissions["schedule"] is False

    def test_preview_source_require_permission(self):
        """It should not allow preview if not the owner"""
        self.login()
        source = HarvestSourceFactory()  # owned by another user

        url = url_for("api.preview_harvest_source", source=source)
        response = self.get(url)
        assert403(response)
