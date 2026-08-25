from udata.core.dataservices.factories import DataserviceFactory
from udata.core.dataset.factories import DatasetFactory
from udata.core.organization.commands import find_unowned_organizations
from udata.core.organization.factories import OrganizationFactory
from udata.core.organization.models import Member, Organization
from udata.core.reuse.factories import ReuseFactory
from udata.core.user.factories import UserFactory
from udata.harvest.tests.factories import HarvestSourceFactory
from udata.tests.api import PytestOnlyDBTestCase


class FindUnownedOrganizationsTest(PytestOnlyDBTestCase):
    """The audit query behind `udata organizations audit-unowned`.

    The shape it looks for is the one a harvester used to leave behind when it
    created an organization on its own: no member, nothing filed under it.
    """

    def test_memberless_and_empty_organization_is_listed(self):
        organization = OrganizationFactory(members=[])

        assert find_unowned_organizations() == [organization]

    def test_organization_with_a_member_is_not_listed(self):
        OrganizationFactory(members=[Member(user=UserFactory(), role="admin")])

        assert find_unowned_organizations() == []

    def test_organization_with_a_dataset_is_not_listed(self):
        organization = OrganizationFactory(members=[])
        DatasetFactory(organization=organization)

        assert find_unowned_organizations() == []

    def test_organization_with_a_reuse_is_not_listed(self):
        organization = OrganizationFactory(members=[])
        ReuseFactory(organization=organization)

        assert find_unowned_organizations() == []

    def test_organization_with_a_dataservice_is_not_listed(self):
        organization = OrganizationFactory(members=[])
        DataserviceFactory(organization=organization)

        assert find_unowned_organizations() == []

    def test_organization_with_a_harvest_source_is_not_listed(self):
        organization = OrganizationFactory(members=[])
        HarvestSourceFactory(organization=organization)

        assert find_unowned_organizations() == []

    def test_deleted_organization_is_not_listed(self):
        OrganizationFactory(members=[], deleted=None)
        deleted = OrganizationFactory(members=[])
        deleted.deleted = deleted.created_at
        deleted.save()

        listed = find_unowned_organizations()

        assert deleted not in listed
        assert len(listed) == 1


class AuditUnownedCommandTest(PytestOnlyDBTestCase):
    """The command itself: read-only, and it names what it found."""

    def test_command_lists_the_candidate_and_deletes_nothing(self):
        OrganizationFactory(members=[], acronym="orphan-org")

        result = self.cli("organizations", "audit-unowned")

        assert "orphan-org" in result.output
        assert Organization.objects(acronym="orphan-org").count() == 1

    def test_command_reports_nothing_to_report(self):
        OrganizationFactory(members=[Member(user=UserFactory(), role="admin")])

        result = self.cli("organizations", "audit-unowned")

        assert "No organization without members" in result.output
