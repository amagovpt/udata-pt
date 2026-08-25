from udata.core.contact_point.factories import ContactPointFactory
from udata.core.dataservices.factories import DataserviceFactory
from udata.core.dataset.factories import CommunityResourceFactory, DatasetFactory
from udata.core.organization.commands import find_unowned_organizations
from udata.core.organization.factories import OrganizationFactory
from udata.core.organization.models import Member, MembershipRequest, Organization
from udata.core.pages.factories import PageFactory
from udata.core.reuse.factories import ReuseFactory
from udata.core.topic.factories import TopicFactory
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

    def test_organization_with_a_topic_is_not_listed(self):
        organization = OrganizationFactory(members=[])
        TopicFactory(organization=organization)

        assert find_unowned_organizations() == []

    def test_organization_with_a_page_is_not_listed(self):
        organization = OrganizationFactory(members=[])
        PageFactory(organization=organization)

        assert find_unowned_organizations() == []

    def test_organization_with_a_contact_point_is_not_listed(self):
        organization = OrganizationFactory(members=[])
        ContactPointFactory(organization=organization)

        assert find_unowned_organizations() == []

    def test_organization_with_a_community_resource_is_not_listed(self):
        organization = OrganizationFactory(members=[])
        CommunityResourceFactory(organization=organization)

        assert find_unowned_organizations() == []

    def test_organization_with_a_pending_request_is_not_listed(self):
        """A request means someone is trying to join: not a leftover."""
        OrganizationFactory(
            members=[],
            requests=[MembershipRequest(user=UserFactory(), kind="request", comment="por favor")],
        )

        assert find_unowned_organizations() == []

    def test_deleted_organization_is_not_listed(self):
        alive = OrganizationFactory(members=[], deleted=None)
        deleted = OrganizationFactory(members=[])
        deleted.deleted = deleted.created_at
        deleted.save()

        assert find_unowned_organizations() == [alive]


class AuditUnownedCommandTest(PytestOnlyDBTestCase):
    """The command itself: read-only, and it names what it found."""

    def test_command_lists_the_candidate_and_deletes_nothing(self):
        OrganizationFactory(members=[], acronym="orphan-org")

        result = self.cli("organizations", "audit-unowned")

        assert "orphan-org" in result.output
        assert Organization.objects(acronym="orphan-org").count() == 1

    def test_command_neutralises_control_characters_in_a_remote_name(self):
        """`name` and `acronym` pass through no sanitiser on any write path.

        A harvester filled them from a remote payload, so a crafted one could carry
        escape sequences and row separators into an operator's terminal.
        """
        OrganizationFactory(
            members=[],
            acronym="orphan-org",
            name="Legit\x1b[2J\tforged\nrow",
        )

        result = self.cli("organizations", "audit-unowned")

        # The escape byte is gone; the `[2J` left behind is printable text and
        # harmless without it, so it legitimately stays.
        assert "\x1b" not in result.output
        assert "Legit [2J forged row" in result.output
        # One candidate, so one row plus the count line - a forged separator would
        # have turned it into more.
        assert len([line for line in result.output.splitlines() if line.strip()]) == 2

    def test_command_reports_nothing_to_report(self):
        OrganizationFactory(members=[Member(user=UserFactory(), role="admin")])

        result = self.cli("organizations", "audit-unowned")

        assert "No organization without members" in result.output
