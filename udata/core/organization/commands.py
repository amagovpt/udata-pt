import logging

import click

from udata.commands import cli, exit_with_error, success, white
from udata.models import GeoZone, Organization

log = logging.getLogger(__name__)


@cli.group("organizations")
def grp():
    """Organizations related operations"""
    pass


@grp.command()
@click.argument("geoid", metavar="<geoid>")
@click.argument("organization_id_or_slug", metavar="<organization>")
def attach_zone(geoid, organization_id_or_slug):
    """Attach a zone <geoid> restricted to level for a given <organization>."""
    organization = Organization.objects.get_by_id_or_slug(organization_id_or_slug)
    if not organization:
        log.error("No organization found for %s", organization_id_or_slug)
    geozone = GeoZone.objects.get(id=geoid)
    if not geozone:
        log.error("No geozone found for %s", geoid)
    log.info(
        "Attaching {organization} with {geozone.name}".format(
            organization=organization, geozone=geozone
        )
    )
    organization.zone = geozone.id
    organization.save()
    log.info("Done")


@grp.command()
@click.argument("organization_id_or_slug", metavar="<organization>")
def detach_zone(organization_id_or_slug):
    """Detach the zone of a given <organization>."""
    organization = Organization.objects.get_by_id_or_slug(organization_id_or_slug)
    if not organization:
        exit_with_error("No organization found for {0}".format(organization_id_or_slug))
    log.info("Detaching {organization} from {organization.zone}".format(organization=organization))
    organization.zone = None
    organization.save()
    log.info("Done")


def find_unowned_organizations():
    """Organizations with no members and nothing filed under them.

    A harvester creating an organization on its own leaves exactly this shape: an
    acronym and a name from the remote, no member, and - if the harvest never ran
    for real afterwards - no dataset either. The shape is a candidate, not a
    verdict: an organization whose members were just removed, or one created by
    hand ahead of its first dataset, looks the same. Hence read-only.
    """
    # Imported here rather than at module level: this module is loaded while the CLI
    # is being built, before the harvest package is importable.
    from udata.harvest.models import HarvestSource
    from udata.models import Dataservice, Dataset, Reuse

    # `members` is filtered in Python on purpose: a document written with an empty
    # list and one written without the key at all are both memberless, and a
    # `members__size=0` query would only match the first.
    return [
        organization
        for organization in Organization.objects(deleted=None)
        if not organization.members
        and not Dataset.objects(organization=organization).count()
        and not Reuse.objects(organization=organization).count()
        and not Dataservice.objects(organization=organization).count()
        and not HarvestSource.objects(organization=organization).count()
    ]


@grp.command()
def audit_unowned():
    """List organizations with no members and nothing filed under them.

    Read-only: it prints candidates and deletes nothing. Written to check whether
    a portal has organizations left behind by a harvester that used to create them
    outside any organization-creation flow.
    """
    organizations = find_unowned_organizations()
    if not organizations:
        success("No organization without members and without content")
        return

    for organization in organizations:
        click.echo(
            white(
                "{0.id}\t{0.acronym}\t{0.name}\tcreated {0.created_at:%Y-%m-%d}".format(
                    organization
                )
            )
        )
    click.echo("{0} organization(s) without members and without content".format(len(organizations)))
