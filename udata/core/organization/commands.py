import logging

import click

from udata.commands import cli, exit_with_error, success, white
from udata.models import (
    CommunityResource,
    ContactPoint,
    Dataservice,
    Dataset,
    GeoZone,
    Organization,
    Page,
    Reuse,
    Topic,
)
from udata.utils import safe_unicode

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
    """Organizations with no members, no pending request, and nothing filed under them.

    A harvester creating an organization on its own leaves exactly this shape: an
    acronym, a name and a description from the remote, no member, and - if the
    harvest never ran for real afterwards - nothing filed under it either.

    The shape is a candidate, not a verdict: an organization whose members were
    just removed, or one created by hand ahead of its first dataset, looks the
    same. Hence read-only. What is checked is every `Owned` document plus harvest
    sources; an organization referenced only from an activity, a follow or an
    OAuth2 client still shows up here, so judge each candidate before acting.
    """
    # `udata.harvest.models` cannot be imported at module level: it imports back
    # through `udata.models`, which is still initialising when this module loads.
    from udata.harvest.models import HarvestSource

    owning_documents = (
        CommunityResource,
        ContactPoint,
        Dataservice,
        Dataset,
        Page,
        Reuse,
        Topic,
        HarvestSource,
    )
    # One `distinct` per collection rather than a count per organization: the
    # question is answered in as many queries as there are collections, instead of
    # four per organization on a database that can hold thousands of them.
    used_ids = set()
    for document in owning_documents:
        for owner in document.objects.distinct("organization"):
            if owner is not None:
                # `distinct` dereferences a `ReferenceField`, so this is usually an
                # `Organization`; `pk` normalises it, and falls through for a raw id.
                used_ids.add(getattr(owner, "pk", owner))

    # `members` and `requests` are filtered in Python on purpose: a document
    # written with an empty list and one written without the key at all are both
    # empty, and a `__size=0` query would only match the first.
    return [
        organization
        for organization in Organization.objects(deleted=None)
        if not organization.members
        and not organization.requests
        and organization.id not in used_ids
    ]


def _printable(value):
    """One line of printable text, safe to send to a terminal.

    Everything printed on a candidate row came from a remote harvest payload.
    `name` and `acronym` go through no sanitisation on any write path - only
    `description` does, via `Organization.pre_save` - so escape sequences and
    control characters have to be dropped here, and the row is tab-separated, so
    tabs and newlines have to go too or a crafted name forges rows.
    """
    text = "".join(
        character if character.isprintable() else " " for character in safe_unicode(value or "")
    )
    # Collapse what is left, so a run of stripped control characters does not leave
    # a gap wide enough to look like the next column.
    return " ".join(text.split())


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

    # Slug and description are printed because on an organization a harvester
    # created they came straight from the remote portal - and the slug is the one
    # that took a name in the public URL namespace. They are what tells a
    # harvester's leftover apart from an organization someone created by hand.
    for organization in organizations:
        click.echo(
            white(
                "\t".join(
                    (
                        str(organization.id),
                        _printable(organization.acronym) or "-",
                        organization.slug,
                        _printable(organization.name),
                        "created {0:%Y-%m-%d}".format(organization.created_at),
                        _printable(organization.description)[:120],
                    )
                )
            )
        )
    click.echo("{0} organization(s) without members and without content".format(len(organizations)))
