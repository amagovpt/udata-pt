"""
This migration does a `count_discussions` on every organization that is itself the
subject of a discussion.

Organizations never had a `count_discussions` method, so the metrics hook raised on
every discussion opened on an organization and their `metrics.discussions` /
`metrics.discussions_open` were never written. The counting is restricted to
Organization subjects on purpose: the 2025-07-18 migration already recounted every
other subject class and the hook has kept them correct since.
"""

import logging

import click

from udata.core.discussions.models import Discussion
from udata.core.organization.models import Organization

log = logging.getLogger(__name__)


def migrate(db):
    organizations_with_discussions = Discussion.objects.aggregate(
        [
            {"$match": {"subject._cls": "Organization"}},
            {"$group": {"_id": "$subject._ref"}},
        ]
    )
    with click.progressbar(organizations_with_discussions) as organizations_with_discussions:
        for organization in organizations_with_discussions:
            organization_id = organization["_id"].id
            try:
                Organization.objects.get(pk=organization_id).count_discussions()
            except Exception as err:
                log.error(f"Cannot count discussions for Organization {organization_id} {err}")
