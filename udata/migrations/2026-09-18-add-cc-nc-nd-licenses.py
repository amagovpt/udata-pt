"""
Add the CC BY-NC and CC BY-NC-ND licenses to the portal

The DGT harvester now reads the licence out of the SNIG `legalConstraints`
instead of stamping `cc-by` on everything, and the source really does publish
these two: of the 2900 records the sources harvest, five carry CC BY-NC and one
CC BY-NC-ND. (The wider index holds more of both, but those sit outside the
`dataPolicy=Dados abertos` filter every dgt source URL applies.)
Without the documents, those records resolve to an id the lookup does not find
and land on the portal default -- which is honest, but is also not what the
source grants.

Written as an upsert rather than through `udata licenses`: that command drops
the whole collection and reseeds it from an external JSON, which would destroy
the eleven licences this portal carries with their Portuguese titles.

`$setOnInsert` is what makes it idempotent AND safe: a second run writes
nothing, and a licence an administrator already created by hand keeps whatever
title and URL they gave it. Only the absence of the document is filled in.

`slug` carries a unique index, and writing through pymongo skips the uniqueness
handling `SlugField` would do. A collision is unlikely with these titles, but
it would abort the whole `db upgrade` halfway and leave the second licence
uncreated, so each insert is guarded on its own and the collision is reported
rather than raised.
"""

import logging
from datetime import UTC, datetime

from pymongo.errors import DuplicateKeyError

from udata.core.dataset.models import License

log = logging.getLogger(__name__)

LICENSES = [
    {
        "_id": "cc-by-nc",
        "title": "Creative Commons Attribution-NonCommercial 4.0 - CC BY-NC 4.0",
        "url": "https://creativecommons.org/licenses/by-nc/4.0/",
    },
    {
        "_id": "cc-by-nc-nd",
        "title": "Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 - CC BY-NC-ND 4.0",
        "url": "https://creativecommons.org/licenses/by-nc-nd/4.0/",
    },
]


def migrate(db):
    log.info("Adding the CC BY-NC and CC BY-NC-ND licenses...")

    added = 0
    for license in LICENSES:
        try:
            result = db.license.update_one(
                {"_id": license["_id"]},
                {
                    "$setOnInsert": {
                        "title": license["title"],
                        # Slugified the way SlugField would, rather than by
                        # hand, so the two cannot drift apart.
                        "slug": License.slug.slugify(license["title"]),
                        "url": license["url"],
                        "alternate_urls": [],
                        "alternate_titles": [],
                        "maintainer": None,
                        "flags": [],
                        "active": True,
                        "created_at": datetime.now(UTC),
                    }
                },
                upsert=True,
            )
        except DuplicateKeyError:
            log.warning(
                'Could not add license "%s": its slug is already taken. Add it by hand.',
                license["title"],
            )
            continue
        if result.upserted_id is not None:
            added += 1
            log.info('Added license "%s"', license["title"])

    log.info("Added %s license(s); %s already present.", added, len(LICENSES) - added)
