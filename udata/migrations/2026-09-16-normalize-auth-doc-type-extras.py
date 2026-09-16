"""
Normalize the punctuated document types already stored on user accounts

autenticacao.gov sends `DocType` as `TR:`, with a trailing colon, and the
sign-in stored it verbatim in `extras.auth_doc_type`. The extraction now
normalizes it, but the values written before that stay punctuated, so counting
how many foreign citizens hold each document type sees `TR` and `TR:` as two
different types.

The stored identity is NEVER touched. `extras.auth_nic` is a one-way digest
whose pre-image cannot be recomputed from here, and the accounts this migration
finds are precisely the ones the composition failed on, so most of them carry
no identity at all. Reuniting the duplicate accounts that failure produced is
support work, not something this migration can decide.

Written through the collection and never through the `User` document: saving a
`User` runs `pre_save`, which re-sanitizes `about`, `first_name` and
`last_name` on any write path. A migration that only means to clean one extras
key would silently rewrite the name of every foreign citizen it touched.

`_normalize_doc_type` is imported rather than reimplemented. A copy would agree
today and drift the first time either side changes, and the two would then
disagree about which stored values are already clean.

Idempotent: a second run reads the same documents, finds every value already
equal to its normalized form and writes nothing.
"""

import logging

from udata.auth.saml.saml_plugin.saml_govpt import _normalize_doc_type

log = logging.getLogger(__name__)


def migrate(db):
    log.info("Normalizing stored auth_doc_type values...")

    users = 0
    for user in db.user.find({"extras.auth_doc_type": {"$exists": True}}, no_cursor_timeout=True):
        stored = (user.get("extras") or {}).get("auth_doc_type")
        if not isinstance(stored, str):
            continue

        normalized = _normalize_doc_type(stored)
        if normalized == stored:
            continue

        db.user.update_one({"_id": user["_id"]}, {"$set": {"extras.auth_doc_type": normalized}})
        users += 1

    log.info("Normalized auth_doc_type on %s user(s).", users)
