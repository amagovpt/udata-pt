"""
Sanitize stored HTML in user-authored fields (VULN-2075, VULN-2076).

Strips dangerous HTML (``<script>``, event handlers, ``javascript:`` URIs,
unsupported tags) from existing documents in the ``organization``, ``reuse``,
``dataset``, ``topic``, ``topic_element`` and ``user`` collections.

Markdown fields (``description``, ``about``) keep the application's
``MD_ALLOWED_TAGS`` allow-list. Plain-string fields (``title``, ``first_name``,
``last_name``) have ALL HTML tags stripped.

The migration is idempotent: ``bleach.clean`` is a fixed point on already
sanitized input, so re-running yields zero updates.

It uses ``update_one`` (not ``save``) to bypass the new ``pre_save`` signals
and avoid double-processing the same document during the run.
"""

import logging

import bleach
from flask import current_app

log = logging.getLogger(__name__)


STRICT = dict(tags=[], strip=True)


def _md_kwargs():
    return dict(
        tags=current_app.config["MD_ALLOWED_TAGS"],
        attributes=current_app.config["MD_ALLOWED_ATTRIBUTES"],
        protocols=current_app.config["MD_ALLOWED_PROTOCOLS"],
        strip=True,
    )


# (collection, [(field_path, mode)]) where mode is "md" or "strict".
# field_path uses dot notation; only top-level fields are sanitized in-place.
TARGETS = [
    ("organization", [("description", "md")]),
    ("reuse", [("title", "strict"), ("description", "md")]),
    ("dataset", [("title", "strict"), ("description", "md")]),
    ("topic", [("description", "md")]),
    ("topic_element", [("description", "md")]),
    ("user", [("about", "md"), ("first_name", "strict"), ("last_name", "strict")]),
]


def _clean(value, mode, md_kwargs):
    if not value or not isinstance(value, str):
        return value
    return bleach.clean(value, **(md_kwargs if mode == "md" else STRICT))


def _sanitize_resources(resources, md_kwargs):
    """Sanitize the embedded ``Resource.description`` field within a dataset."""
    if not resources:
        return resources, False
    changed = False
    for resource in resources:
        if not isinstance(resource, dict):
            continue
        original = resource.get("description")
        cleaned = _clean(original, "md", md_kwargs)
        if cleaned != original:
            resource["description"] = cleaned
            changed = True
    return resources, changed


def migrate(db):
    md = _md_kwargs()
    grand_total = 0

    for coll, fields in TARGETS:
        proj = {f: 1 for f, _ in fields}
        if coll == "dataset":
            proj["resources"] = 1
        cursor = db[coll].find({}, {"_id": 1, **proj})
        coll_total = 0
        for doc in cursor:
            updates = {}
            for field_name, mode in fields:
                original = doc.get(field_name)
                cleaned = _clean(original, mode, md)
                if cleaned != original:
                    updates[field_name] = cleaned
            if coll == "dataset":
                resources, resources_changed = _sanitize_resources(doc.get("resources"), md)
                if resources_changed:
                    updates["resources"] = resources
            if updates:
                db[coll].update_one({"_id": doc["_id"]}, {"$set": updates})
                coll_total += 1
        grand_total += coll_total
        log.info("Sanitized %s collection: %d document(s) updated.", coll, coll_total)

    log.info("Sanitization migration complete. %d document(s) updated overall.", grand_total)
