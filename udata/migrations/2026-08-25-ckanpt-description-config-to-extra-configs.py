"""
Move the CKAN PT harvest config out of the source description into extra configs.

The `ckanpt` backend used to read the source description as a JSON blob holding
`license` and `geozones`. Those are declared extra configs now, so the config has
to move where the backend reads it - and the description goes back to being the
free text the form has always called it, which the blobs conveniently carry under
a `description` key.

Idempotent twice over: after a first run the description is prose, so it no longer
parses as JSON, and a key already present in `extra_configs` is never added again.
"""

import json
import logging

from mongoengine.errors import ValidationError

from udata.harvest.models import HarvestSource
from udata.models import GeoZone
from udata.utils import safe_unicode

log = logging.getLogger(__name__)

CONFIG_KEYS = ("license", "geozones")


def legacy_config(source) -> dict | None:
    """The config blob the description carries, or `None` when it carries none."""
    try:
        config = json.loads(safe_unicode(source.description) or "")
    except (ValueError, TypeError, RecursionError):
        return None

    if not isinstance(config, dict) or not any(key in config for key in CONFIG_KEYS):
        return None

    return config


def as_text(value) -> str:
    """A config scalar as text, or "" for anything that is not one.

    `str()` on its own turns JSON `null` and `false` into the literal strings
    "None" and "False", which would settle in the form as a permanent junk value
    and warn on every job forever.
    """
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    return ""


def as_extra_config_value(key: str, value) -> str | None:
    """The value as an extra config holds it: a string, or `None` to skip it."""
    if key == "geozones":
        # `HarvestExtraConfig` only admits the scalar types of `HarvestFilter.TYPES`,
        # so the list travels comma-separated; a zone identifier has no comma in it.
        zones = value if isinstance(value, list) else [value]
        identifiers = [text for text in (as_text(zone) for zone in zones) if text]
        return ",".join(identifiers) or None

    return as_text(value) or None


def migrate(db):
    log.info("Processing ckanpt harvest sources.")

    migrated = 0
    for source in HarvestSource.objects(backend="ckanpt"):
        config = legacy_config(source)
        if config is None:
            log.info("Source %s carries no config in its description; left alone", source.id)
            continue

        extra_configs = list(source.config.get("extra_configs") or [])
        present = {entry.get("key") for entry in extra_configs}

        for key in CONFIG_KEYS:
            if key not in config or key in present:
                continue
            value = as_extra_config_value(key, config[key])
            if value is None:
                continue
            extra_configs.append({"key": key, "value": value})

            if key == "geozones":
                for identifier in value.split(","):
                    if not GeoZone.objects(id=identifier).first():
                        # Migrated anyway: the backend warns and skips it at harvest
                        # time, and dropping it here would lose the admin's intent.
                        log.warning(
                            "Source %s configures unknown geozone %s",
                            source.id,
                            # `repr` so a crafted identifier cannot forge log lines.
                            repr(identifier)[:200],
                        )

        source.config["extra_configs"] = extra_configs

        # The blobs nest the real description under a `description` key. There is no
        # down migration, so a blob that holds prose anywhere else is logged in full
        # before being replaced: better a recoverable log line than a silent loss.
        description = as_text(config.get("description"))
        if not description and len(config) > len([k for k in CONFIG_KEYS if k in config]):
            log.warning(
                "Source %s has a config blob with no usable description; "
                "replacing it with an empty one. Previous value: %s",
                source.id,
                repr(source.description)[:1000],
            )
        source.description = description

        try:
            source.save()
        except ValidationError as e:
            # One unsaveable source must not stop the ones after it in cursor order:
            # those are exactly the ones left exposed to the un-migrated behaviour.
            log.error(f"Failed to save source {source.id}: {e}")
            continue

        migrated += 1
        log.info("Migrated source %s: %s", source.id, extra_configs)

    log.info(f"Modified {migrated} sources")
