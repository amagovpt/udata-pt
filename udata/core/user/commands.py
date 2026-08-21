import logging
import re
from datetime import datetime

import click
from flask import current_app
from flask_security.forms import RegisterForm
from flask_security.utils import hash_password
from werkzeug.datastructures import MultiDict

from udata.commands import cli, exit_with_error, success
from udata.core.user.constants import SAML_PLACEHOLDER_EMAIL_PREFIX
from udata.core.user.nic import (
    hash_nic,
    is_nic_hashed,
    is_nic_legacy_encrypted,
    is_nic_plain,
)
from udata.models import User, datastore

log = logging.getLogger(__name__)


@cli.group("user")
def grp():
    """User related operations"""
    pass


@grp.command()
@click.option("--first-name")
@click.option("--last-name")
@click.option("--email")
@click.option("--password")
@click.option("--admin", is_flag=True)
def create(first_name, last_name, email, password, admin):
    """Create a new user"""
    data = {
        "first_name": first_name or click.prompt("First name"),
        "last_name": last_name or click.prompt("Last name"),
        "email": email or click.prompt("Email"),
        "password": password or click.prompt("Password", hide_input=True),
        "password_confirm": password or click.prompt("Confirm Password", hide_input=True),
    }
    # Until https://github.com/mattupstate/flask-security/issues/672 is fixed
    with current_app.test_request_context():
        form = RegisterForm(MultiDict(data), meta={"csrf": False})
    if form.validate():
        data["password"] = hash_password(data["password"])
        del data["password_confirm"]
        data["confirmed_at"] = datetime.utcnow()
        user = datastore.create_user(**data)
        if admin:
            role = datastore.find_or_create_role("admin")
            datastore.add_role_to_user(user, role)
        success("User(id={u.id} email={u.email}) created".format(u=user))
        return user
    errors = "\n".join("\n".join([str(m) for m in e]) for e in form.errors.values())
    exit_with_error("Error creating user", errors)


@grp.command()
def activate():
    """Activate an existing user (validate their email confirmation)"""
    email = click.prompt("Email")
    user = User.objects(email=email).first()
    if not user:
        exit_with_error("Invalid user")
    if user.confirmed_at is not None:
        exit_with_error("User email address already confirmed")
        return
    user.confirmed_at = datetime.utcnow()
    user.save()
    success("User activated successfully")


@grp.command()
def delete():
    """Delete an existing user"""
    email = click.prompt("Email")
    user = User.objects(email=email).first()
    if not user:
        exit_with_error("Invalid user")
    user.mark_as_deleted()
    success("User marked as deleted successfully")


@grp.command()
@click.argument("email")
def set_admin(email):
    """Set an user as administrator"""
    user = datastore.find_user(email=email)
    log.info("Adding admin role to user %s (%s)", user.fullname, user.email)
    role = datastore.find_or_create_role("admin")
    datastore.add_role_to_user(user, role)
    success("User %s (%s) is now administrator" % (user.fullname, user.email))


@grp.command()
@click.argument("email")
def password(email):
    user = datastore.find_user(email=email)
    password = click.prompt("Enter new password", hide_input=True)
    user.password = hash_password(password)
    user.save()


@grp.command()
@click.argument("email")
def rotate_password(email):
    """
    Ask user for password rotation on next login and reset any current session
    """
    user = datastore.find_user(email=email)
    user.password_rotation_demanded = datetime.utcnow()
    user.save()
    # Reset ongoing sessions by uniquifier
    datastore.set_uniquifier(user)


def _hash_plain_nics(dry_run):
    """Hash every plain (digits-only) NIC stored in ``extras.auth_nic``.

    Already-hashed values are left alone. Legacy-encrypted ciphertexts and
    unrecognized values are never touched — hashing them would irreversibly
    destroy the only recoverable form of the identifier.
    """
    stats = {"hashed": 0, "already_hashed": 0, "legacy_encrypted": 0, "unrecognized": 0}

    for user in User.objects(extras__auth_nic__exists=True):
        nic = (user.extras or {}).get("auth_nic")
        if not nic:
            continue

        if is_nic_hashed(nic):
            stats["already_hashed"] += 1
        elif is_nic_legacy_encrypted(nic):
            stats["legacy_encrypted"] += 1
        elif is_nic_plain(nic):
            if dry_run:
                log.info("WOULD HASH NIC for %s (id=%s)", user.email, user.id)
            else:
                user.extras["auth_nic"] = hash_nic(nic)
                user.save()
                log.info("HASHED NIC for %s (id=%s)", user.email, user.id)
            stats["hashed"] += 1
        else:
            log.warning(
                "UNRECOGNIZED NIC format for %s (id=%s): %r — left untouched",
                user.email,
                user.id,
                nic[:12],
            )
            stats["unrecognized"] += 1

    return stats


def _merge_cmd_duplicates(dry_run):
    """Merge duplicate SAML accounts into their traditional counterparts.

    Identifies users with placeholder SAML emails (saml-*@autenticacao.gov.pt),
    finds the matching traditional account by first_name + last_name, merges the
    NIC into the traditional account, and deletes the duplicate. Duplicates it
    cannot safely resolve are returned for a manual ``merge-saml`` decision.
    """
    stats = {"merged": 0, "unresolved": []}

    def unresolved(dup, reason):
        log.warning(
            "SKIP %s (%s %s) — %s", dup.email, dup.first_name or "", dup.last_name or "", reason
        )
        stats["unresolved"].append((dup.email, reason))

    for dup in User.objects(email__startswith=SAML_PLACEHOLDER_EMAIL_PREFIX):
        nic = (dup.extras or {}).get("auth_nic")

        if not nic:
            unresolved(dup, "no NIC to merge")
            continue

        # Duplicates created by the current plugin already store the hash;
        # older ones store the plain NIC. Anything else is not mergeable.
        if is_nic_hashed(nic):
            hashed_nic = nic
        elif is_nic_plain(nic):
            hashed_nic = hash_nic(nic)
        else:
            unresolved(dup, "unexpected NIC format on the duplicate")
            continue

        # Find the traditional account by name (case-insensitive, exact match)
        candidates = list(
            User.objects(
                first_name=re.compile(f"^{re.escape(dup.first_name or '')}$", re.IGNORECASE),
                last_name=re.compile(f"^{re.escape(dup.last_name or '')}$", re.IGNORECASE),
                email__not__startswith=SAML_PLACEHOLDER_EMAIL_PREFIX,
                deleted=None,
            )
        )

        if len(candidates) == 0:
            unresolved(dup, "no traditional account found")
            continue

        if len(candidates) > 1:
            unresolved(dup, f"multiple matches: {[c.email for c in candidates]}")
            continue

        target = candidates[0]
        existing_nic = (target.extras or {}).get("auth_nic")

        if existing_nic and existing_nic != hashed_nic:
            unresolved(dup, f"target {target.email} is already linked to a different CMD identity")
            continue

        if dry_run:
            if existing_nic == hashed_nic:
                log.info(
                    "WOULD DELETE duplicate %s (target %s already has hashed NIC)",
                    dup.email,
                    target.email,
                )
            else:
                log.info(
                    "WOULD MERGE hashed NIC into %s | delete %s",
                    target.email,
                    dup.email,
                )
        else:
            if not target.extras:
                target.extras = {}
            target.extras["auth_nic"] = hashed_nic
            target.save()
            dup._delete()
            log.info(
                "MERGED hashed NIC into %s | deleted %s",
                target.email,
                dup.email,
            )
        stats["merged"] += 1

    return stats


@grp.command()
@click.option(
    "--dry-run", is_flag=True, help="Only show what would be done, without making changes"
)
def migrate_nics(dry_run):
    """Migrate stored CMD/eIDAS identifiers to the hashed format and merge duplicates.

    Phase 1 hashes every plain (digits-only) NIC in extras.auth_nic so the
    SAML login can match those accounts again. Phase 2 merges duplicate
    accounts with placeholder SAML emails into their traditional counterparts.

    Legacy-encrypted ciphertexts (long hex values from the previous portal)
    and unrecognized values are reported but never modified — they require a
    separate decryption-based migration.

    Both phases are idempotent: the command can be re-run safely.
    """
    prefix = "[dry-run] " if dry_run else ""

    log.info("%sPhase 1/2 — hashing plain NICs", prefix)
    hash_stats = _hash_plain_nics(dry_run)

    log.info("%sPhase 2/2 — merging duplicate SAML accounts", prefix)
    merge_stats = _merge_cmd_duplicates(dry_run)

    verb = "would be " if dry_run else ""
    log.info("%sReport:", prefix)
    log.info("  plain NICs %shashed: %d", verb, hash_stats["hashed"])
    log.info("  already hashed (untouched): %d", hash_stats["already_hashed"])
    log.info(
        "  legacy-encrypted (untouched, need the legacy decryption migration): %d",
        hash_stats["legacy_encrypted"],
    )
    log.info("  unrecognized values (untouched, listed above): %d", hash_stats["unrecognized"])
    log.info("  duplicate SAML accounts %smerged: %d", verb, merge_stats["merged"])
    if merge_stats["unresolved"]:
        log.info(
            "  unresolved duplicates (handle manually with "
            "'udata user merge-saml <saml_email> <target_email>'):"
        )
        for email, reason in merge_stats["unresolved"]:
            log.info("    - %s — %s", email, reason)

    success(
        f"{'Would migrate' if dry_run else 'Migrated'}: "
        f"{hash_stats['hashed']} NIC(s) hashed, "
        f"{merge_stats['merged']} duplicate(s) merged, "
        f"{len(merge_stats['unresolved'])} unresolved"
    )


@grp.command()
@click.argument("saml_email")
@click.argument("target_email")
@click.option(
    "--dry-run", is_flag=True, help="Only show what would be done, without making changes"
)
def merge_saml(saml_email, target_email, dry_run):
    """Manually merge a SAML duplicate account into a target account.

    Use this when fix-cmd-duplicates cannot auto-resolve (e.g. multiple name matches).
    Copies the NIC from the SAML account into the target and deletes the duplicate.

    Example: udata user merge-saml saml-12345@autenticacao.gov.pt user@example.com
    """
    dup = User.objects(email=saml_email).first()
    if not dup:
        exit_with_error(f"SAML account not found: {saml_email}")

    target = User.objects(email=target_email).first()
    if not target:
        exit_with_error(f"Target account not found: {target_email}")

    nic = (dup.extras or {}).get("auth_nic")
    if not nic:
        exit_with_error(f"SAML account {saml_email} has no NIC to merge")

    log.info(
        "SAML: %s (%s %s) → Target: %s (%s %s) roles=%s",
        dup.email,
        dup.first_name,
        dup.last_name,
        target.email,
        target.first_name,
        target.last_name,
        [r.name for r in target.roles],
    )

    # Hash the NIC if it's still in plain/numeric form; refuse formats that
    # must not be hashed (legacy ciphertexts / unrecognized values).
    if is_nic_hashed(nic):
        hashed_nic = nic
    elif is_nic_plain(nic):
        hashed_nic = hash_nic(nic)
    else:
        exit_with_error(f"SAML account {saml_email} holds an unexpected NIC format; not merging")

    if dry_run:
        success(f"Would merge hashed NIC into {target.email} and delete {dup.email}")
        return

    if not target.extras:
        target.extras = {}
    target.extras["auth_nic"] = hashed_nic
    target.save()
    dup._delete()
    success(f"Merged hashed NIC into {target.email} | deleted {dup.email}")
