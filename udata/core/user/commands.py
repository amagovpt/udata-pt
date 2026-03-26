import logging
from datetime import datetime

import click
from flask import current_app
from flask_security.forms import RegisterForm
from flask_security.utils import hash_password
from werkzeug.datastructures import MultiDict

from udata.commands import cli, exit_with_error, success
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


@grp.command()
@click.option(
    "--dry-run", is_flag=True, help="Only show what would be done, without making changes"
)
def fix_duplicates(dry_run):
    """Find and merge duplicate SAML accounts into their traditional counterparts.

    Identifies users with placeholder SAML emails (saml-*@autenticacao.gov.pt),
    finds the matching traditional account by first_name + last_name, merges the
    NIC into the traditional account, and deletes the duplicate.
    """
    import re

    duplicates = list(User.objects(email__startswith="saml-"))
    if not duplicates:
        success("No duplicate SAML accounts found")
        return

    log.info("Found %d duplicate SAML account(s)", len(duplicates))
    merged = 0
    skipped = 0

    for dup in duplicates:
        nic = (dup.extras or {}).get("auth_nic")
        fname = dup.first_name or ""
        lname = dup.last_name or ""

        if not nic:
            log.warning("SKIP %s — no NIC to merge", dup.email)
            skipped += 1
            continue

        # Find traditional account by name (case-insensitive, exact match)
        candidates = list(
            User.objects(
                first_name=re.compile(f"^{re.escape(fname)}$", re.IGNORECASE),
                last_name=re.compile(f"^{re.escape(lname)}$", re.IGNORECASE),
                email__not__startswith="saml-",
            )
        )

        if len(candidates) == 0:
            log.warning(
                "SKIP %s (%s %s) — no traditional account found",
                dup.email,
                fname,
                lname,
            )
            skipped += 1
            continue

        if len(candidates) > 1:
            emails = [c.email for c in candidates]
            log.warning(
                "SKIP %s (%s %s) — multiple matches: %s",
                dup.email,
                fname,
                lname,
                emails,
            )
            skipped += 1
            continue

        target = candidates[0]
        existing_nic = (target.extras or {}).get("auth_nic")
        if existing_nic:
            log.warning(
                "SKIP %s — already has NIC %s",
                target.email,
                existing_nic,
            )
            skipped += 1
            continue

        if dry_run:
            log.info(
                "WOULD MERGE NIC %s into %s | delete %s",
                nic,
                target.email,
                dup.email,
            )
        else:
            if not target.extras:
                target.extras = {}
            target.extras["auth_nic"] = nic
            target.save()
            dup.delete()
            log.info(
                "MERGED NIC %s into %s | deleted %s",
                nic,
                target.email,
                dup.email,
            )
        merged += 1

    action = "Would merge" if dry_run else "Merged"
    success(f"{action} {merged} account(s), skipped {skipped}")
