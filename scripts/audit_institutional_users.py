#!/usr/bin/env python3
"""
Audit institutional accounts and their link to CMD / autenticacao.gov.

There is no "institutional account" flag in the user model. What the database
actually records is the CMD/eIDAS link, in ``user.extras.auth_nic``:

- present and a 64-hex HMAC digest -> the account is linked to a *personal*
  civil identity (NIC) or an eIDAS PersonIdentifier, and CMD login resolves to it;
- present in another format (plain digits, legacy 512-hex ciphertext, junk) ->
  the account was CMD-linked by an older portal version but no longer matches;
- absent -> the account has never completed a CMD login: email + password only.

An account whose email is saml-<x>@autenticacao.gov.pt was minted by the SAML
flow because the IdP gave no usable email.

"Institutional" is therefore a heuristic applied on top: a generic mailbox
local-part (geral@, dados@, sig@, ...), a public-administration domain, or
membership in an organization. The point of the audit is the cross: an account
that looks institutional but carries an auth_nic is a person's CMD identity
bound to a shared mailbox.

Read-only. Never writes to the database.

Usage:
    uv run python scripts/audit_institutional_users.py --host 10.55.37.143
    uv run python scripts/audit_institutional_users.py --host 10.55.37.40 --only-flagged
    uv run python scripts/audit_institutional_users.py --host 10.55.37.143 --csv audit.csv
    uv run python scripts/audit_institutional_users.py --host 10.55.37.143 --all-users

Environments:
    DEV: --host 10.55.37.143
    TST: --host 10.55.37.40
"""

import argparse
import csv
import re
import sys
from collections import Counter, defaultdict

import pymongo

# Imported, never re-implemented: this script COUNTS accounts by how the login
# classifies their stored identifier, so it has to ask the very code the login
# asks. The copies these replaced had already drifted -- they lowercased before
# testing for hex and these do not, so an uppercase 512-hex ciphertext was
# legacy-encrypted to the script and unrecognized to the login. That is the
# bucket holding most of the accounts, and a counting tool that disagrees with
# production produces wrong counts.
#
# The predicates take no app context (only hash_nic does, for the SECRET_KEY),
# so importing them costs nothing but requires the script to run inside the
# project venv -- hence `uv run python` in the usage above.
from udata.core.user.nic import is_nic_hashed, is_nic_legacy_encrypted, is_nic_plain

SAML_PLACEHOLDER_EMAIL_PREFIX = "saml-"
SAML_PLACEHOLDER_EMAIL_DOMAIN = "autenticacao.gov.pt"

# Shared/functional mailboxes: nobody's personal address.
GENERIC_LOCAL_PARTS = {
    "geral",
    "info",
    "informacao",
    "dados",
    "dadosabertos",
    "opendata",
    "open-data",
    "sig",
    "gis",
    "ti",
    "dsi",
    "di",
    "informatica",
    "sistemas",
    "webmaster",
    "admin",
    "administrador",
    "secretaria",
    "secretariado",
    "expediente",
    "apoio",
    "helpdesk",
    "suporte",
    "support",
    "contacto",
    "contactos",
    "geral.dados",
    "comunicacao",
    "estatistica",
    "estatisticas",
    "gabinete",
    "servicos",
    "noreply",
    "no-reply",
}

# Public-administration domains in .pt.
INSTITUTIONAL_DOMAIN_RE = re.compile(
    r"(\.gov\.pt|\.gov\.pt\.|^cm-|^mun-|\.min-[a-z]+\.pt$|\.pt\.gov|"
    r"\.dgterritorio\.pt$|\.ine\.pt$|\.apambiente\.pt$)",
    re.IGNORECASE,
)


def cmd_status(user):
    """Classify the CMD/eIDAS link recorded on the account.

    Same order and same predicates as ``_hash_plain_nics`` in
    ``udata/core/user/commands.py``, so this audit and ``migrate-nics`` put
    every account in the same bucket.
    """
    nic = (user.get("extras") or {}).get("auth_nic")
    if not nic:
        return "no"
    nic = str(nic)
    if is_nic_hashed(nic):
        return "yes (hashed)"
    if is_nic_legacy_encrypted(nic):
        return "stale (legacy-encrypted)"
    if is_nic_plain(nic):
        return "stale (plain NIC)"
    return "stale (unrecognized)"


def split_email(email):
    email = (email or "").strip().lower()
    if "@" not in email:
        return email, ""
    local, _, domain = email.partition("@")
    return local, domain


def institutional_reasons(user, org_member_ids, extra_domains):
    """Why this account reads as institutional. Empty list -> looks personal."""
    local, domain = split_email(user.get("email"))
    reasons = []
    if local in GENERIC_LOCAL_PARTS:
        reasons.append("generic-mailbox")
    if domain and INSTITUTIONAL_DOMAIN_RE.search(domain):
        reasons.append("public-admin-domain")
    if domain and domain in extra_domains:
        reasons.append("listed-domain")
    if user["_id"] in org_member_ids:
        reasons.append("org-member")
    return reasons


def main():
    parser = argparse.ArgumentParser(
        description="Audit institutional accounts and their CMD/autenticacao.gov link."
    )
    parser.add_argument("--host", required=True, help="MongoDB host IP")
    parser.add_argument("--port", type=int, default=27017, help="MongoDB port (default: 27017)")
    parser.add_argument("--db", default="udata", help="Database name (default: udata)")
    parser.add_argument(
        "--domains",
        default="",
        help="Extra comma-separated domains to treat as institutional (e.g. 'ama.pt,acme.pt')",
    )
    parser.add_argument(
        "--all-users",
        action="store_true",
        help="List every account, not only the ones that look institutional",
    )
    parser.add_argument(
        "--only-flagged",
        action="store_true",
        help="List only institutional-looking accounts that DO carry a CMD link",
    )
    parser.add_argument(
        "--include-deleted", action="store_true", help="Include accounts marked as deleted"
    )
    parser.add_argument("--csv", help="Also write the listed accounts to this CSV file")
    args = parser.parse_args()

    extra_domains = {d.strip().lower() for d in args.domains.split(",") if d.strip()}

    client = pymongo.MongoClient(args.host, args.port, serverSelectionTimeoutMS=10000)
    try:
        client.admin.command("ping")
    except pymongo.errors.PyMongoError as exc:
        print(f"ERROR: cannot reach MongoDB at {args.host}:{args.port} — {exc}", file=sys.stderr)
        return 1
    db = client[args.db]

    # Every user referenced as a member of some organization.
    # Deleted organizations do not count: a membership in one is not a
    # membership, and counting them inflated the sole-admin exposure by half
    # when this audit was first used on production data (three AGIT records,
    # two of them already deleted).
    # Read the roles as well as the ids: an organization with no member holding
    # "admin" is stuck -- nobody can manage members, accept transfers or edit
    # it, and it cannot promote anyone from the inside, so recovering needs a
    # sysadmin. The guard added on the member endpoints stops NEW ones; it does
    # not repair the ones that already exist, and nobody has counted them.
    org_member_ids = set()
    org_admin_ids = set()
    orgs_without_admin = []
    org_member_refs = []  # (org label, user id) for every membership
    for org in db.organization.find(
        {"deleted": None}, {"members.user": 1, "members.role": 1, "name": 1, "slug": 1}
    ):
        label = org.get("name") or org.get("slug") or str(org.get("_id"))
        has_admin = False
        for member in org.get("members") or []:
            if member.get("user"):
                org_member_ids.add(member["user"])
                org_member_refs.append((label, member["user"]))
                if member.get("role") == "admin":
                    has_admin = True
                    org_admin_ids.add(member["user"])
        if not has_admin:
            orgs_without_admin.append(label)

    # Accounts that own content, collected once rather than queried per user.
    # Needed to answer "which of these duplicate accounts can be merged away
    # safely" -- applying the existing merge command to a group where both
    # sides hold content would delete it.
    owners_with_content = set()
    for collection in ("dataset", "reuse", "dataservice"):
        try:
            for doc in db[collection].find({"deleted": None}, {"owner": 1}):
                if doc.get("owner"):
                    owners_with_content.add(doc["owner"])
        except Exception as exc:  # noqa: BLE001 - an absent collection is not fatal
            print(f"WARNING: could not scan {collection}: {exc}", file=sys.stderr)

    # Every user document that exists, regardless of the deleted filter below.
    # A soft-deleted account is still a document, so a membership pointing at
    # one is not dangling -- only a membership pointing at an id with no
    # document at all is, which is what a hard delete leaves behind.
    all_user_ids = {doc["_id"] for doc in db.user.find({}, {"_id": 1})}

    query = {} if args.include_deleted else {"deleted": None}
    projection = {
        "email": 1,
        "first_name": 1,
        "last_name": 1,
        "slug": 1,
        "roles": 1,
        "active": 1,
        "deleted": 1,
        "confirmed_at": 1,
        "created_at": 1,
        "last_login_at": 1,
        "extras": 1,
    }

    rows, counts, flagged, domain_counter = [], Counter(), [], Counter()
    # The two duplicate axes migrate-nics cannot answer. Both are grouped from
    # the values as stored, so neither needs the SECRET_KEY -- see the caveats
    # printed with the report.
    by_nic, by_email = defaultdict(list), defaultdict(list)

    for user in db.user.find(query, projection):
        status = cmd_status(user)
        reasons = institutional_reasons(user, org_member_ids, extra_domains)
        email = (user.get("email") or "").lower()
        nic_raw = (user.get("extras") or {}).get("auth_nic")
        if nic_raw:
            by_nic[str(nic_raw)].append(
                (
                    user.get("email"),
                    status,
                    user.get("created_at"),
                    # What a merge decision needs to know about each side.
                    {
                        "content": user["_id"] in owners_with_content,
                        "member": user["_id"] in org_member_ids,
                        "admin": user["_id"] in org_admin_ids,
                    },
                )
            )
        if email:
            by_email[email].append((user.get("email"), status, user.get("created_at")))
        placeholder = email.startswith(SAML_PLACEHOLDER_EMAIL_PREFIX) and email.endswith(
            f"@{SAML_PLACEHOLDER_EMAIL_DOMAIN}"
        )

        counts["total"] += 1
        if reasons:
            counts["institutional"] += 1
            domain_counter[split_email(email)[1]] += 1
            if status != "no":
                counts["institutional_with_cmd"] += 1
            else:
                counts["institutional_without_cmd"] += 1
        if status != "no":
            counts["cmd_linked"] += 1
        if placeholder:
            counts["placeholder_email"] += 1
        # An account with no confirmation date is refused by password recovery,
        # and the deliberately generic anti-enumeration response makes that
        # refusal look like a mail that was sent. Split by CMD link because the
        # SAML creation path was leaving the field null permanently, so that
        # subset is the population the fix has yet to reach.
        if not user.get("confirmed_at"):
            counts["unconfirmed"] += 1
            if status != "no":
                counts["unconfirmed_with_cmd"] += 1

        row = {
            "email": user.get("email"),
            "name": " ".join(filter(None, [user.get("first_name"), user.get("last_name")])).strip(),
            "cmd": status,
            "institutional": ",".join(reasons) or "-",
            "placeholder_email": "yes" if placeholder else "no",
            "org_member": "yes" if user["_id"] in org_member_ids else "no",
            "active": "yes" if user.get("active") else "no",
            "confirmed": "yes" if user.get("confirmed_at") else "no",
            "last_login_at": str(user.get("last_login_at") or ""),
            "created_at": str(user.get("created_at") or ""),
        }
        if reasons and status != "no":
            flagged.append(row)
        if args.all_users or (reasons and (status != "no" or not args.only_flagged)):
            rows.append(row)

    rows.sort(key=lambda r: (r["cmd"] == "no", r["email"] or ""))

    width = max((len(r["email"] or "") for r in rows), default=5)
    print(f"{'EMAIL':<{width}}  {'CMD':<24}  {'INSTITUTIONAL':<40}  ORG  NAME")
    print("-" * (width + 80))
    for r in rows:
        print(
            f"{r['email'] or '':<{width}}  {r['cmd']:<24}  {r['institutional']:<40}  "
            f"{r['org_member']:<3}  {r['name']}"
        )

    print()
    print(f"accounts scanned .................. {counts['total']}")
    print(f"look institutional ................ {counts['institutional']}")
    print(f"  ...WITHOUT a CMD link ........... {counts['institutional_without_cmd']}")
    print(f"  ...WITH a CMD link (review) ..... {counts['institutional_with_cmd']}")
    print(f"CMD-linked accounts (all) ......... {counts['cmd_linked']}")
    print(f"saml-* placeholder emails ......... {counts['placeholder_email']}")
    print(f"accounts with NO confirmation date  {counts['unconfirmed']}")
    print(f"  ...of those, CMD-linked ......... {counts['unconfirmed_with_cmd']}")

    shared_nics = {v: accts for v, accts in by_nic.items() if len(accts) > 1}
    case_collisions = {e: accts for e, accts in by_email.items() if len(accts) > 1}

    print()
    print(f"accounts sharing one stored NIC ... {len(shared_nics)} group(s)")
    print(f"emails colliding on case only ..... {len(case_collisions)} group(s)")

    if shared_nics:
        print()
        print("Accounts holding the SAME stored identifier — one person, several accounts.")
        print("The CMD login now REFUSES these outright rather than picking one, so every")
        print("account listed here is locked out until the group is merged by hand.")
        print()
        print("[content] owns datasets/reuses/dataservices — merging it away would destroy them")
        print("[member]  belongs to an organization   [ADMIN] administers one")
        for accts in shared_nics.values():
            print("  -")
            for mail, status, created, holds in sorted(accts, key=lambda a: str(a[2] or "")):
                marks = " ".join(
                    filter(
                        None,
                        [
                            "[content]" if holds["content"] else "",
                            "[ADMIN]" if holds["admin"] else ("[member]" if holds["member"] else ""),
                        ],
                    )
                )
                print(f"      {mail}  ({status}; created {created}) {marks}")
        both = sum(
            1
            for accts in shared_nics.values()
            if sum(1 for a in accts if a[3]["content"]) > 1
        )
        print()
        # Printed so a zero above cannot be read as a scan that found nothing:
        # if this number is 0 too, the content check is broken, not clean.
        print(f"  (content check live: {len(owners_with_content)} accounts own content overall)")
        print(f"  ⚠ groups with content on MORE THAN ONE side: {both}")
        print("    Those cannot be merged by moving the identifier alone; the existing")
        print("    merge command deletes the duplicate without transferring anything.")

    if case_collisions:
        print()
        print("Emails differing ONLY in capitalization — two accounts for one address.")
        print("The unique index on User.email is case-sensitive, so these coexist; the")
        print("login resolver matches case-insensitively and _create_saml_user matches")
        print("exactly, which is how they were created in the first place:")
        for accts in case_collisions.values():
            print("  -")
            for mail, status, created in sorted(accts, key=lambda a: str(a[2] or "")):
                print(f"      {mail}  ({status}; created {created})")

    print()
    print(f"organizations with NO administrator  {len(orgs_without_admin)}")
    if orgs_without_admin:
        print("  Stuck: nobody can manage members, accept transfers or edit them, and they")
        print("  cannot promote anyone from the inside — recovering needs a sysadmin.")
        for label in sorted(orgs_without_admin):
            print(f"      {label}")

    dangling = [(org, uid) for org, uid in org_member_refs if uid not in all_user_ids]
    print()
    print(f"membership rows pointing at a MISSING user  {len(dangling)}")
    if dangling:
        print("  Left behind by a hard delete that removed the account without removing")
        print("  its memberships. Worse than an orphaned organization: inconsistent.")
        for org, uid in sorted(dangling, key=lambda d: d[0])[:20]:
            print(f"      {org}  ->  {uid}")
        if len(dangling) > 20:
            print(f"      ... and {len(dangling) - 20} more")

    print()
    print("Caveats on the two counts above — read before quoting them:")
    print("  * Grouped on the values AS STORED, so no SECRET_KEY is needed and the")
    print("    answer holds for any environment. Two accounts with the same plain NIC")
    print("    produce the same hash, so grouping the plain values finds them without")
    print("    hashing anything. This is what migrate-nics --dry-run cannot do:")
    print("    _find_shared_nics filters on is_nic_hashed, so where nothing is hashed")
    print("    yet it has nothing to look at and its zero is guaranteed, not measured.")
    print("  * NOT DETECTED: one account holding a plain NIC and another holding the")
    print("    hash OF THAT SAME NIC. The raw values differ and telling them apart")
    print("    needs the key. Treat the NIC figure as a lower bound.")
    print("  * Deleted accounts are excluded unless --include-deleted is passed.")

    if flagged:
        print()
        print("Institutional-looking accounts carrying a CMD/eIDAS link — a personal")
        print("civil identity is bound to a shared mailbox; each needs a decision:")
        for r in flagged:
            print(f"  - {r['email']}  ({r['cmd']}; {r['institutional']})")

    if domain_counter:
        print()
        print("Domains of the institutional-looking accounts:")
        for domain, n in domain_counter.most_common(20):
            print(f"  {n:>4}  {domain}")

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else ["email"])
            writer.writeheader()
            writer.writerows(rows)
        print(f"\nWrote {len(rows)} row(s) to {args.csv}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
