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
    python scripts/audit_institutional_users.py --host 10.55.37.143
    python scripts/audit_institutional_users.py --host 10.55.37.40 --only-flagged
    python scripts/audit_institutional_users.py --host 10.55.37.143 --csv audit.csv
    python scripts/audit_institutional_users.py --host 10.55.37.143 --all-users

Environments:
    DEV: --host 10.55.37.143
    TST: --host 10.55.37.40
"""

import argparse
import csv
import re
import sys
from collections import Counter

import pymongo

SAML_PLACEHOLDER_EMAIL_PREFIX = "saml-"
SAML_PLACEHOLDER_EMAIL_DOMAIN = "autenticacao.gov.pt"

HEX_DIGITS = set("0123456789abcdef")

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


def is_hashed(nic):
    return bool(nic and len(nic) == 64 and all(c in HEX_DIGITS for c in nic.lower()))


def is_legacy_encrypted(nic):
    return bool(nic and len(nic) >= 128 and all(c in HEX_DIGITS for c in nic.lower()))


def cmd_status(user):
    """Classify the CMD/eIDAS link recorded on the account."""
    nic = (user.get("extras") or {}).get("auth_nic")
    if not nic:
        return "no"
    nic = str(nic)
    if is_hashed(nic):
        return "yes (hashed)"
    if is_legacy_encrypted(nic):
        return "stale (legacy-encrypted)"
    if nic.isdigit():
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
    org_member_ids = set()
    for org in db.organization.find({}, {"members.user": 1}):
        for member in org.get("members") or []:
            if member.get("user"):
                org_member_ids.add(member["user"])

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

    for user in db.user.find(query, projection):
        status = cmd_status(user)
        reasons = institutional_reasons(user, org_member_ids, extra_domains)
        email = (user.get("email") or "").lower()
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
