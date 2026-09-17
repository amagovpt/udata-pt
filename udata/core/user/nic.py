"""Helpers for the CMD/eIDAS identifier stored in ``user.extras.auth_nic``.

The field historically accumulated several formats:

- **hashed** (current): HMAC-SHA256 hex digest (64 hex chars) of the NIC or
  eIDAS PersonIdentifier, keyed with the app ``SECRET_KEY``. This is the only
  format the SAML login flow can match.
- **plain**: the raw NIC digits, stored by older versions of the SAML plugin.
- **legacy encrypted**: long hex ciphertexts (512 hex chars) produced by a
  previous portal version; they cannot be matched or hashed as-is and must be
  decrypted with the legacy portal key before migration.
- **junk**: assorted non-NIC values (old usernames) left behind by even older
  code paths.

It carries no provider prefix, and must not be given one
=======================================================

A prefix naming the provider ("cmd-<hash>", "eidas-<hash>") reads like the
obvious way to make an identity unambiguous, and the original request for the
authentication review asked for exactly that. It was considered and rejected,
and this note exists so nobody concludes it was simply forgotten.

The value is a one-way hash, and it is the key the login resolves accounts by
(``User.objects(extras__auth_nic=hash_nic(nic))``). The original NIC is not
recoverable from it, so the values already stored cannot be recomputed into a
prefixed form. Adding the prefix would therefore mean either accepting two
formats indefinitely, or losing the match for every CMD/eIDAS user already
registered -- which is to say locking them out of their own accounts.

``extras.auth_provider`` (see ``udata/core/user/constants.py``) records the
provider in a field of its own instead. It achieves the same disambiguation
without touching the login key, and it can be extended -- the document type
and nationality of a foreign citizen's identity go in sibling keys when those
attributes start arriving -- where a prefix baked into the hash could not be
changed afterwards at all.
"""

import hashlib
import hmac

from flask import current_app

HEX_DIGITS = set("0123456789abcdef")


def hash_nic(nic):
    """Hash a NIC value using HMAC-SHA256 with the app SECRET_KEY.

    Returns a hex digest that is deterministic (same NIC → same hash)
    but not reversible. Used for storing and matching NIC values
    without exposing the raw personal identifier in the database.

    Note: the digest depends on the environment's ``SECRET_KEY``, so
    hashes are not portable across environments and a key rotation
    invalidates every stored link.
    """
    secret = current_app.config["SECRET_KEY"]
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    return hmac.new(secret, nic.encode("utf-8"), hashlib.sha256).hexdigest()


def is_nic_hashed(nic_value):
    """Check if a stored NIC value is already an HMAC-SHA256 hex digest (64 hex chars)."""
    return bool(nic_value and len(nic_value) == 64 and all(c in HEX_DIGITS for c in nic_value))


def is_nic_plain(nic_value):
    """Check if a stored NIC value is a raw NIC (digits only), safe to hash."""
    return bool(nic_value and nic_value.isdigit())


def is_nic_legacy_encrypted(nic_value):
    """Check if a stored NIC value is a ciphertext from the legacy portal.

    Legacy values are long hex strings (512 hex chars in practice; anything
    hex of 128+ chars is treated as such). They must never be hashed — that
    would irreversibly destroy the only recoverable form of the NIC.
    """
    return bool(nic_value and len(nic_value) >= 128 and all(c in HEX_DIGITS for c in nic_value))
