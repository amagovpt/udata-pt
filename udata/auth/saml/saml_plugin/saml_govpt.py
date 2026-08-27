# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import base64
import binascii
import hashlib
import logging
import os
import random
import re
import secrets
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from urllib.parse import quote

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from email_validator import EmailNotValidError, validate_email
from flask import (
    Blueprint,
    current_app,
    jsonify,
    make_response,
    redirect,
    request,
    session,
    url_for,
)
from flask_login import login_user, logout_user
from flask_security.confirmable import requires_confirmation, send_confirmation_instructions
from flask_security.decorators import anonymous_user_required
from flask_security.utils import do_flash, get_message, verify_and_update_password
from saml2 import (
    BINDING_HTTP_POST,
    BINDING_HTTP_REDIRECT,
    element_to_extension_element,
    entity,
    sigver,
)
from saml2 import validate as _saml_validate
from saml2 import xmldsig as ds

# autenticacao.gov coloca um valor não-IP em <SubjectConfirmationData Address="…">
# (e.g., hostname ou string não-RFC), o que faz pysaml2 rejeitar a resposta com
# `NotValid("address")` em saml2/validate.py:valid_address. A integridade desse
# atributo já é garantida pela assinatura da Response (xmlsec1 valida o digest),
# pelo que tornamos a validação permissiva, registando o valor recebido para
# rastreio. Não relaxa nenhuma das outras defesas anti-XSW/replay.
_original_valid_address = _saml_validate.valid_address


def _lenient_valid_address(address):
    try:
        return _original_valid_address(address)
    except Exception:
        logging.getLogger("udata.saml").warning(
            "SAML: SubjectConfirmation Address ignored (non-IP format): %r", address
        )
        return True


_saml_validate.valid_address = _lenient_valid_address
# saml2.response was loaded transitively by `from saml2 import entity` above and
# captured `valid_address` via `from saml2.validate import valid_address` — a
# local binding that the global patch alone does not reach. Rebind it.
import saml2.response as _saml_response  # noqa: E402

_saml_response.valid_address = _lenient_valid_address
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
from saml2.pack import http_form_post_message
from saml2.saml import NAMEID_FORMAT_UNSPECIFIED, NameID
from saml2.samlp import Extensions
from saml2.sigver import SignatureError

# autenticacao.gov uses C14N 1.0 (http://www.w3.org/TR/2001/REC-xml-c14n-20010315)
# but pysaml2 only allows Exclusive C14N by default. Add C14N 1.0 to allowed sets.
_C14N_INCLUSIVE = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
_C14N_INCLUSIVE_WITH_COMMENTS = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
ds.ALLOWED_CANONICALIZATIONS.add(_C14N_INCLUSIVE)
ds.ALLOWED_CANONICALIZATIONS.add(_C14N_INCLUSIVE_WITH_COMMENTS)
ds.ALLOWED_TRANSFORMS.add(_C14N_INCLUSIVE)
ds.ALLOWED_TRANSFORMS.add(_C14N_INCLUSIVE_WITH_COMMENTS)

from udata.app import csrf
from udata.core.user.nic import hash_nic as _hash_nic
from udata.core.user.nic import is_nic_hashed as _is_nic_hashed
from udata.i18n import lazy_gettext as _
from udata.mail import MailMessage, send_mail
from udata.models import datastore

from .faa_level import FAAALevel, LogoutUrl
from .requested_atributes import RequestedAttribute, RequestedAttributes


def _saml_form_response(html_body):
    """Wrap a pysaml2 HTML form in a Response with a CSP that allows inline scripts.

    pysaml2 generates HTML with inline <script> for auto-submitting SAML forms.
    The default CSP (script-src 'self') blocks these inline scripts, so we set
    a permissive CSP on these specific responses. This is safe because the HTML
    is server-generated, not user-supplied.
    """
    response = make_response(html_body)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; font-src 'self'; frame-ancestors 'self'"
    )
    return response


def _extract_saml_form_data(html_body):
    """Extract action URL and hidden fields from a pysaml2 HTML form.

    The frontend submits the SAML form via JavaScript instead of relying on
    pysaml2's inline auto-submit script (which is blocked by CSP).
    Returns a JSON response with action, SAMLRequest, and RelayState.
    """
    action_match = re.search(r'action="([^"]+)"', html_body)
    saml_match = re.search(r'name="SAMLRequest"\s+value="([^"]+)"', html_body)
    relay_match = re.search(r'name="RelayState"\s+value="([^"]+)"', html_body)

    return jsonify(
        {
            "action": action_match.group(1) if action_match else "",
            "SAMLRequest": saml_match.group(1) if saml_match else "",
            "RelayState": relay_match.group(1) if relay_match else "",
        }
    )


def _resolve_path(path):
    """Resolve a config path relative to the backend root directory."""
    if os.path.isabs(path):
        return path
    backend_root = os.path.dirname(current_app.root_path)
    return os.path.join(backend_root, path)


# DER bytes of OID 1.2.840.113549.1.7.2 (pkcs7-signedData). When the
# IdP signing cert in metadata.xml is shipped as a PKCS#7 bundle, the
# decoded `<X509Certificate>` payload starts with `30 82 LL LL` and then
# this OID at offset 4 — pysaml2 hands the bundle as-is to xmlsec1 which
# rejects it with `PEM_read_bio_X509_AUX:wrong tag` because it expects
# a raw X.509 SEQUENCE.
_PKCS7_SIGNED_DATA_OID = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02"


def _normalize_idp_metadata_certs(metadata_path):
    """Return a metadata file path with `<X509Certificate>` payloads guaranteed
    to be raw X.509 certs.

    autenticacao.gov has shipped the IdP signing cert wrapped in PKCS#7
    SignedData (the same format as the `.p7b` bundle that AMA distributes
    via doc-AUTENTICACAO). When that blob lands in a `<KeyDescriptor>` it
    parses as XML fine, but pysaml2 forwards the decoded bytes to xmlsec1
    via `--pubkey-cert-pem`, and OpenSSL's `PEM_read_bio_X509_AUX` rejects
    PKCS#7 with `wrong tag` because it expects an X.509 SEQUENCE.

    If any element is PKCS#7-wrapped, this helper extracts the leaf cert
    (cryptography.pkcs7.load_der_pkcs7_certificates) and writes a cleaned
    copy of the metadata XML to a content-addressed file under the system
    tmpdir. The normalized file is reused across requests with the same
    content. When nothing needs normalizing, the original path is returned
    unchanged so we do not touch files that are already correct.
    """
    try:
        with open(metadata_path, encoding="utf-8") as f:
            xml = f.read()
    except (OSError, UnicodeDecodeError):
        return metadata_path

    normalized_count = 0

    def _maybe_unwrap(match):
        nonlocal normalized_count
        raw_b64 = re.sub(r"\s+", "", match.group(1))
        if not raw_b64:
            return match.group(0)
        try:
            der = base64.b64decode(raw_b64, validate=False)
        except (binascii.Error, ValueError):
            return match.group(0)
        # PKCS#7 SignedData is SEQUENCE (0x30 0x82 LL LL) + OID at offset 4.
        # A raw X.509 cert is SEQUENCE (0x30 0x82 LL LL) + SEQUENCE (0x30 0x82 ...)
        # at offset 4, so the OID check uniquely identifies the wrapped case.
        if len(der) < 14 or der[4 : 4 + len(_PKCS7_SIGNED_DATA_OID)] != _PKCS7_SIGNED_DATA_OID:
            return match.group(0)
        try:
            certs = pkcs7.load_der_pkcs7_certificates(der)
        except Exception:
            return match.group(0)
        if not certs:
            return match.group(0)
        leaf_b64 = base64.b64encode(certs[0].public_bytes(serialization.Encoding.DER)).decode(
            "ascii"
        )
        normalized_count += 1
        return match.group(0).split(">", 1)[0] + ">" + leaf_b64 + "</X509Certificate>"

    cleaned = re.sub(
        r"<(?:ds:)?X509Certificate>([^<]+)</(?:ds:)?X509Certificate>",
        _maybe_unwrap,
        xml,
    )

    if normalized_count == 0:
        return metadata_path

    digest = hashlib.sha256(cleaned.encode("utf-8")).hexdigest()[:16]
    normalized_path = os.path.join(
        tempfile.gettempdir(),
        f"saml-idp-{digest}-{os.path.basename(metadata_path)}",
    )
    if not os.path.exists(normalized_path):
        # Write atomically: write to a sibling temp file in the same dir,
        # then rename, so concurrent workers never observe a half-written file.
        fd, tmp = tempfile.mkstemp(
            dir=os.path.dirname(normalized_path),
            prefix=os.path.basename(normalized_path) + ".",
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(cleaned)
            os.replace(tmp, normalized_path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        try:
            current_app.logger.info(
                "SAML: unwrapped PKCS#7 IdP cert in %s (%d element(s)) -> %s",
                metadata_path,
                normalized_count,
                normalized_path,
            )
        except RuntimeError:
            # No active Flask app context (e.g., import-time tests) — ignore.
            pass
    return normalized_path


autenticacao_gov = Blueprint("saml", __name__)


def _first_value(identity, key):
    """Extract the first value for a key from pysaml2 identity dict."""
    values = identity.get(key, [])
    if isinstance(values, list) and values:
        return values[0]
    if isinstance(values, str) and values:
        return values
    return None


# ---------------------------------------------------------------------------
# TEMP DIAG (remove once the SAML signature issue is resolved): when pysaml2
# rejects the Response signature, log the certificate(s) embedded in the
# SAMLResponse <ds:KeyInfo> against the certificate(s) in our configured IdP
# metadata. Matching fingerprints rule out an IdP key rotation and point at a
# canonicalization/xmlsec issue; differing fingerprints confirm the IdP rotated
# its signing key and our metadata.xml is stale.
# ---------------------------------------------------------------------------
def _diag_describe_cert(der):
    """Return a 'subject/serial/sha256' description for a DER cert blob.

    The sha256 is formatted exactly like ``openssl x509 -fingerprint -sha256``
    so it can be eyeballed against the values we computed on the host.
    """
    sha = ":".join(hashlib.sha256(der).hexdigest()[i : i + 2] for i in range(0, 64, 2)).upper()
    subject = serial = "?"
    try:
        from cryptography import x509

        cert = x509.load_der_x509_certificate(der)
        subject = cert.subject.rfc4514_string()
        serial = format(cert.serial_number, "X")
    except Exception:
        pass
    return f"subject={subject!r} serial={serial} sha256={sha}"


def _diag_extract_certs(xml_text):
    """Extract every X509Certificate DER blob from an XML/metadata string."""
    certs = []
    for m in re.finditer(
        r"<(?:ds:)?X509Certificate>([^<]+)</(?:ds:)?X509Certificate>", xml_text, re.S
    ):
        try:
            certs.append(base64.b64decode(re.sub(r"\s+", "", m.group(1))))
        except (binascii.Error, ValueError):
            continue
    return certs


def _diag_log_signature_certs(raw_saml_response, auth_servers):
    """Log embedded-vs-metadata signing certs on a signature failure."""
    try:
        try:
            xml_text = base64.b64decode(raw_saml_response).decode("utf-8", "replace")
        except Exception:
            current_app.logger.warning("SAML SIG-DIAG: could not base64-decode response")
            return

        resp_certs = _diag_extract_certs(xml_text)
        current_app.logger.warning("SAML SIG-DIAG: response embeds %d cert(s)", len(resp_certs))
        resp_fps = set()
        for i, der in enumerate(resp_certs):
            desc = _diag_describe_cert(der)
            resp_fps.add(desc.rsplit("sha256=", 1)[-1])
            current_app.logger.warning("SAML SIG-DIAG: response[%d] %s", i, desc)

        meta_fps = set()
        for server in auth_servers:
            server = server.strip()
            if not server:
                continue
            try:
                with open(_resolve_path(server), encoding="utf-8") as f:
                    meta_text = f.read()
            except OSError as exc:
                current_app.logger.warning(
                    "SAML SIG-DIAG: cannot read metadata %s: %s", server, exc
                )
                continue
            for i, der in enumerate(_diag_extract_certs(meta_text)):
                desc = _diag_describe_cert(der)
                meta_fps.add(desc.rsplit("sha256=", 1)[-1])
                current_app.logger.warning("SAML SIG-DIAG: metadata(%s)[%d] %s", server, i, desc)

        current_app.logger.warning(
            "SAML SIG-DIAG: VERDICT match=%s (a match => NOT a key rotation) "
            "response_fps=%s meta_fps=%s",
            bool(resp_fps & meta_fps),
            sorted(resp_fps),
            sorted(meta_fps),
        )
    except Exception as exc:  # diagnostics must never break the auth flow
        current_app.logger.warning("SAML SIG-DIAG: failed: %s", exc)


def _trusted_saml_issuers():
    """Return the set of SAML Issuer entityIDs we trust.

    Derived from the entityID of every metadata file listed in
    ``SECURITY_SAML_IDP_METADATA``, plus any entry in the optional
    ``TRUSTED_SAML_ISSUERS`` config (string CSV or iterable). Used to
    reject responses whose ``<Issuer>`` does not match a configured IdP
    (defence in depth on top of pysaml2's signature check).
    """
    cfg = current_app.config
    issuers = set()
    metadata_paths = (cfg.get("SECURITY_SAML_IDP_METADATA") or "").split(",")
    for path in metadata_paths:
        path = path.strip()
        if not path:
            continue
        try:
            tree = ET.parse(_resolve_path(path))
            entity_id = tree.getroot().attrib.get("entityID")
            if entity_id:
                issuers.add(entity_id)
        except (ET.ParseError, OSError):
            continue

    extra = cfg.get("TRUSTED_SAML_ISSUERS")
    if extra:
        if isinstance(extra, str):
            extra = [s.strip() for s in extra.split(",") if s.strip()]
        issuers.update(extra)
    return issuers


def _name_id_binds_nic(name_id, nic):
    """Check that the Subject NameID is bound to the NIC attribute.

    Defence against XML Signature Wrapping (XSW): if a wrapper assertion
    carries a forged ``<AttributeStatement>`` while the signed assertion
    keeps a different ``<Subject>``, the two will not match and the
    request must be rejected.

    Accepts either the raw NIC or its HMAC-SHA256 form so future IdP
    configuration changes (the IdP may emit either form as ``NameID``)
    can be honoured without code changes.
    """
    if not name_id or not nic:
        return False
    name_id = name_id.strip()
    if not name_id:
        return False
    if name_id == nic:
        return True
    if name_id == _hash_nic(nic):
        return True
    return False


_OUTSTANDING_SESSION_KEY = "saml_outstanding"
_OUTSTANDING_LIMIT = 8
_REPLAY_CACHE_KEY = "saml_consumed:{kind}:{response_id}"
_OUTSTANDING_RELAY_KEY = "saml_outstanding_relay:{token}"
_OUTSTANDING_RELAY_TTL = 600  # 10 minutes — enough for the user to complete CMD
_OUTSTANDING_RELAY_TOKEN_BYTES = 32

# CMD (autenticacao.gov MDC) attribute URIs — used both in the AuthnRequest
# RequestedAttributes and in the SSO postback extraction.
MDC_ATTR_EMAIL = "http://interop.gov.pt/MDC/Cidadao/CorreioElectronico"
MDC_ATTR_NIC = "http://interop.gov.pt/MDC/Cidadao/NIC"
MDC_ATTR_FIRST_NAME = "http://interop.gov.pt/MDC/Cidadao/NomeProprio"
MDC_ATTR_LAST_NAME = "http://interop.gov.pt/MDC/Cidadao/NomeApelido"

# eIDAS natural-person attribute URIs. Field mapping to the CMD equivalents:
# PersonIdentifier → NIC slot (extras.auth_nic, HMAC-hashed),
# CurrentGivenName → first_name (NomeProprio), CurrentFamilyName → last_name
# (NomeApelido). eIDAS has no email attribute, so eIDAS accounts always get
# a placeholder email and must complete registration on the frontend.
EIDAS_ATTR_PERSON_IDENTIFIER = "http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier"
EIDAS_ATTR_GIVEN_NAME = "http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName"
EIDAS_ATTR_FAMILY_NAME = "http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName"

# pysaml2 ships built-in attribute maps (saml2/attributemaps/saml_uri.py) that
# translate the KNOWN eIDAS natural-person URIs above into friendly names when
# NameFormat is urn:oasis:names:tc:SAML:2.0:attrname-format:uri — so
# get_identity() keys eIDAS attributes by these names, NOT by the full URIs.
# The MDC/Cidadao URIs are in no map, which is why they stay as raw URIs
# (allow_unknown_attributes) and the CMD lookups match while URI-based eIDAS
# lookups do not. Extraction must therefore try both forms.
EIDAS_FRIENDLY_PERSON_IDENTIFIER = "PersonIdentifier"
EIDAS_FRIENDLY_GIVEN_NAME = "FirstName"
EIDAS_FRIENDLY_FAMILY_NAME = "FamilyName"


def _remember_outstanding(reqid, kind):
    """Record an AuthnRequest id in the user's session.

    Used by sp_initiated/eidas_sp_initiated so that the SSO callback can
    accept the response only if its ``InResponseTo`` matches a request
    issued by the same browser session (defence in depth on top of
    pysaml2's ``allow_unsolicited=False`` flag).
    """
    if not reqid:
        return
    bucket = dict(session.get(_OUTSTANDING_SESSION_KEY, {}))
    bucket[reqid] = kind
    # Cap the bucket to avoid unbounded session-cookie growth when a user
    # opens many login tabs without completing them.
    while len(bucket) > _OUTSTANDING_LIMIT:
        bucket.pop(next(iter(bucket)))
    session[_OUTSTANDING_SESSION_KEY] = bucket


def _consume_outstanding(in_response_to, kind):
    """Validate and remove an entry from the outstanding-requests bucket.

    Returns True if ``in_response_to`` matches a tracked request of the
    expected ``kind`` (cmd / eidas) and removes it (one-time use).
    Returns False otherwise.
    """
    if not isinstance(in_response_to, str) or not in_response_to:
        return False
    bucket = dict(session.get(_OUTSTANDING_SESSION_KEY, {}))
    if bucket.pop(in_response_to, None) != kind:
        return False
    session[_OUTSTANDING_SESSION_KEY] = bucket
    return True


def _new_relay_state_token():
    """Return a fresh cryptographically random RelayState token.

    URL-safe and short enough to round-trip through HTTP-POST binding
    without bumping into IdP-side length limits. 32 random bytes → 43
    base64url characters, indistinguishable from the static placeholder
    we used to send so middleware shouldn't treat it any differently.
    """
    return secrets.token_urlsafe(_OUTSTANDING_RELAY_TOKEN_BYTES)


def _store_outstanding_relay(relay_token, reqid, kind):
    """Mirror ``_remember_outstanding`` into Redis keyed by ``RelayState``.

    Some deployments sit behind middleware (F5/WAF) that mangles the
    ``Set-Cookie`` ``SameSite`` attribute, breaking the cross-site SAML
    POST and emptying the session bucket on the callback. RelayState is
    a regular SAML form field the IdP echoes back, so the bucket can
    follow the request end-to-end without depending on the cookie.

    Stored as a 1-entry dict (``{reqid: kind}``) so ``idp_initiated``
    can merge it into the same ``outstanding`` dict it already passes
    to pysaml2. Single-use enforcement comes from
    ``_consume_outstanding_relay`` which deletes the Redis entry.
    """
    if not relay_token or not reqid:
        return
    from udata.app import cache

    try:
        cache.set(
            _OUTSTANDING_RELAY_KEY.format(token=relay_token),
            {reqid: kind},
            timeout=_OUTSTANDING_RELAY_TTL,
        )
    except Exception:
        # Cache miss is non-fatal — the session bucket still works in
        # environments where the cookie survives the cross-site POST.
        current_app.logger.warning(
            "SAML: failed to persist outstanding bucket to Redis; "
            "falling back to session cookie only",
            exc_info=True,
        )


def _consume_outstanding_relay(relay_token):
    """Return and delete the outstanding bucket stored under ``relay_token``.

    Returns ``{}`` when the token is empty, unknown, or the cache
    backend is unavailable — callers must treat the dict as advisory
    and fall back to the session-based bucket / pysaml2's own
    ``allow_unsolicited=False`` rejection if both come back empty.
    """
    if not isinstance(relay_token, str) or not relay_token:
        return {}
    from udata.app import cache

    key = _OUTSTANDING_RELAY_KEY.format(token=relay_token)
    try:
        bucket = cache.get(key) or {}
    except Exception:
        return {}
    if bucket:
        try:
            cache.delete(key)
        except Exception:
            # If delete fails the TTL will reap it; we still treat the
            # bucket as consumed for this request to keep replay defence.
            pass
    if not isinstance(bucket, dict):
        return {}
    return bucket


def _check_and_record_replay(response_id, kind, ttl=None):
    """Reject SAML responses that have already been consumed.

    Uses Flask-Caching as a shared (Redis-backed in production) replay
    cache keyed on ``Response@ID``. ``ttl`` defaults to 120 seconds —
    well above the 60-second ``accepted_time_diff`` we tolerate, which
    is the window in which a captured signed response could otherwise
    be replayed.
    """
    from udata.app import cache

    if not isinstance(response_id, str) or not response_id:
        # Without a trustworthy ID we cannot deduplicate; pysaml2's
        # NotOnOrAfter check is the remaining defence.
        return True
    cache_key = _REPLAY_CACHE_KEY.format(kind=kind, response_id=response_id)
    if cache.get(cache_key):
        return False
    cache.set(cache_key, True, timeout=ttl if ttl is not None else 120)
    return True


audit_logger = logging.getLogger("saml.audit")


def _audit_saml(outcome, kind, *, issuer=None, name_id=None, reason=None):
    """Emit a structured SAML SSO audit log line.

    One line per terminal decision (success/reject/error) so the SAML
    authentication funnel can be traced post-hoc without correlating
    multiple debug logs. ``name_id`` is hashed (HMAC-SHA256) so the raw
    Subject identifier is never written to disk; this matches how it is
    stored in ``user.extras.auth_nic``.
    """
    name_id_hash = "-"
    if name_id:
        try:
            name_id_hash = _hash_nic(name_id)
        except Exception:  # noqa: BLE001
            # Hashing requires SECRET_KEY; if missing, swallow rather
            # than turn an audit emission into a 500.
            name_id_hash = "?"
    try:
        ip = request.remote_addr or "-"
        ua = request.user_agent.string if request.user_agent else "-"
    except RuntimeError:
        # Outside of a request context (e.g. unit tests calling helpers
        # directly) audit fields fall back to placeholders.
        ip = "-"
        ua = "-"
    audit_logger.info(
        "saml_sso outcome=%s kind=%s issuer=%s name_id_hash=%s ip=%s ua=%r reason=%s",
        outcome,
        kind,
        issuer or "-",
        name_id_hash,
        ip,
        ua,
        reason or "-",
    )


def _reject_saml_login(
    log_message,
    flash_message,
    log_level="error",
    *,
    kind="cmd",
    issuer=None,
    name_id=None,
    reason=None,
    detail=None,
):
    """Reject a SAML SSO request: log + audit + flash + redirect.

    Used for every fail-closed exit in the SSO callback so the failure
    surface is uniform: no session cookie issued, generic flash for the
    user, structured log for the operator and a dedicated audit entry
    so security can replay rejections without grepping debug logs.
    """
    log = current_app.logger
    getattr(log, log_level)(log_message)
    _audit_saml("rejected", kind, issuer=issuer, name_id=name_id, reason=reason or log_message)
    do_flash(flash_message, "error")
    frontend_url = current_app.config.get("CDATA_BASE_URL") or ""
    # Surface the rejection code in the redirect so the failure is visible
    # in a browser network trace (environments where operators cannot reach
    # the backend logs). Short internal codes only — never log text.
    # ``detail`` may carry non-sensitive schema information (e.g. the
    # attribute URIs the IdP returned) — never identity values.
    error_code = quote(reason or "rejected", safe="")
    destination = f"{frontend_url}/login?saml_error={error_code}"
    if detail:
        destination += f"&saml_detail={quote(detail, safe='')}"
    return redirect(destination)


def _idp_status_rejection(raw_saml_response, kind):
    """Pre-check the raw SAMLResponse for an IdP-side rejection.

    When the IdP returns a non-Success ``samlp:StatusCode`` (e.g. the user
    cancelled, or the request was denied upstream), pysaml2 raises
    ``StatusError`` during parsing — which would surface as a 500. Detect it
    first and return a clean redirect with the human-readable reason; return
    ``None`` when the status is Success (or unreadable, in which case the
    normal fail-closed parsing decides).
    """
    try:
        decoded_xml = base64.b64decode(raw_saml_response)
        xml_str = None
        for codec in ["utf-8", "ISO-8859-1"]:
            try:
                xml_str = decoded_xml.decode(codec)
                break
            except UnicodeDecodeError:
                continue
        if xml_str:
            status_root = ET.fromstring(xml_str)
            ns = {"samlp": "urn:oasis:names:tc:SAML:2.0:protocol"}
            status_code = status_root.find(".//samlp:StatusCode", ns)
            status_msg = status_root.find(".//samlp:StatusMessage", ns)
            if status_code is not None:
                status_value = status_code.attrib.get("Value", "")
                if "Success" not in status_value:
                    # Extract human-readable message; fall back to status URI
                    msg_text = status_msg.text if status_msg is not None else None
                    # Also check for a nested sub-status code (e.g. RequestDenied)
                    sub_code = status_code.find("samlp:StatusCode", ns)
                    sub_value = sub_code.attrib.get("Value", "") if sub_code is not None else ""
                    display_msg = msg_text or sub_value.rsplit(":", 1)[-1] or status_value
                    current_app.logger.error(
                        f"SAML ({kind}): IdP rejeitou o pedido: "
                        f"status={status_value}, sub={sub_value}, msg={msg_text}"
                    )
                    _audit_saml("rejected", kind, reason="idp_denied")
                    frontend_url = current_app.config.get("CDATA_BASE_URL") or ""
                    do_flash(f"Autenticação rejeitada: {display_msg}", "error")
                    return redirect(f"{frontend_url}/login?saml_error=idp_denied")
    except Exception as e:
        current_app.logger.warning(f"SAML ({kind}): Falha ao verificar status da resposta: {e}")
    return None


def _create_saml_user(user_email, user_nic, first_name, last_name):
    """Create a new account from SAML attributes (scenario 4)."""
    # Generate a placeholder email when the IdP does not provide one, or
    # when the CMD email is already taken by an existing account (the
    # user explicitly chose to create a new one in the wizard).
    if not user_email or datastore.find_user(email=user_email):
        import uuid

        from udata.core.user.constants import (
            SAML_PLACEHOLDER_EMAIL_DOMAIN,
            SAML_PLACEHOLDER_EMAIL_PREFIX,
        )

        user_email = (
            f"{SAML_PLACEHOLDER_EMAIL_PREFIX}{uuid.uuid4().hex[:8]}@{SAML_PLACEHOLDER_EMAIL_DOMAIN}"
        )

    user_data = {
        "first_name": (first_name or "").title(),
        "last_name": (last_name or "").title(),
        "email": user_email,
    }
    if user_nic:
        user_data["extras"] = {"auth_nic": _hash_nic(user_nic)}

    user = datastore.create_user(**user_data)
    # Auto-confirm users created via SAML — they were already verified
    # by autenticação.gov, so no email confirmation is needed.
    user.confirmed_at = datetime.utcnow()
    datastore.commit()

    return user


# Marks an account whose email was typed by the user rather than vouched for
# by the IdP. autenticação.gov proves the *identity*; it says nothing about an
# address the user just declared, so that address must be confirmed by its
# owner before the account gets a session. Every other SAML flow keeps today's
# auto-confirm, which is exactly what this marker buys. It never needs
# clearing: once confirmed_at is set the gate opens and the marker is inert.
PENDING_EMAIL_CONFIRMATION = "pending_email_confirmation"

# How many confirmation mails one pending account may ever trigger, and where
# that tally lives. It is monotonic — correcting the address does not reset it —
# so the ceiling is per CMD identity, not per address typed. It is kept on the account rather than in the session because the
# recipient is an address the wizard user typed: a session-held counter is
# reset by replaying an older copy of the signed cookie, which would leave the
# resend endpoint able to mail an arbitrary victim without limit.
CONFIRMATION_SEND_COUNT = "confirmation_send_count"
MAX_CONFIRMATION_SENDS = 5


def _create_pending_saml_user(user_email, user_nic, first_name, last_name):
    """Create an account from a user-declared email, left unconfirmed.

    Unlike :func:`_create_saml_user` this never mints a placeholder address —
    the caller has already validated that ``user_email`` is well-formed and
    unused — and it deliberately does NOT set ``confirmed_at``: the account
    stays unconfirmed, and without a session, until the owner follows the
    emailed confirmation link.
    """
    user = datastore.create_user(
        first_name=(first_name or "").title(),
        last_name=(last_name or "").title(),
        email=user_email,
        extras={"auth_nic": _hash_nic(user_nic), PENDING_EMAIL_CONFIRMATION: True},
    )
    datastore.commit()

    return user


def _find_user_by_email_ci(email):
    """Resolve an address case-insensitively, preferring an exact match.

    Every login and recovery lookup is case-insensitive, so the wizard has to
    be too. But the unique index on ``User.email`` is case-SENSITIVE, so
    "maria@x.pt" and "MARIA@x.pt" can coexist (the email-change form and
    _create_saml_user both still check exact), and ``User`` orders by
    ``-created_at`` — a bare ``__iexact`` lookup would hand back whichever row
    was created last. Where two rows answer to one address, the one the caller
    typed is the one they meant.
    """
    from udata.core.user.models import User

    if not email:
        return None
    matches = list(User.objects(email__iexact=email))
    if not matches:
        return None
    for user in matches:
        if user.email == email:
            return user
    return matches[0]


def _has_linked_nic(user):
    """True when the account holds a properly linked (hashed) CMD identity.

    Plain, legacy-encrypted or junk ``auth_nic`` values left behind by older
    portal versions do not count as a link: they can never match a login
    lookup, so the account must stay eligible for the migration wizard to
    re-link it (the wizard overwrites the stale value with a fresh hash).
    """
    return _is_nic_hashed((user.extras or {}).get("auth_nic"))


def _find_or_create_saml_user(user_email, user_nic, first_name, last_name):
    """Resolve the CMD/SAML identity to an account.

    ``user_nic`` carries the unique identifier of the authenticated identity:
    the NIC for CMD logins, or the eIDAS PersonIdentifier (e.g. "ES/PT/...")
    for eIDAS logins. Both are HMAC-hashed into ``extras.auth_nic`` — the
    formats cannot collide, and every lookup/linking rule below applies to
    either provider identically.

    Decision order:
    1. NIC already linked (hashed, or stored in plain form by an old plugin
       version — upgraded to the hash on the spot) → direct login (entry
       rule). This is the ONLY path that logs the user in without ownership
       confirmation.
    2. Email match → suspected existing account; the user must confirm
       ownership through the migration wizard before linking
    3. Name-only match → same, suspected existing account
    4. No match → no account; the caller decides what to do

    Accounts whose ``auth_nic`` holds a stale non-hashed value (plain NIC of
    a different identity, legacy ciphertext, junk) are NOT treated as linked:
    they remain wizard candidates in rules 2 and 3.

    This is a pure resolver: it never creates an account. Creating one is the
    caller's decision, because it depends on whether the migration wizard is
    enabled — with the wizard on, an unmatched identity goes through it and
    must supply a confirmed email before any account exists.

    Returns a tuple (user, status) where status is one of:
    - "existing_saml" — NIC already linked, normal login
    - "migration_candidate" — email or name match; user is the single
      candidate account, or None when several homonyms exist
    - "no_match" — nothing matched; user is always None
    - "error" — neither email nor NIC available
    """
    from udata.core.user.models import User

    # 1. CMD identity already linked: direct login, nothing else to check.
    #    (Use MongoEngine nested dict syntax, not find_user, because
    #    find_user(extras={...}) matches the entire dict exactly.)
    if user_nic:
        user = User.objects(extras__auth_nic=_hash_nic(user_nic)).first()
        if user:
            return user, "existing_saml"

        # 1b. Same identity stored in plain form by an old plugin version:
        #     the incoming NIC comes from a signed autenticacao.gov
        #     assertion, so an exact match proves the link — upgrade the
        #     stored value to the hashed format and log the user in.
        user = User.objects(extras__auth_nic=user_nic).first()
        if user:
            user.extras["auth_nic"] = _hash_nic(user_nic)
            user.save()
            current_app.logger.info(f"SAML: upgraded plain stored NIC to hash for user {user.id}")
            return user, "existing_saml"

    # 2. Match by email: never auto-link — ownership must be proven
    #    (password or email code) via the migration wizard. Accounts
    #    already linked to another CMD identity are not candidates.
    if user_email:
        # Case-insensitive, as everywhere else the wizard resolves an
        # address: an exact match here sends the owner of "maria@x.pt" whose
        # CMD carries "Maria@x.pt" down the no_match branch, making them ask
        # for an account they already have.
        user = _find_user_by_email_ci(user_email)
        if user and not _has_linked_nic(user):
            current_app.logger.info(
                f"SAML: email match for an existing account "
                f"(id={user.id}) — ownership confirmation required"
            )
            return user, "migration_candidate"

    # 3. Name-only match against accounts without a linked CMD identity:
    #    never auto-merge — ownership must be proven (password or email
    #    code) via the migration wizard before linking. The non-hashed
    #    filter cannot be expressed in the query, so filter in Python.
    if first_name and last_name:
        candidates = [
            candidate
            for candidate in User.objects(
                first_name__iexact=first_name,
                last_name__iexact=last_name,
                deleted=None,
            )
            if not _has_linked_nic(candidate)
        ]
        count = len(candidates)
        if count:
            candidate = candidates[0] if count == 1 else None
            current_app.logger.info(
                f"SAML: name-only match for {first_name} {last_name} "
                f"({count} candidate(s)) — ownership confirmation required"
            )
            return candidate, "migration_candidate"

    if not user_email and not user_nic:
        current_app.logger.error("SAML: Cannot create user without email or NIC")
        return None, "error"

    return None, "no_match"


def _handle_saml_user_login(user, new_account=False):
    """Handle login/redirect after SAML authentication.

    When ``new_account`` is True the redirect carries ``cmd_new_account=1``
    so the frontend can inform the user that a new account was created
    (scenario 4).
    """
    frontend_url = current_app.config.get("CDATA_BASE_URL") or ""
    next_path = session.pop("saml_next_url", "")

    if user is None:
        current_app.logger.warning(
            f"[DEBUG] _handle_saml_user_login: user is None -> redirect /login "
            f"(frontend_url={frontend_url!r})"
        )
        do_flash(*get_message("CONFIRMATION_REQUIRED"))
        # user is None only when the IdP response carried neither an email
        # nor a NIC/PersonIdentifier — expose it in the redirect for
        # browser-trace diagnosis (see _reject_saml_login).
        return redirect(f"{frontend_url}/login?saml_error=missing_attributes")

    if user.deleted:
        current_app.logger.warning(
            f"[DEBUG] _handle_saml_user_login: user.deleted=True, email={user.email!r}"
        )
        do_flash(*get_message("DISABLED_ACCOUNT"))
        return redirect(frontend_url or "/")

    # An account created by the wizard from a self-declared email must not be
    # let in — nor auto-confirmed — until its owner follows the emailed link.
    # This gate has to sit BEFORE the auto-confirm below: the account already
    # carries the NIC, so a repeat CMD login resolves straight to it, and the
    # auto-confirm would otherwise turn the whole confirmation requirement
    # into a "just try again". The gate needs no cleanup: once confirmed_at is
    # set by the stock confirm flow, it stops matching and the marker is inert.
    if user.confirmed_at is None and (user.extras or {}).get(PENDING_EMAIL_CONFIRMATION):
        current_app.logger.info(
            f"SAML: login blocked, email confirmation still pending for user {user.id}"
        )
        # Identifies the user to the resend endpoint without authenticating
        # them — the wizard shows the pending-confirmation screen from it.
        # Any wizard state still lying around belongs to an earlier, abandoned
        # assertion; left in place, migration_pending would answer with that
        # stale wizard instead of this screen.
        session.pop("saml_migration_pending", None)
        session.pop("migration_code", None)
        session.pop("migration_send_count", None)
        session.pop("migration_password_attempts", None)
        session["saml_confirmation_pending"] = {"user_id": str(user.id)}
        return redirect(f"{frontend_url}/migrate-account")

    if requires_confirmation(user):
        # Auto-confirm on SAML login — autenticação.gov already verified the
        # user. This vouches for the IDENTITY, which is why it does not apply
        # to the self-declared addresses gated above.
        user.confirmed_at = datetime.utcnow()
        datastore.commit()

    login_user(user)
    session["saml_login"] = True
    # Whoever is logging in now owns this session. A confirmation handle left
    # by someone else on a shared browser would otherwise disclose their masked
    # address through migration_pending and let this user spend their send
    # budget.
    session.pop("saml_confirmation_pending", None)

    # Accounts still holding a minted saml-* placeholder email (new accounts
    # created without a usable CMD email, or older ones from before this
    # check) must provide a real email before using the portal. The original
    # destination is dropped on purpose: completing registration is a hard
    # precondition, and the page explains the situation itself (no
    # cmd_new_account banner needed).
    if user.has_placeholder_email:
        return redirect(f"{frontend_url}/complete-registration")

    destination = f"{frontend_url}{next_path}" if next_path else (frontend_url or "/")
    if new_account:
        separator = "&" if "?" in destination else "?"
        destination = f"{destination}{separator}cmd_new_account=1"
    current_app.logger.warning(
        f"[DEBUG] _handle_saml_user_login: login_user OK, email={user.email!r}, "
        f"redirect destination={destination!r}, next_path={next_path!r}"
    )
    return redirect(destination)


def _handle_migration_redirect(user, user_email, user_nic, first_name, last_name, no_match=False):
    """Store SAML data in session and redirect to migration page.

    ``user`` is the single candidate account matched by name, or None
    when several homonym accounts exist — in that case the wizard asks
    the user to identify the account (login or search).
    ``saml_email`` is always the email coming from the CMD identity,
    never the candidate account's email.

    ``no_match`` says the identity matched nothing at all, as opposed to
    matching several homonyms. Both cases arrive with ``user`` unset, so the
    wizard cannot tell them apart otherwise — and they need different first
    steps: create an account, versus help me find mine.
    """
    session["saml_migration_pending"] = {
        "legacy_user_id": str(user.id) if user else None,
        "no_match": no_match,
        "saml_email": user_email,
        "saml_nic": user_nic,
        "saml_first_name": first_name,
        "saml_last_name": last_name,
    }
    frontend_url = current_app.config.get("CDATA_BASE_URL") or ""
    has_email = bool(user_email)
    no_email_param = "" if has_email else "?no_email=true"
    return redirect(f"{frontend_url}/migrate-account{no_email_param}")


def _mask_email(email):
    """Mask an email address for display (e.g. j***@example.com)."""
    if not email or "@" not in email:
        return ""
    local, domain = email.rsplit("@", 1)
    if len(local) <= 1:
        masked = local + "***"
    else:
        masked = local[0] + "***"
    return f"{masked}@{domain}"


def _point_migration_candidate(pending, user):
    """Point the pending migration at ``user`` as the account to link.

    The single place that mutates the candidate reference. Any code already
    emailed was issued for a different target, so it has to die with the
    re-point — copying that invariant to a second call site is how
    target-confusion gets reintroduced.
    """
    # Store only the candidate reference — saml_email must keep holding
    # the email coming from the CMD identity (or None), never the
    # legacy account's email.
    pending["legacy_user_id"] = str(user.id)
    session["saml_migration_pending"] = pending
    session.pop("migration_code", None)
    session.modified = True


def _send_migration_code(user, code):
    """Send a verification code email for account migration."""
    msg = MailMessage(
        subject=_("Account migration verification code"),
        paragraphs=[
            _(
                "Someone is linking a CMD identity to your %(site)s account.",
                site=current_app.config.get("SITE_TITLE", "dados.gov.pt"),
            ),
            _("Your verification code is: %(code)s", code=code),
            _("This code expires in 10 minutes."),
            _("If you did not request this, ignore this email."),
        ],
    )
    send_mail(user, msg)


def _find_legacy_user(email=None, first_name=None, last_name=None):
    """Find a legacy user (has password, no NIC, not deleted) by email or name."""
    user = None
    if email:
        # Case-insensitive, for the same reason the skip uniqueness check
        # is: every login and recovery lookup goes through
        # SECURITY_USER_IDENTITY_ATTRIBUTES, which is case-INSENSITIVE. An
        # exact match here would leave the owner of "maria@x.pt" unable to
        # find their own account by typing "Maria@x.pt" — the one address
        # they are sure of.
        user = _find_user_by_email_ci(email)
    elif first_name and last_name:
        from udata.core.user.models import User

        user = User.objects(
            first_name__iexact=first_name,
            last_name__iexact=last_name,
            deleted=None,
        ).first()

    if user and user.password and not _has_linked_nic(user):
        if not user.deleted:
            return user
    return None


#################################################################
# Given the name of an IdP, return a configuation.
##
#################################################################


def _build_sp_settings(acs_url, out_url, metadata_file):
    """Build pysaml2 SP settings with encryption support."""
    key_file = _resolve_path(current_app.config.get("SECURITY_SAML_KEY_FILE"))
    cert_file = _resolve_path(current_app.config.get("SECURITY_SAML_CERT_FILE"))

    return {
        "entityid": current_app.config.get("SECURITY_SAML_ENTITY_ID"),
        "name": current_app.config.get("SECURITY_SAML_ENTITY_NAME"),
        "key_file": key_file,
        "cert_file": cert_file,
        # Use SHA256 — this xmlsec1 build does not support rsa-sha1
        "signing_algorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        "digest_algorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
        # Keypair for decrypting encrypted assertions from autenticacao.gov
        "encryption_keypairs": [
            {
                "key_file": key_file,
                "cert_file": cert_file,
            },
        ],
        "metadata": {"local": [_normalize_idp_metadata_certs(_resolve_path(metadata_file))]},
        # Trust anchor pinning: verify SAML Response signatures exclusively
        # against the IdP cert loaded from metadata.xml, never against the
        # cert that autenticacao.gov inlines in <ds:KeyInfo>/<X509Certificate>.
        # AMA sometimes ships that inline element as a PKCS#7 SignedData
        # bundle, which pysaml2 base64-wraps with PEM CERTIFICATE markers and
        # hands to xmlsec1; OpenSSL's PEM_read_bio_X509_AUX then rejects it
        # with "wrong tag" (it expects an X.509 SEQUENCE, not PKCS#7), and
        # signature verification fails with no path to recover. Pinning to
        # the offline-distributed metadata cert also hardens trust anchoring.
        "only_use_keys_in_metadata": True,
        "accepted_time_diff": 60,
        # autenticacao.gov ships attributes with URIs from the
        # `http://interop.gov.pt/MDC/Cidadao/*` namespace, which is not part
        # of pysaml2's default URI converters. With allow_unknown_attributes
        # disabled the parser silently drops those attributes and get_identity()
        # returns {}, yielding a `user_not_found` redirect to /login
        # without an error. Allow unknown attributes so they reach the
        # extraction code in idp_initiated.
        "allow_unknown_attributes": True,
        "service": {
            "sp": {
                "endpoints": {
                    "assertion_consumer_service": [
                        (acs_url, BINDING_HTTP_REDIRECT),
                        (acs_url, BINDING_HTTP_POST),
                    ],
                    "single_logout_service": [
                        (out_url, BINDING_HTTP_REDIRECT),
                        (out_url, BINDING_HTTP_POST),
                    ],
                },
                # Refuse responses that are not tied to an AuthnRequest we
                # issued. The req_id is stored in the user's Flask session
                # by sp_initiated() and passed to parse_authn_request_response
                # via the ``outstanding`` argument (VULN-2077 / TICKET-58).
                "allow_unsolicited": False,
                # Sign authn requests
                "authn_requests_signed": True,
                "logout_requests_signed": True,
                # autenticacao.gov assina o <Response> mas não cada <Assertion>.
                # Aceitamos só assinatura da Response — xmlsec1 verifica o digest
                # sobre o XML canonical, garantindo integridade do conteúdo interno.
                # Defesas anti-XSW continuam: Issuer whitelist, replay cache e
                # binding Subject↔NIC (`_name_id_binds_nic`).
                "want_assertions_signed": False,
                "want_response_signed": True,
            },
        },
    }


def _force_scheme(url):
    """Force the URL scheme to match PREFERRED_URL_SCHEME config.

    Next.js rewrites proxy requests to the backend over plain HTTP,
    so Flask sees http:// even when the real client uses https://.
    """
    scheme = current_app.config.get("PREFERRED_URL_SCHEME")
    if scheme and url.startswith("http://") and scheme == "https":
        return "https://" + url[len("http://") :]
    return url


def _saml_endpoint_url(endpoint_name):
    """Build an absolute URL for a SAML endpoint advertised to the IdP.

    When ``SAML_ACS_BASE_URL`` is set, prepend it to the endpoint path so the
    SP always advertises the same registered URL to the IdP regardless of the
    hostname the current request arrived on (e.g., when the SP is reachable
    via multiple hostnames or fronted by a gateway). When unset, fall back to
    the existing behaviour of resolving the URL from the active request via
    ``url_for(..., _external=True)`` and ``PREFERRED_URL_SCHEME``.
    """
    base = (current_app.config.get("SAML_ACS_BASE_URL") or "").rstrip("/")
    if base:
        return base + url_for(endpoint_name)
    return _force_scheme(url_for(endpoint_name, _external=True))


def saml_client_for(metadata_file):
    acs_url = _saml_endpoint_url("saml.idp_initiated")
    out_url = _saml_endpoint_url("saml.saml_logout_postback")

    settings = _build_sp_settings(acs_url, out_url, metadata_file)
    spConfig = Saml2Config()
    spConfig.load(settings)
    saml_client = Saml2Client(config=spConfig)
    return saml_client


#################################################################
# Prepares and sends SAML Auth Request.
##
#################################################################
@autenticacao_gov.route("/saml/login")
@anonymous_user_required
def sp_initiated():
    next_url = request.args.get("next", "")
    if next_url.startswith("/") and not next_url.startswith("//"):
        session["saml_next_url"] = next_url

    saml_client = saml_client_for(
        current_app.config.get("SECURITY_SAML_IDP_METADATA").split(",")[0]
    )

    faa = FAAALevel(text=str(current_app.config.get("SECURITY_SAML_FAAALEVEL")))

    spcertenc = RequestedAttributes(
        [
            RequestedAttribute(
                name=MDC_ATTR_EMAIL,
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                is_required="True",
            ),
            RequestedAttribute(
                name=MDC_ATTR_NIC,
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                is_required="False",
            ),
            RequestedAttribute(
                name=MDC_ATTR_FIRST_NAME,
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                is_required="False",
            ),
            RequestedAttribute(
                name=MDC_ATTR_LAST_NAME,
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                is_required="False",
            ),
        ]
    )

    extensions = Extensions(
        extension_elements=[
            element_to_extension_element(faa),
            element_to_extension_element(spcertenc),
        ]
    )

    relay_token = _new_relay_state_token()
    args = {
        "binding": BINDING_HTTP_POST,
        "relay_state": relay_token,
        "sign": True,
        "force_authn": "true",
        "is_passive": "false",
        "nameid_format": "",
        "extensions": extensions,
    }

    reqid, info = saml_client.prepare_for_authenticate(**args)
    # Track the AuthnRequest id so idp_initiated() can reject responses
    # that are not ``InResponseTo`` a request we issued
    # (VULN-2077 / TICKET-58 — defence-in-depth on top of pysaml2's
    # ``allow_unsolicited=False`` flag).
    _remember_outstanding(reqid, kind="cmd")
    # Mirror into Redis keyed by RelayState. Some deployments sit behind
    # WAFs/load-balancers (F5) that mangle the SameSite attribute on
    # `Set-Cookie`, dropping the session cookie on the cross-site SAML
    # POST and emptying the bucket on the callback. RelayState rides
    # the form payload end-to-end so the bucket survives that path too.
    _store_outstanding_relay(relay_token, reqid, kind="cmd")
    # TEMP DIAG (remove after PPR is green): confirm bucket landed in Redis.
    try:
        from udata.app import cache as _diag_cache

        _diag_stored = _diag_cache.get(_OUTSTANDING_RELAY_KEY.format(token=relay_token))
    except Exception as _diag_exc:
        _diag_stored = f"cache_err:{type(_diag_exc).__name__}"
    current_app.logger.info(
        "SAML diag sp_initiated kind=cmd reqid=%s relay_token=%s relay_token_len=%d "
        "redis_readback=%r session_bucket_keys=%s",
        reqid,
        relay_token,
        len(relay_token),
        _diag_stored,
        list(session.get(_OUTSTANDING_SESSION_KEY, {}).keys()),
    )
    return _extract_saml_form_data(info["data"])


#################################################################
# Receives SAML Response.
##
#################################################################


@autenticacao_gov.route("/saml/sso", methods=["POST"])
@csrf.exempt
def idp_initiated():
    user_email = None
    user_nic = None
    first_name = None
    last_name = None
    authn_response = None

    raw_saml_response = request.form.get("SAMLResponse")
    if not raw_saml_response:
        return "Erro: SAMLResponse em falta", 400

    auth_servers = current_app.config.get("SECURITY_SAML_IDP_METADATA").split(",")

    # 0. Verificar se o IdP rejeitou o pedido (antes de tentar pysaml2)
    denied = _idp_status_rejection(raw_saml_response, kind="cmd")
    if denied is not None:
        return denied

    # 1. Validar a resposta SAML com pysaml2 (verifica assinatura + desencripta).
    # Política fail-closed (VULN-2077 / TICKET-58):
    # - MissingKey ou SignatureError em um IdP só é tolerado se ainda houver
    #   outro IdP por tentar; após esgotados, o pedido é rejeitado.
    # - Outras excepções propagam (500) — pedidos malformados não devem
    #   contornar a validação.
    # - ``outstanding`` liga o ``InResponseTo`` ao pedido SP-initiated; com
    #   ``allow_unsolicited=False``, pysaml2 rejeita respostas sem um
    #   AuthnRequest correspondente (defesa contra replay/IdP-initiated).
    #   O bucket vem (a) da sessão (cookie path) e (b) do Redis indexado
    #   pelo RelayState ecoado pela AMA — assim sobrevivemos a middleware
    #   que mangleia o atributo SameSite do cookie de sessão.
    outstanding = dict(session.get(_OUTSTANDING_SESSION_KEY, {}))
    relay_token = request.form.get("RelayState", "")
    _diag_redis_bucket = _consume_outstanding_relay(relay_token)
    outstanding.update(_diag_redis_bucket)
    # TEMP DIAG (remove after PPR is green): see what AMA actually echoed and
    # whether we matched it in Redis. `in_response_to` is parsed from raw XML
    # below by pysaml2; here we just confirm the inputs we received.
    try:
        _diag_form_keys = list(request.form.keys())
    except Exception:
        _diag_form_keys = []
    _diag_inresponse_to = None
    try:
        _decoded_diag = base64.b64decode(raw_saml_response)
        _m = re.search(r'\bInResponseTo="([^"]+)"', _decoded_diag.decode("utf-8", "replace"))
        if _m:
            _diag_inresponse_to = _m.group(1)
    except Exception:
        pass
    current_app.logger.info(
        "SAML diag idp_initiated kind=cmd form_keys=%s relay_state_recv=%r "
        "relay_state_len=%d session_bucket_keys=%s redis_bucket=%s "
        "merged_outstanding_keys=%s in_response_to=%r cookie_keys=%s",
        _diag_form_keys,
        relay_token,
        len(relay_token or ""),
        list(session.get(_OUTSTANDING_SESSION_KEY, {}).keys()),
        _diag_redis_bucket,
        list(outstanding.keys()),
        _diag_inresponse_to,
        list(request.cookies.keys()),
    )
    last_validation_error = None
    for server in auth_servers:
        saml_client = saml_client_for(server)
        try:
            authn_response = saml_client.parse_authn_request_response(
                raw_saml_response,
                entity.BINDING_HTTP_POST,
                outstanding=outstanding,
            )
        except (sigver.MissingKey, SignatureError) as exc:
            last_validation_error = exc
            current_app.logger.warning(f"SAML rejeitado por {server}: {type(exc).__name__}: {exc}")
            continue
        current_app.logger.info(f"SAML: pysaml2 processou com sucesso via {server}")
        break

    if authn_response is None:
        _diag_log_signature_certs(raw_saml_response, auth_servers)  # TEMP DIAG
        return _reject_saml_login(
            "SAML SSO rejeitado: nenhum IdP validou a resposta assinada "
            f"(último erro: {last_validation_error})",
            _("Autenticação rejeitada: assinatura SAML inválida."),
            kind="cmd",
            reason="signature_invalid",
        )

    # 1a. Replay cache: refuse a Response@ID we have already consumed
    # (VULN-2077 / TICKET-58). Skipped for non-string IDs (test mocks).
    response_id = getattr(getattr(authn_response, "response", None), "id", None)
    if not _check_and_record_replay(response_id, kind="cmd"):
        return _reject_saml_login(
            f"SAML SSO rejeitado: replay de Response@ID={response_id!r}",
            _("Autenticação rejeitada: resposta já utilizada."),
            kind="cmd",
            reason="replay",
        )

    # 1aa. One-time use of the matched AuthnRequest id (defence in depth
    # on top of pysaml2's outstanding-queries check).
    in_response_to = getattr(authn_response, "in_response_to", None)
    if isinstance(in_response_to, str) and in_response_to:
        _consume_outstanding(in_response_to, kind="cmd")

    # 1b. Validar Issuer e Subject/NameID (VULN-2077 / TICKET-58).
    # pysaml2 já confirmou a assinatura; defesa-em-profundidade contra XSW
    # exige que o Issuer venha da nossa whitelist e que o Subject NameID
    # exista para mais tarde ser confrontado com o atributo NIC.
    try:
        issuer = authn_response.issuer()
    except Exception as exc:  # noqa: BLE001 — pysaml2 attribute access surfaces
        return _reject_saml_login(
            f"SAML SSO rejeitado: falha a obter Issuer ({exc})",
            _("Autenticação rejeitada: resposta SAML inválida."),
            kind="cmd",
            reason="issuer_unreadable",
        )

    trusted_issuers = _trusted_saml_issuers()
    if issuer not in trusted_issuers:
        return _reject_saml_login(
            f"SAML SSO rejeitado: Issuer não confiado ({issuer!r})",
            _("Autenticação rejeitada: emissor SAML desconhecido."),
            kind="cmd",
            issuer=issuer,
            reason="issuer_untrusted",
        )

    try:
        subject = authn_response.get_subject()
    except Exception as exc:  # noqa: BLE001
        return _reject_saml_login(
            f"SAML SSO rejeitado: falha a obter Subject ({exc})",
            _("Autenticação rejeitada: identidade SAML em falta."),
            kind="cmd",
            issuer=issuer,
            reason="subject_unreadable",
        )
    name_id_value = (getattr(subject, "text", None) or "").strip() if subject else ""
    name_id_format = (getattr(subject, "format", None) or "").strip() if subject else ""
    if not name_id_value:
        return _reject_saml_login(
            "SAML SSO rejeitado: Subject/NameID em falta",
            _("Autenticação rejeitada: identidade SAML em falta."),
            kind="cmd",
            issuer=issuer,
            reason="subject_missing",
        )

    # 2. Extrair atributos a partir do objecto validado pelo pysaml2.
    # Não existe fallback: atributos só são lidos depois da assinatura
    # ter sido verificada por pysaml2 (VULN-2077 / TICKET-58).
    try:
        identity = authn_response.get_identity()
        current_app.logger.info(f"SAML pysaml2 identity: {identity}")

        # Também tentar ava (attribute value assertions) como alternativa
        if not identity:
            try:
                ava = authn_response.ava
                current_app.logger.info(f"SAML pysaml2 ava: {ava}")
                if ava:
                    identity = ava
            except AttributeError:
                pass

        if identity:
            user_email = _first_value(identity, MDC_ATTR_EMAIL)
            user_nic = _first_value(identity, MDC_ATTR_NIC)
            first_name = _first_value(identity, MDC_ATTR_FIRST_NAME)
            last_name = _first_value(identity, MDC_ATTR_LAST_NAME)
            current_app.logger.warning(
                f"[DEBUG] SAML atributos extraídos: email={user_email!r}, "
                f"nic_present={bool(user_nic)}, nome={first_name!r} {last_name!r}, "
                f"identity_keys={list(identity.keys()) if identity else None}"
            )
        else:
            # Log debug info para diagnosticar
            current_app.logger.warning(
                f"SAML pysaml2: identity vazio. "
                f"response type={type(authn_response).__name__}, "
                f"assertions={getattr(authn_response, 'assertions', 'N/A')}, "
                f"encrypted_assertions="
                f"{bool(getattr(authn_response, 'encrypted_assertions', None))}"
            )
    except Exception as e:
        current_app.logger.warning(f"Falha ao extrair identity do pysaml2: {e}")

    if not user_email and not user_nic:
        current_app.logger.error(
            "SAML SSO: nenhum atributo extraído (email/NIC). "
            "Verificar se as assertions estão encriptadas e se o pysaml2 "
            "tem acesso à chave privada para desencriptar."
        )

    # 2b. NameID ↔ NIC binding (VULN-2077 / TICKET-58).
    # If the IdP shipped a NIC, it must match the authenticated Subject.
    # Mismatch indicates either a misconfigured IdP or an XSW-style attack
    # where a wrapper assertion is feeding a forged NIC alongside a valid
    # signed assertion with a different Subject.
    # autenticacao.gov emits NameID as an opaque persistent pseudonym with
    # Format=unspecified — it is unrelated to the NIC attribute, so the
    # Subject↔NIC equality check would always fail. XSW protection here
    # comes from Response signature (xmlsec1), Issuer whitelist, replay
    # cache and allow_unsolicited=False; the NameID↔NIC binding only adds
    # value for IdPs that actually emit the NIC as Subject. Skip it when
    # the format is unspecified (or absent).
    nameid_is_pseudonym = name_id_format in (
        "",
        "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
    )
    if user_nic and not nameid_is_pseudonym and not _name_id_binds_nic(name_id_value, user_nic):
        return _reject_saml_login(
            "SAML SSO rejeitado: Subject/NIC binding mismatch (possível XSW)",
            _("Autenticação rejeitada: identidade SAML inconsistente."),
            kind="cmd",
            issuer=issuer,
            name_id=name_id_value,
            reason="subject_nic_mismatch",
        )

    user, status = _find_or_create_saml_user(user_email, user_nic, first_name, last_name)
    current_app.logger.warning(
        f"[DEBUG cmd] post _find_or_create_saml_user: user_id={getattr(user, 'id', None)}, "
        f"user_email={getattr(user, 'email', None)!r}, status={status!r}, "
        f"MIGRATION_MODE_ENABLED={current_app.config.get('MIGRATION_MODE_ENABLED', False)}"
    )

    if status in ("migration_candidate", "no_match"):
        if _migration_enabled():
            _audit_saml(
                "migration_pending",
                "cmd",
                issuer=issuer,
                name_id=name_id_value,
                reason=status,
            )
            return _handle_migration_redirect(
                user,
                user_email,
                user_nic,
                first_name,
                last_name,
                no_match=(status == "no_match"),
            )
        # Migration wizard disabled: never log into an unproven account, and
        # nobody is around to ask for a confirmed email — fall back to
        # creating the account outright, exactly as before (scenario 4).
        user = _create_saml_user(user_email, user_nic, first_name, last_name)
        status = "new"

    _audit_saml(
        "success" if user else "user_not_found",
        "cmd",
        issuer=issuer,
        name_id=name_id_value,
        reason=status,
    )
    # Remember the authenticated Subject so SP-initiated logout can send the
    # IdP a LogoutRequest for the RIGHT session (see _saml_session_name_id).
    session["saml_name_id"] = name_id_value
    # Only ever store plain strings in the session (the format may be a
    # non-string sentinel in edge cases; production values are str or None).
    session["saml_name_id_format"] = name_id_format if isinstance(name_id_format, str) else ""
    return _handle_saml_user_login(user, new_account=(status == "new"))


#################################################################
# Receives SAML Logout
#################################################################
@autenticacao_gov.route("/saml/sso_logout", methods=["GET", "POST"])
@csrf.exempt
def saml_logout_postback():
    frontend_url = current_app.config.get("CDATA_BASE_URL") or ""
    saml_response = request.form.get("SAMLResponse") or request.args.get("SAMLResponse")

    if saml_response:
        auth_servers = current_app.config.get("SECURITY_SAML_IDP_METADATA").split(",")
        binding = entity.BINDING_HTTP_POST if request.method == "POST" else BINDING_HTTP_REDIRECT

        for server in auth_servers:
            saml_client = saml_client_for(server)
            try:
                saml_client.parse_logout_request_response(saml_response, binding)
            except sigver.MissingKey:
                continue
            except Exception as e:
                current_app.logger.warning(f"SAML logout parse error: {e}")
                break
            else:
                break

    _terminate_local_session()
    return redirect(frontend_url or "/")


def _saml_session_name_id():
    """Build the NameID for a LogoutRequest from the session, if stored.

    The SSO postbacks record the Subject NameID the IdP authenticated
    (``saml_name_id``/``saml_name_id_format``); using it lets the IdP tie
    the LogoutRequest to the right session. Falls back to the historical
    dummy value when nothing was recorded (e.g. sessions from before this
    was stored, or wizard-created logins).
    """
    text = session.get("saml_name_id") or "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
    fmt = session.get("saml_name_id_format") or NAMEID_FORMAT_UNSPECIFIED
    return NameID(format=fmt, text=text)


def _terminate_local_session():
    """End the dados.gov.pt session immediately.

    Called by the SP-initiated logout routes BEFORE handing the user to the
    IdP single-logout dance: if any step of that round-trip fails (IdP
    error, unreachable postback, dummy NameID the IdP cannot resolve), the
    local session must already be dead — clicking "Sair" always logs the
    user out of the portal. The SLO postback clears the same keys again,
    which is harmless.
    """
    session.pop("saml_login", None)
    session.pop("saml_name_id", None)
    session.pop("saml_name_id_format", None)
    # Ends with the session like the rest: it is a handle onto someone's
    # pending account, and the next person on this browser must not inherit it.
    session.pop("saml_confirmation_pending", None)
    logout_user()


#################################################################
# Sends SAML Logout
#################################################################
@autenticacao_gov.route("/saml/logout")
def saml_logout():
    saml_client = saml_client_for(
        current_app.config.get("SECURITY_SAML_IDP_METADATA").split(",")[0]
    )
    nid = _saml_session_name_id()

    logout_url = LogoutUrl(text=_saml_endpoint_url("saml.saml_logout_postback"))
    destination = current_app.config.get("SECURITY_SAML_FA_URL")

    extensions = Extensions(extension_elements=[logout_url])

    req_id, logout_request = saml_client.create_logout_request(
        name_id=nid,
        destination=destination,
        issuer_entity_id=current_app.config.get("SECURITY_SAML_ENTITY_ID"),
        sign=True,
        consent="urn:oasis:names:tc:SAML:2.0:logout:user",
        extensions=extensions,
    )

    # Local session first, IdP dance second (best effort) — see
    # _terminate_local_session.
    _terminate_local_session()

    post_message = http_form_post_message(message=logout_request, location=destination)
    return _saml_form_response(post_message["data"])


#################################################################
# eIDAS
##
#################################################################


def eidas_client_for(metadata_file):
    acs_url = _saml_endpoint_url("saml.idp_eidas_initiated")
    out_url = _saml_endpoint_url("saml.eidas_logout_postback")

    settings = _build_sp_settings(acs_url, out_url, metadata_file)
    spConfig = Saml2Config()
    spConfig.load(settings)
    saml_client = Saml2Client(config=spConfig)
    return saml_client


#################################################################
# Prepares and sends eIDAS Auth Request.
##
#################################################################
@autenticacao_gov.route("/saml/eidas/login")
@anonymous_user_required
def sp_eidas_initiated():
    next_url = request.args.get("next", "")
    if next_url.startswith("/") and not next_url.startswith("//"):
        session["saml_next_url"] = next_url

    saml_client = eidas_client_for(
        current_app.config.get("SECURITY_SAML_IDP_METADATA").split(",")[0]
    )

    faa = FAAALevel(text=str(current_app.config.get("SECURITY_SAML_FAAALEVEL")))

    # eIDAS natural-person Minimum Data Set (MDS): PersonIdentifier,
    # CurrentFamilyName, CurrentGivenName and DateOfBirth are guaranteed by
    # every member state and must be requested as required per the eIDAS
    # spec (the PT node was already forwarding them as Optional="false"
    # downstream). The optional attributes (CurrentAddress, Gender,
    # PlaceOfBirth) are no longer requested: they were never read nor
    # stored, and requesting them showed up on the citizen's consent
    # screen without any use (data minimisation). DateOfBirth still
    # arrives (MDS) but is intentionally not stored — the User model has
    # no birth-date field.
    spcertenc = RequestedAttributes(
        [
            RequestedAttribute(
                name=EIDAS_ATTR_PERSON_IDENTIFIER,
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                is_required="True",
            ),
            RequestedAttribute(
                name=EIDAS_ATTR_FAMILY_NAME,
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                is_required="True",
            ),
            RequestedAttribute(
                name=EIDAS_ATTR_GIVEN_NAME,
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                is_required="True",
            ),
            RequestedAttribute(
                name="http://eidas.europa.eu/attributes/naturalperson/DateOfBirth",
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                is_required="True",
            ),
        ]
    )

    extensions = Extensions(
        extension_elements=[
            element_to_extension_element(faa),
            element_to_extension_element(spcertenc),
        ]
    )

    relay_token = _new_relay_state_token()
    args = {
        "binding": BINDING_HTTP_POST,
        "relay_state": relay_token,
        "sign": True,
        "force_authn": "true",
        "is_passive": "false",
        "nameid_format": "",
        "extensions": extensions,
    }

    reqid, info = saml_client.prepare_for_authenticate(**args)
    _remember_outstanding(reqid, kind="eidas")
    _store_outstanding_relay(relay_token, reqid, kind="eidas")
    return _extract_saml_form_data(info["data"])


#################################################################
# Receives eIDAS Response.
##
#################################################################


@autenticacao_gov.route("/saml/eidas/sso", methods=["POST"])
@csrf.exempt
def idp_eidas_initiated():
    user_email = None
    user_nic = None
    first_name = None
    last_name = None
    authn_response = None

    raw_saml_response = request.form.get("SAMLResponse")
    if not raw_saml_response:
        return "Erro: SAMLResponse em falta", 400

    auth_servers = current_app.config.get("SECURITY_SAML_IDP_METADATA").split(",")

    # 0. Verificar se o IdP rejeitou o pedido (antes de tentar pysaml2) —
    # sem este pre-check um StatusCode non-Success faria o pysaml2 levantar
    # StatusError e o pedido terminaria em 500 em vez de redirect limpo.
    denied = _idp_status_rejection(raw_saml_response, kind="eidas")
    if denied is not None:
        return denied

    # 1. Validar a resposta eIDAS com pysaml2 (verifica assinatura + desencripta).
    # Política fail-closed (VULN-2077 / TICKET-58): MissingKey/SignatureError
    # de um IdP só é tolerado enquanto restarem outros IdPs por tentar; após
    # esgotados, o pedido é rejeitado. Outras excepções propagam (500).
    # ``outstanding`` liga o ``InResponseTo`` ao pedido SP-initiated
    # (allow_unsolicited=False) — bucket vem da sessão (cookie) e do Redis
    # indexado pelo RelayState ecoado pela IdP (resiliente a middleware
    # que mangleia o cookie SameSite).
    outstanding = dict(session.get(_OUTSTANDING_SESSION_KEY, {}))
    relay_token = request.form.get("RelayState", "")
    outstanding.update(_consume_outstanding_relay(relay_token))
    last_validation_error = None
    for server in auth_servers:
        saml_client = eidas_client_for(server)
        try:
            authn_response = saml_client.parse_authn_request_response(
                raw_saml_response,
                entity.BINDING_HTTP_POST,
                outstanding=outstanding,
            )
        except (sigver.MissingKey, SignatureError) as exc:
            last_validation_error = exc
            current_app.logger.warning(f"eIDAS rejeitado por {server}: {type(exc).__name__}: {exc}")
            continue
        break

    if authn_response is None:
        return _reject_saml_login(
            "eIDAS SSO rejeitado: nenhum IdP validou a resposta assinada "
            f"(último erro: {last_validation_error})",
            _("Autenticação rejeitada: assinatura SAML inválida."),
            kind="eidas",
            reason="signature_invalid",
        )

    # 1a. Replay cache (VULN-2077 / TICKET-58).
    response_id = getattr(getattr(authn_response, "response", None), "id", None)
    if not _check_and_record_replay(response_id, kind="eidas"):
        return _reject_saml_login(
            f"eIDAS SSO rejeitado: replay de Response@ID={response_id!r}",
            _("Autenticação rejeitada: resposta já utilizada."),
            kind="eidas",
            reason="replay",
        )

    # 1aa. One-time use of the matched AuthnRequest id.
    in_response_to = getattr(authn_response, "in_response_to", None)
    if isinstance(in_response_to, str) and in_response_to:
        _consume_outstanding(in_response_to, kind="eidas")

    # 1b. Validar Issuer e Subject/NameID (VULN-2077 / TICKET-58).
    try:
        issuer = authn_response.issuer()
    except Exception as exc:  # noqa: BLE001
        return _reject_saml_login(
            f"eIDAS SSO rejeitado: falha a obter Issuer ({exc})",
            _("Autenticação rejeitada: resposta SAML inválida."),
            kind="eidas",
            reason="issuer_unreadable",
        )

    trusted_issuers = _trusted_saml_issuers()
    if issuer not in trusted_issuers:
        return _reject_saml_login(
            f"eIDAS SSO rejeitado: Issuer não confiado ({issuer!r})",
            _("Autenticação rejeitada: emissor SAML desconhecido."),
            kind="eidas",
            issuer=issuer,
            reason="issuer_untrusted",
        )

    try:
        subject = authn_response.get_subject()
    except Exception as exc:  # noqa: BLE001
        return _reject_saml_login(
            f"eIDAS SSO rejeitado: falha a obter Subject ({exc})",
            _("Autenticação rejeitada: identidade SAML em falta."),
            kind="eidas",
            issuer=issuer,
            reason="subject_unreadable",
        )
    name_id_value = (getattr(subject, "text", None) or "").strip() if subject else ""
    name_id_format = (getattr(subject, "format", None) or "").strip() if subject else ""
    if not name_id_value:
        return _reject_saml_login(
            "eIDAS SSO rejeitado: Subject/NameID em falta",
            _("Autenticação rejeitada: identidade SAML em falta."),
            kind="eidas",
            issuer=issuer,
            reason="subject_missing",
        )

    # 2. Extrair atributos a partir do objecto validado pelo pysaml2.
    # Atributos só são lidos depois da assinatura ter sido verificada
    # por pysaml2 (VULN-2077 / TICKET-58).
    identity_keys_csv = ""
    try:
        identity = authn_response.get_identity()

        if identity:
            identity_keys_csv = ",".join(sorted(identity.keys())[:12])
            # MDC (CMD) URIs first — the PT node may translate eIDAS
            # attributes into them — then the eIDAS natural-person URIs the
            # AuthnRequest asks for, and finally the FRIENDLY NAMES pysaml2's
            # built-in attribute maps translate those URIs into (this is how
            # they actually arrive from get_identity(); see the
            # EIDAS_FRIENDLY_* constants). Mapping: PersonIdentifier →
            # NIC slot, CurrentGivenName → first_name, CurrentFamilyName →
            # last_name. eIDAS carries no email attribute: the account is
            # created with a placeholder email and the user completes
            # registration on the frontend.
            user_email = _first_value(identity, MDC_ATTR_EMAIL)
            user_nic = (
                _first_value(identity, MDC_ATTR_NIC)
                or _first_value(identity, EIDAS_ATTR_PERSON_IDENTIFIER)
                or _first_value(identity, EIDAS_FRIENDLY_PERSON_IDENTIFIER)
            )
            first_name = (
                _first_value(identity, MDC_ATTR_FIRST_NAME)
                or _first_value(identity, EIDAS_ATTR_GIVEN_NAME)
                or _first_value(identity, EIDAS_FRIENDLY_GIVEN_NAME)
            )
            last_name = (
                _first_value(identity, MDC_ATTR_LAST_NAME)
                or _first_value(identity, EIDAS_ATTR_FAMILY_NAME)
                or _first_value(identity, EIDAS_FRIENDLY_FAMILY_NAME)
            )
            if _first_value(identity, MDC_ATTR_NIC):
                id_source = "mdc"
            elif _first_value(identity, EIDAS_ATTR_PERSON_IDENTIFIER):
                id_source = "eidas-uri"
            elif user_nic:
                id_source = "eidas-friendly"
            else:
                id_source = None
            current_app.logger.info(
                f"eIDAS atributos via pysaml2: email={user_email}, "
                f"id={'***' if user_nic else None} (source={id_source}), "
                f"nome={first_name} {last_name}, "
                f"identity_keys={list(identity.keys())}, "
                f"name_id_format={name_id_format!r}"
            )
        else:
            # Mesmo log de diagnóstico do postback CMD.
            current_app.logger.warning(
                f"eIDAS pysaml2: identity vazio. "
                f"response type={type(authn_response).__name__}, "
                f"assertions={getattr(authn_response, 'assertions', 'N/A')}, "
                f"encrypted_assertions="
                f"{bool(getattr(authn_response, 'encrypted_assertions', None))}"
            )
    except Exception as e:
        current_app.logger.warning(f"Falha ao extrair identity do pysaml2 (eIDAS): {e}")

    if not user_email and not user_nic:
        current_app.logger.error(
            "eIDAS SSO: nenhum atributo extraído (email/NIC/PersonIdentifier). "
            "Verificar se as assertions estão encriptadas e se o pysaml2 "
            "tem acesso à chave privada para desencriptar. "
            f"identity_keys={identity_keys_csv!r}"
        )

    # 2b. NameID ↔ identifier binding (VULN-2077 / TICKET-58).
    # Same rule as the CMD postback: autenticacao.gov emits NameID as an
    # opaque pseudonym with Format=unspecified — it is unrelated to the
    # NIC/PersonIdentifier attribute, so the equality check would always
    # fail (observed in TST: every eIDAS login was rejected with
    # subject_nic_mismatch once PersonIdentifier extraction landed). XSW
    # protection still comes from the Response signature (xmlsec1), the
    # Issuer whitelist, the replay cache and allow_unsolicited=False; the
    # binding only adds value for IdPs that emit the identifier as Subject.
    # Skip it when the format is unspecified (or absent).
    nameid_is_pseudonym = name_id_format in (
        "",
        "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
    )
    if user_nic and not nameid_is_pseudonym and not _name_id_binds_nic(name_id_value, user_nic):
        return _reject_saml_login(
            "eIDAS SSO rejeitado: Subject/NIC binding mismatch (possível XSW)",
            _("Autenticação rejeitada: identidade SAML inconsistente."),
            kind="eidas",
            issuer=issuer,
            name_id=name_id_value,
            reason="subject_nic_mismatch",
        )

    user, status = _find_or_create_saml_user(user_email, user_nic, first_name, last_name)

    if status in ("migration_candidate", "no_match"):
        if _migration_enabled():
            _audit_saml(
                "migration_pending",
                "eidas",
                issuer=issuer,
                name_id=name_id_value,
                reason=status,
            )
            return _handle_migration_redirect(
                user,
                user_email,
                user_nic,
                first_name,
                last_name,
                no_match=(status == "no_match"),
            )
        # Migration wizard disabled: never log into an unproven account, and
        # nobody is around to ask for a confirmed email — fall back to
        # creating the account outright, exactly as before (scenario 4).
        user = _create_saml_user(user_email, user_nic, first_name, last_name)
        status = "new"

    if user is None:
        # Neither email nor NIC/PersonIdentifier came through: nothing to
        # authenticate against. Surface the attribute URIs that DID arrive
        # (schema names only, never values) so a browser network trace is
        # enough to diagnose what the IdP actually returned.
        return _reject_saml_login(
            f"eIDAS SSO rejeitado: sem atributos utilizáveis (identity_keys={identity_keys_csv!r})",
            _("Autenticação rejeitada: resposta sem atributos de identidade."),
            kind="eidas",
            issuer=issuer,
            name_id=name_id_value,
            reason="missing_attributes",
            detail=identity_keys_csv,
        )

    _audit_saml(
        "success",
        "eidas",
        issuer=issuer,
        name_id=name_id_value,
        reason=status,
    )
    # Remember the authenticated Subject so SP-initiated logout can send the
    # IdP a LogoutRequest for the RIGHT session (see _saml_session_name_id).
    session["saml_name_id"] = name_id_value
    # Only ever store plain strings in the session (the format may be a
    # non-string sentinel in edge cases; production values are str or None).
    session["saml_name_id_format"] = name_id_format if isinstance(name_id_format, str) else ""
    return _handle_saml_user_login(user, new_account=(status == "new"))


#################################################################
# Receives eIDAS Logout
#################################################################
@autenticacao_gov.route("/saml/eidas/sso_logout", methods=["GET", "POST"])
@csrf.exempt
def eidas_logout_postback():
    saml_response = request.form.get("SAMLResponse") or request.args.get("SAMLResponse")

    if saml_response:
        auth_servers = current_app.config.get("SECURITY_SAML_IDP_METADATA").split(",")
        binding = entity.BINDING_HTTP_POST if request.method == "POST" else BINDING_HTTP_REDIRECT

        for server in auth_servers:
            saml_client = eidas_client_for(server)
            try:
                saml_client.parse_logout_request_response(saml_response, binding)
            except sigver.MissingKey:
                continue
            except Exception as e:
                current_app.logger.warning(f"eIDAS logout parse error: {e}")
                break
            else:
                break

    _terminate_local_session()
    frontend_url = current_app.config.get("CDATA_BASE_URL") or "/"
    return redirect(frontend_url)


#################################################################
# Sends eIDAS Logout
#################################################################
@autenticacao_gov.route("/saml/eidas/logout")
def eidas_logout():
    saml_client = eidas_client_for(
        current_app.config.get("SECURITY_SAML_IDP_METADATA").split(",")[0]
    )
    nid = _saml_session_name_id()

    logout_url = LogoutUrl(text=_saml_endpoint_url("saml.eidas_logout_postback"))
    destination = current_app.config.get("SECURITY_SAML_FA_URL")

    extensions = Extensions(extension_elements=[logout_url])

    req_id, logout_request = saml_client.create_logout_request(
        name_id=nid,
        destination=destination,
        issuer_entity_id=current_app.config.get("SECURITY_SAML_ENTITY_ID"),
        sign=True,
        consent="urn:oasis:names:tc:SAML:2.0:logout:user",
        extensions=extensions,
    )

    # Local session first, IdP dance second (best effort) — see
    # _terminate_local_session.
    _terminate_local_session()

    post_message = http_form_post_message(message=logout_request, location=destination)
    return _saml_form_response(post_message["data"])


#################################################################
# Account Migration Endpoints
#################################################################


def _migration_enabled():
    """Check if the migration mode is enabled in config."""
    return current_app.config.get("MIGRATION_MODE_ENABLED", False)


@autenticacao_gov.route("/saml/migration/check", methods=["GET"])
@csrf.exempt
def migration_check():
    """Check if the currently authenticated user is a legacy user that needs migration."""
    if not _migration_enabled():
        return jsonify({"needs_migration": False})

    from flask_login import current_user

    if not current_user.is_authenticated:
        return jsonify({"needs_migration": False})

    has_nic = _has_linked_nic(current_user)
    needs = bool(not has_nic and current_user.password)
    return jsonify({"needs_migration": needs})


@autenticacao_gov.route("/saml/migration/pending", methods=["GET"])
@csrf.exempt
def migration_pending():
    """Check if there is a pending migration in the session."""
    if not _migration_enabled():
        return jsonify({"error": "Migration mode is not enabled"}), 403

    pending = session.get("saml_migration_pending")
    if not pending:
        # The wizard is over but the account it created is still waiting for
        # its owner to follow the confirmation link. Tell the frontend so it
        # can explain the situation and offer a resend, instead of bouncing
        # the user to /login with no explanation.
        awaiting = session.get("saml_confirmation_pending")
        if awaiting:
            from udata.core.user.models import User

            user = User.objects(id=awaiting.get("user_id")).first()
            if user and user.confirmed_at is None:
                return jsonify(
                    {
                        "pending": False,
                        "awaiting_confirmation": True,
                        "email": _mask_email(user.email),
                    }
                )
        return jsonify({"pending": False})

    # Whether the CMD identity itself carries an email address.
    has_email = bool(pending.get("saml_email"))

    # The email the CMD identity carried, but only when no account holds it:
    # the wizard pre-fills the account-creation field with it, and offering an
    # address that is already taken would only produce a guaranteed rejection.
    saml_email = pending.get("saml_email")
    suggested_email = (
        saml_email if saml_email and not datastore.find_user(email=saml_email) else None
    )

    # True only when the identity matched no account at all (as opposed to
    # matching several homonyms) AND carries a NIC. Both cases reach the
    # wizard with legacy_user_id unset, so `candidate` alone cannot tell them
    # apart. The NIC is required because an identity without one cannot create
    # an account through this flow (see migration_skip): without auth_nic the
    # pending account would match itself as a wizard candidate on the next
    # login and could be confirmed without ever following the emailed link.
    no_match = bool(pending.get("no_match")) and bool(pending.get("saml_nic"))

    # Fetch candidate (legacy) account details for user confirmation.
    legacy_user_id = pending.get("legacy_user_id")
    first_name = None
    last_name = None
    legacy_email = None
    if legacy_user_id:
        from udata.core.user.models import User

        user = User.objects(id=legacy_user_id).first()
        if user:
            first_name = user.first_name
            last_name = user.last_name
            legacy_email = user.email

    return jsonify(
        {
            "pending": True,
            "email": _mask_email(legacy_email) if legacy_email else None,
            "has_email": has_email,
            "suggested_email": suggested_email,
            "candidate": bool(legacy_user_id),
            "no_match": no_match,
            "first_name": first_name,
            "last_name": last_name,
        }
    )


@autenticacao_gov.route("/saml/migration/search", methods=["POST"])
@csrf.exempt
def migration_search():
    """Search for a legacy account when SAML did not return an email."""
    if not _migration_enabled():
        return jsonify({"error": "Migration mode is not enabled"}), 403

    pending = session.get("saml_migration_pending")
    if not pending:
        return jsonify({"error": "No pending migration"}), 400

    # Coerce to strings at the boundary, as confirm and skip already do. A
    # JSON body can carry a dict, and a dict reaching a MongoEngine query is
    # how a field lookup becomes an operator lookup: `{"$regex": "^adm"}`
    # turned this endpoint's `found` flag into a per-character oracle over
    # every registered address. The case-insensitive lookup happens to reject
    # it now — re.escape raises on a dict — but that is an accident of the
    # query type, and it comes back as a 500 rather than an answer.
    data = request.get_json(silent=True) or {}
    email = str(data.get("email") or "").strip()
    first_name = str(data.get("first_name") or "").strip()
    last_name = str(data.get("last_name") or "").strip()

    user = _find_legacy_user(email=email, first_name=first_name, last_name=last_name)
    if not user:
        return jsonify({"found": False})

    _point_migration_candidate(pending, user)

    return jsonify(
        {
            "found": True,
            "email": _mask_email(user.email),
        }
    )


@autenticacao_gov.route("/saml/migration/send-code", methods=["POST"])
@csrf.exempt
def migration_send_code():
    """Generate and send a 6-digit verification code to the legacy user's email."""
    if not _migration_enabled():
        return jsonify({"error": "Migration mode is not enabled"}), 403

    pending = session.get("saml_migration_pending")
    if not pending:
        return jsonify({"error": "No pending migration"}), 400

    # Rate limit: max 3 sends per session
    send_count = session.get("migration_send_count", 0)
    if send_count >= 3:
        return jsonify({"error": "Maximum code sends exceeded"}), 429

    legacy_user_id = pending.get("legacy_user_id")
    if not legacy_user_id:
        return jsonify({"error": "No legacy user found"}), 400

    from udata.core.user.models import User

    user = User.objects(id=legacy_user_id).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    code = str(random.randint(100000, 999999))
    session["migration_code"] = {
        "code": code,
        # Bind the code to the account it was emailed to, so it cannot be
        # replayed against a different candidate re-pointed via search.
        "legacy_user_id": legacy_user_id,
        "expires": (datetime.utcnow() + timedelta(minutes=10)).isoformat(),
        "attempts": 0,
    }
    session["migration_send_count"] = send_count + 1
    session.modified = True

    _send_migration_code(user, code)
    current_app.logger.info(f"Migration code sent to user {legacy_user_id}")

    return jsonify({"sent": True})


@autenticacao_gov.route("/saml/migration/confirm", methods=["POST"])
@csrf.exempt
def migration_confirm():
    """Confirm migration via verification code or old password."""
    if not _migration_enabled():
        return jsonify({"error": "Migration mode is not enabled"}), 403

    pending = session.get("saml_migration_pending")
    if not pending:
        return jsonify({"error": "No pending migration"}), 400

    data = request.get_json(silent=True) or {}
    method = data.get("method")

    from udata.core.user.models import User

    if method == "code":
        # Code verification targets the candidate account found by
        # name/search — a code was emailed to that account's address.
        legacy_user_id = pending.get("legacy_user_id")
        if not legacy_user_id:
            return jsonify({"error": "No legacy user found"}), 400

        user = User.objects(id=legacy_user_id).first()
        if not user:
            return jsonify({"error": "User not found"}), 404

        code_data = session.get("migration_code")
        if not code_data:
            return jsonify({"error": "No code sent"}), 400

        # The code is only valid for the account it was emailed to. If the
        # candidate was re-pointed (via search) after the code was issued,
        # refuse it — otherwise a code sent to an attacker-controlled
        # mailbox could link the NIC to a victim account.
        if code_data.get("legacy_user_id") != legacy_user_id:
            return jsonify({"error": "No code sent"}), 400

        if code_data["attempts"] >= 5:
            return jsonify({"error": "Maximum attempts exceeded"}), 429

        code_data["attempts"] += 1
        session["migration_code"] = code_data
        session.modified = True

        expires = datetime.fromisoformat(code_data["expires"])
        if datetime.utcnow() > expires:
            return jsonify({"error": "Code expired"}), 400

        if data.get("code") != code_data["code"]:
            return jsonify({"error": "Invalid code"}), 400

    elif method == "password":
        # Full default login (email + password): the linked account is
        # the one whose credentials are proven, which may differ from
        # the name-matched candidate (homonym case).
        attempts = session.get("migration_password_attempts", 0)
        if attempts >= 5:
            return jsonify({"error": "Maximum attempts exceeded"}), 429
        session["migration_password_attempts"] = attempts + 1
        session.modified = True

        email = (data.get("email") or "").strip()
        password = data.get("password", "")
        # Case-insensitive, to match the login form this branch stands in
        # for. Exact-matching here failed the ownership proof for a correct
        # password, and the generic error below made that indistinguishable
        # from a wrong one.
        user = _find_user_by_email_ci(email)
        # Generic error on any failure to avoid account enumeration.
        if (
            not user
            or user.deleted
            or not user.password
            or _has_linked_nic(user)
            or not verify_and_update_password(password, user)
        ):
            return jsonify({"error": "Invalid credentials"}), 400

    else:
        return jsonify({"error": "Invalid method"}), 400

    # Link: add NIC and update names. The password is kept so the
    # account remains accessible through both login methods.
    saml_nic = pending.get("saml_nic")
    saml_first_name = pending.get("saml_first_name")
    saml_last_name = pending.get("saml_last_name")

    if not user.extras:
        user.extras = {}
    if saml_nic:
        user.extras["auth_nic"] = _hash_nic(saml_nic)
    if saml_first_name:
        user.first_name = saml_first_name.title()
    if saml_last_name:
        user.last_name = saml_last_name.title()
    if not user.confirmed_at:
        user.confirmed_at = datetime.utcnow()
    user.save()

    login_user(user)
    session["saml_login"] = True

    # Clean up migration session data
    session.pop("saml_migration_pending", None)
    session.pop("migration_code", None)
    session.pop("migration_send_count", None)
    session.pop("migration_password_attempts", None)

    current_app.logger.info(f"Account migration completed for user {user.id}")

    return jsonify({"success": True})


@autenticacao_gov.route("/saml/migration/skip", methods=["POST"])
@csrf.exempt
def migration_skip():
    """Create a new account from a user-declared, confirmation-pending email.

    The CMD proves who the person is; it does not prove that the address they
    typed is theirs. So this endpoint validates the submitted email, creates
    the account UNCONFIRMED, mails the standard confirmation link, and
    deliberately starts NO session: authenticated access waits for the click.
    """
    if not _migration_enabled():
        return jsonify({"error": "Migration mode is not enabled"}), 403

    pending = session.get("saml_migration_pending")
    if not pending:
        return jsonify({"error": "No pending migration"}), 400

    # Without a NIC the new account gets no auth_nic, and an account with no
    # auth_nic is not excluded by _has_linked_nic: on the next CMD login it
    # would match itself as a wizard candidate, letting the user mail a code
    # to the very address awaiting confirmation and log in through
    # migration_confirm — confirming the email without ever following the
    # link. These identities belong in the search branch, not here.
    user_nic = pending.get("saml_nic")
    if not user_nic:
        return jsonify({"error": "nic_required"}), 400

    email = (request.get_json(silent=True) or {}).get("email") or ""
    email = email.strip()
    if not email:
        return jsonify({"error": "email_required"}), 400

    try:
        # Shape only, never deliverability. email_validator defaults
        # check_deliverability to True, and SECURITY_EMAIL_VALIDATOR_ARGS is
        # defined only in settings.Testing — so relying on the config alone
        # would run a live MX lookup, for an attacker-chosen domain, inside
        # the request. That both hands out an outbound DNS primitive and lets
        # a resolver blip tell a user their valid address is invalid.
        validator_args = {
            "check_deliverability": False,
            **(current_app.config.get("SECURITY_EMAIL_VALIDATOR_ARGS") or {}),
        }
        # Store the normalised form, as the registration path does — not the
        # raw string, whose casing would otherwise decide which of two rows
        # the unique index accepts.
        email = validate_email(email, **validator_args).normalized
    except EmailNotValidError:
        return jsonify({"error": "invalid_email"}), 400

    # case_insensitive matters and is not cosmetic. The unique index on
    # User.email is case-SENSITIVE, while every login and recovery lookup goes
    # through SECURITY_USER_IDENTITY_ATTRIBUTES, which is case-INSENSITIVE. An
    # exact-match check here therefore accepts "MARIA@x.pt" alongside an
    # existing "maria@x.pt", and the victim's own login then resolves to the
    # newer, password-less shadow row (User._meta ordering is -created_at) —
    # locking them out of both login and password recovery, permanently.
    from udata.core.user.models import User

    existing = datastore.find_user(case_insensitive=True, email=email)
    linked = User.objects(extras__auth_nic=_hash_nic(user_nic)).first()

    if existing and (not linked or existing.id != linked.id):
        # The address is taken — but by whom? If it is a legacy account this
        # identity could legitimately claim, refusing is the wrong answer:
        # linking it is exactly what the wizard exists for, and the machinery
        # is one step away. Point the candidate and say so, instead of
        # sending the user back to retype an address the server has already
        # resolved. Nothing is linked here: ownership still has to be proven
        # at migration_confirm, by password or by a code mailed to that same
        # account. Guarded on `not linked` to keep the replay hardening below
        # intact — note this only narrows the skip: migration_search already
        # points an arbitrary candidate with no such guard, so the guard is
        # local prudence, not a boundary the flow enforces.
        candidate = _find_legacy_user(email=email) if not linked else None
        if candidate:
            _point_migration_candidate(pending, candidate)
            return jsonify(
                {
                    "error": "email_taken",
                    "candidate_found": True,
                    "email": _mask_email(candidate.email),
                }
            ), 409
        return jsonify({"error": "email_taken"}), 409

    if linked:
        # This identity already has an account. Normally unreachable — rule 1
        # of _find_or_create_saml_user resolves it long before the wizard — but
        # the Flask session is a client-held signed cookie, so replaying a copy
        # taken before the first skip re-enters here with the pending state
        # intact; the session pops are no defence, they only rewrite a response
        # cookie the caller may discard. Creating a second account per replay
        # would mint them without bound, each mailing a chosen address.
        #
        # Refusing outright is not right either: it would brick the identity on
        # a typo, and on an SMTP failure mid-request, with no way back — the
        # account has no password, so neither login nor recovery is available,
        # and the address can never be changed. So the pending account's
        # address stays correctable until it is confirmed, while the send tally
        # below stays monotonic, which is what keeps the mailer bounded.
        if linked.confirmed_at is not None:
            return jsonify({"error": "identity_already_registered"}), 409
        user = linked
        user.email = email
        user.save()
    else:
        user = _create_pending_saml_user(
            email,
            user_nic,
            pending.get("saml_first_name"),
            pending.get("saml_last_name"),
        )

    send_count = (user.extras or {}).get(CONFIRMATION_SEND_COUNT, 0)
    if send_count >= MAX_CONFIRMATION_SENDS:
        return jsonify({"error": "too_many_sends"}), 429

    send_confirmation_instructions(user)
    user.extras[CONFIRMATION_SEND_COUNT] = send_count + 1
    user.save()

    # No login_user: the account has no session until the email is confirmed.
    # The wizard state is done, but a resend handle must survive it — this key
    # identifies the user to the resend endpoint without authenticating them.
    session.pop("saml_migration_pending", None)
    session.pop("migration_code", None)
    session.pop("migration_send_count", None)
    session.pop("migration_password_attempts", None)
    session["saml_confirmation_pending"] = {"user_id": str(user.id)}

    return jsonify({"success": True, "email": user.email})


@autenticacao_gov.route("/saml/migration/resend-confirmation", methods=["POST"])
@csrf.exempt
def migration_resend_confirmation():
    """Resend the confirmation link for the account awaiting confirmation.

    At this point there is no session to authenticate: the account exists but
    is deliberately not logged in. The pending-confirmation key left in the
    session identifies the user without authenticating them, which is why this
    endpoint takes no email argument — it would otherwise be an open relay,
    and the stock ``security.send_confirmation`` view carries no rate limit of
    its own to fall back on.
    """
    if not _migration_enabled():
        return jsonify({"error": "Migration mode is not enabled"}), 403

    awaiting = session.get("saml_confirmation_pending")
    if not awaiting:
        return jsonify({"error": "No pending confirmation"}), 400

    from udata.core.user.models import User

    user = User.objects(id=awaiting.get("user_id")).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    if user.confirmed_at is not None:
        # Already done — nothing to resend, and saying so lets the frontend
        # send the user to the login instead of waiting for another mail.
        return jsonify({"sent": False, "confirmed": True})

    # The cap is counted ON THE ACCOUNT, not in the session. migration_send_code
    # keeps its counter in the session, but it can only ever mail the candidate
    # account's own address; here the recipient was chosen by whoever ran the
    # wizard, so a session-only counter would be no cap at all — the Flask
    # session is a client-held signed cookie, and replaying a copy taken before
    # the first send resets it to zero on every request.
    send_count = (user.extras or {}).get(CONFIRMATION_SEND_COUNT, 0)
    if send_count >= MAX_CONFIRMATION_SENDS:
        return jsonify({"error": "Maximum confirmation sends exceeded"}), 429

    send_confirmation_instructions(user)
    user.extras[CONFIRMATION_SEND_COUNT] = send_count + 1
    user.save()

    return jsonify({"sent": True})
