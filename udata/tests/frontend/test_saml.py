"""Tests for SAML authentication flow with autenticacao.gov.

Ensures the SAML plugin does not render Jinja2 templates (which would cause
TemplateNotFound errors) and instead auto-creates users from SAML data.

Also tests the full SSO callback flow: after autenticacao.gov returns a
successful SAMLResponse, the backend must parse the SAML attributes and
then perform the udata login (login_user + session['saml_login']).
"""

import base64
import inspect
import os
import re
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID
from flask import session

from udata.auth.saml.saml_plugin.saml_govpt import (
    _consume_outstanding_relay,
    _hash_nic,
    _new_relay_state_token,
    _normalize_idp_metadata_certs,
    _store_outstanding_relay,
)
from udata.core.user.factories import UserFactory
from udata.tests.api import APITestCase
from udata.tests.helpers import requires_saml_credentials

# Placeholder email shape generated when the IdP does not return an email:
# saml-<uuid4().hex[:8]>@autenticacao.gov.pt — 8 lowercase hex characters.
# We assert the structure, not the literal value, because the NIC must NOT
# leak into the email address (privacy fix; see
# saml_govpt._find_or_create_saml_user).
_SAML_PLACEHOLDER_EMAIL_RE = re.compile(r"^saml-[a-f0-9]{8}@autenticacao\.gov\.pt$")


def _build_saml_response_xml(
    email=None,
    nic=None,
    first_name=None,
    last_name=None,
    person_identifier=None,
    given_name=None,
    family_name=None,
):
    """Build a minimal SAML Response XML with the given attributes.

    This simulates what autenticacao.gov returns after successful
    authentication — MDC/Cidadao attributes for CMD, and the
    eidas.europa.eu natural-person attributes for eIDAS logins.
    """
    attributes = ""
    if email:
        attributes += f"""
        <saml:Attribute Name="http://interop.gov.pt/MDC/Cidadao/CorreioElectronico"
                        NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml:AttributeValue>{email}</saml:AttributeValue>
        </saml:Attribute>"""
    if nic:
        attributes += f"""
        <saml:Attribute Name="http://interop.gov.pt/MDC/Cidadao/NIC"
                        NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml:AttributeValue>{nic}</saml:AttributeValue>
        </saml:Attribute>"""
    if first_name:
        attributes += f"""
        <saml:Attribute Name="http://interop.gov.pt/MDC/Cidadao/NomeProprio"
                        NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml:AttributeValue>{first_name}</saml:AttributeValue>
        </saml:Attribute>"""
    if last_name:
        attributes += f"""
        <saml:Attribute Name="http://interop.gov.pt/MDC/Cidadao/NomeApelido"
                        NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml:AttributeValue>{last_name}</saml:AttributeValue>
        </saml:Attribute>"""
    if person_identifier:
        attributes += f"""
        <saml:Attribute Name="http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier"
                        NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml:AttributeValue>{person_identifier}</saml:AttributeValue>
        </saml:Attribute>"""
    if given_name:
        attributes += f"""
        <saml:Attribute Name="http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName"
                        NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml:AttributeValue>{given_name}</saml:AttributeValue>
        </saml:Attribute>"""
    if family_name:
        attributes += f"""
        <saml:Attribute Name="http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName"
                        NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml:AttributeValue>{family_name}</saml:AttributeValue>
        </saml:Attribute>"""

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_response123" Version="2.0"
                IssueInstant="2024-01-01T00:00:00Z"
                Destination="https://dados.gov.pt/saml/sso">
    <saml:Assertion ID="_assertion123" Version="2.0"
                    IssueInstant="2024-01-01T00:00:00Z">
        <saml:AttributeStatement>{attributes}
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>"""


TEST_SAML_ISSUER = "https://autenticacao.cartaodecidadao.pt"


def _make_authn_response_mock(
    email=None,
    nic=None,
    first_name=None,
    last_name=None,
    issuer=TEST_SAML_ISSUER,
    name_id=None,
    name_id_format=None,
    person_identifier=None,
    given_name=None,
    family_name=None,
    eidas_friendly_names=False,
):
    """Build a MagicMock that mimics a validated pysaml2 AuthnResponse.

    Returns an object that exposes the SAML attributes via ``get_identity()``
    just like ``saml2.response.AuthnResponse`` would after a successful
    signature + envelope check. Tests must use this helper instead of a
    bare ``MagicMock()`` because, post-VULN-2077, attributes are only read
    from the validated pysaml2 object — there is no XML fallback parser,
    and the SSO callback now also checks ``issuer()`` against a whitelist
    and binds the ``Subject/NameID`` to the NIC attribute.

    ``name_id`` defaults to ``nic`` so the binding check passes for the
    common case; pass an explicit value (e.g. ``""``) to simulate a
    Subject mismatch in dedicated tests. ``name_id_format`` sets the
    Subject's NameID Format (e.g. the ``unspecified`` pseudonym format the
    real IdP emits, which makes the handlers skip the binding check); when
    omitted the mock behaves as a specified format and the binding applies.
    """
    identity = {}
    if email:
        identity["http://interop.gov.pt/MDC/Cidadao/CorreioElectronico"] = [email]
    if nic:
        identity["http://interop.gov.pt/MDC/Cidadao/NIC"] = [nic]
    if first_name:
        identity["http://interop.gov.pt/MDC/Cidadao/NomeProprio"] = [first_name]
    if last_name:
        identity["http://interop.gov.pt/MDC/Cidadao/NomeApelido"] = [last_name]
    # pysaml2's built-in attribute maps translate the eIDAS natural-person
    # URIs into friendly names in get_identity() (PersonIdentifier,
    # FirstName, FamilyName) — that is what the real IdP responses yield.
    # eidas_friendly_names=True models that; False keeps the raw URIs
    # (defensive path kept in the extraction).
    if person_identifier:
        key = (
            "PersonIdentifier"
            if eidas_friendly_names
            else "http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier"
        )
        identity[key] = [person_identifier]
    if given_name:
        key = (
            "FirstName"
            if eidas_friendly_names
            else "http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName"
        )
        identity[key] = [given_name]
    if family_name:
        key = (
            "FamilyName"
            if eidas_friendly_names
            else "http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName"
        )
        identity[key] = [family_name]

    response = MagicMock()
    response.get_identity.return_value = identity
    response.ava = identity
    response.issuer.return_value = issuer

    subject_mock = MagicMock()
    if name_id is not None:
        subject_mock.text = name_id
    else:
        # Default to the unique identifier (NIC for CMD, PersonIdentifier
        # for eIDAS) so the Subject↔identifier binding check passes; fall
        # back to a stable placeholder for tests that do not exercise it
        # at all (e.g. email-only logins).
        subject_mock.text = nic or person_identifier or "test-name-id"
    if name_id_format is not None:
        subject_mock.format = name_id_format
    response.get_subject.return_value = subject_mock
    return response


class SAMLCodeIntegrityTest(APITestCase):
    """Verify the SAML plugin code does not reference Jinja2 templates."""

    def test_register_user_has_no_template_rendering(self):
        """register_user.py must NOT call render_template or reference register_saml.html."""
        from udata.auth.saml.saml_plugin import register_user

        source = inspect.getsource(register_user)
        assert "render_template" not in source, (
            "register_user.py still calls render_template — this causes TemplateNotFound"
        )
        assert "register_saml.html" not in source, (
            "register_user.py still references register_saml.html template"
        )

    def test_saml_govpt_has_no_template_rendering(self):
        """saml_govpt.py must NOT call render_template or reference register_saml.html."""
        from udata.auth.saml.saml_plugin import saml_govpt

        source = inspect.getsource(saml_govpt)
        assert "register_saml.html" not in source, (
            "saml_govpt.py still references register_saml.html template"
        )

    def test_no_redirect_to_saml_register(self):
        """saml_govpt.py must NOT redirect to saml.register (no intermediate form)."""
        from udata.auth.saml.saml_plugin import saml_govpt

        source = inspect.getsource(saml_govpt)
        assert "url_for('saml.register')" not in source, (
            "saml_govpt.py still redirects to saml.register instead of auto-creating users"
        )
        assert 'url_for("saml.register")' not in source, (
            "saml_govpt.py still redirects to saml.register instead of auto-creating users"
        )


def _make_test_cert_and_key():
    """Return a freshly-minted self-signed X.509 cert + matching RSA key."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-idp.example")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _make_pkcs7_signed_data_bundle(cert, key):
    """Return DER bytes of a PKCS#7 SignedData bundle wrapping the given cert.

    Mirrors the shape autenticacao.gov has shipped inside metadata
    `<X509Certificate>` elements in some environments (OID
    1.2.840.113549.1.7.2 — pkcs7-signedData), which xmlsec1 cannot parse
    when handed to OpenSSL as a `--pubkey-cert-pem` argument.
    """
    return (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(b"")
        .add_signer(cert, key, hashes.SHA256())
        .sign(serialization.Encoding.DER, [])
    )


def _write_metadata(tmp_path, x509_b64):
    """Write a minimal IdP metadata file with a single signing cert."""
    path = os.path.join(tmp_path, "metadata.xml")
    with open(path, "w", encoding="utf-8") as f:
        f.write(
            '<EntityDescriptor entityID="https://test-idp.example" '
            'xmlns="urn:oasis:names:tc:SAML:2.0:metadata">'
            "<IDPSSODescriptor protocolSupportEnumeration="
            '"urn:oasis:names:tc:SAML:2.0:protocol">'
            '<KeyDescriptor use="signing">'
            '<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">'
            f"<X509Data><X509Certificate>{x509_b64}</X509Certificate></X509Data>"
            "</KeyInfo></KeyDescriptor></IDPSSODescriptor></EntityDescriptor>"
        )
    return path


class SAMLIdpMetadataCertNormalizationTest:
    """`_normalize_idp_metadata_certs` must unwrap PKCS#7-wrapped IdP certs in
    `<X509Certificate>` so xmlsec1 can verify SAML Response signatures.

    Triggered by autenticacao.gov shipping the IdP signing cert as PKCS#7
    SignedData in some environments. Without this normalization, even with
    `only_use_keys_in_metadata=True`, xmlsec1 fails with
    `PEM_read_bio_X509_AUX:error=4:wrong tag` because OpenSSL expects an
    X.509 SEQUENCE, not the PKCS#7 OID 1.2.840.113549.1.7.2.
    """

    def test_passthrough_when_cert_is_already_x509(self, tmp_path):
        cert, _key = _make_test_cert_and_key()
        x509_b64 = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
        path = _write_metadata(str(tmp_path), x509_b64)

        result = _normalize_idp_metadata_certs(path)

        assert result == path, "clean metadata must not be rewritten"

    def test_unwraps_pkcs7_signed_data(self, tmp_path):
        cert, key = _make_test_cert_and_key()
        pkcs7_der = _make_pkcs7_signed_data_bundle(cert, key)
        path = _write_metadata(str(tmp_path), base64.b64encode(pkcs7_der).decode())

        result = _normalize_idp_metadata_certs(path)

        assert result != path, "PKCS#7-wrapped metadata must be rewritten"
        with open(result, encoding="utf-8") as f:
            cleaned = f.read()
        match = re.search(r"<X509Certificate>([^<]+)</X509Certificate>", cleaned)
        assert match, "normalized file must still contain <X509Certificate>"
        cleaned_der = base64.b64decode(match.group(1))
        # Round-trip parse must yield the same cert that was wrapped.
        x509.load_der_x509_certificate(cleaned_der)
        assert cleaned_der == cert.public_bytes(serialization.Encoding.DER)

    def test_normalized_output_is_content_addressed(self, tmp_path):
        cert, key = _make_test_cert_and_key()
        pkcs7_der = _make_pkcs7_signed_data_bundle(cert, key)
        path = _write_metadata(str(tmp_path), base64.b64encode(pkcs7_der).decode())

        first = _normalize_idp_metadata_certs(path)
        second = _normalize_idp_metadata_certs(path)

        assert first == second, "repeated calls with the same source must reuse the same temp file"

    def test_handles_invalid_base64_gracefully(self, tmp_path):
        path = _write_metadata(str(tmp_path), "not-valid-base64-@@@")

        result = _normalize_idp_metadata_certs(path)

        assert result == path, "malformed b64 must not trigger a rewrite"


class _InMemoryCache:
    """Minimal Flask-Caching stand-in for unit tests.

    The default test config uses `flask_caching.backends.null` (no-op),
    which silently drops every `cache.set` and makes round-trip tests
    impossible. Patch `udata.app.cache` with this to validate the
    store/consume cycle of the RelayState-backed outstanding bucket.
    """

    def __init__(self):
        self._store = {}

    def set(self, key, value, timeout=None):
        self._store[key] = value
        return True

    def get(self, key):
        return self._store.get(key)

    def delete(self, key):
        return self._store.pop(key, None) is not None


class SAMLOutstandingRelayTest(APITestCase):
    """Redis-backed `outstanding` bucket via SAML RelayState.

    Bypasses the session cookie on the SAML callback so deployments
    behind middleware that mangles the `Set-Cookie` `SameSite` attribute
    (e.g. F5 appending `SameSite=Lax` to cookies already marked
    `SameSite=None`) can still match `InResponseTo` against the issued
    AuthnRequest. RelayState is a regular SAML form field the IdP
    echoes back, so it rides the cross-site POST end-to-end.
    """

    def test_token_is_random_and_url_safe(self):
        a = _new_relay_state_token()
        b = _new_relay_state_token()

        assert a and b and a != b, "tokens must be unique per call"
        assert re.fullmatch(r"[A-Za-z0-9_\-]+", a), (
            "token must be URL-safe so it round-trips through HTTP-POST RelayState"
        )

    def test_store_then_consume_returns_bucket(self):
        cache = _InMemoryCache()
        with patch("udata.app.cache", cache):
            token = _new_relay_state_token()
            _store_outstanding_relay(token, "id-abc", kind="cmd")

            assert _consume_outstanding_relay(token) == {"id-abc": "cmd"}

    def test_consume_is_single_use(self):
        cache = _InMemoryCache()
        with patch("udata.app.cache", cache):
            token = _new_relay_state_token()
            _store_outstanding_relay(token, "id-abc", kind="cmd")

            first = _consume_outstanding_relay(token)
            second = _consume_outstanding_relay(token)

            assert first == {"id-abc": "cmd"}
            assert second == {}, (
                "second consume must return empty so the response cannot be replayed"
            )

    def test_consume_unknown_token_returns_empty(self):
        with patch("udata.app.cache", _InMemoryCache()):
            assert _consume_outstanding_relay("unknown-token-xyz") == {}

    def test_consume_empty_or_invalid_returns_empty(self):
        with patch("udata.app.cache", _InMemoryCache()):
            assert _consume_outstanding_relay("") == {}
            assert _consume_outstanding_relay(None) == {}

    def test_store_ignores_empty_inputs(self):
        cache = _InMemoryCache()
        with patch("udata.app.cache", cache):
            # Both empty token and empty reqid are no-ops; nothing to consume.
            _store_outstanding_relay("", "id-abc", kind="cmd")
            _store_outstanding_relay("token-xyz", "", kind="cmd")

            assert _consume_outstanding_relay("") == {}
            assert _consume_outstanding_relay("token-xyz") == {}

    def test_store_failure_does_not_raise(self):
        """Cache outage must not break SP-initiated flow; fall back to cookie."""

        class _BrokenCache:
            def set(self, *a, **kw):
                raise RuntimeError("Redis is down")

            def get(self, *a, **kw):
                raise RuntimeError("Redis is down")

            def delete(self, *a, **kw):
                raise RuntimeError("Redis is down")

        with patch("udata.app.cache", _BrokenCache()):
            # No exception escapes; both calls return safe empty defaults.
            _store_outstanding_relay("token-xyz", "id-abc", kind="cmd")
            assert _consume_outstanding_relay("token-xyz") == {}


class SAMLAutoRegistrationTest(APITestCase):
    """Test the _find_or_create_saml_user helper function."""

    def test_unmatched_identity_creates_nothing(self):
        """The resolver is pure: an identity that matches no account yields
        no_match and creates nothing. Whether an account is created — and on
        what terms — is the caller's decision, because with the wizard on the
        user must supply a confirmed email first."""
        from udata.auth.saml.saml_plugin.saml_govpt import _find_or_create_saml_user
        from udata.core.user.models import User

        with self.app.app_context():
            users_before = User.objects.count()
            user, status = _find_or_create_saml_user(
                user_email="saml_new@example.com",
                user_nic="12345678",
                first_name="João",
                last_name="Silva",
            )

            assert status == "no_match"
            assert user is None
            assert User.objects.count() == users_before

    def test_finds_existing_user_by_email(self):
        """An email match never logs in nor auto-links — the existing
        account becomes the wizard candidate."""
        from udata.auth.saml.saml_plugin.saml_govpt import _find_or_create_saml_user

        with self.app.app_context():
            existing = UserFactory(email="existing@example.com")

            user, status = _find_or_create_saml_user(
                user_email="existing@example.com",
                user_nic="99999999",
                first_name="Another",
                last_name="Name",
            )

            assert status == "migration_candidate"
            assert user.id == existing.id
            existing.reload()
            assert not (existing.extras or {}).get("auth_nic")

    def test_finds_existing_user_by_nic(self):
        from udata.auth.saml.saml_plugin.saml_govpt import _find_or_create_saml_user

        with self.app.app_context():
            existing = UserFactory(extras={"auth_nic": _hash_nic("11111111")})

            user, status = _find_or_create_saml_user(
                user_email=None,
                user_nic="11111111",
                first_name="Test",
                last_name="User",
            )

            assert status == "existing_saml"
            assert user.id == existing.id

    def test_handles_missing_nic(self):
        from udata.auth.saml.saml_plugin.saml_govpt import _find_or_create_saml_user

        with self.app.app_context():
            user, status = _find_or_create_saml_user(
                user_email="no_nic@example.com",
                user_nic=None,
                first_name="Maria",
                last_name="Santos",
            )

            assert status == "no_match"
            assert user is None

    def test_placeholder_is_minted_when_creating_without_an_email(self):
        """The placeholder path still exists for the wizard-disabled fallback,
        which creates the account outright. Asserted on _create_saml_user
        directly now that the resolver no longer creates anything."""
        from udata.auth.saml.saml_plugin.saml_govpt import _create_saml_user

        with self.app.app_context():
            user = _create_saml_user(None, "77777777", "Carlos", "Ferreira")

            assert user is not None
            # Email must be the random-uuid placeholder, NOT a NIC-derived value.
            assert _SAML_PLACEHOLDER_EMAIL_RE.match(user.email), user.email
            assert "77777777" not in user.email  # NIC must not leak
            assert user.extras.get("auth_nic") == _hash_nic("77777777")

    def test_returns_none_when_no_email_and_no_nic(self):
        """When IdP provides neither email nor NIC, return None."""
        from udata.auth.saml.saml_plugin.saml_govpt import _find_or_create_saml_user

        with self.app.app_context():
            user, status = _find_or_create_saml_user(
                user_email=None,
                user_nic=None,
                first_name="Unknown",
                last_name="User",
            )

            assert status == "error"
            assert user is None


class SAMLLoginFlowTest(APITestCase):
    """Test the _handle_saml_user_login helper function."""

    def test_login_active_user_redirects_home(self):
        from udata.auth.saml.saml_plugin.saml_govpt import _handle_saml_user_login

        with self.app.test_request_context():
            self.app.config["CDATA_BASE_URL"] = "http://localhost:3000"
            user = UserFactory(confirmed_at="2024-01-01")

            response = _handle_saml_user_login(user)

            assert response.status_code == 302
            assert "login" not in response.location.lower()

    def test_unconfirmed_user_without_pending_marker_is_auto_confirmed(self):
        """The SAML auto-confirm survives, but only where it was ever
        justified: autenticacao.gov vouches for the IDENTITY, so a legacy
        account, or one created by the wizard-disabled fallback, is confirmed
        and logged in. It says nothing about an address the user declared
        themselves — that case carries the pending marker and is gated
        instead (see test_pending_marker_blocks_auto_confirm_and_login)."""
        from udata.auth.saml.saml_plugin.saml_govpt import _handle_saml_user_login

        with self.app.test_request_context():
            self.app.config["CDATA_BASE_URL"] = "http://localhost:3000"
            user = UserFactory(confirmed_at=None)
            assert not (user.extras or {}).get("pending_email_confirmation")

            response = _handle_saml_user_login(user)

            assert response.status_code == 302
            assert user.confirmed_at is not None
            assert "login" not in response.location.lower()

    def test_pending_marker_blocks_auto_confirm_and_login(self):
        """The counterpart: with the marker set and no confirmation yet, the
        same call neither confirms nor logs in, and sends the user back to
        the wizard to be told a confirmation is pending."""
        from udata.auth.saml.saml_plugin.saml_govpt import _handle_saml_user_login

        with self.app.test_request_context():
            self.app.config["CDATA_BASE_URL"] = "http://localhost:3000"
            user = UserFactory(
                confirmed_at=None,
                extras={"auth_nic": _hash_nic("55556666"), "pending_email_confirmation": True},
            )

            with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
                response = _handle_saml_user_login(user)
                assert mock_login.call_count == 0

            assert response.status_code == 302
            assert "/migrate-account" in response.location
            user.reload()
            assert user.confirmed_at is None

    def test_deleted_user_redirects_home(self):
        from udata.auth.saml.saml_plugin.saml_govpt import _handle_saml_user_login

        with self.app.test_request_context():
            self.app.config["CDATA_BASE_URL"] = "http://localhost:3000"
            user = UserFactory(confirmed_at="2024-01-01", deleted="2024-06-01")

            response = _handle_saml_user_login(user)

            assert response.status_code == 302
            assert "login" not in response.location.lower()

    def test_none_user_redirects_to_login(self):
        from udata.auth.saml.saml_plugin.saml_govpt import _handle_saml_user_login

        with self.app.test_request_context():
            self.app.config["CDATA_BASE_URL"] = "http://localhost:3000"

            response = _handle_saml_user_login(None)

            assert response.status_code == 302
            assert "login" in response.location.lower()
            # The redirect carries a diagnosis code readable from a browser
            # network trace (no backend-log access needed).
            assert "saml_error=missing_attributes" in response.location

    def test_login_sets_saml_session_flag(self):
        from udata.auth.saml.saml_plugin.saml_govpt import _handle_saml_user_login

        with self.app.test_request_context():
            self.app.config["CDATA_BASE_URL"] = "http://localhost:3000"
            user = UserFactory(confirmed_at="2024-01-01")

            with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
                _handle_saml_user_login(user)

                mock_login.assert_called_once_with(user)
                assert session.get("saml_login") is True

    def test_placeholder_email_user_redirects_to_complete_registration(self):
        """A user still holding a minted saml-* placeholder email must be
        sent to the complete-registration page — new accounts and older
        placeholder accounts logging in again alike."""
        from udata.auth.saml.saml_plugin.saml_govpt import _handle_saml_user_login

        with self.app.test_request_context():
            self.app.config["CDATA_BASE_URL"] = "http://localhost:3000"
            user = UserFactory(email="saml-abcdef01@autenticacao.gov.pt", confirmed_at="2024-01-01")

            response = _handle_saml_user_login(user)

            assert response.status_code == 302
            assert response.location == "http://localhost:3000/complete-registration"
            # The user is logged in: completing registration happens in-session.
            assert session.get("saml_login") is True

    def test_placeholder_email_redirect_drops_next_url_and_new_account_flag(self):
        """Completing registration is a hard precondition: the original
        destination and the cmd_new_account banner are dropped on purpose."""
        from udata.auth.saml.saml_plugin.saml_govpt import _handle_saml_user_login

        with self.app.test_request_context():
            self.app.config["CDATA_BASE_URL"] = "http://localhost:3000"
            session["saml_next_url"] = "/datasets"
            user = UserFactory(email="saml-deadbeef@autenticacao.gov.pt", confirmed_at="2024-01-01")

            response = _handle_saml_user_login(user, new_account=True)

            assert response.status_code == 302
            assert response.location == "http://localhost:3000/complete-registration"
            assert "saml_next_url" not in session

    def test_regular_user_keeps_next_url(self):
        """Guard: the placeholder redirect must not affect normal accounts."""
        from udata.auth.saml.saml_plugin.saml_govpt import _handle_saml_user_login

        with self.app.test_request_context():
            self.app.config["CDATA_BASE_URL"] = "http://localhost:3000"
            session["saml_next_url"] = "/datasets"
            user = UserFactory(confirmed_at="2024-01-01")

            response = _handle_saml_user_login(user)

            assert response.status_code == 302
            assert response.location == "http://localhost:3000/datasets"


class SAMLSSOCallbackTest(APITestCase):
    """Test the full /saml/sso endpoint (idp_initiated).

    This verifies the critical flow: after autenticacao.gov returns a
    successful SAML Response, the backend parses the attributes and
    then performs the udata login. The udata login_user call must only
    happen AFTER the SAML response is successfully validated and the
    user attributes are extracted.
    """

    @pytest.fixture(autouse=True)
    def _set_frontend_url(self, app):
        app.config["CDATA_BASE_URL"] = "http://localhost:3000"

    def _post_saml_response(self, saml_xml):
        """Helper: POST a base64-encoded SAMLResponse to /saml/sso."""
        encoded = base64.b64encode(saml_xml.encode("utf-8")).decode("utf-8")
        return self.client.post(
            "/saml/sso",
            data={"SAMLResponse": encoded},
            follow_redirects=False,
        )

    @patch("udata.auth.saml.saml_plugin.saml_govpt.requires_confirmation", return_value=False)
    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_sso_callback_sends_an_unmatched_identity_to_the_wizard(
        self, mock_client_for, mock_requires_conf
    ):
        """An identity matching no account no longer gets one created behind
        its back: it goes through the wizard, which asks for an email and
        confirms it before any account or session exists."""
        from udata.core.user.models import User

        mock_saml_client = MagicMock()
        mock_saml_client.parse_authn_request_response.return_value = _make_authn_response_mock(
            email="cidadao@example.pt",
            nic="12345678",
            first_name="João",
            last_name="Silva",
        )
        mock_client_for.return_value = mock_saml_client

        xml = _build_saml_response_xml(
            email="cidadao@example.pt",
            nic="12345678",
            first_name="João",
            last_name="Silva",
        )

        users_before = User.objects.count()

        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            response = self._post_saml_response(xml)
            assert mock_login.call_count == 0

        assert response.status_code == 302
        assert "/migrate-account" in response.headers["Location"]
        assert User.objects.count() == users_before

        # The identity travels in the session for the wizard to use, flagged
        # as matching nothing so it opens straight on the email step.
        with self.client.session_transaction() as sess:
            pending = sess["saml_migration_pending"]
            assert pending["no_match"] is True
            assert pending["saml_email"] == "cidadao@example.pt"
            assert pending["saml_nic"] == "12345678"

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_sso_callback_email_match_requires_ownership_confirmation(self, mock_client_for):
        """An email match must NOT log the user in — only a NIC match
        does. The user is redirected to the migration wizard instead."""
        self.app.config["MIGRATION_MODE_ENABLED"] = True
        mock_saml_client = MagicMock()
        mock_saml_client.parse_authn_request_response.return_value = _make_authn_response_mock(
            email="existing@example.pt",
            nic="99999999",
            first_name="Test",
            last_name="User",
        )
        mock_client_for.return_value = mock_saml_client

        existing = UserFactory(email="existing@example.pt", confirmed_at="2024-01-01")

        xml = _build_saml_response_xml(
            email="existing@example.pt",
            nic="99999999",
            first_name="Test",
            last_name="User",
        )

        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            response = self._post_saml_response(xml)

            assert mock_login.call_count == 0

        assert response.status_code == 302
        assert "/migrate-account" in response.headers["Location"]
        existing.reload()
        assert not (existing.extras or {}).get("auth_nic")

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_sso_callback_finds_existing_user_by_nic(self, mock_client_for):
        """If user exists with that NIC, login existing user even without email."""
        mock_saml_client = MagicMock()
        mock_saml_client.parse_authn_request_response.return_value = _make_authn_response_mock(
            nic="55555555", first_name="Test", last_name="User"
        )
        mock_client_for.return_value = mock_saml_client

        existing = UserFactory(
            confirmed_at="2024-01-01", extras={"auth_nic": _hash_nic("55555555")}
        )

        xml = _build_saml_response_xml(
            nic="55555555",
            first_name="Test",
            last_name="User",
        )

        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            self._post_saml_response(xml)

            assert mock_login.call_count == 1
            logged_in_user = mock_login.call_args[0][0]
            assert logged_in_user.id == existing.id

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_sso_callback_no_login_without_saml_attributes(self, mock_client_for):
        """If SAML response has no email/NIC, login_user must NOT be called."""
        mock_saml_client = MagicMock()
        mock_saml_client.parse_authn_request_response.return_value = MagicMock()
        mock_client_for.return_value = mock_saml_client

        # Empty attributes — no email, no NIC
        xml = _build_saml_response_xml()

        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            response = self._post_saml_response(xml)

            # login_user must NOT be called when no user can be found/created
            mock_login.assert_not_called()

        # Should redirect to login page (user is None)
        assert response.status_code == 302

    @patch("udata.auth.saml.saml_plugin.saml_govpt.requires_confirmation", return_value=False)
    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_sso_callback_login_happens_after_attribute_parsing(
        self, mock_client_for, mock_requires_conf
    ):
        """Verify the sequence: SAML parse → attribute extraction → login.

        This is the core test: login_user must only be called AFTER the
        SAML response from autenticacao.gov is successfully processed and
        the user attributes (email, NIC, name) are extracted.
        """
        # This test is about attribute plumbing, not creation policy: run it
        # on the wizard-disabled path, where the account is still created
        # and logged in outright.
        self.app.config["MIGRATION_MODE_ENABLED"] = False
        call_order = []

        mock_saml_client = MagicMock()

        def track_parse(*args, **kwargs):
            call_order.append("saml_parse")
            return _make_authn_response_mock(
                email="order_test@example.pt",
                nic="33333333",
                first_name="Ana",
                last_name="Costa",
            )

        mock_saml_client.parse_authn_request_response.side_effect = track_parse
        mock_client_for.return_value = mock_saml_client

        xml = _build_saml_response_xml(
            email="order_test@example.pt",
            nic="33333333",
            first_name="Ana",
            last_name="Costa",
        )

        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:

            def track_login(user):
                call_order.append("login_user")
                # Verify user was created with correct SAML attributes
                assert user.email == "order_test@example.pt"
                assert user.extras.get("auth_nic") == _hash_nic("33333333")
                return True

            mock_login.side_effect = track_login
            self._post_saml_response(xml)

        # SAML parse must happen before login_user
        assert call_order == [
            "saml_parse",
            "login_user",
        ], f"Expected saml_parse before login_user, got: {call_order}"

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_sso_callback_no_login_on_signature_error(self, mock_client_for):
        """SignatureError must abort the SSO and never call login_user.

        Regression test for VULN-2077 / TICKET-58: previously, a manual
        XML fallback would extract attributes from an unverified response
        and grant a session, allowing account takeover. After the fix, no
        attributes are read from a response whose signature pysaml2 could
        not validate.
        """
        from saml2.sigver import SignatureError

        mock_saml_client = MagicMock()
        mock_saml_client.parse_authn_request_response.side_effect = SignatureError(
            "Invalid signature"
        )
        mock_client_for.return_value = mock_saml_client

        # XML carries attributes that, before the fix, the fallback parser
        # would have used to log in as the victim. After the fix these
        # attributes are ignored because the signature check failed.
        xml = _build_saml_response_xml(
            email="hacker@evil.com",
            nic="00000000",
            first_name="Bad",
            last_name="Actor",
        )

        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            response = self._post_saml_response(xml)

            # login_user MUST NOT be called when signature validation fails.
            mock_login.assert_not_called()

        # Must redirect (no session cookie set, no user logged in).
        assert response.status_code == 302

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_sso_callback_sets_session_saml_login(self, mock_client_for):
        """After successful SAML login, session['saml_login'] must be True."""
        mock_saml_client = MagicMock()
        mock_saml_client.parse_authn_request_response.return_value = _make_authn_response_mock(
            email="session_test@example.pt",
            nic="44444444",
            first_name="Rui",
            last_name="Mendes",
        )
        mock_client_for.return_value = mock_saml_client

        # NIC already linked → direct login (the only no-wizard path).
        UserFactory(
            email="session_test@example.pt",
            confirmed_at="2024-01-01",
            extras={"auth_nic": _hash_nic("44444444")},
        )

        xml = _build_saml_response_xml(
            email="session_test@example.pt",
            nic="44444444",
            first_name="Rui",
            last_name="Mendes",
        )

        with self.client.session_transaction() as sess:
            assert sess.get("saml_login") is None

        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            mock_login.return_value = True
            self._post_saml_response(xml)

        with self.client.session_transaction() as sess:
            assert sess.get("saml_login") is True

    @patch("udata.auth.saml.saml_plugin.saml_govpt.requires_confirmation", return_value=False)
    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_sso_callback_with_only_email(self, mock_client_for, mock_requires_conf):
        """autenticacao.gov may return only email (NIC is optional). Without a
        match the identity goes to the wizard; no_match stays false because
        there is no NIC, so the wizard offers the search branch rather than
        account creation (an account with no auth_nic could confirm itself)."""
        mock_saml_client = MagicMock()
        mock_saml_client.parse_authn_request_response.return_value = _make_authn_response_mock(
            email="email_only@example.pt"
        )
        mock_client_for.return_value = mock_saml_client

        xml = _build_saml_response_xml(email="email_only@example.pt")

        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            response = self._post_saml_response(xml)
            assert mock_login.call_count == 0

        assert "/migrate-account" in response.headers["Location"]
        assert self.client.get("/saml/migration/pending").json["no_match"] is False

    @patch("udata.auth.saml.saml_plugin.saml_govpt.requires_confirmation", return_value=False)
    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_sso_callback_with_only_nic_goes_to_the_wizard(
        self, mock_client_for, mock_requires_conf
    ):
        """autenticacao.gov may return NIC but no email. Rather than minting a
        placeholder and dropping the user on /complete-registration with a
        session, the wizard now collects a real email up front."""
        mock_saml_client = MagicMock()
        mock_saml_client.parse_authn_request_response.return_value = _make_authn_response_mock(
            nic="88888888", first_name="Pedro", last_name="Nunes"
        )
        mock_client_for.return_value = mock_saml_client

        xml = _build_saml_response_xml(nic="88888888", first_name="Pedro", last_name="Nunes")

        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            response = self._post_saml_response(xml)
            assert mock_login.call_count == 0

        assert response.status_code == 302
        # ?no_email=true is the pre-existing marker for "the IdP brought no
        # email address"; the wizard base URL is what matters here.
        assert response.headers["Location"].startswith("http://localhost:3000/migrate-account")

        # A NIC is present, so the wizard can open straight on the email step.
        data = self.client.get("/saml/migration/pending").json
        assert data["no_match"] is True
        assert data["suggested_email"] is None  # the CMD brought no email

    @patch("udata.auth.saml.saml_plugin.saml_govpt.requires_confirmation", return_value=False)
    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_sso_callback_existing_placeholder_account_redirects_to_complete_registration(
        self, mock_client_for, mock_requires_conf
    ):
        """An older account created with a placeholder email (before the
        complete-registration flow) is forced to the page on its next login."""
        existing = UserFactory(
            email="saml-cafe0123@autenticacao.gov.pt",
            extras={"auth_nic": _hash_nic("33334444")},
            confirmed_at="2024-01-01",
        )

        mock_saml_client = MagicMock()
        mock_saml_client.parse_authn_request_response.return_value = _make_authn_response_mock(
            nic="33334444", first_name="Pedro", last_name="Nunes"
        )
        mock_client_for.return_value = mock_saml_client

        xml = _build_saml_response_xml(nic="33334444", first_name="Pedro", last_name="Nunes")

        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            response = self._post_saml_response(xml)

            assert mock_login.call_count == 1
            assert mock_login.call_args[0][0].id == existing.id

        assert response.status_code == 302
        assert response.headers["Location"] == "http://localhost:3000/complete-registration"

    def test_sso_rejects_missing_saml_response(self):
        """POST to /saml/sso without SAMLResponse should fail."""
        response = self.client.post("/saml/sso", data={})
        assert response.status_code in (400, 500)

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_sso_with_invalid_base64_does_not_login(self, mock_client_for):
        """POST with invalid base64 must not login any user."""
        mock_client_for.return_value = MagicMock()

        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            response = self.client.post(
                "/saml/sso",
                data={"SAMLResponse": "not-valid-base64!!!"},
            )
            mock_login.assert_not_called()

        # Redirects to login page (no user created)
        assert response.status_code == 302


class SAMLVuln2077RegressionTest(APITestCase):
    """Regression suite for VULN-2077 / TICKET-58 (Account Takeover via SAML).

    Each test exercises one fail-closed exit added to ``idp_initiated`` so
    a future regression that re-introduces the manual XML fallback, the
    permissive ``except`` clauses or relaxes the Issuer / Subject /
    replay checks will be caught here.
    """

    @pytest.fixture(autouse=True)
    def _set_frontend_url(self, app):
        app.config["CDATA_BASE_URL"] = "http://localhost:3000"

    def _post_saml_response(self, saml_xml):
        encoded = base64.b64encode(saml_xml.encode("utf-8")).decode("utf-8")
        return self.client.post(
            "/saml/sso",
            data={"SAMLResponse": encoded},
            follow_redirects=False,
        )

    def _post_eidas_response(self, saml_xml):
        encoded = base64.b64encode(saml_xml.encode("utf-8")).decode("utf-8")
        return self.client.post(
            "/saml/eidas/sso",
            data={"SAMLResponse": encoded},
            follow_redirects=False,
        )

    # ----- CMD path ----------------------------------------------------

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_sso_rejects_unsigned_response(self, mock_client_for):
        """A SAML Response with no <Signature> raises SignatureError → reject."""
        from saml2.sigver import SignatureError

        mock_saml_client = MagicMock()
        mock_saml_client.parse_authn_request_response.side_effect = SignatureError(
            "Response is not signed"
        )
        mock_client_for.return_value = mock_saml_client

        xml = _build_saml_response_xml(email="a@b.pt", nic="12345678")

        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            response = self._post_saml_response(xml)
            mock_login.assert_not_called()
        assert response.status_code == 302
        assert "/login" in response.headers["Location"]

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_sso_rejects_response_signed_by_unknown_key(self, mock_client_for):
        """SignatureError from a key not present in the IdP metadata → reject."""
        from saml2.sigver import SignatureError

        mock_saml_client = MagicMock()
        mock_saml_client.parse_authn_request_response.side_effect = SignatureError(
            "Signature key not in trust store"
        )
        mock_client_for.return_value = mock_saml_client

        xml = _build_saml_response_xml(email="a@b.pt", nic="12345678")

        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            response = self._post_saml_response(xml)
            mock_login.assert_not_called()
        assert response.status_code == 302

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_sso_rejects_xsw_attack(self, mock_client_for):
        """Subject NameID does not match the NIC carried by AttributeStatement.

        Simulates an XML Signature Wrapping (XSW) attack: pysaml2 validated
        a signed assertion whose Subject points at one user, while a
        wrapper assertion smuggled an AttributeStatement with a NIC for a
        different user. The binding check must catch the mismatch.
        """
        mock_saml_client = MagicMock()
        mock_saml_client.parse_authn_request_response.return_value = _make_authn_response_mock(
            email="victim@example.pt",
            nic="11111111",  # forged NIC in attribute statement
            name_id="22222222",  # legitimate Subject
        )
        mock_client_for.return_value = mock_saml_client

        xml = _build_saml_response_xml(email="victim@example.pt", nic="11111111")

        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            response = self._post_saml_response(xml)
            mock_login.assert_not_called()
        assert response.status_code == 302

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_sso_rejects_replay(self, mock_client_for):
        """A second consumption of the same Response@ID is refused."""
        mock_saml_client = MagicMock()
        mock_saml_client.parse_authn_request_response.return_value = _make_authn_response_mock(
            email="replay@example.pt", nic="33333333"
        )
        mock_client_for.return_value = mock_saml_client

        xml = _build_saml_response_xml(email="replay@example.pt", nic="33333333")

        with patch(
            "udata.auth.saml.saml_plugin.saml_govpt._check_and_record_replay",
            return_value=False,  # simulate "already consumed"
        ):
            with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
                response = self._post_saml_response(xml)
                mock_login.assert_not_called()
        assert response.status_code == 302

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_sso_rejects_untrusted_issuer(self, mock_client_for):
        """An <Issuer> outside the configured metadata is rejected."""
        mock_saml_client = MagicMock()
        mock_saml_client.parse_authn_request_response.return_value = _make_authn_response_mock(
            email="a@b.pt",
            nic="44444444",
            issuer="https://evil-idp.example.com",
        )
        mock_client_for.return_value = mock_saml_client

        xml = _build_saml_response_xml(email="a@b.pt", nic="44444444")

        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            response = self._post_saml_response(xml)
            mock_login.assert_not_called()
        assert response.status_code == 302
        # The rejection code is exposed in the redirect for browser-trace
        # diagnosis (environments without backend-log access).
        assert "saml_error=issuer_untrusted" in response.headers["Location"]

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_sso_rejects_subject_attribute_mismatch(self, mock_client_for):
        """Subject NameID present but pointing at a different user than NIC."""
        mock_saml_client = MagicMock()
        mock_saml_client.parse_authn_request_response.return_value = _make_authn_response_mock(
            email="a@b.pt",
            nic="55555555",
            name_id="not-the-same-id",
        )
        mock_client_for.return_value = mock_saml_client

        xml = _build_saml_response_xml(email="a@b.pt", nic="55555555")

        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            response = self._post_saml_response(xml)
            mock_login.assert_not_called()
        assert response.status_code == 302

    # ----- eIDAS path --------------------------------------------------
    # The eIDAS handler mirrors idp_initiated; the same six rejections
    # must hold there too.

    @patch("udata.auth.saml.saml_plugin.saml_govpt.eidas_client_for")
    def test_eidas_rejects_unsigned_response(self, mock_client_for):
        from saml2.sigver import SignatureError

        mock_saml_client = MagicMock()
        mock_saml_client.parse_authn_request_response.side_effect = SignatureError(
            "Response is not signed"
        )
        mock_client_for.return_value = mock_saml_client

        xml = _build_saml_response_xml(email="a@b.pt", nic="12345678")

        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            response = self._post_eidas_response(xml)
            mock_login.assert_not_called()
        assert response.status_code == 302

    @patch("udata.auth.saml.saml_plugin.saml_govpt.eidas_client_for")
    def test_eidas_rejects_response_signed_by_unknown_key(self, mock_client_for):
        from saml2.sigver import SignatureError

        mock_saml_client = MagicMock()
        mock_saml_client.parse_authn_request_response.side_effect = SignatureError(
            "Signature key not in trust store"
        )
        mock_client_for.return_value = mock_saml_client

        xml = _build_saml_response_xml(email="a@b.pt", nic="12345678")

        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            response = self._post_eidas_response(xml)
            mock_login.assert_not_called()
        assert response.status_code == 302

    @patch("udata.auth.saml.saml_plugin.saml_govpt.eidas_client_for")
    def test_eidas_rejects_xsw_attack(self, mock_client_for):
        mock_saml_client = MagicMock()
        mock_saml_client.parse_authn_request_response.return_value = _make_authn_response_mock(
            email="victim@example.pt",
            nic="11111111",
            name_id="22222222",
        )
        mock_client_for.return_value = mock_saml_client

        xml = _build_saml_response_xml(email="victim@example.pt", nic="11111111")

        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            response = self._post_eidas_response(xml)
            mock_login.assert_not_called()
        assert response.status_code == 302

    @patch("udata.auth.saml.saml_plugin.saml_govpt.eidas_client_for")
    def test_eidas_rejects_replay(self, mock_client_for):
        mock_saml_client = MagicMock()
        mock_saml_client.parse_authn_request_response.return_value = _make_authn_response_mock(
            email="replay@example.pt", nic="33333333"
        )
        mock_client_for.return_value = mock_saml_client

        xml = _build_saml_response_xml(email="replay@example.pt", nic="33333333")

        with patch(
            "udata.auth.saml.saml_plugin.saml_govpt._check_and_record_replay",
            return_value=False,
        ):
            with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
                response = self._post_eidas_response(xml)
                mock_login.assert_not_called()
        assert response.status_code == 302

    @patch("udata.auth.saml.saml_plugin.saml_govpt.eidas_client_for")
    def test_eidas_rejects_untrusted_issuer(self, mock_client_for):
        mock_saml_client = MagicMock()
        mock_saml_client.parse_authn_request_response.return_value = _make_authn_response_mock(
            email="a@b.pt",
            nic="44444444",
            issuer="https://evil-idp.example.com",
        )
        mock_client_for.return_value = mock_saml_client

        xml = _build_saml_response_xml(email="a@b.pt", nic="44444444")

        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            response = self._post_eidas_response(xml)
            mock_login.assert_not_called()
        assert response.status_code == 302

    @patch("udata.auth.saml.saml_plugin.saml_govpt.eidas_client_for")
    def test_eidas_rejects_subject_attribute_mismatch(self, mock_client_for):
        mock_saml_client = MagicMock()
        mock_saml_client.parse_authn_request_response.return_value = _make_authn_response_mock(
            email="a@b.pt",
            nic="55555555",
            name_id="not-the-same-id",
        )
        mock_client_for.return_value = mock_saml_client

        xml = _build_saml_response_xml(email="a@b.pt", nic="55555555")

        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            response = self._post_eidas_response(xml)
            mock_login.assert_not_called()
        assert response.status_code == 302


class SAMLEidasSSOTest(APITestCase):
    """Success-path coverage for /saml/eidas/sso — parity with CMD.

    eIDAS responses carry the eidas.europa.eu natural-person attributes
    (PersonIdentifier, CurrentGivenName, CurrentFamilyName) instead of the
    MDC/Cidadao ones, and never carry an email. Field mapping:
    PersonIdentifier → extras.auth_nic (HMAC), CurrentGivenName →
    first_name, CurrentFamilyName → last_name; the account gets a
    placeholder email and must complete registration on the frontend.
    """

    PERSON_ID = "ES/PT/1234567890"

    @pytest.fixture(autouse=True)
    def _set_frontend_url(self, app):
        app.config["CDATA_BASE_URL"] = "http://localhost:3000"
        app.config["MIGRATION_MODE_ENABLED"] = True

    def _post_eidas_response(self, saml_xml):
        encoded = base64.b64encode(saml_xml.encode("utf-8")).decode("utf-8")
        return self.client.post(
            "/saml/eidas/sso",
            data={"SAMLResponse": encoded},
            follow_redirects=False,
        )

    def _sso_with(self, mock_client_for, **attrs):
        mock_saml_client = MagicMock()
        mock_saml_client.parse_authn_request_response.return_value = _make_authn_response_mock(
            **attrs
        )
        mock_client_for.return_value = mock_saml_client
        # name_id/name_id_format/issuer/eidas_friendly_names only shape the
        # validated mock, not the raw XML.
        xml_attrs = {
            k: v
            for k, v in attrs.items()
            if k not in ("name_id", "name_id_format", "issuer", "eidas_friendly_names")
        }
        return self._post_eidas_response(_build_saml_response_xml(**xml_attrs))

    @patch("udata.auth.saml.saml_plugin.saml_govpt.requires_confirmation", return_value=False)
    @patch("udata.auth.saml.saml_plugin.saml_govpt.eidas_client_for")
    def test_eidas_creates_account_from_eidas_attributes(self, mock_client_for, mock_requires_conf):
        """eIDAS shares the resolver with CMD, so an unmatched eIDAS identity
        also goes through the wizard instead of getting a placeholder account
        and a session. The attributes travel in the session for it to use."""
        from udata.core.user.models import User

        users_before = User.objects.count()

        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            response = self._sso_with(
                mock_client_for,
                person_identifier=self.PERSON_ID,
                given_name="Carmen",
                family_name="García",
            )
            assert mock_login.call_count == 0

        assert response.status_code == 302
        # ?no_email=true is the pre-existing marker for "the IdP brought no
        # email address"; the wizard base URL is what matters here.
        assert response.headers["Location"].startswith("http://localhost:3000/migrate-account")
        assert User.objects.count() == users_before

        with self.client.session_transaction() as sess:
            pending = sess["saml_migration_pending"]
            assert pending["no_match"] is True
            # CurrentGivenName → first_name, CurrentFamilyName → last_name
            assert pending["saml_first_name"] == "Carmen"
            assert pending["saml_last_name"] == "García"
            # The raw PersonIdentifier is only hashed once an account exists.
            assert pending["saml_nic"] == self.PERSON_ID

    @patch("udata.auth.saml.saml_plugin.saml_govpt.requires_confirmation", return_value=False)
    @patch("udata.auth.saml.saml_plugin.saml_govpt.eidas_client_for")
    def test_eidas_repeat_login_resolves_same_account(self, mock_client_for, mock_requires_conf):
        """A second login with the same PersonIdentifier must resolve the
        existing account instead of creating a duplicate."""
        from udata.core.user.models import User

        existing = UserFactory(
            email="saml-feedc0de@autenticacao.gov.pt",
            extras={"auth_nic": _hash_nic(self.PERSON_ID)},
            confirmed_at="2024-01-01",
        )
        users_before = User.objects.count()

        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            response = self._sso_with(
                mock_client_for,
                person_identifier=self.PERSON_ID,
                given_name="Carmen",
                family_name="García",
            )

            assert mock_login.call_count == 1
            assert mock_login.call_args[0][0].id == existing.id

        assert User.objects.count() == users_before
        # Still holding the placeholder → forced back to the page.
        assert response.status_code == 302
        assert response.headers["Location"] == "http://localhost:3000/complete-registration"

    @patch("udata.auth.saml.saml_plugin.saml_govpt.eidas_client_for")
    def test_eidas_name_match_redirects_to_migration_wizard(self, mock_client_for):
        """A homonym account without a linked identity becomes a wizard
        candidate — same ownership-confirmation rule as CMD."""
        existing = UserFactory(
            email="carmen@example.pt",
            password="S3cretPass!",
            first_name="Carmen",
            last_name="García",
        )

        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            response = self._sso_with(
                mock_client_for,
                person_identifier=self.PERSON_ID,
                given_name="Carmen",
                family_name="García",
            )
            assert mock_login.call_count == 0

        assert response.status_code == 302
        assert "/migrate-account" in response.headers["Location"]
        existing.reload()
        assert not (existing.extras or {}).get("auth_nic")

    @patch("udata.auth.saml.saml_plugin.saml_govpt.eidas_client_for")
    def test_eidas_rejects_name_id_person_identifier_mismatch(self, mock_client_for):
        """Strict Subject↔identifier binding (anti-XSW) applies to the
        eIDAS PersonIdentifier exactly as it does to the CMD NIC — for a
        NameID with a specific (non-pseudonym) format."""
        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            response = self._sso_with(
                mock_client_for,
                person_identifier=self.PERSON_ID,
                given_name="Carmen",
                family_name="García",
                name_id="ES/PT/9999999999",
                name_id_format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
            )
            mock_login.assert_not_called()

        assert response.status_code == 302
        assert "/login" in response.headers["Location"]
        assert "saml_error=subject_nic_mismatch" in response.headers["Location"]

    @patch("udata.auth.saml.saml_plugin.saml_govpt.requires_confirmation", return_value=False)
    @patch("udata.auth.saml.saml_plugin.saml_govpt.eidas_client_for")
    def test_eidas_pseudonym_name_id_skips_binding(self, mock_client_for, mock_requires_conf):
        """The real IdP emits NameID as an opaque pseudonym with
        Format=unspecified, unrelated to the PersonIdentifier (observed in
        TST: every eIDAS login was rejected with subject_nic_mismatch).
        Same rule as CMD: the binding check is skipped for pseudonym
        NameIDs and the login proceeds."""
        # This test is about attribute plumbing, not creation policy: run it
        # on the wizard-disabled path, where the account is still created
        # and logged in outright.
        self.app.config["MIGRATION_MODE_ENABLED"] = False
        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            response = self._sso_with(
                mock_client_for,
                person_identifier="CZ/PT/83e5a4b9-5524-4ed6-a30e-bf9ee71c8fc6",
                given_name="Pavel",
                family_name="Novák",
                name_id="opaque-pseudonym-value",
                name_id_format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
            )

            assert mock_login.call_count == 1
            user = mock_login.call_args[0][0]
            assert user.extras.get("auth_nic") == _hash_nic(
                "CZ/PT/83e5a4b9-5524-4ed6-a30e-bf9ee71c8fc6"
            )
            assert _SAML_PLACEHOLDER_EMAIL_RE.match(user.email), user.email

        assert response.status_code == 302
        assert response.headers["Location"] == "http://localhost:3000/complete-registration"

    @patch("udata.auth.saml.saml_plugin.saml_govpt.requires_confirmation", return_value=False)
    @patch("udata.auth.saml.saml_plugin.saml_govpt.eidas_client_for")
    def test_eidas_still_accepts_mdc_attributes(self, mock_client_for, mock_requires_conf):
        """If the PT node translates eIDAS attributes into the MDC/Cidadao
        namespace, the postback keeps working (MDC is read first)."""
        # This test is about attribute plumbing, not creation policy: run it
        # on the wizard-disabled path, where the account is still created
        # and logged in outright.
        self.app.config["MIGRATION_MODE_ENABLED"] = False
        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            self._sso_with(
                mock_client_for,
                email="citizen@example.pt",
                nic="12345678",
                first_name="Ana",
                last_name="Bento",
            )

            assert mock_login.call_count == 1
            user = mock_login.call_args[0][0]
            assert user.email == "citizen@example.pt"
            assert user.extras.get("auth_nic") == _hash_nic("12345678")

    @patch("udata.auth.saml.saml_plugin.saml_govpt.requires_confirmation", return_value=False)
    @patch("udata.auth.saml.saml_plugin.saml_govpt.eidas_client_for")
    def test_eidas_friendly_name_attributes_from_pysaml2_maps(
        self, mock_client_for, mock_requires_conf
    ):
        """The real-world shape: pysaml2's built-in attribute maps translate
        the eIDAS URIs into friendly names (PersonIdentifier, FirstName,
        FamilyName), so get_identity() keys them that way — the extraction
        must find them (this was the DEV `missing_attributes` failure)."""
        # This test is about attribute plumbing, not creation policy: run it
        # on the wizard-disabled path, where the account is still created
        # and logged in outright.
        self.app.config["MIGRATION_MODE_ENABLED"] = False
        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            response = self._sso_with(
                mock_client_for,
                person_identifier=self.PERSON_ID,
                given_name="Carmen",
                family_name="García",
                eidas_friendly_names=True,
                name_id="opaque-pseudonym-value",
                name_id_format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
            )

            assert mock_login.call_count == 1
            user = mock_login.call_args[0][0]
            assert user.extras.get("auth_nic") == _hash_nic(self.PERSON_ID)
            assert user.first_name == "Carmen"
            assert user.last_name == "García"
            assert _SAML_PLACEHOLDER_EMAIL_RE.match(user.email), user.email

        assert response.status_code == 302
        assert response.headers["Location"] == "http://localhost:3000/complete-registration"

    def test_eidas_idp_denied_status_redirects_cleanly(self):
        """A non-Success StatusCode from the IdP must produce a clean
        redirect with saml_error=idp_denied instead of a pysaml2
        StatusError 500 (parity with the CMD pre-check)."""
        denied_xml = """<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                ID="_denied123" Version="2.0"
                IssueInstant="2024-01-01T00:00:00Z">
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder">
            <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:RequestDenied"/>
        </samlp:StatusCode>
        <samlp:StatusMessage>User cancelled the authentication</samlp:StatusMessage>
    </samlp:Status>
</samlp:Response>"""

        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            response = self._post_eidas_response(denied_xml)
            mock_login.assert_not_called()

        assert response.status_code == 302
        assert "saml_error=idp_denied" in response.headers["Location"]

    @patch("udata.auth.saml.saml_plugin.saml_govpt.eidas_client_for")
    def test_eidas_without_identifier_reports_received_attribute_uris(self, mock_client_for):
        """When the response carries neither email nor NIC/PersonIdentifier,
        the rejection redirect exposes the attribute URIs that DID arrive
        (schema names only) so a browser trace suffices to diagnose."""
        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            response = self._sso_with(
                mock_client_for,
                given_name="Carmen",
                family_name="García",
            )
            mock_login.assert_not_called()

        assert response.status_code == 302
        location = response.headers["Location"]
        assert "saml_error=missing_attributes" in location
        # URL-encoded CurrentGivenName URI must be present in saml_detail.
        assert "saml_detail=" in location
        assert "CurrentGivenName" in location


@requires_saml_credentials
class SAMLLogoutInitiationTest(APITestCase):
    """SP-initiated logout (/saml/logout, /saml/eidas/logout).

    The local session must be terminated BEFORE the user is handed to the
    IdP single-logout dance: if any step of that round-trip fails, clicking
    "Sair" must still have logged the user out of the portal. The
    LogoutRequest must carry the Subject NameID recorded at SSO time so the
    IdP can resolve the right session.
    """

    @pytest.fixture(autouse=True)
    def _saml_config(self, app):
        app.config["SECURITY_SAML_ENTITY_ID"] = "www.dados.gov.pt"
        app.config["SECURITY_SAML_ENTITY_NAME"] = "dados.gov.pt"
        app.config["SECURITY_SAML_KEY_FILE"] = "udata/auth/saml/credentials/private.pem"
        app.config["SECURITY_SAML_CERT_FILE"] = "udata/auth/saml/credentials/AMA.pem"
        app.config["SECURITY_SAML_IDP_METADATA"] = "udata/auth/saml/credentials/metadata.xml"
        app.config["SECURITY_SAML_FA_URL"] = "https://preprod.autenticacao.gov.pt/fa/"
        app.config["SECURITY_SAML_FAAALEVEL"] = 3
        app.config["CDATA_BASE_URL"] = "http://localhost:3000"

    def test_saml_logout_terminates_local_session_first(self):
        with self.client.session_transaction() as sess:
            sess["saml_login"] = True
            sess["saml_name_id"] = "pseudonym-abc123"
            sess["saml_name_id_format"] = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"

        with patch("udata.auth.saml.saml_plugin.saml_govpt.logout_user") as mock_logout:
            response = self.client.get("/saml/logout")

            mock_logout.assert_called_once()

        # The IdP hand-off form is still returned (best-effort SLO)...
        assert response.status_code == 200
        body = response.get_data(as_text=True)
        assert 'name="SAMLRequest"' in body
        assert "https://preprod.autenticacao.gov.pt/fa/" in body
        # ...carrying the NameID recorded at SSO time.
        saml_request = re.search(r'name="SAMLRequest"\s+value="([^"]+)"', body).group(1)
        decoded = base64.b64decode(saml_request).decode("utf-8", "replace")
        assert "pseudonym-abc123" in decoded

        # ...but the local session is already dead.
        with self.client.session_transaction() as sess:
            assert sess.get("saml_login") is None
            assert sess.get("saml_name_id") is None
            assert sess.get("saml_name_id_format") is None

    def test_eidas_logout_terminates_local_session_first(self):
        with self.client.session_transaction() as sess:
            sess["saml_login"] = True
            sess["saml_name_id"] = "CZ/PT/83e5a4b9-5524-4ed6-a30e-bf9ee71c8fc6"

        with patch("udata.auth.saml.saml_plugin.saml_govpt.logout_user") as mock_logout:
            response = self.client.get("/saml/eidas/logout")

            mock_logout.assert_called_once()

        assert response.status_code == 200
        assert 'name="SAMLRequest"' in response.get_data(as_text=True)
        with self.client.session_transaction() as sess:
            assert sess.get("saml_login") is None
            assert sess.get("saml_name_id") is None

    def test_saml_logout_without_stored_name_id_uses_fallback(self):
        """Sessions from before the NameID was recorded still log out."""
        with self.client.session_transaction() as sess:
            sess["saml_login"] = True

        with patch("udata.auth.saml.saml_plugin.saml_govpt.logout_user") as mock_logout:
            response = self.client.get("/saml/logout")
            mock_logout.assert_called_once()

        assert response.status_code == 200
        with self.client.session_transaction() as sess:
            assert sess.get("saml_login") is None


class SAMLLogoutFlowTest(APITestCase):
    """Test the SAML logout callback clears the session."""

    @patch("udata.auth.saml.saml_plugin.saml_govpt.url_for", return_value="/")
    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    @patch("udata.auth.saml.saml_plugin.saml_govpt.logout_user")
    def test_sso_logout_clears_session_and_logs_out(
        self, mock_logout, mock_client_for, mock_url_for
    ):
        """After autenticacao.gov logout callback, session flag is cleared."""
        mock_saml_client = MagicMock()
        mock_saml_client.parse_logout_request_response.return_value = MagicMock()
        mock_client_for.return_value = mock_saml_client

        # Set up session with saml_login flag
        with self.client.session_transaction() as sess:
            sess["saml_login"] = True

        fake_response = base64.b64encode(b"<fake/>").decode("utf-8")
        response = self.client.post(
            "/saml/sso_logout",
            data={"SAMLResponse": fake_response},
        )

        assert response.status_code == 302
        mock_logout.assert_called_once()

        with self.client.session_transaction() as sess:
            assert sess.get("saml_login") is None


class SAMLAccountLinkingTest(APITestCase):
    """Verify the CMD (Chave Móvel Digital) account resolution rules.

    Direct login happens ONLY when the NIC is already linked. Any other
    match (email or name) requires the user to prove ownership of the
    default account through the migration wizard, so accounts are never
    linked or logged into without confirmation — and never duplicated,
    keeping permissions, roles, memberships and content.
    """

    def test_cmd_email_match_requires_confirmation(self):
        """A CMD login matching an account by email does NOT auto-link:
        the account becomes the wizard candidate, untouched."""
        from udata.auth.saml.saml_plugin.saml_govpt import _find_or_create_saml_user
        from udata.core.user.models import User

        with self.app.app_context():
            existing = UserFactory(
                email="cidadao@example.pt",
                password="S3cretPass!",
                first_name="João",
                last_name="Silva",
                confirmed_at=datetime(2024, 1, 1),
            )
            original_password_hash = existing.password
            users_before = User.objects.count()

            user, status = _find_or_create_saml_user(
                user_email="cidadao@example.pt",
                user_nic="12345678",
                first_name="João",
                last_name="Silva",
            )

            # The existing account is the candidate — no new account.
            assert status == "migration_candidate"
            assert user.id == existing.id
            assert User.objects.count() == users_before

            # Nothing was linked or changed — ownership not proven yet.
            existing.reload()
            assert not (existing.extras or {}).get("auth_nic")
            assert existing.password == original_password_hash
            assert existing.email == "cidadao@example.pt"

    def test_email_match_candidate_account_is_left_untouched(self):
        """Roles, memberships and content of the email-matched account
        stay intact while ownership is not proven (the preservation
        after wizard linking is covered by SAMLMigrationWizardTest)."""
        from udata.auth.saml.saml_plugin.saml_govpt import _find_or_create_saml_user
        from udata.core.dataset.factories import DatasetFactory
        from udata.core.organization.factories import OrganizationFactory
        from udata.core.organization.models import Member
        from udata.core.user.factories import AdminFactory

        with self.app.app_context():
            existing = AdminFactory(
                email="admin@example.pt",
                password="S3cretPass!",
                first_name="Maria",
                last_name="Santos",
            )
            org = OrganizationFactory(members=[Member(user=existing, role="admin")])
            dataset = DatasetFactory(owner=existing)

            user, status = _find_or_create_saml_user(
                user_email="admin@example.pt",
                user_nic="87654321",
                first_name="Maria",
                last_name="Santos",
            )

            assert status == "migration_candidate"
            assert user.id == existing.id

            existing.reload()
            assert not (existing.extras or {}).get("auth_nic")
            assert existing.sysadmin
            org.reload()
            assert org.is_admin(existing)
            dataset.reload()
            assert dataset.owner.id == existing.id

    def test_cmd_without_email_name_match_requires_confirmation(self):
        """When the CMD identity has no email and only the name matches
        an existing account (scenario 2), no auto-merge happens — the
        user must confirm ownership through the migration wizard."""
        from udata.auth.saml.saml_plugin.saml_govpt import _find_or_create_saml_user
        from udata.core.user.models import User

        with self.app.app_context():
            existing = UserFactory(
                email="pedro@example.pt",
                password="S3cretPass!",
                first_name="Pedro",
                last_name="Almeida",
            )
            users_before = User.objects.count()

            # CMD returns NIC + name but no email; the NIC was never
            # linked before, so only the name lookup can match.
            user, status = _find_or_create_saml_user(
                user_email=None,
                user_nic="55667788",
                first_name="PEDRO",
                last_name="almeida",
            )

            assert status == "migration_candidate"
            assert user.id == existing.id  # single candidate, case-insensitive
            assert User.objects.count() == users_before

            # Nothing was linked yet — ownership not proven.
            existing.reload()
            assert not (existing.extras or {}).get("auth_nic")

    def test_cmd_with_different_email_name_match_requires_confirmation(self):
        """When the CMD email differs from the account's email but the
        name matches (scenario 3), the wizard is required as well."""
        from udata.auth.saml.saml_plugin.saml_govpt import _find_or_create_saml_user

        with self.app.app_context():
            existing = UserFactory(
                email="rita.old@example.pt",
                password="S3cretPass!",
                first_name="Rita",
                last_name="Gomes",
            )

            user, status = _find_or_create_saml_user(
                user_email="rita.cmd@example.pt",
                user_nic="44556677",
                first_name="Rita",
                last_name="Gomes",
            )

            assert status == "migration_candidate"
            assert user.id == existing.id
            existing.reload()
            assert not (existing.extras or {}).get("auth_nic")

    def test_cmd_without_email_ambiguous_name_requires_confirmation(self):
        """When the name matches more than one account, the wizard is
        triggered without a pre-selected candidate."""
        from udata.auth.saml.saml_plugin.saml_govpt import _find_or_create_saml_user
        from udata.core.user.models import User

        with self.app.app_context():
            first = UserFactory(first_name="Maria", last_name="Sousa")
            second = UserFactory(first_name="Maria", last_name="Sousa")
            users_before = User.objects.count()

            user, status = _find_or_create_saml_user(
                user_email=None,
                user_nic="99887766",
                first_name="Maria",
                last_name="Sousa",
            )

            assert status == "migration_candidate"
            assert user is None  # ambiguous: no candidate pre-selected
            assert User.objects.count() == users_before
            first.reload()
            second.reload()
            assert not (first.extras or {}).get("auth_nic")
            assert not (second.extras or {}).get("auth_nic")

    def test_name_match_ignores_accounts_already_linked_to_cmd(self):
        """Accounts that already have a CMD identity are not name-match
        candidates — the homonym with CMD is left alone and the incoming
        identity matches nothing."""
        from udata.auth.saml.saml_plugin.saml_govpt import _find_or_create_saml_user

        with self.app.app_context():
            linked = UserFactory(
                first_name="Nuno",
                last_name="Matos",
                extras={"auth_nic": _hash_nic("00001111")},
            )

            user, status = _find_or_create_saml_user(
                user_email=None,
                user_nic="22223333",
                first_name="Nuno",
                last_name="Matos",
            )

            assert status == "no_match"
            assert user is None
            # The invariant that matters: the account linked to another CMD
            # identity was neither matched nor touched.
            linked.reload()
            assert linked.extras["auth_nic"] == _hash_nic("00001111")

    def test_linked_nic_takes_precedence_over_email_match(self):
        """Entry rule: a CMD identity already linked logs straight into
        its account, even when the CMD email matches another account."""
        from udata.auth.saml.saml_plugin.saml_govpt import _find_or_create_saml_user

        with self.app.app_context():
            linked = UserFactory(extras={"auth_nic": _hash_nic("31415926")})
            other = UserFactory(email="other@example.pt")

            user, status = _find_or_create_saml_user(
                user_email="other@example.pt",
                user_nic="31415926",
                first_name="Test",
                last_name="User",
            )

            assert status == "existing_saml"
            assert user.id == linked.id
            other.reload()
            assert not (other.extras or {}).get("auth_nic")

    def test_subsequent_cmd_logins_resolve_to_linked_account(self):
        """Once the NIC is linked (after wizard confirmation), later CMD
        logins resolve directly to the same account — even without email."""
        from udata.auth.saml.saml_plugin.saml_govpt import _find_or_create_saml_user
        from udata.core.user.models import User

        with self.app.app_context():
            existing = UserFactory(
                email="cidadao2@example.pt",
                password="S3cretPass!",
                extras={"auth_nic": _hash_nic("11223344")},
            )

            # CMD login where the IdP returns only the NIC.
            user, status = _find_or_create_saml_user(
                user_email=None,
                user_nic="11223344",
                first_name="Rui",
                last_name="Costa",
            )
            assert status == "existing_saml"
            assert user.id == existing.id

            # And with a different email too — the NIC always wins.
            user, status = _find_or_create_saml_user(
                user_email="outro@example.pt",
                user_nic="11223344",
                first_name="Rui",
                last_name="Costa",
            )
            assert status == "existing_saml"
            assert user.id == existing.id
            assert User.objects.count() == 1


class SAMLStaleNicRelinkTest(APITestCase):
    """Accounts holding stale (non-hashed) auth_nic values left by older
    portal versions: plain digit NICs, legacy-encrypted ciphertexts (512
    hex chars) and junk. Those values can never match the login lookup, so
    they must not lock the account out of CMD login: a plain NIC identical
    to the authenticated one upgrades in place, and any other stale value
    keeps the account eligible for the migration wizard. Only a properly
    hashed auth_nic counts as \"already linked to another identity\"."""

    LEGACY_ENCRYPTED = "ab12" * 128  # 512 hex chars

    def test_plain_stored_nic_logs_in_and_upgrades_to_hash(self):
        """Old plugin versions stored the NIC in plain form. The incoming
        NIC comes from a signed assertion, so an exact match proves the
        link: direct login, and the stored value is upgraded to the hash."""
        from udata.auth.saml.saml_plugin.saml_govpt import _find_or_create_saml_user

        with self.app.app_context():
            existing = UserFactory(
                email="cristina@example.pt",
                password="S3cretPass!",
                extras={"auth_nic": "08133404"},
            )

            user, status = _find_or_create_saml_user(
                user_email="cristina.cmd@example.pt",
                user_nic="08133404",
                first_name="Cristina",
                last_name="Isidro",
            )

            assert status == "existing_saml"
            assert user.id == existing.id
            existing.reload()
            assert existing.extras["auth_nic"] == _hash_nic("08133404")

    def test_plain_stored_nic_of_someone_else_does_not_match(self):
        """A different plain NIC on another account is neither matched nor
        modified — the login proceeds to the normal wizard/new-account path."""
        from udata.auth.saml.saml_plugin.saml_govpt import _find_or_create_saml_user

        with self.app.app_context():
            other = UserFactory(
                first_name="Alguém",
                last_name="Diferente",
                extras={"auth_nic": "99990000"},
            )

            user, status = _find_or_create_saml_user(
                user_email=None,
                user_nic="08133404",
                first_name="Cristina",
                last_name="Isidro",
            )

            assert status == "no_match"
            assert user is None
            other.reload()
            assert other.extras["auth_nic"] == "99990000"

    def test_email_match_with_legacy_encrypted_nic_is_wizard_candidate(self):
        """A legacy ciphertext does not count as a linked identity: the
        email-matched account is offered in the wizard for re-linking."""
        from udata.auth.saml.saml_plugin.saml_govpt import _find_or_create_saml_user

        with self.app.app_context():
            existing = UserFactory(
                email="legacy@example.pt",
                password="S3cretPass!",
                extras={"auth_nic": self.LEGACY_ENCRYPTED},
            )

            user, status = _find_or_create_saml_user(
                user_email="legacy@example.pt",
                user_nic="12345678",
                first_name="Rui",
                last_name="Martinho",
            )

            assert status == "migration_candidate"
            assert user.id == existing.id
            # Nothing linked yet — ownership not proven.
            existing.reload()
            assert existing.extras["auth_nic"] == self.LEGACY_ENCRYPTED

    def test_email_match_with_hashed_nic_stays_excluded(self):
        """Security invariant: an account properly linked to ANOTHER CMD
        identity is never offered in the wizard on email match."""
        from udata.auth.saml.saml_plugin.saml_govpt import _find_or_create_saml_user

        with self.app.app_context():
            linked = UserFactory(
                email="linked@example.pt",
                extras={"auth_nic": _hash_nic("00001111")},
            )

            user, status = _find_or_create_saml_user(
                user_email="linked@example.pt",
                user_nic="22223333",
                first_name="Nuno",
                last_name="Matos",
            )

            assert status == "no_match"
            assert user is None
            linked.reload()
            assert linked.extras["auth_nic"] == _hash_nic("00001111")

    def test_name_match_with_junk_nic_is_wizard_candidate(self):
        """Junk auth_nic values (old usernames) do not count as a linked
        identity either: the name-matched account goes to the wizard."""
        from udata.auth.saml.saml_plugin.saml_govpt import _find_or_create_saml_user

        with self.app.app_context():
            existing = UserFactory(
                first_name="Pedro",
                last_name="Almeida",
                password="S3cretPass!",
                extras={"auth_nic": "johndoe"},
            )

            user, status = _find_or_create_saml_user(
                user_email=None,
                user_nic="55667788",
                first_name="Pedro",
                last_name="Almeida",
            )

            assert status == "migration_candidate"
            assert user.id == existing.id
            existing.reload()
            assert existing.extras["auth_nic"] == "johndoe"

    def test_find_legacy_user_allows_stale_nic(self):
        """The wizard search/password path must also accept accounts with
        stale values, so they can prove ownership and be re-linked."""
        from udata.auth.saml.saml_plugin.saml_govpt import _find_legacy_user

        with self.app.app_context():
            stale = UserFactory(
                email="stale@example.pt",
                password="S3cretPass!",
                extras={"auth_nic": self.LEGACY_ENCRYPTED},
            )
            UserFactory(
                email="linked2@example.pt",
                password="S3cretPass!",
                extras={"auth_nic": _hash_nic("13579246")},
            )

            found = _find_legacy_user(email="stale@example.pt")
            assert found is not None and found.id == stale.id
            assert _find_legacy_user(email="linked2@example.pt") is None


class SAMLMigrationWizardTest(APITestCase):
    """End-to-end coverage of the account-linking wizard: an email or
    name match redirects to /migrate-account, where the user
    either proves ownership of the default account (email + password
    login, or emailed code) to link it, or explicitly creates a new
    account. Only a NIC match logs in directly.
    """

    @pytest.fixture(autouse=True)
    def _set_frontend_url(self, app):
        app.config["CDATA_BASE_URL"] = "http://localhost:3000"
        # A local udata.cfg may override the flag — the wizard behavior
        # under test requires it on (it is the default in settings.py).
        app.config["MIGRATION_MODE_ENABLED"] = True

    def _post_saml_response(self, saml_xml):
        encoded = base64.b64encode(saml_xml.encode("utf-8")).decode("utf-8")
        return self.client.post(
            "/saml/sso",
            data={"SAMLResponse": encoded},
            follow_redirects=False,
        )

    def _sso_with(self, mock_client_for, **attrs):
        mock_saml_client = MagicMock()
        mock_saml_client.parse_authn_request_response.return_value = _make_authn_response_mock(
            **attrs
        )
        mock_client_for.return_value = mock_saml_client
        return self._post_saml_response(_build_saml_response_xml(**attrs))

    def _mailed_token(self, mock_send):
        """The token behind the CTA of the mail that was just sent."""
        ctas = [p for p in mock_send.call_args[0][1].paragraphs if getattr(p, "link", None)]
        assert len(ctas) == 1
        return ctas[0].link.rsplit("/", 1)[1]

    def _click(self, token, client=None):
        """Follow a validation link — the only thing that links the identity
        and starts a session.

        Defaults to this test's own client, which is where the owner opens the
        mail in the ordinary case, and is what lets a test assert the pending
        session was cleared. Pass a fresh client to exercise the click with no
        wizard session at all; SAMLMigrationLinkClickTest owns that angle.
        """
        return (client or self.client).get(f"/saml/migration/confirm-link/{token}")

    def _confirm_by_password(self, email, password, click=True):
        """Prove which account to link, then follow the link that proof mails.

        The password no longer completes anything on its own, so a test that
        cares about the account being linked has to go through the click as
        well. Returns the response of the confirm call itself.
        """
        with patch("udata.auth.saml.saml_plugin.saml_govpt.send_mail") as mock_send:
            response = self.client.post(
                "/saml/migration/confirm",
                json={"method": "password", "email": email, "password": password},
            )
            if click and response.status_code == 200:
                assert self._click(self._mailed_token(mock_send)).status_code == 302
        return response

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_name_match_redirects_to_migration_wizard(self, mock_client_for):
        """Scenario 2: name matches, CMD has no email — no login, no new
        account; the user is sent to the wizard."""
        from udata.core.user.models import User

        existing = UserFactory(
            email="pedro@example.pt",
            password="S3cretPass!",
            first_name="Pedro",
            last_name="Almeida",
        )
        users_before = User.objects.count()

        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            response = self._sso_with(
                mock_client_for,
                nic="55667788",
                first_name="Pedro",
                last_name="Almeida",
            )
            assert mock_login.call_count == 0

        assert response.status_code == 302
        assert "/migrate-account" in response.headers["Location"]
        assert User.objects.count() == users_before
        existing.reload()
        assert not (existing.extras or {}).get("auth_nic")

        with self.client.session_transaction() as sess:
            pending = sess.get("saml_migration_pending")
            assert pending is not None
            assert pending["legacy_user_id"] == str(existing.id)
            assert pending["saml_nic"] == "55667788"
            assert pending["saml_email"] is None

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_password_then_link_click_links_account_and_preserves_data(self, mock_client_for):
        """'Já possuo uma conta' + login (email+password) bem-sucedido, then
        the validation link: the CMD identity is linked to the default
        account, keeping the password, roles, organization memberships and
        owned content. The password says which account; the click links it."""
        from udata.core.dataset.factories import DatasetFactory
        from udata.core.organization.factories import OrganizationFactory
        from udata.core.organization.models import Member
        from udata.core.user.factories import AdminFactory
        from udata.core.user.models import User

        existing = AdminFactory(
            email="maria@example.pt",
            password="S3cretPass!",
            first_name="Maria",
            last_name="Santos",
            confirmed_at=datetime(2024, 1, 1),
        )
        original_password_hash = existing.password
        org = OrganizationFactory(members=[Member(user=existing, role="admin")])
        dataset = DatasetFactory(owner=existing)
        users_before = User.objects.count()

        # CMD login with a different email and matching name → wizard.
        response = self._sso_with(
            mock_client_for,
            email="maria.cmd@example.pt",
            nic="87654321",
            first_name="Maria",
            last_name="Santos",
        )
        assert "/migrate-account" in response.headers["Location"]

        # The user chooses "Já possuo uma conta", logs in, and follows the
        # validation link that proof mails to that account's own address.
        response = self._confirm_by_password("maria@example.pt", "S3cretPass!")
        assert response.status_code == 200
        assert response.json["sent"] is True

        assert User.objects.count() == users_before
        existing.reload()
        assert existing.extras.get("auth_nic") == _hash_nic("87654321")
        # Password kept: both login methods remain available.
        assert existing.password == original_password_hash
        # Permissions and content preserved.
        assert existing.sysadmin
        org.reload()
        assert org.is_admin(existing)
        dataset.reload()
        assert dataset.owner.id == existing.id

        with self.client.session_transaction() as sess:
            assert sess.get("saml_migration_pending") is None

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_confirm_with_password_mails_link_and_grants_no_session(self, mock_client_for):
        """The password identifies the account; it no longer proves the email
        is reachable, so it links nothing and starts no session on its own.
        The link goes to the account's own address, never to one the request
        supplied, and the wizard session stays pending for the resend."""
        legacy = UserFactory(
            email="bruno@example.pt",
            password="S3cretPass!",
            first_name="Bruno",
            last_name="Matos",
        )

        self._sso_with(
            mock_client_for,
            email="bruno.cmd@example.pt",
            nic="31313131",
            first_name="Bruno",
            last_name="Matos",
        )

        with patch("udata.auth.saml.saml_plugin.saml_govpt.send_mail") as mock_send:
            response = self.client.post(
                "/saml/migration/confirm",
                json={
                    "method": "password",
                    "email": "bruno@example.pt",
                    "password": "S3cretPass!",
                },
            )
            assert response.status_code == 200
            assert response.json["sent"] is True
            mock_send.assert_called_once()
            assert mock_send.call_args[0][0].id == legacy.id

        legacy.reload()
        assert not (legacy.extras or {}).get("auth_nic")
        assert self.client.get("/api/1/me/").status_code == 401

        # Still pending: the resend and a second attempt both need it, and it
        # now points at the account the password proved.
        with self.client.session_transaction() as sess:
            pending = sess.get("saml_migration_pending")
            assert pending is not None
            assert pending["legacy_user_id"] == str(legacy.id)

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_confirm_send_cap_returns_429_without_burning_a_password_attempt(self, mock_client_for):
        """A correct password must not count against the brute-force cap.
        The tally is incremented before the password is checked, so without a
        reset the send cap would spend attempts that were all correct and
        lock the account out of the only branch that can identify it."""
        from udata.auth.saml.saml_plugin.saml_govpt import (
            MAX_MIGRATION_LINK_SENDS,
            MIGRATION_LINK_SEND_COUNT,
        )

        legacy = UserFactory(
            email="rita@example.pt",
            password="S3cretPass!",
            first_name="Rita",
            last_name="Gomes",
        )
        legacy.extras = {
            MIGRATION_LINK_SEND_COUNT: {
                "count": MAX_MIGRATION_LINK_SENDS,
                "window_start": datetime.utcnow().isoformat(),
            }
        }
        legacy.save()

        self._sso_with(mock_client_for, nic="41414141", first_name="Rita", last_name="Gomes")

        # Six correct passwords in a row: every one hits the send cap, and
        # none of them is ever answered with the attempts cap.
        for _ in range(6):
            with patch("udata.auth.saml.saml_plugin.saml_govpt.send_mail") as mock_send:
                response = self.client.post(
                    "/saml/migration/confirm",
                    json={
                        "method": "password",
                        "email": "rita@example.pt",
                        "password": "S3cretPass!",
                    },
                )
            assert response.status_code == 429
            assert response.json["error"] == "Maximum confirmation sends exceeded"
            mock_send.assert_not_called()

        with self.client.session_transaction() as sess:
            assert sess.get("migration_password_attempts") == 0

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_confirm_with_wrong_password_blocks_linking(self, mock_client_for):
        """Login falhado: the linking is refused and the account stays
        untouched; repeated failures hit the attempts cap (429)."""
        existing = UserFactory(
            email="pedro@example.pt",
            password="S3cretPass!",
            first_name="Pedro",
            last_name="Almeida",
        )

        self._sso_with(mock_client_for, nic="55667788", first_name="Pedro", last_name="Almeida")

        for _ in range(5):
            response = self.client.post(
                "/saml/migration/confirm",
                json={"method": "password", "email": "pedro@example.pt", "password": "wrong"},
            )
            assert response.status_code == 400

        # 6th attempt is blocked regardless of credentials.
        response = self.client.post(
            "/saml/migration/confirm",
            json={"method": "password", "email": "pedro@example.pt", "password": "S3cretPass!"},
        )
        assert response.status_code == 429

        existing.reload()
        assert not (existing.extras or {}).get("auth_nic")

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_confirm_can_link_a_different_account_than_the_candidate(self, mock_client_for):
        """Homonym case: the credentials decide which account is linked,
        not the name-matched candidate."""
        homonym = UserFactory(first_name="Rui", last_name="Costa")
        real_account = UserFactory(
            email="rui.real@example.pt",
            password="S3cretPass!",
            first_name="Rui Miguel",
            last_name="Costa",
        )

        self._sso_with(mock_client_for, nic="11223344", first_name="Rui", last_name="Costa")

        response = self._confirm_by_password("rui.real@example.pt", "S3cretPass!")
        assert response.status_code == 200

        real_account.reload()
        assert real_account.extras.get("auth_nic") == _hash_nic("11223344")
        homonym.reload()
        assert not (homonym.extras or {}).get("auth_nic")

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_confirm_rejects_account_already_linked_to_another_cmd(self, mock_client_for):
        """An account that already carries a CMD identity cannot be
        re-linked through the wizard."""
        taken = UserFactory(
            email="taken@example.pt",
            password="S3cretPass!",
            first_name="Ana",
            last_name="Lopes",
            extras={"auth_nic": _hash_nic("99990000")},
        )

        self._sso_with(mock_client_for, nic="12121212", first_name="Ana", last_name="Lopes")
        # No candidate (linked accounts are excluded) → wizard came from
        # an ambiguous/new path; force a pending session for the test.
        with self.client.session_transaction() as sess:
            sess["saml_migration_pending"] = {
                "legacy_user_id": None,
                "saml_email": None,
                "saml_nic": "12121212",
                "saml_first_name": "Ana",
                "saml_last_name": "Lopes",
            }

        response = self.client.post(
            "/saml/migration/confirm",
            json={"method": "password", "email": "taken@example.pt", "password": "S3cretPass!"},
        )
        assert response.status_code == 400
        taken.reload()
        assert taken.extras.get("auth_nic") == _hash_nic("99990000")

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_skip_creates_unconfirmed_account_with_submitted_email(self, mock_client_for):
        """'Criar nova conta': the account is created with the email the
        user submitted, left unconfirmed, mailed a confirmation link, and
        given NO session. The candidate account is never touched."""
        from udata.core.user.models import User

        homonym = UserFactory(
            email="rita.old@example.pt",
            password="S3cretPass!",
            first_name="Rita",
            last_name="Gomes",
        )

        self._sso_with(
            mock_client_for,
            email="rita.cmd@example.pt",
            nic="44556677",
            first_name="Rita",
            last_name="Gomes",
        )

        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            # Criterion 8: assert we drive the STOCK Flask-Security
            # confirmable — no new token, template or mechanism. Counting
            # mails cannot show this: under test SEND_MAIL is False, so
            # security mails go through NoopMailUtil and never reach the
            # mail_sent signal that capture_mails listens on.
            with patch(
                "udata.auth.saml.saml_plugin.saml_govpt.send_confirmation_instructions"
            ) as mock_confirm:
                response = self.client.post(
                    "/saml/migration/skip",
                    json={"email": "rita.chosen@example.pt"},
                )
            # Criterion 10: no session is started by this endpoint.
            assert mock_login.call_count == 0

        assert response.status_code == 200
        assert response.json == {"success": True, "email": "rita.chosen@example.pt"}

        new_user = User.objects(email="rita.chosen@example.pt").first()
        assert mock_confirm.call_count == 1
        assert mock_confirm.call_args[0][0].id == new_user.id
        assert new_user is not None
        assert new_user.extras.get("auth_nic") == _hash_nic("44556677")
        # Criterion 9: unconfirmed until the owner follows the link.
        assert new_user.confirmed_at is None
        assert new_user.extras.get("pending_email_confirmation") is True
        homonym.reload()
        assert not (homonym.extras or {}).get("auth_nic")

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_skip_rejects_missing_invalid_and_taken_emails(self, mock_client_for):
        """Criterion 5: each rejection is distinguishable and leaves the
        pending migration intact, so the user can correct and resubmit."""
        from udata.core.user.models import User

        UserFactory(
            email="taken@example.pt",
            password="S3cretPass!",
            first_name="Rita",
            last_name="Gomes",
        )
        self._sso_with(
            mock_client_for,
            email="rita.cmd@example.pt",
            nic="44556677",
            first_name="Rita",
            last_name="Gomes",
        )
        users_before = User.objects.count()

        for payload, status, error in (
            ({}, 400, "email_required"),
            ({"email": "   "}, 400, "email_required"),
            ({"email": "not-an-email"}, 400, "invalid_email"),
            ({"email": "taken@example.pt"}, 409, "email_taken"),
        ):
            response = self.client.post("/saml/migration/skip", json=payload)
            assert response.status_code == status, payload
            assert response.json["error"] == error, payload
            # The wizard session survives, and nothing was created.
            with self.client.session_transaction() as sess:
                assert sess.get("saml_migration_pending") is not None
            assert User.objects.count() == users_before

        # Correcting the address still works after the rejections.
        response = self.client.post("/saml/migration/skip", json={"email": "rita.fixed@example.pt"})
        assert response.status_code == 200
        assert User.objects(email="rita.fixed@example.pt").first() is not None

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_pending_exposes_candidate_account_details(self, mock_client_for):
        """The wizard can show 'Identificámos uma conta com o seu nome'
        with the candidate's masked email."""
        UserFactory(
            email="pedro@example.pt",
            password="S3cretPass!",
            first_name="Pedro",
            last_name="Almeida",
        )

        self._sso_with(mock_client_for, nic="55667788", first_name="Pedro", last_name="Almeida")

        response = self.client.get("/saml/migration/pending")
        assert response.status_code == 200
        data = response.json
        assert data["pending"] is True
        assert data["candidate"] is True
        assert data["has_email"] is False  # CMD brought no email
        assert data["first_name"] == "Pedro"
        assert data["email"] == "p***@example.pt"  # candidate account email, masked

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_pending_exposes_suggested_email(self, mock_client_for):
        """The account-creation step pre-fills the CMD email, but only when
        no account holds it — offering a taken address would guarantee a
        rejection. no_match stays false here: these identities matched a
        homonym, so they are not the 'no account at all' case."""
        UserFactory(
            email="marta@example.pt",
            password="S3cretPass!",
            first_name="Marta",
            last_name="Bento",
        )

        # CMD carries an email no account holds -> offered as a suggestion.
        self._sso_with(
            mock_client_for,
            email="marta.cmd@example.pt",
            nic="66778899",
            first_name="Marta",
            last_name="Bento",
        )
        data = self.client.get("/saml/migration/pending").json
        assert data["suggested_email"] == "marta.cmd@example.pt"
        assert data["no_match"] is False

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_pending_omits_suggested_email_when_already_taken(self, mock_client_for):
        """An email that already belongs to an account is never suggested."""
        UserFactory(
            email="sofia@example.pt",
            password="S3cretPass!",
            first_name="Sofia",
            last_name="Cardoso",
        )

        # The CMD email is the candidate account's own address: match by
        # email, and nothing to suggest.
        self._sso_with(
            mock_client_for,
            email="sofia@example.pt",
            nic="77889900",
            first_name="Sofia",
            last_name="Cardoso",
        )
        data = self.client.get("/saml/migration/pending").json
        assert data["candidate"] is True
        assert data["suggested_email"] is None
        assert data["no_match"] is False

    @patch("udata.auth.saml.saml_plugin.saml_govpt.requires_confirmation", return_value=False)
    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_new_account_redirect_informs_user(self, mock_client_for, mock_requires_conf):
        """Scenario 4 (direct): with the wizard disabled, no match at all
        still creates the account outright and the redirect carries
        cmd_new_account=1 so the frontend can inform the user. With the
        wizard enabled this population goes through it instead."""
        self.app.config["MIGRATION_MODE_ENABLED"] = False
        response = self._sso_with(
            mock_client_for,
            email="novo@example.pt",
            nic="13131313",
            first_name="Bruno",
            last_name="Novo",
        )
        assert response.status_code == 302
        assert "cmd_new_account=1" in response.headers["Location"]

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_email_match_links_only_after_password_confirmation(self, mock_client_for):
        """E2E for the email-match case: redirect to the wizard with the
        account as candidate, then linking happens only after the full
        default login — password and account data preserved."""
        from udata.core.user.models import User

        existing = UserFactory(
            email="default@example.pt",
            password="S3cretPass!",
            first_name="Ana",
            last_name="Pereira",
            confirmed_at=datetime(2024, 1, 1),
        )
        original_password_hash = existing.password
        users_before = User.objects.count()

        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            response = self._sso_with(
                mock_client_for,
                email="default@example.pt",
                nic="12121212",
                first_name="Ana",
                last_name="Pereira",
            )
            assert mock_login.call_count == 0

        assert response.status_code == 302
        assert "/migrate-account" in response.headers["Location"]

        with self.client.session_transaction() as sess:
            pending = sess.get("saml_migration_pending")
            assert pending["legacy_user_id"] == str(existing.id)

        existing.reload()
        assert not (existing.extras or {}).get("auth_nic")

        # Account identified by the default login, then linked by the click.
        response = self._confirm_by_password("default@example.pt", "S3cretPass!")
        assert response.status_code == 200

        assert User.objects.count() == users_before
        existing.reload()
        assert existing.extras.get("auth_nic") == _hash_nic("12121212")
        assert existing.password == original_password_hash

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_skip_after_email_match_never_mints_a_placeholder(self, mock_client_for):
        """When the CMD email is already taken by the matched account and the
        user chooses 'create new account', they must supply a different
        address. Criterion 6: this flow never mints a saml-* placeholder."""
        from udata.core.user.models import User

        existing = UserFactory(
            email="default@example.pt",
            password="S3cretPass!",
            first_name="Ana",
            last_name="Pereira",
        )

        self._sso_with(
            mock_client_for,
            email="default@example.pt",
            nic="12121212",
            first_name="Ana",
            last_name="Pereira",
        )

        # Reusing the taken CMD address is refused, not silently worked
        # around with a placeholder as it was before.
        response = self.client.post("/saml/migration/skip", json={"email": "default@example.pt"})
        assert response.status_code == 409
        assert response.json["error"] == "email_taken"

        response = self.client.post("/saml/migration/skip", json={"email": "ana.nova@example.pt"})
        assert response.status_code == 200

        new_user = User.objects(extras__auth_nic=_hash_nic("12121212")).first()
        assert new_user is not None
        assert new_user.id != existing.id
        assert new_user.email == "ana.nova@example.pt"
        assert not _SAML_PLACEHOLDER_EMAIL_RE.match(new_user.email)
        assert new_user.confirmed_at is None

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_repeat_cmd_login_with_pending_confirmation_does_not_login(self, mock_client_for):
        """Criterion 11: the account created by the wizard already carries the
        NIC, so a repeat CMD login resolves straight to it. It must not be
        auto-confirmed nor logged in — otherwise the confirmation requirement
        is just a 'try again'."""
        from udata.core.user.models import User

        UserFactory(
            email="tiago.old@example.pt",
            password="S3cretPass!",
            first_name="Tiago",
            last_name="Nunes",
        )
        self._sso_with(
            mock_client_for,
            email="tiago.cmd@example.pt",
            nic="31313131",
            first_name="Tiago",
            last_name="Nunes",
        )
        self.client.post("/saml/migration/skip", json={"email": "tiago.novo@example.pt"})
        created = User.objects(email="tiago.novo@example.pt").first()
        assert created.confirmed_at is None

        # Same identity comes back through the IdP.
        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            response = self._sso_with(
                mock_client_for,
                email="tiago.cmd@example.pt",
                nic="31313131",
                first_name="Tiago",
                last_name="Nunes",
            )
            assert mock_login.call_count == 0

        assert response.status_code == 302
        assert "/migrate-account" in response.headers["Location"]
        created.reload()
        assert created.confirmed_at is None

        data = self.client.get("/saml/migration/pending").json
        assert data["pending"] is False
        assert data["awaiting_confirmation"] is True
        assert data["email"] == "t***@example.pt"

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_resend_confirmation_requires_pending_session_and_rate_limits(self, mock_client_for):
        """Criterion 15: the resend works without an authenticated session —
        the pending-confirmation key identifies the user — but only for the
        account's own address, and no more than three times per session."""
        from udata.core.user.models import User

        # No pending confirmation in session: refused, not an open relay.
        response = self.client.post("/saml/migration/resend-confirmation")
        assert response.status_code == 400

        UserFactory(
            email="ines.old@example.pt",
            password="S3cretPass!",
            first_name="Ines",
            last_name="Duarte",
        )
        self._sso_with(
            mock_client_for,
            email="ines.cmd@example.pt",
            nic="33333333",
            first_name="Ines",
            last_name="Duarte",
        )
        self.client.post("/saml/migration/skip", json={"email": "ines.nova@example.pt"})
        created = User.objects(email="ines.nova@example.pt").first()

        with patch(
            "udata.auth.saml.saml_plugin.saml_govpt.send_confirmation_instructions"
        ) as mock_confirm:
            # The mail sent when the account was created already counts as one
            # of the five, so four resends remain.
            for _ in range(4):
                response = self.client.post("/saml/migration/resend-confirmation")
                assert response.status_code == 200
                assert response.json == {"sent": True}

            # The next resend would be the sixth mail overall: refused.
            response = self.client.post("/saml/migration/resend-confirmation")
            assert response.status_code == 429

        assert mock_confirm.call_count == 4
        # Always the account's own address — never an arbitrary one.
        for call in mock_confirm.call_args_list:
            assert call[0][0].id == created.id

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_skip_rejects_a_taken_email_whatever_its_casing(self, mock_client_for):
        """The unique index on User.email is case-sensitive, but every login and
        recovery lookup is case-INSENSITIVE. An exact-match check here would
        accept MARIA@ alongside an existing maria@, and the victim's own login
        would then resolve to the newer password-less row — locking them out of
        both login and recovery, permanently."""
        from udata.core.user.models import User

        victim = UserFactory(
            email="maria@example.pt",
            password="S3cretPass!",
            first_name="Maria",
            last_name="Sousa",
        )
        self._sso_with(
            mock_client_for,
            email="atacante.cmd@example.pt",
            nic="37373737",
            first_name="Maria",
            last_name="Sousa",
        )
        users_before = User.objects.count()

        response = self.client.post("/saml/migration/skip", json={"email": "MARIA@example.pt"})
        assert response.status_code == 409
        assert response.json["error"] == "email_taken"
        assert User.objects.count() == users_before
        # Exactly one account still answers to that address.
        assert User.objects(email__iexact="maria@example.pt").count() == 1
        assert User.objects(email__iexact="maria@example.pt").first().id == victim.id

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_skip_with_own_legacy_email_points_the_candidate(self, mock_client_for):
        """The dead end this ticket exists for. A CMD whose email and name both
        miss lands on the account-creation step; the address the person then
        types is their own portal account. Refusing it sends them back to retype
        an address the server has already resolved. Point the candidate instead
        — still linking nothing, still 409, ownership still unproven."""
        from udata.core.user.models import User

        existing = UserFactory(
            email="teresa@example.pt",
            password="S3cretPass!",
            first_name="Teresa",
            last_name="Matos",
        )

        self._sso_with(
            mock_client_for,
            email="teresa.matos@servico.gov.pt",
            nic="53535353",
            first_name="Teresa Alexandra",
            last_name="Matos Ribeiro",
        )
        with self.client.session_transaction() as sess:
            assert sess["saml_migration_pending"]["no_match"] is True
            assert sess["saml_migration_pending"]["legacy_user_id"] is None
        users_before = User.objects.count()

        # Typed in a different casing, which only resolves because the search
        # lookup is case-insensitive.
        response = self.client.post("/saml/migration/skip", json={"email": "Teresa@Example.pt"})
        assert response.status_code == 409
        assert response.json["error"] == "email_taken"
        assert response.json["candidate_found"] is True
        assert response.json["email"] == "t***@example.pt"

        # Nothing was created and nothing was linked: this only points.
        assert User.objects.count() == users_before
        existing.reload()
        assert not (existing.extras or {}).get("auth_nic")

        with self.client.session_transaction() as sess:
            pending = sess.get("saml_migration_pending")
            # The wizard did not end — it moved to the linking branch.
            assert pending is not None
            assert pending["legacy_user_id"] == str(existing.id)

        # And the linking branch now works from here.
        assert self.client.get("/saml/migration/pending").json["candidate"] is True

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_link_via_skip_divert_keeps_ownership_proof_and_next_login_is_direct(
        self, mock_client_for
    ):
        """The whole path the divert opens, end to end: no_match -> own address
        on the creation step -> candidate pointed -> validation link mailed to
        that same account -> clicked -> linked -> the next CMD login walks
        straight in.

        The negative assertion is the point of the test as much as the positive
        one: between the divert and the confirm, nothing is linked. The divert
        is a signpost, not a grant.
        """
        from udata.core.user.models import User

        existing = UserFactory(
            email="joana@example.pt",
            password="S3cretPass!",
            first_name="Joana",
            last_name="Pinto",
        )
        users_before = User.objects.count()

        # 1. CMD brings a different address and a name that does not match.
        response = self._sso_with(
            mock_client_for,
            email="joana.pinto@servico.gov.pt",
            nic="55555555",
            first_name="Joana Cristina",
            last_name="Pinto Azevedo",
        )
        assert "/migrate-account" in response.headers["Location"]
        assert self.client.get("/saml/migration/pending").json["no_match"] is True

        # 2. On the creation step the user types their own portal address.
        response = self.client.post("/saml/migration/skip", json={"email": "joana@example.pt"})
        assert response.status_code == 409
        assert response.json["candidate_found"] is True

        # Still nothing linked, and nothing created.
        existing.reload()
        assert not (existing.extras or {}).get("auth_nic")
        assert User.objects.count() == users_before

        # 3. The link goes to the candidate account's own address — the one
        #    thing that makes this a proof of ownership rather than a claim.
        with patch("udata.auth.saml.saml_plugin.saml_govpt.send_mail") as mock_send:
            response = self.client.post("/saml/migration/send-link")
            assert response.status_code == 200
        assert mock_send.call_args[0][0].id == existing.id
        assert mock_send.call_args[0][0].email == "joana@example.pt"
        ctas = [p for p in mock_send.call_args[0][1].paragraphs if getattr(p, "link", None)]
        token = ctas[0].link.rsplit("/", 1)[1]

        # Ownership is still unproven right up to the click.
        existing.reload()
        assert not (existing.extras or {}).get("auth_nic")

        # 4. Clicking it links the identity to the existing account.
        response = self.client.get(f"/saml/migration/confirm-link/{token}")
        assert response.status_code == 302
        assert "flash=" not in response.headers["Location"]

        assert User.objects.count() == users_before
        existing.reload()
        assert existing.extras.get("auth_nic") == _hash_nic("55555555")

        # 5. The next CMD login resolves by NIC and skips the wizard entirely.
        self.client.get("/logout", follow_redirects=False)
        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            response = self._sso_with(
                mock_client_for,
                email="joana.pinto@servico.gov.pt",
                nic="55555555",
                first_name="Joana Cristina",
                last_name="Pinto Azevedo",
            )
            assert mock_login.call_count == 1
            assert mock_login.call_args[0][0].id == existing.id
        assert response.status_code == 302
        assert "/migrate-account" not in response.headers["Location"]

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_pending_does_not_suggest_an_address_taken_in_another_casing(self, mock_client_for):
        """suggested_email exists so the creation step is never pre-filled with
        an address that would only produce a guaranteed rejection. Checking it
        exactly missed the case the skip's own uniqueness check catches: with
        the CMD carrying Rui@Example.pt and the account at rui@example.pt, the
        wizard offered the address and the submit then bounced it."""
        UserFactory(
            email="rui@example.pt",
            password="S3cretPass!",
            first_name="Rui",
            last_name="Tavares",
        )

        # The name deliberately misses, so the identity reaches the creation
        # step rather than being offered the account as a candidate.
        self._sso_with(
            mock_client_for,
            email="Rui@Example.pt",
            nic="60606060",
            first_name="Rui Alexandre",
            last_name="Tavares Pinho",
        )

        data = self.client.get("/saml/migration/pending").json
        assert data["suggested_email"] is None
        assert data["has_email"] is True

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_search_refuses_a_query_operator_instead_of_answering_it(self, mock_client_for):
        """A JSON body can carry a dict, and a dict reaching a MongoEngine
        query turns a field lookup into an operator lookup: {"$regex": "^adm"}
        made `found` a per-character oracle over every registered address, and
        handed back the domain plus the first character of the match."""
        UserFactory(
            email="admin.geral@example.pt",
            password="S3cretPass!",
            first_name="Admin",
            last_name="Geral",
        )

        self._sso_with(
            mock_client_for,
            email="tiago.cmd@servico.gov.pt",
            nic="59595959",
            first_name="Tiago Manuel",
            last_name="Brito Faria",
        )

        for payload in (
            {"email": {"$regex": "^adm"}},
            {"email": {"$gt": ""}},
            {"first_name": {"$ne": None}, "last_name": {"$ne": None}},
        ):
            response = self.client.post("/saml/migration/search", json=payload)
            # Answered, not crashed, and nothing disclosed.
            assert response.status_code == 200, payload
            assert response.json["found"] is False, payload
            assert "email" not in response.json, payload
            with self.client.session_transaction() as sess:
                assert sess["saml_migration_pending"]["legacy_user_id"] is None

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_case_insensitive_lookups_prefer_the_exactly_matching_row(self, mock_client_for):
        """The unique index on User.email is case-sensitive, so a shadow row
        differing only in case can exist — the email-change form and
        _create_saml_user both still check exact. User orders by -created_at,
        so a bare __iexact lookup hands back whichever row is NEWER. That would
        point the wizard at the shadow and link the CMD to an empty account,
        orphaning the real one. Where two rows answer to one address, the row
        that matches exactly is the one the caller meant.
        """
        from udata.core.user.models import User

        real = UserFactory(
            email="sara@example.pt",
            password="S3cretPass!",
            first_name="Sara",
            last_name="Nunes",
        )
        shadow = UserFactory(
            email="SARA@example.pt",
            password="0therPass!",
            first_name="Shadow",
            last_name="Row",
        )
        # Both rows really do coexist, and the shadow is the newer one.
        assert User.objects(email__iexact="sara@example.pt").count() == 2
        assert User.objects(email__iexact="sara@example.pt").first().id == shadow.id

        self._sso_with(
            mock_client_for,
            email="joao.cmd@servico.gov.pt",
            nic="56565656",
            first_name="Joao Carlos",
            last_name="Mendes Rocha",
        )

        # The search resolves the row the user typed, not the newest one.
        response = self.client.post("/saml/migration/search", json={"email": "sara@example.pt"})
        assert response.status_code == 200
        assert response.json["found"] is True
        with self.client.session_transaction() as sess:
            assert sess["saml_migration_pending"]["legacy_user_id"] == str(real.id)

        # And the ownership proof accepts the real account's own password,
        # which is the path the shadow would otherwise have blocked.
        response = self._confirm_by_password("sara@example.pt", "S3cretPass!")
        assert response.status_code == 200
        real.reload()
        assert real.extras.get("auth_nic") == _hash_nic("56565656")
        shadow.reload()
        assert not (shadow.extras or {}).get("auth_nic")

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_skip_divert_does_not_fire_for_an_identity_that_already_has_an_account(
        self, mock_client_for
    ):
        """The `not linked` guard. The Flask session is a client-held signed
        cookie, so a copy taken before the first skip can be replayed with the
        pending state intact. Pointing a candidate then would let one identity
        end up claiming a second account, so the divert stays off and the plain
        refusal stands."""
        from udata.core.user.models import User

        legacy = UserFactory(
            email="vera@example.pt",
            password="S3cretPass!",
            first_name="Vera",
            last_name="Antunes",
        )

        self._sso_with(
            mock_client_for,
            email="bruno.cmd@servico.gov.pt",
            nic="57575757",
            first_name="Bruno Filipe",
            last_name="Costa Neves",
        )
        # Keep the pending state as it was before the first skip consumed it.
        with self.client.session_transaction() as sess:
            replayed = dict(sess["saml_migration_pending"])

        response = self.client.post("/saml/migration/skip", json={"email": "bruno@example.pt"})
        assert response.status_code == 200
        created = User.objects(extras__auth_nic=_hash_nic("57575757")).first()
        assert created is not None

        # Replay, then aim at a perfectly linkable legacy account.
        with self.client.session_transaction() as sess:
            sess["saml_migration_pending"] = replayed

        response = self.client.post("/saml/migration/skip", json={"email": "vera@example.pt"})
        assert response.status_code == 409
        assert response.json["error"] == "email_taken"
        assert "candidate_found" not in response.json
        with self.client.session_transaction() as sess:
            assert sess["saml_migration_pending"]["legacy_user_id"] is None
        legacy.reload()
        assert not (legacy.extras or {}).get("auth_nic")

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_skip_divert_invalidates_a_link_issued_for_the_previous_target(self, mock_client_for):
        """The same target-confusion hole the search endpoint had, reached
        through the skip instead. A validation link emailed for candidate A
        must not still work once the divert has re-pointed the session at B."""
        first = UserFactory(
            email="alice@example.pt",
            password="S3cretPass!",
            first_name="Alice",
            last_name="Ramos",
        )
        second = UserFactory(
            email="bianca@example.pt",
            password="S3cretPass!",
            first_name="Bianca",
            last_name="Sousa",
        )

        self._sso_with(
            mock_client_for,
            email="carla.cmd@servico.gov.pt",
            nic="58585858",
            first_name="Carla Sofia",
            last_name="Lopes Dias",
        )

        # Point A and get a link issued for it.
        response = self.client.post("/saml/migration/search", json={"email": first.email})
        assert response.json["found"] is True
        with patch("udata.auth.saml.saml_plugin.saml_govpt.send_mail") as mock_send:
            assert self.client.post("/saml/migration/send-link").status_code == 200
        ctas = [p for p in mock_send.call_args[0][1].paragraphs if getattr(p, "link", None)]
        token = ctas[0].link.rsplit("/", 1)[1]

        # Now the divert re-points at B.
        response = self.client.post("/saml/migration/skip", json={"email": second.email})
        assert response.status_code == 409
        assert response.json["candidate_found"] is True

        # The record backing the old link is destroyed, not merely mismatched.
        from udata.auth.saml.saml_plugin.saml_govpt import MIGRATION_LINK_PENDING

        first.reload()
        assert MIGRATION_LINK_PENDING not in (first.extras or {})

        response = self.client.get(f"/saml/migration/confirm-link/{token}")
        assert "flash=migration_link_invalid" in response.headers["Location"]
        for account in (first, second):
            account.reload()
            assert not (account.extras or {}).get("auth_nic")

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_skip_still_refuses_emails_of_non_candidate_accounts(self, mock_client_for):
        """The divert must not become a way in. It fires only where
        _find_legacy_user returns an account, so an address held by one this
        identity cannot claim is still refused — and refused *without*
        candidate_found, which is what tells the wizard to say so rather than
        offer a confirmation screen.

        The 'deleted' case is asserted defensively, not as a scenario from
        production: User.mark_as_deleted rewrites the address to <id>@deleted
        and clears password and extras, so the original email is free again and
        the skip creates a new account instead of reaching this branch.
        """
        from udata.core.user.models import User

        # Already linked to a different CMD identity: linking it would
        # overwrite that link and lock the other person out of CMD login.
        other_cmd = UserFactory(
            email="ines@example.pt",
            password="S3cretPass!",
            first_name="Ines",
            last_name="Duarte",
            extras={"auth_nic": _hash_nic("99999999")},
        )
        # No password: not a legacy account with portal credentials to
        # migrate. The argument is omitted, not passed as None — the factory
        # hashes whatever it is given, and hash_password(None) yields a
        # perfectly truthy hash.
        no_password = UserFactory(
            email="rita@example.pt",
            first_name="Rita",
            last_name="Gomes",
        )
        deleted = UserFactory(
            email="hugo@example.pt",
            password="S3cretPass!",
            first_name="Hugo",
            last_name="Silva",
            deleted=datetime(2025, 1, 1),
        )

        self._sso_with(
            mock_client_for,
            email="nuno.cmd@servico.gov.pt",
            nic="54545454",
            first_name="Nuno Miguel",
            last_name="Ferreira Lopes",
        )
        with self.client.session_transaction() as sess:
            assert sess["saml_migration_pending"]["legacy_user_id"] is None
        users_before = User.objects.count()

        for account in (other_cmd, no_password, deleted):
            response = self.client.post("/saml/migration/skip", json={"email": account.email})
            assert response.status_code == 409, account.email
            assert response.json["error"] == "email_taken", account.email
            assert "candidate_found" not in response.json, account.email

            # No account created, and no candidate pointed to confirm against.
            assert User.objects.count() == users_before, account.email
            with self.client.session_transaction() as sess:
                assert sess["saml_migration_pending"]["legacy_user_id"] is None

        # The other person's CMD link is untouched.
        other_cmd.reload()
        assert other_cmd.extras.get("auth_nic") == _hash_nic("99999999")

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_email_match_is_case_insensitive_for_the_wizard_candidate(self, mock_client_for):
        """Rule 2 is what decides migration_candidate. Exact-matching there sent
        the owner of maria@ whose CMD carries Maria@ down the no_match branch —
        asked to create an account they already have. The name deliberately does
        not match, so only the email rule can produce the candidate."""
        existing = UserFactory(
            email="beatriz@example.pt",
            password="S3cretPass!",
            first_name="Beatriz",
            last_name="Lima",
        )

        self._sso_with(
            mock_client_for,
            email="Beatriz@Example.pt",
            nic="51515151",
            first_name="Beatriz Maria",
            last_name="Lima Correia",
        )

        data = self.client.get("/saml/migration/pending").json
        assert data["candidate"] is True
        assert data["no_match"] is False
        assert data["email"] == "b***@example.pt"

        with self.client.session_transaction() as sess:
            assert sess["saml_migration_pending"]["legacy_user_id"] == str(existing.id)

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_confirm_with_password_accepts_a_differently_cased_email(self, mock_client_for):
        """This branch stands in for the login form, which is case-insensitive.
        Exact-matching failed the ownership proof for a *correct* password, and
        the deliberately generic error made that indistinguishable from a wrong
        one — a dead end with no way to tell what went wrong."""
        from udata.core.user.models import User

        existing = UserFactory(
            email="claudia@example.pt",
            password="S3cretPass!",
            first_name="Claudia",
            last_name="Faria",
        )
        users_before = User.objects.count()

        self._sso_with(
            mock_client_for,
            email="claudia.cmd@example.pt",
            nic="52525252",
            first_name="Claudia",
            last_name="Faria",
        )

        response = self._confirm_by_password("CLAUDIA@example.pt", "S3cretPass!")
        assert response.status_code == 200
        assert response.json["sent"] is True

        assert User.objects.count() == users_before
        existing.reload()
        assert existing.extras.get("auth_nic") == _hash_nic("52525252")

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_search_finds_the_legacy_account_whatever_the_email_casing(self, mock_client_for):
        """The search lookup was the last exact-match one in the wizard. Login
        and recovery are case-INSENSITIVE, so the owner of maria@ who types
        Maria@ — the one address they are sure of — must still find their own
        account here, not be told none exists."""
        existing = UserFactory(
            email="maria@example.pt",
            password="S3cretPass!",
            first_name="Maria",
            last_name="Sousa",
        )

        # Neither the CMD email nor the CMD name matches the account, so the
        # wizard opens with no candidate pointed at all.
        self._sso_with(
            mock_client_for,
            email="maria.sousa@servico.gov.pt",
            nic="48484848",
            first_name="Maria Isabel",
            last_name="Sousa Pereira",
        )
        with self.client.session_transaction() as sess:
            assert sess["saml_migration_pending"]["legacy_user_id"] is None

        response = self.client.post("/saml/migration/search", json={"email": "MARIA@example.pt"})
        assert response.status_code == 200
        assert response.json["found"] is True
        assert response.json["email"] == "m***@example.pt"

        with self.client.session_transaction() as sess:
            assert sess["saml_migration_pending"]["legacy_user_id"] == str(existing.id)

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_skip_stores_the_normalised_address(self, mock_client_for):
        """The stored address is the normalised one, as on the registration
        path — not the raw string, whose casing would otherwise decide which of
        two rows the case-sensitive unique index accepts."""
        from udata.core.user.models import User

        UserFactory(
            email="rui.old@example.pt",
            password="S3cretPass!",
            first_name="Rui",
            last_name="Pinto",
        )
        self._sso_with(
            mock_client_for,
            email="rui.cmd@example.pt",
            nic="38383838",
            first_name="Rui",
            last_name="Pinto",
        )

        response = self.client.post(
            "/saml/migration/skip", json={"email": "  Rui.Novo@Example.PT  "}
        )
        assert response.status_code == 200
        created = User.objects(extras__auth_nic=_hash_nic("38383838")).first()
        assert created.email == "Rui.Novo@example.pt"  # domain lowercased, local part kept
        assert response.json["email"] == created.email

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_skip_refuses_a_second_account_for_the_same_identity(self, mock_client_for):
        """The Flask session is a client-held signed cookie, so a caller can
        replay a copy taken before the first skip and re-enter with the pending
        state intact — the session pops only rewrite a response cookie they are
        free to discard. Without a server-side check that replay mints an
        unbounded number of accounts against one NIC, each mailing a
        confirmation to an address the caller chooses."""
        from udata.core.user.models import User

        UserFactory(
            email="vera.old@example.pt",
            password="S3cretPass!",
            first_name="Vera",
            last_name="Lima",
        )
        self._sso_with(
            mock_client_for,
            email="vera.cmd@example.pt",
            nic="35353535",
            first_name="Vera",
            last_name="Lima",
        )

        # Capture the wizard cookie, exactly as a replaying caller would.
        with self.client.session_transaction() as sess:
            replayed = dict(sess.get("saml_migration_pending"))

        assert (
            self.client.post(
                "/saml/migration/skip", json={"email": "vera.a@example.pt"}
            ).status_code
            == 200
        )
        users_after_first = User.objects.count()

        # Replay: put the pre-skip state back and try another address.
        with self.client.session_transaction() as sess:
            sess["saml_migration_pending"] = replayed

        response = self.client.post("/saml/migration/skip", json={"email": "vera.b@example.pt"})
        assert response.status_code == 200
        # No second account: the pending one had its address corrected, which
        # is what keeps a typo (or an SMTP failure mid-request) from bricking
        # the identity for good.
        assert User.objects.count() == users_after_first
        assert User.objects(email="vera.a@example.pt").first() is None
        corrected = User.objects(email="vera.b@example.pt").first()
        assert corrected is not None
        assert corrected.extras["auth_nic"] == _hash_nic("35353535")
        # The tally is monotonic, so correcting does not buy more mail.
        assert corrected.extras["confirmation_send_count"] == 2

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_resend_confirmation_cap_survives_a_replayed_session(self, mock_client_for):
        """The cap is counted on the account, not in the session: the recipient
        was chosen by whoever ran the wizard, so a session-only counter would be
        reset by replaying an older cookie and the endpoint could mail an
        arbitrary victim without limit."""
        from udata.core.user.models import User

        UserFactory(
            email="nuno.old@example.pt",
            password="S3cretPass!",
            first_name="Nuno",
            last_name="Faria",
        )
        self._sso_with(
            mock_client_for,
            email="nuno.cmd@example.pt",
            nic="36363636",
            first_name="Nuno",
            last_name="Faria",
        )
        self.client.post("/saml/migration/skip", json={"email": "nuno.novo@example.pt"})
        created = User.objects(email="nuno.novo@example.pt").first()

        with self.client.session_transaction() as sess:
            pristine = dict(sess.get("saml_confirmation_pending"))

        with patch("udata.auth.saml.saml_plugin.saml_govpt.send_confirmation_instructions"):
            # The creation mail already counts as one, so four more are allowed.
            for _ in range(4):
                assert self.client.post("/saml/migration/resend-confirmation").status_code == 200

            # Replaying a session captured before any resend must not reset it.
            for _ in range(3):
                with self.client.session_transaction() as sess:
                    sess["saml_confirmation_pending"] = pristine
                    sess.pop("migration_confirmation_send_count", None)
                response = self.client.post("/saml/migration/resend-confirmation")
                assert response.status_code == 429, response.json

        created.reload()
        assert created.extras["confirmation_send_count"] == 5

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_resend_confirmation_reports_an_already_confirmed_account(self, mock_client_for):
        """Nothing to resend once the link was followed — say so, so the
        frontend can point the user at the login instead of a new mail."""
        from udata.core.user.models import User

        UserFactory(
            email="hugo.old@example.pt",
            password="S3cretPass!",
            first_name="Hugo",
            last_name="Reis",
        )
        self._sso_with(
            mock_client_for,
            email="hugo.cmd@example.pt",
            nic="34343434",
            first_name="Hugo",
            last_name="Reis",
        )
        self.client.post("/saml/migration/skip", json={"email": "hugo.novo@example.pt"})

        created = User.objects(email="hugo.novo@example.pt").first()
        created.confirmed_at = datetime.utcnow()
        created.save()

        response = self.client.post("/saml/migration/resend-confirmation")
        assert response.status_code == 200
        assert response.json == {"sent": False, "confirmed": True}

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_cmd_login_after_confirmation_enters_directly(self, mock_client_for):
        """Criteria 12/13: once the link is followed, confirmed_at is set, the
        gate stops matching and the NIC takes the user straight in — no
        second trip through the wizard."""
        from udata.core.user.models import User

        UserFactory(
            email="clara.old@example.pt",
            password="S3cretPass!",
            first_name="Clara",
            last_name="Matos",
        )
        self._sso_with(
            mock_client_for,
            email="clara.cmd@example.pt",
            nic="32323232",
            first_name="Clara",
            last_name="Matos",
        )
        self.client.post("/saml/migration/skip", json={"email": "clara.nova@example.pt"})

        # Stand in for the user following the emailed confirmation link.
        created = User.objects(email="clara.nova@example.pt").first()
        created.confirmed_at = datetime.utcnow()
        created.save()

        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            response = self._sso_with(
                mock_client_for,
                email="clara.cmd@example.pt",
                nic="32323232",
                first_name="Clara",
                last_name="Matos",
            )
            assert mock_login.call_count == 1
            assert mock_login.call_args[0][0].id == created.id

        assert response.status_code == 302
        assert "/migrate-account" not in response.headers["Location"]

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_skip_refuses_an_identity_without_a_nic(self, mock_client_for):
        """An account with no auth_nic would not be excluded by
        _has_linked_nic, so on the next CMD login it would match itself as a
        wizard candidate — letting the user mail a code to the very address
        awaiting confirmation and log in without ever following the link.
        Those identities belong in the search branch."""
        from udata.core.user.models import User

        UserFactory(
            email="bruno@example.pt",
            password="S3cretPass!",
            first_name="Bruno",
            last_name="Silva",
        )
        self._sso_with(
            mock_client_for,
            email="bruno@example.pt",
            first_name="Bruno",
            last_name="Silva",
        )
        users_before = User.objects.count()

        response = self.client.post("/saml/migration/skip", json={"email": "bruno.novo@example.pt"})
        assert response.status_code == 400
        assert response.json["error"] == "nic_required"
        assert User.objects.count() == users_before

    @patch("udata.auth.saml.saml_plugin.saml_govpt.requires_confirmation", return_value=False)
    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_migration_disabled_falls_back_to_new_account(
        self, mock_client_for, mock_requires_conf
    ):
        """With MIGRATION_MODE_ENABLED off, a name-only match never logs
        into the candidate account — a new one is created instead."""
        from udata.core.user.models import User

        self.app.config["MIGRATION_MODE_ENABLED"] = False
        try:
            existing = UserFactory(
                email="pedro@example.pt",
                password="S3cretPass!",
                first_name="Pedro",
                last_name="Almeida",
            )
            users_before = User.objects.count()

            with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
                response = self._sso_with(
                    mock_client_for,
                    nic="55667788",
                    first_name="Pedro",
                    last_name="Almeida",
                )
                assert mock_login.call_count == 1
                logged_in_user = mock_login.call_args[0][0]
                assert logged_in_user.id != existing.id

            assert response.status_code == 302
            # The CMD brought no email, so the new account got a placeholder:
            # the user is sent to complete registration instead of the
            # cmd_new_account homepage banner.
            assert response.headers["Location"].endswith("/complete-registration")
            assert User.objects.count() == users_before + 1
            existing.reload()
            assert not (existing.extras or {}).get("auth_nic")
        finally:
            self.app.config["MIGRATION_MODE_ENABLED"] = True

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_send_link_mails_the_account_own_address_and_grants_no_session(self, mock_client_for):
        """LEDG-2357: the validation link goes to the address already on the
        legacy account, and sending it leaves the caller unauthenticated —
        the click is what grants the session."""
        from udata.auth.saml.saml_plugin.saml_govpt import MIGRATION_LINK_PENDING
        from udata.core.user.models import User

        legacy = UserFactory(
            email="rita.old@example.pt",
            password="S3cretPass!",
            first_name="Rita",
            last_name="Nunes",
        )

        self._sso_with(
            mock_client_for,
            nic="91827364",
            first_name="Rita",
            last_name="Nunes",
        )

        with patch("udata.auth.saml.saml_plugin.saml_govpt.send_mail") as mock_send:
            response = self.client.post("/saml/migration/send-link")

        assert response.status_code == 200
        assert response.json == {"sent": True}

        # Recipient is the account's own address, never one from the request.
        assert mock_send.call_count == 1
        assert mock_send.call_args[0][0].id == legacy.id

        # The body names the requesting identity and warns against opening it.
        body = " ".join(str(p) for p in mock_send.call_args[0][1].paragraphs)
        assert "Rita Nunes" in body
        assert "do NOT open the link" in body

        # The pending record landed on the account, and carries no cleartext NIC.
        legacy.reload()
        record = (legacy.extras or {})[MIGRATION_LINK_PENDING]
        assert record["nonce"]
        assert record["nic_hash"] != "91827364"
        assert "91827364" not in str(record)

        # Nothing is linked yet and there is no session.
        assert not (legacy.extras or {}).get("auth_nic")
        assert self.client.get("/api/1/me/").status_code == 401
        assert User.objects(id=legacy.id).first().confirmed_at is None

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_linking_by_password_supersedes_an_outstanding_validation_link(self, mock_client_for):
        """LEDG-2357 held this invariant by clearing the record: a link
        already in the wild must never stay clickable once a second proof has
        happened, or it would overwrite the identity that proof bound.

        The password branch no longer binds anything, so it no longer clears
        — it mints a fresh nonce over the same record, and that is what makes
        the earlier token stop validating. The invariant is the same; only
        the mechanism moved, so this asserts it through the click.
        """
        from udata.auth.saml.saml_plugin.saml_govpt import MIGRATION_LINK_PENDING

        legacy = UserFactory(
            email="nuno.old@example.pt",
            password="S3cretPass!",
            first_name="Nuno",
            last_name="Reis",
        )

        self._sso_with(mock_client_for, nic="65432198", first_name="Nuno", last_name="Reis")

        with patch("udata.auth.saml.saml_plugin.saml_govpt.send_mail") as mock_send:
            assert self.client.post("/saml/migration/send-link").status_code == 200
        first_token = self._mailed_token(mock_send)
        legacy.reload()
        first_nonce = legacy.extras[MIGRATION_LINK_PENDING]["nonce"]

        with patch("udata.auth.saml.saml_plugin.saml_govpt.send_mail") as mock_send:
            response = self.client.post(
                "/saml/migration/confirm",
                json={
                    "method": "password",
                    "email": "nuno.old@example.pt",
                    "password": "S3cretPass!",
                },
            )
            assert response.status_code == 200
            second_token = self._mailed_token(mock_send)

        legacy.reload()
        assert legacy.extras[MIGRATION_LINK_PENDING]["nonce"] != first_nonce
        assert not (legacy.extras or {}).get("auth_nic")

        # The token issued before the proof is dead.
        assert "flash=migration_link_invalid" in self._click(first_token).headers["Location"]
        legacy.reload()
        assert not (legacy.extras or {}).get("auth_nic")

        # Only the one the proof mailed completes the link.
        assert self._click(second_token).status_code == 302
        legacy.reload()
        assert legacy.extras.get("auth_nic") == _hash_nic("65432198")

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_send_link_caps_sends_per_window_without_locking_the_account_out(self, mock_client_for):
        """LEDG-2357: the cap stops a mail flood, but it is a window and not a
        lifetime ceiling — otherwise five anonymous requests would deny the
        owner the email route for good."""
        from udata.auth.saml.saml_plugin.saml_govpt import (
            MIGRATION_LINK_SEND_COUNT,
            MIGRATION_LINK_SEND_WINDOW,
        )

        legacy = UserFactory(
            email="hugo.old@example.pt",
            password="S3cretPass!",
            first_name="Hugo",
            last_name="Matos",
        )

        self._sso_with(mock_client_for, nic="19283746", first_name="Hugo", last_name="Matos")

        with patch("udata.auth.saml.saml_plugin.saml_govpt.send_mail"):
            for _i in range(5):
                assert self.client.post("/saml/migration/send-link").status_code == 200

            response = self.client.post("/saml/migration/send-link")
            assert response.status_code == 429
            assert response.json["error"] == "Maximum confirmation sends exceeded"

            # Roll the window back: the account is usable again, not bricked.
            legacy.reload()
            tally = legacy.extras[MIGRATION_LINK_SEND_COUNT]
            tally["window_start"] = (
                datetime.utcnow() - MIGRATION_LINK_SEND_WINDOW - timedelta(minutes=1)
            ).isoformat()
            legacy.extras[MIGRATION_LINK_SEND_COUNT] = tally
            legacy.save()

            assert self.client.post("/saml/migration/send-link").status_code == 200

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_send_link_refuses_without_a_candidate_or_when_already_linked(self, mock_client_for):
        """LEDG-2357: no candidate pointed, an account already bound to an
        identity, and migration mode off are all refused before any mail."""
        legacy = UserFactory(
            email="ana.old@example.pt",
            password="S3cretPass!",
            first_name="Ana",
            last_name="Ferreira",
        )

        # No pending migration at all.
        assert self.client.post("/saml/migration/send-link").status_code == 400

        # Pending, but SAML brought no email and no name matched: no candidate.
        self._sso_with(mock_client_for, nic="12121212", first_name="Zzz", last_name="Yyy")
        with self.client.session_transaction() as sess:
            assert sess["saml_migration_pending"].get("legacy_user_id") is None
        with patch("udata.auth.saml.saml_plugin.saml_govpt.send_mail") as mock_send:
            assert self.client.post("/saml/migration/send-link").status_code == 400
            assert mock_send.call_count == 0

        # A candidate that already holds a linked identity is refused, so the
        # wizard never mails a link the click would reject.
        legacy.extras = {"auth_nic": _hash_nic("55555555")}
        legacy.save()
        self._sso_with(mock_client_for, nic="23232323", first_name="Ana", last_name="Ferreira")
        with self.client.session_transaction() as sess:
            sess["saml_migration_pending"] = {
                "legacy_user_id": str(legacy.id),
                "saml_nic": "23232323",
                "saml_first_name": "Ana",
                "saml_last_name": "Ferreira",
                "saml_email": None,
            }
        with patch("udata.auth.saml.saml_plugin.saml_govpt.send_mail") as mock_send:
            response = self.client.post("/saml/migration/send-link")
            assert response.status_code == 400
            assert response.json["error"] == "Invalid credentials"
            assert mock_send.call_count == 0

        # Migration mode off: 403, like every sibling endpoint.
        self.app.config["MIGRATION_MODE_ENABLED"] = False
        try:
            assert self.client.post("/saml/migration/send-link").status_code == 403
        finally:
            self.app.config["MIGRATION_MODE_ENABLED"] = True


class SAMLMigrationLinkClickTest(APITestCase):
    """LEDG-2357: consumption of the emailed validation link.

    The click is the ownership proof, so it has to work with no session at
    all — possibly in another browser — and it must be single-use, bound to
    the account and identity it was issued for, and never able to overwrite
    an identity somebody else legitimately linked in the meantime.
    """

    @pytest.fixture(autouse=True)
    def _set_frontend_url(self, app):
        app.config["CDATA_BASE_URL"] = "http://localhost:3000"
        app.config["MIGRATION_MODE_ENABLED"] = True

    def _post_saml_response(self, saml_xml, endpoint="/saml/sso"):
        encoded = base64.b64encode(saml_xml.encode("utf-8")).decode("utf-8")
        return self.client.post(endpoint, data={"SAMLResponse": encoded}, follow_redirects=False)

    def _sso_with(self, mock_client_for, endpoint="/saml/sso", **attrs):
        mock_saml_client = MagicMock()
        mock_saml_client.parse_authn_request_response.return_value = _make_authn_response_mock(
            **attrs
        )
        mock_client_for.return_value = mock_saml_client
        xml_attrs = {
            k: v
            for k, v in attrs.items()
            if k not in ("name_id", "name_id_format", "issuer", "eidas_friendly_names")
        }
        return self._post_saml_response(_build_saml_response_xml(**xml_attrs), endpoint)

    def _issue_link_for(self, mock_client_for, legacy, **attrs):
        """Drive the wizard to the point of holding a validation link, and
        return the token that was emailed."""
        self._sso_with(mock_client_for, **attrs)
        with patch("udata.auth.saml.saml_plugin.saml_govpt.send_mail") as mock_send:
            assert self.client.post("/saml/migration/send-link").status_code == 200
        # The token is what the CTA in the mail points at.
        ctas = [p for p in mock_send.call_args[0][1].paragraphs if getattr(p, "link", None)]
        assert len(ctas) == 1
        return ctas[0].link.rsplit("/", 1)[1]

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_click_links_the_account_and_starts_a_session_without_one(self, mock_client_for):
        """Criteria 2 and 3: 401 before the click, and the click alone links
        the NIC and authenticates — in a client that never saw the wizard."""
        legacy = UserFactory(
            email="clara.old@example.pt",
            password="S3cretPass!",
            first_name="clara",
            last_name="pinto",
            confirmed_at=None,
        )

        token = self._issue_link_for(
            mock_client_for,
            legacy,
            nic="10203040",
            first_name="Clara",
            last_name="Pinto",
        )

        # Before the click: nothing linked, no session.
        assert self.client.get("/api/1/me/").status_code == 401
        legacy.reload()
        assert not (legacy.extras or {}).get("auth_nic")

        # A brand-new client: no wizard session, no cookies at all.
        # login_user is asserted directly rather than through /api/1/me/: once
        # anything in the process calls it, current_user stays set for the rest
        # of the test and every later client reads as authenticated, so a 200
        # there would pass even if no session cookie were ever issued. This is
        # the same way SAMLLoginFlowTest pins the login it cares about.
        with self.app.test_client() as fresh:
            with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
                response = fresh.get(f"/saml/migration/confirm-link/{token}")
                mock_login.assert_called_once()
                assert mock_login.call_args[0][0].id == legacy.id
            assert response.status_code == 302
            assert response.headers["Location"] == "http://localhost:3000"

        legacy.reload()
        assert legacy.extras["auth_nic"] == _hash_nic("10203040")
        assert legacy.first_name == "Clara"
        assert legacy.last_name == "Pinto"
        assert legacy.confirmed_at is not None

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_the_link_is_single_use(self, mock_client_for):
        """Criterion 6: a second click reports itself instead of relinking."""
        legacy = UserFactory(
            email="bruno.old@example.pt",
            password="S3cretPass!",
            first_name="Bruno",
            last_name="Sa",
        )
        token = self._issue_link_for(
            mock_client_for, legacy, nic="50607080", first_name="Bruno", last_name="Sa"
        )

        with self.app.test_client() as fresh:
            assert fresh.get(f"/saml/migration/confirm-link/{token}").status_code == 302

        with self.app.test_client() as second:
            response = second.get(f"/saml/migration/confirm-link/{token}")
            assert response.status_code == 302
            assert "flash=migration_link_already_done" in response.headers["Location"]
            # Deliberately no /api/1/me/ assertion here: APITestCase.login and
            # our own consumption both call login_user inside the ambient test
            # request context, so current_user stays set for the rest of the
            # test and every later client reads as authenticated. The 401 that
            # proves criterion 2 is asserted in the test above, before any
            # login has happened. What matters here is that the second click
            # changed nothing, asserted on the account below.

        legacy.reload()
        assert legacy.extras["auth_nic"] == _hash_nic("50607080")
        assert legacy.first_name == "Bruno"

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_expired_link_is_refused_without_mailing_anything(self, mock_client_for):
        """Criterion 6: an expired link says so and points at re-authentication.
        It deliberately does NOT reissue: this is an unauthenticated GET, and
        mail scanners open links before their owners do, so reissuing here
        would let a scanner keep an old mail alive indefinitely."""
        from udata.auth.saml.saml_plugin.saml_govpt import MIGRATION_LINK_PENDING

        legacy = UserFactory(
            email="sofia.old@example.pt",
            password="S3cretPass!",
            first_name="Sofia",
            last_name="Lima",
        )
        token = self._issue_link_for(
            mock_client_for, legacy, nic="11223344", first_name="Sofia", last_name="Lima"
        )

        # Age the record past its deadline.
        legacy.reload()
        record = legacy.extras[MIGRATION_LINK_PENDING]
        record["expires"] = (datetime.utcnow() - timedelta(minutes=1)).isoformat()
        legacy.extras[MIGRATION_LINK_PENDING] = record
        legacy.save()

        with self.app.test_client() as fresh:
            with patch("udata.auth.saml.saml_plugin.saml_govpt.send_mail") as mock_send:
                response = fresh.get(f"/saml/migration/confirm-link/{token}")
            assert response.status_code == 302
            assert "flash=migration_link_expired" in response.headers["Location"]
            # Nothing was mailed: a scanner cannot use an old link to mint a
            # fresh one with a fresh deadline.
            assert mock_send.call_count == 0
            assert fresh.get("/api/1/me/").status_code == 401

        legacy.reload()
        assert not (legacy.extras or {}).get("auth_nic")
        # Repeating the click stays inert rather than escalating.
        with self.app.test_client() as again:
            with patch("udata.auth.saml.saml_plugin.saml_govpt.send_mail") as mock_send:
                response = again.get(f"/saml/migration/confirm-link/{token}")
            assert "flash=migration_link_expired" in response.headers["Location"]
            assert mock_send.call_count == 0

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_link_cannot_overwrite_an_identity_linked_meanwhile(self, mock_client_for):
        """The gap a stateless token opens: the account gets linked to another
        identity between issue and click. The link must not overwrite it."""
        legacy = UserFactory(
            email="tiago.old@example.pt",
            password="S3cretPass!",
            first_name="Tiago",
            last_name="Melo",
        )
        token = self._issue_link_for(
            mock_client_for, legacy, nic="99887766", first_name="Tiago", last_name="Melo"
        )

        # Somebody else's identity is now legitimately linked to the account.
        legacy.reload()
        legacy.extras["auth_nic"] = _hash_nic("00001111")
        legacy.save()

        with self.app.test_client() as fresh:
            response = fresh.get(f"/saml/migration/confirm-link/{token}")
            assert response.status_code == 302
            assert "flash=migration_link_invalid" in response.headers["Location"]
            assert fresh.get("/api/1/me/").status_code == 401

        legacy.reload()
        assert legacy.extras["auth_nic"] == _hash_nic("00001111")

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_the_code_branch_is_gone(self, mock_client_for):
        """LEDG-2357 removes the 6-digit code outright rather than leaving it
        unreachable from the UI: while the endpoint answered, the takeover
        chain of LEDG-2355 stayed reachable by direct POST. The password
        branch is untouched."""
        UserFactory(
            email="paulo.old@example.pt",
            password="S3cretPass!",
            first_name="Paulo",
            last_name="Faria",
        )
        self._sso_with(mock_client_for, nic="31313131", first_name="Paulo", last_name="Faria")

        # 405, not 404: the endpoint is gone from the blueprint, and a
        # GET-only catch-all further down the map is what the path now hits.
        assert self.client.post("/saml/migration/send-code").status_code in (404, 405)
        assert not any("send-code" in str(rule) for rule in self.app.url_map.iter_rules())

        response = self.client.post(
            "/saml/migration/confirm", json={"method": "code", "code": "123456"}
        )
        assert response.status_code == 400
        assert response.json["error"] == "Invalid method"

        # The surviving proof of ownership still works.
        response = self.client.post(
            "/saml/migration/confirm",
            json={
                "method": "password",
                "email": "paulo.old@example.pt",
                "password": "S3cretPass!",
            },
        )
        assert response.status_code == 200

    def test_a_forged_or_unknown_token_never_500s(self):
        """Criterion 6: garbage in the URL is an answer, not a stack trace."""
        for token in ("", "not-a-token", "a.b.c", "x" * 400):
            response = self.client.get(f"/saml/migration/confirm-link/{token}")
            assert response.status_code in (302, 404)
            if response.status_code == 302:
                assert "flash=migration_link_invalid" in response.headers["Location"]

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_link_cannot_put_one_identity_on_two_accounts(self, mock_client_for):
        """Takeover regression. The password branch identifies whichever
        account proved its password, which by design may not be the pointed
        candidate. A link mailed to that candidate stays in their inbox; if
        clicking it also linked, one NIC would sit on two accounts — and the
        login lookup resolves by auth_nic ordered by -created_at, so the
        account created later silently wins the identity. Re-pointing now
        kills the victim's link at the proof, and the click refuses it too."""
        victim = UserFactory(
            email="victim2@example.pt",
            password="VictimPass1!",
            first_name="Sara",
            last_name="Brito",
        )
        attacker = UserFactory(
            email="attacker2@example.pt",
            password="AttackerPass1!",
            first_name="Sara",
            last_name="Brito",
        )

        # Point the victim (search proves nothing — LEDG-2355 #6) and mail a
        # link to their address.
        self._sso_with(mock_client_for, nic="45454545", first_name="Sara", last_name="Brito")
        assert (
            self.client.post("/saml/migration/search", json={"email": victim.email}).json["found"]
            is True
        )
        with patch("udata.auth.saml.saml_plugin.saml_govpt.send_mail") as mock_send:
            assert self.client.post("/saml/migration/send-link").status_code == 200
        ctas = [p for p in mock_send.call_args[0][1].paragraphs if getattr(p, "link", None)]
        token = ctas[0].link.rsplit("/", 1)[1]

        # Now prove a DIFFERENT account by password, and follow the link that
        # proof mails to that account's own address.
        with patch("udata.auth.saml.saml_plugin.saml_govpt.send_mail") as mock_send:
            assert (
                self.client.post(
                    "/saml/migration/confirm",
                    json={
                        "method": "password",
                        "email": attacker.email,
                        "password": "AttackerPass1!",
                    },
                ).status_code
                == 200
            )
            attacker_ctas = [
                p for p in mock_send.call_args[0][1].paragraphs if getattr(p, "link", None)
            ]
            attacker_token = attacker_ctas[0].link.rsplit("/", 1)[1]

        with self.app.test_client() as fresh:
            assert fresh.get(f"/saml/migration/confirm-link/{attacker_token}").status_code == 302
        attacker.reload()
        assert attacker.extras["auth_nic"] == _hash_nic("45454545")

        # The victim opens the link that is still in their inbox.
        with self.app.test_client() as fresh:
            response = fresh.get(f"/saml/migration/confirm-link/{token}")
            assert "flash=migration_link_invalid" in response.headers["Location"]

        victim.reload()
        assert not (victim.extras or {}).get("auth_nic"), "one NIC landed on two accounts"

        from udata.core.user.models import User

        holders = User.objects(extras__auth_nic=_hash_nic("45454545"))
        assert holders.count() == 1
        assert holders.first().id == attacker.id

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_creating_a_new_account_kills_the_candidate_link(self, mock_client_for):
        """Same hazard through the skip: the new account carries the NIC, so a
        link left in the abandoned candidate's inbox must not still work."""
        from udata.auth.saml.saml_plugin.saml_govpt import MIGRATION_LINK_PENDING

        candidate = UserFactory(
            email="cand@example.pt",
            password="S3cretPass!",
            first_name="Nadia",
            last_name="Rocha",
        )

        self._sso_with(mock_client_for, nic="64646464", first_name="Nadia", last_name="Rocha")
        with patch("udata.auth.saml.saml_plugin.saml_govpt.send_mail"):
            assert self.client.post("/saml/migration/send-link").status_code == 200
        candidate.reload()
        assert MIGRATION_LINK_PENDING in candidate.extras

        with patch("udata.auth.saml.saml_plugin.saml_govpt.send_confirmation_instructions"):
            response = self.client.post(
                "/saml/migration/skip", json={"email": "nadia.nova@example.pt"}
            )
        assert response.status_code == 200

        candidate.reload()
        assert MIGRATION_LINK_PENDING not in (candidate.extras or {})

    def test_a_stock_confirmation_token_is_refused_not_a_500(self):
        """The confirm serializer and its salt are shared with flask-security's
        own confirmation token, whose payload is also a two-element list of
        strings — and anyone who registers gets one in their inbox. Untagged,
        it reached this route and its uuid uniquifier hit an ObjectIdField as
        an unauthenticated 500."""
        from flask_security.confirmable import generate_confirmation_token

        user = UserFactory(email="stock@example.pt", password="S3cretPass!")
        foreign = generate_confirmation_token(user)

        response = self.client.get(f"/saml/migration/confirm-link/{foreign}")
        assert response.status_code == 302
        assert "flash=migration_link_invalid" in response.headers["Location"]

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_re_pointing_the_candidate_kills_the_link_already_sent(self, mock_client_for):
        """LEDG-2357, the link-flow equivalent of the target-confusion guard:
        a link issued for one account must not survive the wizard being
        pointed at another. The code died with a session pop; a mailed token
        can only be killed by destroying the record it was issued against."""
        from udata.auth.saml.saml_plugin.saml_govpt import MIGRATION_LINK_PENDING

        first = UserFactory(
            email="first.old@example.pt",
            password="S3cretPass!",
            first_name="Marta",
            last_name="Costa",
        )
        second = UserFactory(
            email="second.old@example.pt",
            password="S3cretPass!",
            first_name="Marta",
            last_name="Costa",
        )

        # Two homonyms means no automatic candidate: the wizard asks, the user
        # names one, takes a link for it — and then names the other.
        self._sso_with(mock_client_for, nic="77778888", first_name="Marta", last_name="Costa")
        found = self.client.post("/saml/migration/search", json={"email": first.email})
        assert found.json["found"] is True

        with patch("udata.auth.saml.saml_plugin.saml_govpt.send_mail") as mock_send:
            assert self.client.post("/saml/migration/send-link").status_code == 200
        ctas = [p for p in mock_send.call_args[0][1].paragraphs if getattr(p, "link", None)]
        token = ctas[0].link.rsplit("/", 1)[1]

        first.reload()
        assert MIGRATION_LINK_PENDING in first.extras

        repointed = self.client.post("/saml/migration/search", json={"email": second.email})
        assert repointed.json["found"] is True

        # The record on the account the link was issued for is gone.
        first.reload()
        assert MIGRATION_LINK_PENDING not in (first.extras or {})

        with self.app.test_client() as fresh:
            response = fresh.get(f"/saml/migration/confirm-link/{token}")
            assert response.status_code == 302
            assert "flash=migration_link_invalid" in response.headers["Location"]

        for account in (first, second):
            account.reload()
            assert not (account.extras or {}).get("auth_nic")

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_pending_reports_which_provider_started_the_migration(self, mock_client_for):
        """The wizard names the provider on every screen it renders, and it
        cannot infer which one started the flow: both ACS routes converge on
        the same redirect. So the pending state carries it."""
        UserFactory(
            email="hugo.old@example.pt",
            password="S3cretPass!",
            first_name="Hugo",
            last_name="Freitas",
        )

        self._sso_with(mock_client_for, nic="72727272", first_name="Hugo", last_name="Freitas")

        response = self.client.get("/saml/migration/pending")
        assert response.status_code == 200
        assert response.json["provider"] == "cmd"

    @patch("udata.auth.saml.saml_plugin.saml_govpt.requires_confirmation", return_value=False)
    @patch("udata.auth.saml.saml_plugin.saml_govpt.eidas_client_for")
    def test_pending_reports_eidas_when_eidas_started_the_migration(
        self, mock_client_for, mock_requires_conf
    ):
        """Same field, the other provider — otherwise every eIDAS user would
        read "Chave Movel Digital" on the screen that asks for their
        credentials."""
        UserFactory(
            email="ines.old@example.pt",
            password="S3cretPass!",
            first_name="Ines",
            last_name="Bravo",
        )

        self._sso_with(
            mock_client_for,
            endpoint="/saml/eidas/sso",
            person_identifier="ES/PT/1231231230",
            given_name="Ines",
            family_name="Bravo",
        )

        response = self.client.get("/saml/migration/pending")
        assert response.status_code == 200
        assert response.json["provider"] == "eidas"

    @patch("udata.auth.saml.saml_plugin.saml_govpt.requires_confirmation", return_value=False)
    @patch("udata.auth.saml.saml_plugin.saml_govpt.eidas_client_for")
    def test_the_same_flow_works_from_eidas(self, mock_client_for, mock_requires_conf):
        """Criterion 4: one consumption route serves CMD and eIDAS, because
        both enter through the same migration redirect."""
        person_id = "ES/PT/9876543210"
        legacy = UserFactory(
            email="carmen.old@example.pt",
            password="S3cretPass!",
            first_name="Carmen",
            last_name="Garcia",
        )

        token = self._issue_link_for(
            mock_client_for,
            legacy,
            endpoint="/saml/eidas/sso",
            person_identifier=person_id,
            given_name="Carmen",
            family_name="Garcia",
        )

        with self.app.test_client() as fresh:
            with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
                response = fresh.get(f"/saml/migration/confirm-link/{token}")
                mock_login.assert_called_once()
                assert mock_login.call_args[0][0].id == legacy.id
            assert response.status_code == 302

        legacy.reload()
        assert legacy.extras["auth_nic"] == _hash_nic(person_id)


class SAMLMigrationSecurityTest(APITestCase):
    """Adversarial tests for the account-linking wizard.

    The security boundary: an attacker must never link their CMD (NIC)
    to — or log into — a victim account without proving ownership of
    that account (its password, or a code emailed to it).
    """

    @pytest.fixture(autouse=True)
    def _set_frontend_url(self, app):
        app.config["CDATA_BASE_URL"] = "http://localhost:3000"
        app.config["MIGRATION_MODE_ENABLED"] = True

    def _sso_with(self, mock_client_for, **attrs):
        mock_saml_client = MagicMock()
        mock_saml_client.parse_authn_request_response.return_value = _make_authn_response_mock(
            **attrs
        )
        mock_client_for.return_value = mock_saml_client
        encoded = base64.b64encode(_build_saml_response_xml(**attrs).encode("utf-8")).decode(
            "utf-8"
        )
        return self.client.post("/saml/sso", data={"SAMLResponse": encoded}, follow_redirects=False)

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_emailed_link_cannot_link_a_re_targeted_account(self, mock_client_for):
        """Target-confusion / account takeover: a validation link emailed to
        the attacker's own account must not link the CMD identity to a
        DIFFERENT account after migration/search re-points the candidate to a
        victim. The code this replaced died with a session pop; the link is
        stateless, so it dies with the record on the account it was issued
        against."""
        # Victim: legacy account (password, no NIC). The attacker cannot
        # read the victim's mailbox nor knows its password.
        victim = UserFactory(
            email="victim@gov.pt",
            password="VictimPass1!",
            first_name="Vic",
            last_name="Tim",
        )
        # Attacker's own legacy account, matched by name from their CMD.
        UserFactory(
            email="attacker@evil.com",
            password="AttackerPass1!",
            first_name="Mallory",
            last_name="Evil",
        )

        # 1. Attacker authenticates with their real CMD (name match → own
        #    account becomes the pending candidate).
        resp = self._sso_with(
            mock_client_for, nic="66667777", first_name="Mallory", last_name="Evil"
        )
        assert "/migrate-account" in resp.headers["Location"]

        # 2. Attacker requests a link — emailed to their OWN address. We take
        #    the token as the attacker would read it from their inbox.
        with patch("udata.auth.saml.saml_plugin.saml_govpt.send_mail") as mock_send:
            r = self.client.post("/saml/migration/send-link")
            assert r.status_code == 200
        ctas = [p for p in mock_send.call_args[0][1].paragraphs if getattr(p, "link", None)]
        token = ctas[0].link.rsplit("/", 1)[1]

        # 3. Attacker re-targets the candidate to the victim via search.
        r = self.client.post("/saml/migration/search", json={"email": "victim@gov.pt"})
        assert r.status_code == 200 and r.json["found"] is True

        # 4. Attacker opens the link they received. It must NOT link the NIC
        #    to the victim, nor log the attacker in as the victim.
        r = self.client.get(f"/saml/migration/confirm-link/{token}")
        assert "flash=migration_link_invalid" in r.headers["Location"], (
            "Account takeover: re-targeted link was accepted"
        )

        victim.reload()
        assert not (victim.extras or {}).get("auth_nic"), "Victim account was taken over"

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_password_brute_force_is_capped_per_session(self, mock_client_for):
        """Online password guessing against a candidate is capped."""
        UserFactory(
            email="pedro@example.pt",
            password="S3cretPass1!",
            first_name="Pedro",
            last_name="Almeida",
        )
        self._sso_with(mock_client_for, nic="55667788", first_name="Pedro", last_name="Almeida")

        for _ in range(5):
            r = self.client.post(
                "/saml/migration/confirm",
                json={"method": "password", "email": "pedro@example.pt", "password": "x"},
            )
            assert r.status_code == 400
        r = self.client.post(
            "/saml/migration/confirm",
            json={"method": "password", "email": "pedro@example.pt", "password": "x"},
        )
        assert r.status_code == 429

    def test_confirm_requires_a_pending_migration(self):
        """No pending SAML migration in session → confirm is refused."""
        UserFactory(email="pedro@example.pt", password="S3cretPass1!")
        r = self.client.post(
            "/saml/migration/confirm",
            json={"method": "password", "email": "pedro@example.pt", "password": "S3cretPass1!"},
        )
        assert r.status_code == 400
