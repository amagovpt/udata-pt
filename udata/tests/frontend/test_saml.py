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

# Placeholder email shape generated when the IdP does not return an email:
# saml-<uuid4().hex[:8]>@autenticacao.gov.pt — 8 lowercase hex characters.
# We assert the structure, not the literal value, because the NIC must NOT
# leak into the email address (privacy fix; see
# saml_govpt._find_or_create_saml_user).
_SAML_PLACEHOLDER_EMAIL_RE = re.compile(r"^saml-[a-f0-9]{8}@autenticacao\.gov\.pt$")


def _build_saml_response_xml(email=None, nic=None, first_name=None, last_name=None):
    """Build a minimal SAML Response XML with the given attributes.

    This simulates what autenticacao.gov returns after successful authentication.
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
    Subject mismatch in dedicated tests.
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

    response = MagicMock()
    response.get_identity.return_value = identity
    response.ava = identity
    response.issuer.return_value = issuer

    subject_mock = MagicMock()
    if name_id is not None:
        subject_mock.text = name_id
    else:
        # Default to the NIC so the Subject↔NIC binding check passes when a
        # NIC is present; fall back to a stable placeholder for tests that
        # do not exercise NIC at all (e.g. email-only logins).
        subject_mock.text = nic or "test-name-id"
    response.get_subject.return_value = subject_mock
    return response


class SAMLCodeIntegrityTest(APITestCase):
    """Verify the SAML plugin code does not reference Jinja2 templates."""

    def test_register_user_has_no_template_rendering(self):
        """register_user.py must NOT call render_template or reference register_saml.html."""
        from udata.auth.saml.saml_plugin import register_user

        source = inspect.getsource(register_user)
        assert (
            "render_template" not in source
        ), "register_user.py still calls render_template — this causes TemplateNotFound"
        assert (
            "register_saml.html" not in source
        ), "register_user.py still references register_saml.html template"

    def test_saml_govpt_has_no_template_rendering(self):
        """saml_govpt.py must NOT call render_template or reference register_saml.html."""
        from udata.auth.saml.saml_plugin import saml_govpt

        source = inspect.getsource(saml_govpt)
        assert (
            "register_saml.html" not in source
        ), "saml_govpt.py still references register_saml.html template"

    def test_no_redirect_to_saml_register(self):
        """saml_govpt.py must NOT redirect to saml.register (no intermediate form)."""
        from udata.auth.saml.saml_plugin import saml_govpt

        source = inspect.getsource(saml_govpt)
        assert (
            "url_for('saml.register')" not in source
        ), "saml_govpt.py still redirects to saml.register instead of auto-creating users"
        assert (
            'url_for("saml.register")' not in source
        ), "saml_govpt.py still redirects to saml.register instead of auto-creating users"


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
        assert re.fullmatch(
            r"[A-Za-z0-9_\-]+", a
        ), "token must be URL-safe so it round-trips through HTTP-POST RelayState"

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
            assert (
                second == {}
            ), "second consume must return empty so the response cannot be replayed"

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

    def test_creates_new_user_from_saml_data(self):
        from udata.auth.saml.saml_plugin.saml_govpt import _find_or_create_saml_user

        with self.app.app_context():
            user, status = _find_or_create_saml_user(
                user_email="saml_new@example.com",
                user_nic="12345678",
                first_name="João",
                last_name="Silva",
            )

            assert status == "new"
            assert user is not None
            assert user.email == "saml_new@example.com"
            assert user.first_name == "João"
            assert user.last_name == "Silva"
            assert user.extras.get("auth_nic") == _hash_nic("12345678")

    def test_finds_existing_user_by_email(self):
        from udata.auth.saml.saml_plugin.saml_govpt import _find_or_create_saml_user

        with self.app.app_context():
            existing = UserFactory(email="existing@example.com")

            user, status = _find_or_create_saml_user(
                user_email="existing@example.com",
                user_nic="99999999",
                first_name="Another",
                last_name="Name",
            )

            assert user.id == existing.id

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

            assert status == "new"
            assert user is not None
            assert user.email == "no_nic@example.com"
            assert not user.extras.get("auth_nic")

    def test_handles_missing_email_generates_placeholder(self):
        """When IdP provides NIC but no email, a placeholder email is generated."""
        from udata.auth.saml.saml_plugin.saml_govpt import _find_or_create_saml_user

        with self.app.app_context():
            user, status = _find_or_create_saml_user(
                user_email=None,
                user_nic="77777777",
                first_name="Carlos",
                last_name="Ferreira",
            )

            assert status == "new"
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

    def test_unconfirmed_user_is_auto_confirmed_and_logged_in(self):
        """SAML users are auto-confirmed since autenticacao.gov already verified them."""
        from udata.auth.saml.saml_plugin.saml_govpt import _handle_saml_user_login

        with self.app.test_request_context():
            self.app.config["CDATA_BASE_URL"] = "http://localhost:3000"
            user = UserFactory(confirmed_at=None)

            response = _handle_saml_user_login(user)

            assert response.status_code == 302
            assert user.confirmed_at is not None
            assert "login" not in response.location.lower()

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

    def test_login_sets_saml_session_flag(self):
        from udata.auth.saml.saml_plugin.saml_govpt import _handle_saml_user_login

        with self.app.test_request_context():
            self.app.config["CDATA_BASE_URL"] = "http://localhost:3000"
            user = UserFactory(confirmed_at="2024-01-01")

            with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
                _handle_saml_user_login(user)

                mock_login.assert_called_once_with(user)
                assert session.get("saml_login") is True


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
    def test_sso_callback_creates_user_and_logs_in(self, mock_client_for, mock_requires_conf):
        """After autenticacao.gov success, udata must create user and login."""
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

        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            response = self._post_saml_response(xml)

            # login_user must have been called exactly once
            assert mock_login.call_count == 1
            logged_in_user = mock_login.call_args[0][0]
            assert logged_in_user.email == "cidadao@example.pt"
            # auth_nic is stored as HMAC-SHA256 hex, never the raw NIC.
            assert logged_in_user.extras.get("auth_nic") == _hash_nic("12345678")
            assert logged_in_user.first_name == "João"
            assert logged_in_user.last_name == "Silva"

        assert response.status_code == 302

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_sso_callback_finds_existing_user_by_email(self, mock_client_for):
        """If user already exists with that email, login existing user."""
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
            self._post_saml_response(xml)

            assert mock_login.call_count == 1
            logged_in_user = mock_login.call_args[0][0]
            assert logged_in_user.id == existing.id

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

        UserFactory(email="session_test@example.pt", confirmed_at="2024-01-01")

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
        """autenticacao.gov may return only email (NIC is optional)."""
        mock_saml_client = MagicMock()
        mock_saml_client.parse_authn_request_response.return_value = _make_authn_response_mock(
            email="email_only@example.pt"
        )
        mock_client_for.return_value = mock_saml_client

        xml = _build_saml_response_xml(email="email_only@example.pt")

        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            self._post_saml_response(xml)

            assert mock_login.call_count == 1
            logged_in_user = mock_login.call_args[0][0]
            assert logged_in_user.email == "email_only@example.pt"

    @patch("udata.auth.saml.saml_plugin.saml_govpt.requires_confirmation", return_value=False)
    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_sso_callback_with_only_nic_generates_placeholder_email(
        self, mock_client_for, mock_requires_conf
    ):
        """autenticacao.gov may return NIC but no email; placeholder generated."""
        mock_saml_client = MagicMock()
        mock_saml_client.parse_authn_request_response.return_value = _make_authn_response_mock(
            nic="88888888", first_name="Pedro", last_name="Nunes"
        )
        mock_client_for.return_value = mock_saml_client

        xml = _build_saml_response_xml(nic="88888888", first_name="Pedro", last_name="Nunes")

        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            self._post_saml_response(xml)

            assert mock_login.call_count == 1
            logged_in_user = mock_login.call_args[0][0]
            # Placeholder email must be a random uuid hex, NOT NIC-derived.
            assert _SAML_PLACEHOLDER_EMAIL_RE.match(logged_in_user.email), logged_in_user.email
            assert "88888888" not in logged_in_user.email  # NIC must not leak
            assert logged_in_user.extras.get("auth_nic") == _hash_nic("88888888")

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
        assert "/pages/login" in response.headers["Location"]

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
    """Verify that a CMD (Chave Móvel Digital) login is linked to a
    pre-existing default account (registered with email + password).

    The existing account must be reused — never duplicated — so that the
    user keeps the permissions, roles, organization memberships and
    content (datasets, etc.) created before linking the CMD identity.
    """

    def test_cmd_login_links_to_existing_password_account(self):
        """A CMD login with the same email merges the NIC into the
        existing password account instead of creating a new user."""
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

            # The existing account is linked, not duplicated.
            assert status == "merged"
            assert user.id == existing.id
            assert User.objects.count() == users_before

            # The CMD identity (hashed NIC) is now bound to the account.
            user.reload()
            assert user.extras.get("auth_nic") == _hash_nic("12345678")

            # The original credentials are untouched — the user can still
            # log in with email + password.
            assert user.password == original_password_hash
            assert user.email == "cidadao@example.pt"

    def test_linked_account_preserves_roles_memberships_and_content(self):
        """Permissions and prior actions survive the CMD linking: admin
        role, organization membership and owned datasets stay with the
        same account."""
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

            assert status == "merged"
            assert user.id == existing.id

            # Admin role preserved.
            user.reload()
            assert user.sysadmin

            # Organization membership preserved.
            org.reload()
            assert org.is_member(user)
            assert org.is_admin(user)

            # Owned content preserved.
            dataset.reload()
            assert dataset.owner.id == user.id

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
        candidates — a homonym with CMD gets a new account instead."""
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

            assert status == "new"
            assert user.id != linked.id

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
        """After the first merge, later CMD logins (even without email,
        matching by NIC only) resolve to the same account."""
        from udata.auth.saml.saml_plugin.saml_govpt import _find_or_create_saml_user
        from udata.core.user.models import User

        with self.app.app_context():
            existing = UserFactory(
                email="cidadao2@example.pt",
                password="S3cretPass!",
            )

            # First CMD login: merge.
            user, status = _find_or_create_saml_user(
                user_email="cidadao2@example.pt",
                user_nic="11223344",
                first_name="Rui",
                last_name="Costa",
            )
            assert status == "merged"
            assert user.id == existing.id

            # Second CMD login: IdP returns only the NIC.
            user, status = _find_or_create_saml_user(
                user_email=None,
                user_nic="11223344",
                first_name="Rui",
                last_name="Costa",
            )
            assert status == "existing_saml"
            assert user.id == existing.id
            assert User.objects.count() == 1


class SAMLSSOLinkingCallbackTest(APITestCase):
    """End-to-end: the /saml/sso callback links the CMD identity to the
    pre-existing password account and logs that same account in."""

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

    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_sso_callback_links_cmd_to_existing_password_account(self, mock_client_for):
        from udata.core.user.models import User

        mock_saml_client = MagicMock()
        mock_saml_client.parse_authn_request_response.return_value = _make_authn_response_mock(
            email="default@example.pt",
            nic="12121212",
            first_name="Ana",
            last_name="Pereira",
        )
        mock_client_for.return_value = mock_saml_client

        existing = UserFactory(
            email="default@example.pt",
            password="S3cretPass!",
            first_name="Ana",
            last_name="Pereira",
            confirmed_at=datetime(2024, 1, 1),
        )
        original_password_hash = existing.password
        users_before = User.objects.count()

        xml = _build_saml_response_xml(
            email="default@example.pt",
            nic="12121212",
            first_name="Ana",
            last_name="Pereira",
        )

        with patch("udata.auth.saml.saml_plugin.saml_govpt.login_user") as mock_login:
            response = self._post_saml_response(xml)

            # The logged-in user is the pre-existing account.
            assert mock_login.call_count == 1
            logged_in_user = mock_login.call_args[0][0]
            assert logged_in_user.id == existing.id

        assert response.status_code == 302

        # No duplicate account; NIC linked; password credentials intact.
        assert User.objects.count() == users_before
        existing.reload()
        assert existing.extras.get("auth_nic") == _hash_nic("12121212")
        assert existing.password == original_password_hash


class SAMLMigrationWizardTest(APITestCase):
    """End-to-end coverage of the account-linking wizard: a name-only
    match redirects to /pages/migrate-account, where the user either
    proves ownership of the default account (email + password login, or
    emailed code) to link it, or explicitly creates a new account.
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
        assert "/pages/migrate-account" in response.headers["Location"]
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
    def test_confirm_with_password_links_account_and_preserves_data(self, mock_client_for):
        """'Já possuo uma conta' + login (email+password) bem-sucedido:
        the CMD identity is linked to the default account, keeping the
        password, roles, organization memberships and owned content."""
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
        assert "/pages/migrate-account" in response.headers["Location"]

        # The user chooses "Já possuo uma conta" and logs in.
        response = self.client.post(
            "/saml/migration/confirm",
            json={"method": "password", "email": "maria@example.pt", "password": "S3cretPass!"},
        )
        assert response.status_code == 200
        assert response.json["success"] is True

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

        response = self.client.post(
            "/saml/migration/confirm",
            json={"method": "password", "email": "rui.real@example.pt", "password": "S3cretPass!"},
        )
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
    def test_skip_creates_new_account_with_cmd_email(self, mock_client_for):
        """'Criar nova conta' (scenario 4 via wizard): the new account
        uses the CMD email when it exists, and the candidate account is
        never touched."""
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

        response = self.client.post("/saml/migration/skip")
        assert response.status_code == 200

        new_user = User.objects(email="rita.cmd@example.pt").first()
        assert new_user is not None
        assert new_user.extras.get("auth_nic") == _hash_nic("44556677")
        homonym.reload()
        assert not (homonym.extras or {}).get("auth_nic")

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

    @patch("udata.auth.saml.saml_plugin.saml_govpt.requires_confirmation", return_value=False)
    @patch("udata.auth.saml.saml_plugin.saml_govpt.saml_client_for")
    def test_new_account_redirect_informs_user(self, mock_client_for, mock_requires_conf):
        """Scenario 4 (direct): no match at all — the account is created
        and the redirect carries cmd_new_account=1 so the frontend can
        inform the user."""
        response = self._sso_with(
            mock_client_for,
            email="novo@example.pt",
            nic="13131313",
            first_name="Bruno",
            last_name="Novo",
        )
        assert response.status_code == 302
        assert "cmd_new_account=1" in response.headers["Location"]

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
            assert "cmd_new_account=1" in response.headers["Location"]
            assert User.objects.count() == users_before + 1
            existing.reload()
            assert not (existing.extras or {}).get("auth_nic")
        finally:
            self.app.config["MIGRATION_MODE_ENABLED"] = True
