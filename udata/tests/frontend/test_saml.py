"""Tests for SAML authentication flow with autenticacao.gov.

Ensures the SAML plugin does not render Jinja2 templates (which would cause
TemplateNotFound errors) and instead auto-creates users from SAML data.

Also tests the full SSO callback flow: after autenticacao.gov returns a
successful SAMLResponse, the backend must parse the SAML attributes and
then perform the udata login (login_user + session['saml_login']).
"""

import base64
import inspect
from unittest.mock import MagicMock, patch

import pytest
from flask import session

from udata.auth.saml.saml_plugin.saml_govpt import _hash_nic
from udata.core.user.factories import UserFactory
from udata.tests.api import APITestCase


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
            assert user.email == "saml-77777777@autenticacao.gov.pt"
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
                response = _handle_saml_user_login(user)

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
            assert logged_in_user.extras.get("auth_nic") == "12345678"
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
            response = self._post_saml_response(xml)

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
            response = self._post_saml_response(xml)

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
        assert call_order == ["saml_parse", "login_user"], (
            f"Expected saml_parse before login_user, got: {call_order}"
        )

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
            response = self._post_saml_response(xml)

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
            response = self._post_saml_response(xml)

            assert mock_login.call_count == 1
            logged_in_user = mock_login.call_args[0][0]
            assert logged_in_user.email == "saml-88888888@autenticacao.gov.pt"
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
