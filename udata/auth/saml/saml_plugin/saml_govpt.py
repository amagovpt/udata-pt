# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import base64
import os
import random
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta

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
from flask_security.confirmable import requires_confirmation
from flask_security.decorators import anonymous_user_required
from flask_security.utils import do_flash, get_message, verify_and_update_password
from saml2 import (
    BINDING_HTTP_POST,
    BINDING_HTTP_REDIRECT,
    element_to_extension_element,
    entity,
    sigver,
)
from saml2 import xmldsig as ds
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


autenticacao_gov = Blueprint("saml", __name__)


def _first_value(identity, key):
    """Extract the first value for a key from pysaml2 identity dict."""
    values = identity.get(key, [])
    if isinstance(values, list) and values:
        return values[0]
    if isinstance(values, str) and values:
        return values
    return None


def _find_or_create_saml_user(user_email, user_nic, first_name, last_name):
    """Find an existing user by email/NIC or auto-create from SAML data.

    Returns a tuple (user, status) where status is one of:
    - "existing_saml" — user already has NIC, normal login
    - "migration_candidate" — legacy user with password and no NIC
    - "new" — newly created user
    """
    user = None
    if user_email:
        user = datastore.find_user(email=user_email)
    if not user and user_nic:
        user = datastore.find_user(extras={"auth_nic": user_nic})

    if user:
        has_nic = user.extras and user.extras.get("auth_nic")
        if not has_nic and user.password:
            return user, "migration_candidate"
        return user, "existing_saml"

    if not user_email and not user_nic:
        current_app.logger.error("SAML: Cannot create user without email or NIC")
        return None, "error"

    # Generate a placeholder email when the IdP does not provide one.
    if not user_email:
        import uuid

        user_email = f"saml-{user_nic or uuid.uuid4().hex[:8]}@autenticacao.gov.pt"

    user_data = {
        "first_name": (first_name or "").title(),
        "last_name": (last_name or "").title(),
        "email": user_email,
    }
    if user_nic:
        user_data["extras"] = {"auth_nic": user_nic}

    user = datastore.create_user(**user_data)
    # Auto-confirm users created via SAML — they were already verified
    # by autenticação.gov, so no email confirmation is needed.
    user.confirmed_at = datetime.utcnow()
    datastore.commit()

    return user, "new"


def _handle_saml_user_login(user):
    """Handle login/redirect after SAML authentication."""
    frontend_url = current_app.config.get("CDATA_BASE_URL") or ""

    if user is None:
        do_flash(*get_message("CONFIRMATION_REQUIRED"))
        return redirect(f"{frontend_url}/pages/login")

    if requires_confirmation(user):
        # Auto-confirm on SAML login — autenticação.gov already verified the user.
        user.confirmed_at = datetime.utcnow()
        datastore.commit()

    if user.deleted:
        do_flash(*get_message("DISABLED_ACCOUNT"))
        return redirect(frontend_url or "/")

    login_user(user)
    session["saml_login"] = True
    return redirect(frontend_url or "/")


def _handle_migration_redirect(user, user_email, user_nic, first_name, last_name):
    """Store SAML data in session and redirect to migration page."""
    session["saml_migration_pending"] = {
        "legacy_user_id": str(user.id),
        "saml_email": user_email,
        "saml_nic": user_nic,
        "saml_first_name": first_name,
        "saml_last_name": last_name,
    }
    frontend_url = current_app.config.get("CDATA_BASE_URL") or ""
    has_email = bool(user_email)
    no_email_param = "" if has_email else "?no_email=true"
    return redirect(f"{frontend_url}/pages/migrate-account{no_email_param}")


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
        user = datastore.find_user(email=email)
    elif first_name and last_name:
        from udata.core.user.models import User

        user = User.objects(
            first_name__iexact=first_name,
            last_name__iexact=last_name,
            deleted=None,
        ).first()

    if user and user.password and not (user.extras and user.extras.get("auth_nic")):
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
        "metadata": {"local": [_resolve_path(metadata_file)]},
        "accepted_time_diff": 60,
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
                # Don't verify that the incoming requests originate from us via
                # the built-in cache for authn request ids in pysaml2
                "allow_unsolicited": True,
                # Sign authn requests
                "authn_requests_signed": True,
                "logout_requests_signed": True,
                "want_assertions_signed": True,
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


def _frontend_saml_url(endpoint_func_name):
    """Build a SAML callback URL routed through the frontend proxy.

    When the frontend runs separately (e.g. Next.js on port 3000), the SAML
    callback must point to the frontend origin so that session cookies are set
    on the same domain the browser uses.  The frontend proxies /saml/* to the
    backend via its rewrite rules.

    Falls back to Flask's url_for when CDATA_BASE_URL is not configured.
    """
    frontend_url = current_app.config.get("CDATA_BASE_URL", "").rstrip("/")
    if frontend_url:
        path = url_for(endpoint_func_name)
        return _force_scheme(f"{frontend_url}{path}")
    return _force_scheme(url_for(endpoint_func_name, _external=True))


def saml_client_for(metadata_file):
    acs_url = _frontend_saml_url("saml.idp_initiated")
    out_url = _frontend_saml_url("saml.saml_logout_postback")

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
    saml_client = saml_client_for(
        current_app.config.get("SECURITY_SAML_IDP_METADATA").split(",")[0]
    )

    faa = FAAALevel(text=str(current_app.config.get("SECURITY_SAML_FAAALEVEL")))

    spcertenc = RequestedAttributes(
        [
            RequestedAttribute(
                name="http://interop.gov.pt/MDC/Cidadao/CorreioElectronico",
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                is_required="True",
            ),
            RequestedAttribute(
                name="http://interop.gov.pt/MDC/Cidadao/NIC",
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                is_required="False",
            ),
            RequestedAttribute(
                name="http://interop.gov.pt/MDC/Cidadao/NomeProprio",
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                is_required="False",
            ),
            RequestedAttribute(
                name="http://interop.gov.pt/MDC/Cidadao/NomeApelido",
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

    args = {
        "binding": BINDING_HTTP_POST,
        "relay_state": "dWRhdGEtZ291dnB0",
        "sign": True,
        "force_authn": "true",
        "is_passive": "false",
        "nameid_format": "",
        "extensions": extensions,
    }

    reqid, info = saml_client.prepare_for_authenticate(**args)
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
                    msg = status_msg.text if status_msg is not None else status_value
                    current_app.logger.error(f"SAML: IdP rejeitou o pedido: {msg}")
                    frontend_url = current_app.config.get("CDATA_BASE_URL") or ""
                    do_flash(f"Autenticação rejeitada: {msg}", "error")
                    return redirect(f"{frontend_url}/pages/login")
    except Exception as e:
        current_app.logger.warning(f"SAML: Falha ao verificar status da resposta: {e}")

    # 1. Validar a resposta SAML com pysaml2 (verifica assinatura + desencripta)
    for server in auth_servers:
        try:
            saml_client = saml_client_for(server)
            authn_response = saml_client.parse_authn_request_response(
                raw_saml_response, entity.BINDING_HTTP_POST
            )
            current_app.logger.info(f"SAML: pysaml2 processou com sucesso via {server}")
        except sigver.MissingKey as e:
            current_app.logger.warning(f"SAML MissingKey para {server}: {e}")
            continue
        except SignatureError as se:
            current_app.logger.error(f"SAML SignatureError para {server}: {se}")
            continue
        except Exception as e:
            current_app.logger.error(
                f"SAML Erro ao processar resposta com {server}: {type(e).__name__}: {e}",
                exc_info=True,
            )
            continue
        else:
            break

    # 2. Extrair atributos — primeiro do pysaml2, depois fallback para XML manual
    if authn_response is not None:
        # pysaml2 desencriptou e validou — extrair atributos do objeto
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
                user_email = _first_value(
                    identity, "http://interop.gov.pt/MDC/Cidadao/CorreioElectronico"
                )
                user_nic = _first_value(identity, "http://interop.gov.pt/MDC/Cidadao/NIC")
                first_name = _first_value(identity, "http://interop.gov.pt/MDC/Cidadao/NomeProprio")
                last_name = _first_value(identity, "http://interop.gov.pt/MDC/Cidadao/NomeApelido")
                current_app.logger.info(
                    f"SAML atributos extraídos: email={user_email}, nic={user_nic}, "
                    f"nome={first_name} {last_name}"
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
    else:
        current_app.logger.error(
            "SAML: pysaml2 não conseguiu processar a resposta de nenhum servidor"
        )

    # 3. Fallback: parsing manual do XML (para respostas não encriptadas)
    if not user_email and not user_nic:
        current_app.logger.info("pysaml2 não extraiu atributos, a tentar parsing manual do XML")
        try:
            decoded_response = base64.b64decode(raw_saml_response)
            root = None
            for codec in ["utf-8", "ISO-8859-1"]:
                try:
                    decoded_str = decoded_response.decode(codec)
                    root = ET.fromstring(decoded_str)
                    break
                except (UnicodeDecodeError, ET.ParseError):
                    continue

            if root is not None:
                ns = {
                    "assertion": "urn:oasis:names:tc:SAML:2.0:assertion",
                    "atributos": "http://autenticacao.cartaodecidadao.pt/atributos",
                }
                attribute_statement = root.find(".//assertion:AttributeStatement", ns)
                if attribute_statement is not None:
                    for child in attribute_statement:
                        try:
                            attr_name = child.attrib.get("Name", "")
                            value = child.find(".//assertion:AttributeValue", ns)
                            if value is None or value.text is None:
                                continue
                            if attr_name == "http://interop.gov.pt/MDC/Cidadao/CorreioElectronico":
                                user_email = value.text
                            elif attr_name == "http://interop.gov.pt/MDC/Cidadao/NIC":
                                user_nic = value.text
                            elif attr_name == "http://interop.gov.pt/MDC/Cidadao/NomeProprio":
                                first_name = value.text
                            elif attr_name == "http://interop.gov.pt/MDC/Cidadao/NomeApelido":
                                last_name = value.text
                        except (AttributeError, KeyError):
                            pass
                    current_app.logger.info(
                        f"SAML atributos via XML manual: email={user_email}, nic={user_nic}, "
                        f"nome={first_name} {last_name}"
                    )
                else:
                    current_app.logger.warning(
                        "AttributeStatement não encontrado no XML — "
                        "as assertions podem estar encriptadas"
                    )
        except Exception as e:
            current_app.logger.error(f"Erro no parsing manual do XML: {e}")

    if not user_email and not user_nic:
        current_app.logger.error(
            "SAML SSO: nenhum atributo extraído (email/NIC). "
            "Verificar se as assertions estão encriptadas e se o pysaml2 "
            "tem acesso à chave privada para desencriptar."
        )

    user, status = _find_or_create_saml_user(user_email, user_nic, first_name, last_name)

    if status == "migration_candidate" and current_app.config.get("MIGRATION_MODE_ENABLED", False):
        return _handle_migration_redirect(user, user_email, user_nic, first_name, last_name)

    return _handle_saml_user_login(user)


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

    session.pop("saml_login", None)
    logout_user()
    return redirect(frontend_url or "/")


#################################################################
# Sends SAML Logout
#################################################################
@autenticacao_gov.route("/saml/logout")
def saml_logout():
    saml_client = saml_client_for(
        current_app.config.get("SECURITY_SAML_IDP_METADATA").split(",")[0]
    )
    nid = NameID(
        format=NAMEID_FORMAT_UNSPECIFIED,
        text="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
    )

    logout_url = LogoutUrl(text=_frontend_saml_url("saml.saml_logout_postback"))
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

    post_message = http_form_post_message(message=logout_request, location=destination)
    return _saml_form_response(post_message["data"])


#################################################################
# eIDAS
##
#################################################################


def eidas_client_for(metadata_file):
    acs_url = _frontend_saml_url("saml.idp_eidas_initiated")
    out_url = _frontend_saml_url("saml.eidas_logout_postback")

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
    saml_client = eidas_client_for(
        current_app.config.get("SECURITY_SAML_IDP_METADATA").split(",")[0]
    )

    faa = FAAALevel(text=str(current_app.config.get("SECURITY_SAML_FAAALEVEL")))

    spcertenc = RequestedAttributes(
        [
            RequestedAttribute(
                name="http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier",
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                is_required="True",
            ),
            RequestedAttribute(
                name="http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName",
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                is_required="False",
            ),
            RequestedAttribute(
                name="http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName",
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                is_required="False",
            ),
            RequestedAttribute(
                name="http://eidas.europa.eu/attributes/naturalperson/DateOfBirth",
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                is_required="False",
            ),
            RequestedAttribute(
                name="http://eidas.europa.eu/attributes/naturalperson/CurrentAddress",
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                is_required="False",
            ),
            RequestedAttribute(
                name="http://eidas.europa.eu/attributes/naturalperson/Gender",
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                is_required="False",
            ),
            RequestedAttribute(
                name="http://eidas.europa.eu/attributes/naturalperson/PlaceOfBirth",
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

    args = {
        "binding": BINDING_HTTP_POST,
        "relay_state": "dWRhdGEtZ291dnB0",
        "sign": True,
        "force_authn": "true",
        "is_passive": "false",
        "nameid_format": "",
        "extensions": extensions,
    }

    reqid, info = saml_client.prepare_for_authenticate(**args)
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

    # 1. Validar a resposta eIDAS com pysaml2 (verifica assinatura + desencripta)
    for server in auth_servers:
        saml_client = eidas_client_for(server)
        try:
            authn_response = saml_client.parse_authn_request_response(
                raw_saml_response, entity.BINDING_HTTP_POST
            )
        except sigver.MissingKey:
            continue
        except SignatureError as se:
            current_app.logger.error(f"eIDAS SignatureError para {server}: {se}")
            continue
        except Exception as e:
            current_app.logger.error(f"Erro ao processar resposta eIDAS com {server}: {e}")
            continue
        else:
            break

    # 2. Extrair atributos — primeiro do pysaml2, depois fallback para XML manual
    if authn_response is not None:
        try:
            identity = authn_response.get_identity()
            if identity:
                user_email = _first_value(
                    identity, "http://interop.gov.pt/MDC/Cidadao/CorreioElectronico"
                )
                user_nic = _first_value(identity, "http://interop.gov.pt/MDC/Cidadao/NIC")
                first_name = _first_value(identity, "http://interop.gov.pt/MDC/Cidadao/NomeProprio")
                last_name = _first_value(identity, "http://interop.gov.pt/MDC/Cidadao/NomeApelido")
                current_app.logger.info(
                    f"eIDAS atributos via pysaml2: email={user_email}, nic={user_nic}, "
                    f"nome={first_name} {last_name}"
                )
        except Exception as e:
            current_app.logger.warning(f"Falha ao extrair identity do pysaml2 (eIDAS): {e}")

    # 3. Fallback: parsing manual do XML (para respostas não encriptadas)
    if not user_email and not user_nic:
        current_app.logger.info("eIDAS: pysaml2 não extraiu atributos, a tentar parsing manual")
        try:
            decoded_response = base64.b64decode(raw_saml_response)
            root = None
            for codec in ["utf-8", "ISO-8859-1"]:
                try:
                    decoded_str = decoded_response.decode(codec)
                    root = ET.fromstring(decoded_str)
                    break
                except (UnicodeDecodeError, ET.ParseError):
                    continue

            if root is not None:
                ns = {
                    "assertion": "urn:oasis:names:tc:SAML:2.0:assertion",
                    "atributos": "http://autenticacao.cartaodecidadao.pt/atributos",
                }
                attribute_statement = root.find(".//assertion:AttributeStatement", ns)
                if attribute_statement is not None:
                    for child in attribute_statement:
                        try:
                            attr_name = child.attrib.get("Name", "")
                            value = child.find(".//assertion:AttributeValue", ns)
                            if value is None or value.text is None:
                                continue
                            if attr_name == "http://interop.gov.pt/MDC/Cidadao/CorreioElectronico":
                                user_email = value.text
                            elif attr_name == "http://interop.gov.pt/MDC/Cidadao/NIC":
                                user_nic = value.text
                            elif attr_name == "http://interop.gov.pt/MDC/Cidadao/NomeProprio":
                                first_name = value.text
                            elif attr_name == "http://interop.gov.pt/MDC/Cidadao/NomeApelido":
                                last_name = value.text
                        except (AttributeError, KeyError):
                            pass
                    current_app.logger.info(
                        f"eIDAS atributos via XML manual: email={user_email}, nic={user_nic}, "
                        f"nome={first_name} {last_name}"
                    )
                else:
                    current_app.logger.warning(
                        "eIDAS: AttributeStatement não encontrado no XML — "
                        "as assertions podem estar encriptadas"
                    )
        except Exception as e:
            current_app.logger.error(f"eIDAS: Erro no parsing manual do XML: {e}")

    if not user_email and not user_nic:
        current_app.logger.error(
            "eIDAS SSO: nenhum atributo extraído (email/NIC). "
            "Verificar se as assertions estão encriptadas e se o pysaml2 "
            "tem acesso à chave privada para desencriptar."
        )

    user, status = _find_or_create_saml_user(user_email, user_nic, first_name, last_name)

    if status == "migration_candidate" and current_app.config.get("MIGRATION_MODE_ENABLED", False):
        return _handle_migration_redirect(user, user_email, user_nic, first_name, last_name)

    return _handle_saml_user_login(user)


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

    session.pop("saml_login", None)
    logout_user()
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
    nid = NameID(
        format=NAMEID_FORMAT_UNSPECIFIED,
        text="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
    )

    logout_url = LogoutUrl(
        text=_frontend_saml_url("saml.eidas_logout_postback")
    )
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

    has_nic = current_user.extras and current_user.extras.get("auth_nic")
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
        return jsonify({"pending": False})

    user_email = pending.get("saml_email")
    has_email = bool(user_email)

    # Fetch legacy account details for user confirmation
    legacy_user_id = pending.get("legacy_user_id")
    first_name = None
    last_name = None
    if legacy_user_id:
        from udata.core.user.models import User

        user = User.objects(id=legacy_user_id).first()
        if user:
            first_name = user.first_name
            last_name = user.last_name

    return jsonify(
        {
            "pending": True,
            "email": _mask_email(user_email) if user_email else None,
            "has_email": has_email,
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

    data = request.get_json(silent=True) or {}
    email = data.get("email")
    first_name = data.get("first_name")
    last_name = data.get("last_name")

    user = _find_legacy_user(email=email, first_name=first_name, last_name=last_name)
    if not user:
        return jsonify({"found": False})

    pending["legacy_user_id"] = str(user.id)
    pending["saml_email"] = user.email
    session["saml_migration_pending"] = pending
    session.modified = True

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

    legacy_user_id = pending.get("legacy_user_id")
    if not legacy_user_id:
        return jsonify({"error": "No legacy user found"}), 400

    from udata.core.user.models import User

    user = User.objects(id=legacy_user_id).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    if method == "code":
        code_data = session.get("migration_code")
        if not code_data:
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
        password = data.get("password", "")
        if not verify_and_update_password(password, user):
            return jsonify({"error": "Invalid password"}), 400

    else:
        return jsonify({"error": "Invalid method"}), 400

    # Merge: add NIC, clear password, update names
    saml_nic = pending.get("saml_nic")
    saml_first_name = pending.get("saml_first_name")
    saml_last_name = pending.get("saml_last_name")

    if not user.extras:
        user.extras = {}
    if saml_nic:
        user.extras["auth_nic"] = saml_nic
    user.password = None
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

    current_app.logger.info(f"Account migration completed for user {user.id}")

    return jsonify({"success": True})


@autenticacao_gov.route("/saml/migration/skip", methods=["POST"])
@csrf.exempt
def migration_skip():
    """Skip migration and create a new account from SAML data."""
    if not _migration_enabled():
        return jsonify({"error": "Migration mode is not enabled"}), 403

    pending = session.get("saml_migration_pending")
    if not pending:
        return jsonify({"error": "No pending migration"}), 400

    saml_nic = pending.get("saml_nic")
    saml_first_name = pending.get("saml_first_name")
    saml_last_name = pending.get("saml_last_name")

    # Generate a unique email to avoid conflicts with the legacy account
    import uuid

    saml_email = f"saml-{saml_nic or uuid.uuid4().hex[:8]}@autenticacao.gov.pt"

    user_data = {
        "first_name": (saml_first_name or "").title(),
        "last_name": (saml_last_name or "").title(),
        "email": saml_email,
    }
    if saml_nic:
        user_data["extras"] = {"auth_nic": saml_nic}

    user = datastore.create_user(**user_data)
    user.confirmed_at = datetime.utcnow()
    datastore.commit()

    login_user(user)
    session["saml_login"] = True

    # Clean up migration session data
    session.pop("saml_migration_pending", None)
    session.pop("migration_code", None)
    session.pop("migration_send_count", None)

    return jsonify({"success": True})
