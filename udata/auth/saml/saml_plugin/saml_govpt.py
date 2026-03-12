# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import base64
import os
import xml.etree.ElementTree as ET

from flask import Blueprint, current_app, redirect, request, session, url_for
from flask_login import login_user, logout_user
from flask_security.confirmable import requires_confirmation, send_confirmation_instructions
from flask_security.decorators import anonymous_user_required
from flask_security.utils import do_flash, get_message
from saml2 import (
    BINDING_HTTP_POST,
    BINDING_HTTP_REDIRECT,
    element_to_extension_element,
    entity,
    sigver,
)
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
from saml2.pack import http_form_post_message
from saml2.saml import NAMEID_FORMAT_UNSPECIFIED, NameID
from saml2.samlp import Extensions
from saml2.sigver import SignatureError
from saml2 import xmldsig as ds

# autenticacao.gov uses C14N 1.0 (http://www.w3.org/TR/2001/REC-xml-c14n-20010315)
# but pysaml2 only allows Exclusive C14N by default. Add C14N 1.0 to allowed sets.
_C14N_INCLUSIVE = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
_C14N_INCLUSIVE_WITH_COMMENTS = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
ds.ALLOWED_CANONICALIZATIONS.add(_C14N_INCLUSIVE)
ds.ALLOWED_CANONICALIZATIONS.add(_C14N_INCLUSIVE_WITH_COMMENTS)
ds.ALLOWED_TRANSFORMS.add(_C14N_INCLUSIVE)
ds.ALLOWED_TRANSFORMS.add(_C14N_INCLUSIVE_WITH_COMMENTS)

from udata.app import csrf
from udata.models import datastore

from .faa_level import FAAALevel, LogoutUrl
from .requested_atributes import RequestedAttribute, RequestedAttributes


def _resolve_path(path):
    """Resolve a config path relative to the backend root directory."""
    if os.path.isabs(path):
        return path
    backend_root = os.path.dirname(current_app.root_path)
    return os.path.join(backend_root, path)

autenticacao_gov = Blueprint('saml', __name__)


def _first_value(identity, key):
    """Extract the first value for a key from pysaml2 identity dict."""
    values = identity.get(key, [])
    if isinstance(values, list) and values:
        return values[0]
    if isinstance(values, str) and values:
        return values
    return None


def _find_or_create_saml_user(user_email, user_nic, first_name, last_name):
    """Find an existing user by email/NIC or auto-create from SAML data."""
    user = None
    if user_email:
        user = datastore.find_user(email=user_email)
    if not user and user_nic:
        user = datastore.find_user(extras={'auth_nic': user_nic})

    if not user:
        if not user_email and not user_nic:
            current_app.logger.error(
                "SAML: Cannot create user without email or NIC"
            )
            return None

        # Generate a placeholder email when the IdP does not provide one.
        if not user_email:
            import uuid
            user_email = f"saml-{user_nic or uuid.uuid4().hex[:8]}@autenticacao.gov.pt"

        user_data = {
            'first_name': (first_name or '').title(),
            'last_name': (last_name or '').title(),
            'email': user_email,
        }
        if user_nic:
            user_data['extras'] = {'auth_nic': user_nic}

        user = datastore.create_user(**user_data)
        datastore.commit()
        send_confirmation_instructions(user)

    return user


def _handle_saml_user_login(user):
    """Handle login/redirect after SAML authentication."""
    frontend_url = current_app.config.get('CDATA_BASE_URL') or ''

    if user is None:
        do_flash(*get_message('CONFIRMATION_REQUIRED'))
        return redirect(f"{frontend_url}/pages/login")

    if requires_confirmation(user):
        do_flash(*get_message('CONFIRMATION_REQUIRED'))
        return redirect(f"{frontend_url}/pages/login")

    if user.deleted:
        do_flash(*get_message('DISABLED_ACCOUNT'))
        return redirect(frontend_url or url_for('site.home'))

    login_user(user)
    session['saml_login'] = True
    return redirect(frontend_url or url_for('site.home'))


#################################################################
# Given the name of an IdP, return a configuation.
##
#################################################################


def _build_sp_settings(acs_url, out_url, metadata_file):
    """Build pysaml2 SP settings with encryption support."""
    key_file = _resolve_path(current_app.config.get('SECURITY_SAML_KEY_FILE'))
    cert_file = _resolve_path(current_app.config.get('SECURITY_SAML_CERT_FILE'))

    return {
        'entityid': current_app.config.get('SECURITY_SAML_ENTITY_ID'),
        'name': current_app.config.get('SECURITY_SAML_ENTITY_NAME'),
        'key_file': key_file,
        'cert_file': cert_file,
        # Use SHA256 — this xmlsec1 build does not support rsa-sha1
        'signing_algorithm': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
        'digest_algorithm': 'http://www.w3.org/2001/04/xmlenc#sha256',
        # Keypair for decrypting encrypted assertions from autenticacao.gov
        'encryption_keypairs': [
            {
                'key_file': key_file,
                'cert_file': cert_file,
            },
        ],
        'metadata': {
            "local": [_resolve_path(metadata_file)]
        },
        'accepted_time_diff': 60,
        'service': {
            'sp': {
                'endpoints': {
                    'assertion_consumer_service': [
                        (acs_url, BINDING_HTTP_REDIRECT),
                        (acs_url, BINDING_HTTP_POST)
                    ],
                    'single_logout_service': [
                        (out_url, BINDING_HTTP_REDIRECT),
                        (out_url, BINDING_HTTP_POST),
                    ],
                },
                # Don't verify that the incoming requests originate from us via
                # the built-in cache for authn request ids in pysaml2
                'allow_unsolicited': True,
                # Sign authn requests
                'authn_requests_signed': True,
                'logout_requests_signed': True,
                'want_assertions_signed': True,
                'want_response_signed': True,
            },
        },
    }


def _force_scheme(url):
    """Force the URL scheme to match PREFERRED_URL_SCHEME config.

    Next.js rewrites proxy requests to the backend over plain HTTP,
    so Flask sees http:// even when the real client uses https://.
    """
    scheme = current_app.config.get('PREFERRED_URL_SCHEME')
    if scheme and url.startswith('http://') and scheme == 'https':
        return 'https://' + url[len('http://'):]
    return url


def saml_client_for(metadata_file):

    acs_url = _force_scheme(url_for("saml.idp_initiated", _external=True))
    out_url = _force_scheme(url_for("saml.saml_logout_postback", _external=True))

    settings = _build_sp_settings(acs_url, out_url, metadata_file)
    spConfig = Saml2Config()
    spConfig.load(settings)
    saml_client = Saml2Client(config=spConfig)
    return saml_client


#################################################################
# Prepares and sends SAML Auth Request.
##
#################################################################
@autenticacao_gov.route('/saml/login')
@anonymous_user_required
def sp_initiated():
    saml_client = saml_client_for(current_app.config.get(
        'SECURITY_SAML_IDP_METADATA').split(',')[0])

    faa = FAAALevel(text=str(current_app.config.get('SECURITY_SAML_FAAALEVEL')))

    spcertenc = RequestedAttributes([
        RequestedAttribute(name="http://interop.gov.pt/MDC/Cidadao/CorreioElectronico",
                           name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri", is_required='True'),
        RequestedAttribute(name="http://interop.gov.pt/MDC/Cidadao/NIC",
                           name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri", is_required='False'),
        RequestedAttribute(name="http://interop.gov.pt/MDC/Cidadao/NomeProprio",
                           name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri", is_required='False'),
        RequestedAttribute(name="http://interop.gov.pt/MDC/Cidadao/NomeApelido",
                           name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri", is_required='False')
    ])

    extensions = Extensions(
        extension_elements=[element_to_extension_element(
            faa), element_to_extension_element(spcertenc)]
    )

    args = {
        'binding': BINDING_HTTP_POST,
        'relay_state': 'dWRhdGEtZ291dnB0',
        'sign': True,
        'force_authn': 'true',
        'is_passive': 'false',
        'nameid_format': '',
        'extensions': extensions
    }

    reqid, info = saml_client.prepare_for_authenticate(**args)
    response = info['data']
    return response

#################################################################
# Receives SAML Response.
##
#################################################################


@autenticacao_gov.route('/saml/sso', methods=['POST'])
@csrf.exempt
def idp_initiated():
    user_email = None
    user_nic = None
    first_name = None
    last_name = None
    authn_response = None

    raw_saml_response = request.form.get('SAMLResponse')
    if not raw_saml_response:
        return "Erro: SAMLResponse em falta", 400

    auth_servers = current_app.config.get('SECURITY_SAML_IDP_METADATA').split(',')

    # 0. Verificar se o IdP rejeitou o pedido (antes de tentar pysaml2)
    try:
        decoded_xml = base64.b64decode(raw_saml_response)
        xml_str = None
        for codec in ['utf-8', 'ISO-8859-1']:
            try:
                xml_str = decoded_xml.decode(codec)
                break
            except UnicodeDecodeError:
                continue
        if xml_str:
            status_root = ET.fromstring(xml_str)
            ns = {'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol'}
            status_code = status_root.find('.//samlp:StatusCode', ns)
            status_msg = status_root.find('.//samlp:StatusMessage', ns)
            if status_code is not None:
                status_value = status_code.attrib.get('Value', '')
                if 'Success' not in status_value:
                    msg = status_msg.text if status_msg is not None else status_value
                    current_app.logger.error(f"SAML: IdP rejeitou o pedido: {msg}")
                    frontend_url = current_app.config.get('CDATA_BASE_URL') or ''
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
                f"SAML Erro ao processar resposta com {server}: "
                f"{type(e).__name__}: {e}",
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
                user_email = _first_value(identity, 'http://interop.gov.pt/MDC/Cidadao/CorreioElectronico')
                user_nic = _first_value(identity, 'http://interop.gov.pt/MDC/Cidadao/NIC')
                first_name = _first_value(identity, 'http://interop.gov.pt/MDC/Cidadao/NomeProprio')
                last_name = _first_value(identity, 'http://interop.gov.pt/MDC/Cidadao/NomeApelido')
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
        current_app.logger.error("SAML: pysaml2 não conseguiu processar a resposta de nenhum servidor")

    # 3. Fallback: parsing manual do XML (para respostas não encriptadas)
    if not user_email and not user_nic:
        current_app.logger.info("pysaml2 não extraiu atributos, a tentar parsing manual do XML")
        try:
            decoded_response = base64.b64decode(raw_saml_response)
            root = None
            for codec in ['utf-8', 'ISO-8859-1']:
                try:
                    decoded_str = decoded_response.decode(codec)
                    root = ET.fromstring(decoded_str)
                    break
                except (UnicodeDecodeError, ET.ParseError):
                    continue

            if root is not None:
                ns = {
                    'assertion': 'urn:oasis:names:tc:SAML:2.0:assertion',
                    'atributos': 'http://autenticacao.cartaodecidadao.pt/atributos',
                }
                attribute_statement = root.find('.//assertion:AttributeStatement', ns)
                if attribute_statement is not None:
                    for child in attribute_statement:
                        try:
                            attr_name = child.attrib.get('Name', '')
                            value = child.find('.//assertion:AttributeValue', ns)
                            if value is None or value.text is None:
                                continue
                            if attr_name == 'http://interop.gov.pt/MDC/Cidadao/CorreioElectronico':
                                user_email = value.text
                            elif attr_name == 'http://interop.gov.pt/MDC/Cidadao/NIC':
                                user_nic = value.text
                            elif attr_name == 'http://interop.gov.pt/MDC/Cidadao/NomeProprio':
                                first_name = value.text
                            elif attr_name == 'http://interop.gov.pt/MDC/Cidadao/NomeApelido':
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

    userUdata = _find_or_create_saml_user(user_email, user_nic, first_name, last_name)
    return _handle_saml_user_login(userUdata)


#################################################################
# Receives SAML Logout
#################################################################
@autenticacao_gov.route('/saml/sso_logout', methods=['POST'])
@csrf.exempt
def saml_logout_postback():

    auth_servers = current_app.config.get('SECURITY_SAML_IDP_METADATA').split(',')

    for server in auth_servers:
        saml_client = saml_client_for(server)
        try:
            authn_response = saml_client.parse_logout_request_response(
                request.form['SAMLResponse'], entity.BINDING_HTTP_POST)
        except sigver.MissingKey:
            continue
        else:
            break

    session.pop('saml_login', None)
    logout_user()
    return redirect(url_for('site.home'))


#################################################################
# Sends SAML Logout
#################################################################
@autenticacao_gov.route('/saml/logout')
def saml_logout():
    saml_client = saml_client_for(current_app.config.get(
        'SECURITY_SAML_IDP_METADATA').split(',')[0])
    nid = NameID(format=NAMEID_FORMAT_UNSPECIFIED,
                 text="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")

    logout_url = LogoutUrl(text=_force_scheme(url_for("saml.saml_logout_postback", _external=True)))
    destination = current_app.config.get('SECURITY_SAML_FA_URL')

    extensions = Extensions(extension_elements=[logout_url])

    req_id, logout_request = saml_client.create_logout_request(
        name_id=nid,
        destination=destination,
        issuer_entity_id=current_app.config.get('SECURITY_SAML_ENTITY_ID'),
        sign=True,
        consent="urn:oasis:names:tc:SAML:2.0:logout:user",
        extensions=extensions
    )

    post_message = http_form_post_message(message=logout_request, location=destination)
    return post_message['data']


#################################################################
# eIDAS
##
#################################################################


def eidas_client_for(metadata_file):

    acs_url = _force_scheme(url_for("saml.idp_eidas_initiated", _external=True))
    out_url = _force_scheme(url_for("saml.eidas_logout_postback", _external=True))

    settings = _build_sp_settings(acs_url, out_url, metadata_file)
    spConfig = Saml2Config()
    spConfig.load(settings)
    saml_client = Saml2Client(config=spConfig)
    return saml_client


#################################################################
# Prepares and sends eIDAS Auth Request.
##
#################################################################
@autenticacao_gov.route('/saml/eidas/login')
@anonymous_user_required
def sp_eidas_initiated():
    saml_client = eidas_client_for(current_app.config.get(
        'SECURITY_SAML_IDP_METADATA').split(',')[0])

    faa = FAAALevel(text=str(current_app.config.get('SECURITY_SAML_FAAALEVEL')))

    spcertenc = RequestedAttributes([
        RequestedAttribute(name="http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier",
                           name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri", is_required='True'),
        RequestedAttribute(name="http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName",
                           name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri", is_required='False'),
        RequestedAttribute(name="http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName",
                           name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri", is_required='False'),
        RequestedAttribute(name="http://eidas.europa.eu/attributes/naturalperson/DateOfBirth",
                           name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri", is_required='False'),
        RequestedAttribute(name="http://eidas.europa.eu/attributes/naturalperson/CurrentAddress",
                           name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri", is_required='False'),
        RequestedAttribute(name="http://eidas.europa.eu/attributes/naturalperson/Gender",
                           name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri", is_required='False'),
        RequestedAttribute(name="http://eidas.europa.eu/attributes/naturalperson/PlaceOfBirth",
                           name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri", is_required='False'),
    ])

    extensions = Extensions(
        extension_elements=[element_to_extension_element(
            faa), element_to_extension_element(spcertenc)]
    )

    args = {
        'binding': BINDING_HTTP_POST,
        'relay_state': 'dWRhdGEtZ291dnB0',
        'sign': True,
        'force_authn': 'true',
        'is_passive': 'false',
        'nameid_format': '',
        'extensions': extensions
    }

    reqid, info = saml_client.prepare_for_authenticate(**args)
    response = info['data']
    return response
#################################################################
# Receives eIDAS Response.
##
#################################################################


@autenticacao_gov.route('/saml/eidas/sso', methods=['POST'])
@csrf.exempt
def idp_eidas_initiated():
    user_email = None
    user_nic = None
    first_name = None
    last_name = None
    authn_response = None

    raw_saml_response = request.form.get('SAMLResponse')
    if not raw_saml_response:
        return "Erro: SAMLResponse em falta", 400

    auth_servers = current_app.config.get('SECURITY_SAML_IDP_METADATA').split(',')

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
                user_email = _first_value(identity, 'http://interop.gov.pt/MDC/Cidadao/CorreioElectronico')
                user_nic = _first_value(identity, 'http://interop.gov.pt/MDC/Cidadao/NIC')
                first_name = _first_value(identity, 'http://interop.gov.pt/MDC/Cidadao/NomeProprio')
                last_name = _first_value(identity, 'http://interop.gov.pt/MDC/Cidadao/NomeApelido')
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
            for codec in ['utf-8', 'ISO-8859-1']:
                try:
                    decoded_str = decoded_response.decode(codec)
                    root = ET.fromstring(decoded_str)
                    break
                except (UnicodeDecodeError, ET.ParseError):
                    continue

            if root is not None:
                ns = {
                    'assertion': 'urn:oasis:names:tc:SAML:2.0:assertion',
                    'atributos': 'http://autenticacao.cartaodecidadao.pt/atributos',
                }
                attribute_statement = root.find('.//assertion:AttributeStatement', ns)
                if attribute_statement is not None:
                    for child in attribute_statement:
                        try:
                            attr_name = child.attrib.get('Name', '')
                            value = child.find('.//assertion:AttributeValue', ns)
                            if value is None or value.text is None:
                                continue
                            if attr_name == 'http://interop.gov.pt/MDC/Cidadao/CorreioElectronico':
                                user_email = value.text
                            elif attr_name == 'http://interop.gov.pt/MDC/Cidadao/NIC':
                                user_nic = value.text
                            elif attr_name == 'http://interop.gov.pt/MDC/Cidadao/NomeProprio':
                                first_name = value.text
                            elif attr_name == 'http://interop.gov.pt/MDC/Cidadao/NomeApelido':
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

    userUdata = _find_or_create_saml_user(user_email, user_nic, first_name, last_name)
    return _handle_saml_user_login(userUdata)


#################################################################
# Receives eIDAS Logout
#################################################################
@autenticacao_gov.route('/saml/eidas/sso_logout', methods=['POST'])
@csrf.exempt
def eidas_logout_postback():

    auth_servers = current_app.config.get('SECURITY_SAML_IDP_METADATA').split(',')

    for server in auth_servers:
        saml_client = eidas_client_for(server)
        try:
            authn_response = saml_client.parse_logout_request_response(
                request.form['SAMLResponse'], entity.BINDING_HTTP_POST)
        except sigver.MissingKey:
            continue
        else:
            break

    session.pop('saml_login', None)
    logout_user()
    return redirect(url_for('site.home'))


#################################################################
# Sends eIDAS Logout
#################################################################
@autenticacao_gov.route('/saml/eidas/logout')
def eidas_logout():
    saml_client = eidas_client_for(current_app.config.get(
        'SECURITY_SAML_IDP_METADATA').split(',')[0])
    nid = NameID(format=NAMEID_FORMAT_UNSPECIFIED,
                 text="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")

    logout_url = LogoutUrl(text=_force_scheme(url_for("saml.eidas_logout_postback", _external=True)))
    destination = current_app.config.get('SECURITY_SAML_FA_URL')

    extensions = Extensions(extension_elements=[logout_url])

    req_id, logout_request = saml_client.create_logout_request(
        name_id=nid,
        destination=destination,
        issuer_entity_id=current_app.config.get('SECURITY_SAML_ENTITY_ID'),
        sign=True,
        consent="urn:oasis:names:tc:SAML:2.0:logout:user",
        extensions=extensions
    )

    post_message = http_form_post_message(message=logout_request, location=destination)
    return post_message['data']
