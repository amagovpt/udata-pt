# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from flask import current_app, Blueprint, url_for, request, redirect, session
from flask_login import login_user, logout_user
from flask_security.utils import get_message, do_flash
from flask_security.decorators import anonymous_user_required
from flask_security.confirmable import requires_confirmation

from udata.app import csrf
from udata.models import datastore

from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2 import entity, element_to_extension_element, sigver
from saml2.samlp import Extensions
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
from saml2.saml import NameID, NAMEID_FORMAT_UNSPECIFIED
from saml2.pack import http_form_post_message
from saml2.sigver import SignatureError

import base64
import xml.etree.ElementTree as ET

from .faa_level import FAAALevel, LogoutUrl
from .requested_atributes import RequestedAttributes, RequestedAttribute

autenticacao_gov = Blueprint('saml', __name__)

#################################################################
# Given the name of an IdP, return a configuation.
##
#################################################################


def saml_client_for(metadata_file):

    acs_url = url_for("saml.idp_initiated", _external=True)
    out_url = url_for("saml.saml_logout_postback", _external=True)

    settings = {
        'entityid': current_app.config.get('SECURITY_SAML_ENTITY_ID'),
        'name': current_app.config.get('SECURITY_SAML_ENTITY_NAME'),
        'key_file': current_app.config.get('SECURITY_SAML_KEY_FILE'),
        'cert_file': current_app.config.get('SECURITY_SAML_CERT_FILE'),
        'metadata': {
            "local": [metadata_file]
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
    root = None  # Inicialize root para evitar UnboundLocalError

    auth_servers = current_app.config.get('SECURITY_SAML_IDP_METADATA').split(',')

    for server in auth_servers:
        saml_client = saml_client_for(server)
        try:
            #decoded_response = base64.b64decode(request.form['SAMLResponse']).decode('utf-8')
            decoded_response = base64.b64decode(request.form['SAMLResponse'])
            root = None
            for codec in ['utf-8', 'ISO-8859-1']:  # Diferentes codecs
                try:
                    decoded_response_str = decoded_response.decode(codec)
                    root = ET.fromstring(decoded_response_str)
                    break
                except UnicodeDecodeError:
                    continue
            if root is None:
                raise ValueError("Não foi possível decodificar o XML com codecs disponíveis.")
            authn_response = saml_client.parse_authn_request_response(decoded_response, entity.BINDING_HTTP_POST)
            root = ET.fromstring(decoded_response)  # Analisar a resposta decodificada para diagnóstico
        except sigver.MissingKey:
            continue
        except SignatureError as se:
            current_app.logger.error(f"SignatureError: {se}")
            # Adicione qualquer ação necessária em caso de erro na assinatura
        except ET.ParseError as pe:
            current_app.logger.error(f"XML Parse Error: {pe}")
            current_app.logger.error(f"Invalid XML: {decoded_response}")
            # Adicione qualquer ação necessária em caso de erro de análise XML
        except Exception as e:
            current_app.logger.error(f"Error processing XML: {e}")
            # Adicione qualquer ação necessária em caso de outros erros relacionados ao XML
        else:
            # Se nenhum servidor com assinatura válida for encontrado, retornar um erro
            #return "Erro: Assinatura ausente ou inválida na resposta SAML", 400
            break
    
    #if root is None:
        # Se não foi possível obter a raiz do XML, retornar um erro ou fazer qualquer ação necessária
    #    return "Erro: Não foi possível obter a raiz do XML", 400

    ns = {'assertion': 'urn:oasis:names:tc:SAML:2.0:assertion',
          'atributos': 'http://autenticacao.cartaodecidadao.pt/atributos'}

    for child in root.find('.//assertion:AttributeStatement', ns):
        try:
            if child.attrib['Name'] == 'http://interop.gov.pt/MDC/Cidadao/CorreioElectronico':
                user_email = child.find('.//assertion:AttributeValue', ns).text
            elif child.attrib['Name'] == 'http://interop.gov.pt/MDC/Cidadao/NIC':
                user_nic = child.find('.//assertion:AttributeValue', ns).text
            elif child.attrib['Name'] == 'http://interop.gov.pt/MDC/Cidadao/NomeProprio':
                first_name = child.find('.//assertion:AttributeValue', ns).text
            elif child.attrib['Name'] == 'http://interop.gov.pt/MDC/Cidadao/NomeApelido':
                last_name = child.find('.//assertion:AttributeValue', ns).text
        except AttributeError:
            pass

    data = {'email': user_email}
    extras = {'extras': {'auth_nic': user_nic}}
    #userUdata = datastore.find_user(**extras) or datastore.find_user(**data)
    userUdata = datastore.find_user(**data) or datastore.find_user(**extras)

    if not userUdata:
        # Redirects to new custom registration form
        session['user_email'] = user_email
        session['user_nic'] = user_nic
        session['first_name'] = first_name
        session['last_name'] = last_name
        return redirect(url_for('saml.register'))

    elif requires_confirmation(userUdata):
        do_flash(*get_message('CONFIRMATION_REQUIRED'))
        return redirect(url_for('security.login'))

    elif userUdata.deleted:
        do_flash(*get_message('DISABLED_ACCOUNT'))
        return redirect(url_for('site.home'))

    else:
        login_user(userUdata)
        session['saml_login'] = True
        # do_flash(*get_message('PASSWORDLESS_LOGIN_SUCCESSFUL'))
        return redirect(url_for('site.home'))


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

    logout_url = LogoutUrl(text=url_for("saml.saml_logout_postback", _external=True))
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

    acs_url = url_for("saml.idp_eidas_initiated", _external=True)
    out_url = url_for("saml.eidas_logout_postback", _external=True)

    settings = {
        'entityid': current_app.config.get('SECURITY_SAML_ENTITY_ID'),
        'name': current_app.config.get('SECURITY_SAML_ENTITY_NAME'),
        'key_file': current_app.config.get('SECURITY_SAML_KEY_FILE'),
        'cert_file': current_app.config.get('SECURITY_SAML_CERT_FILE'),
        'metadata': {
            "local": [metadata_file]
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
    root = None  # Inicialize root para evitar UnboundLocalError

    auth_servers = current_app.config.get('SECURITY_SAML_IDP_METADATA').split(',')

    for server in auth_servers:
        saml_client = eidas_client_for(server)
        try:
            #decoded_response = base64.b64decode(request.form['SAMLResponse']).decode('utf-8')
            decoded_response = base64.b64decode(request.form['SAMLResponse'])
            root = None
            for codec in ['utf-8', 'ISO-8859-1']:  # Diferentes codecs
                try:
                    decoded_response_str = decoded_response.decode(codec)
                    root = ET.fromstring(decoded_response_str)
                    break
                except UnicodeDecodeError:
                    continue
            if root is None:
                raise ValueError("Não foi possível decodificar o XML com codecs disponíveis.")
            authn_response = saml_client.parse_authn_request_response(decoded_response, entity.BINDING_HTTP_POST)
            root = ET.fromstring(decoded_response)  # Analisar a resposta decodificada para diagnóstico
        except sigver.MissingKey:
            continue
        except SignatureError as se:
            current_app.logger.error(f"SignatureError: {se}")
            # Adicione qualquer ação necessária em caso de erro na assinatura
        except ET.ParseError as pe:
            current_app.logger.error(f"XML Parse Error: {pe}")
            current_app.logger.error(f"Invalid XML: {decoded_response}")
            # Adicione qualquer ação necessária em caso de erro de análise XML
        except Exception as e:
            current_app.logger.error(f"Error processing XML: {e}")
            # Adicione qualquer ação necessária em caso de outros erros relacionados ao XML
        else:
            # Se nenhum servidor com assinatura válida for encontrado, retornar um erro
            #return "Erro: Assinatura ausente ou inválida na resposta SAML", 400
            break
    
    #if root is None:
        # Se não foi possível obter a raiz do XML, retornar um erro ou fazer qualquer ação necessária
    #    return "Erro: Não foi possível obter a raiz do XML", 400

    ns = {'assertion': 'urn:oasis:names:tc:SAML:2.0:assertion',
          'atributos': 'http://autenticacao.cartaodecidadao.pt/atributos'}

    for child in root.find('.//assertion:AttributeStatement', ns):
        try:
            if child.attrib['Name'] == 'http://interop.gov.pt/MDC/Cidadao/CorreioElectronico':
                user_email = child.find('.//assertion:AttributeValue', ns).text
            elif child.attrib['Name'] == 'http://interop.gov.pt/MDC/Cidadao/NIC':
                user_nic = child.find('.//assertion:AttributeValue', ns).text
            elif child.attrib['Name'] == 'http://interop.gov.pt/MDC/Cidadao/NomeProprio':
                first_name = child.find('.//assertion:AttributeValue', ns).text
            elif child.attrib['Name'] == 'http://interop.gov.pt/MDC/Cidadao/NomeApelido':
                last_name = child.find('.//assertion:AttributeValue', ns).text
        except AttributeError:
            pass

    data = {'email': user_email}
    extras = {'extras': {'auth_nic': user_nic}}
    #userUdata = datastore.find_user(**extras) or datastore.find_user(**data)
    userUdata = datastore.find_user(**data) or datastore.find_user(**extras)

    if not userUdata:
        # Redirects to new custom registration form
        session['user_email'] = user_email
        session['user_nic'] = user_nic
        session['first_name'] = first_name
        session['last_name'] = last_name
        return redirect(url_for('saml.register'))

    elif requires_confirmation(userUdata):
        do_flash(*get_message('CONFIRMATION_REQUIRED'))
        return redirect(url_for('security.login'))

    elif userUdata.deleted:
        do_flash(*get_message('DISABLED_ACCOUNT'))
        return redirect(url_for('site.home'))

    else:
        login_user(userUdata)
        session['saml_login'] = True
        # do_flash(*get_message('PASSWORDLESS_LOGIN_SUCCESSFUL'))
        return redirect(url_for('site.home'))


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

    logout_url = LogoutUrl(text=url_for("saml.eidas_logout_postback", _external=True))
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
