# -*- coding: utf-8 -*
#
# SAML user registration is now handled automatically in saml_govpt.py
# via _find_or_create_saml_user(). No separate registration endpoint needed.
#
# This module only re-exports the blueprint for backwards compatibility.
##

from .saml_govpt import autenticacao_gov  # noqa: F401
