# -*- coding: utf-8 -*-
"""
Package for Authentication with portuguese SmartID Cards
with PySAML2
"""

from __future__ import unicode_literals

# Portuguese Single signOn Plugin with PySAML2
# Re-exported: udata/auth/__init__.py imports `blueprint` from this package and
# registers it. Ruff's suggested fix renames the export and breaks SAML/CMD login.
from .register_user import autenticacao_gov as blueprint  # noqa: F401
