"""HTML input sanitization helpers (VULN-2075, VULN-2076).

Two strategies are exposed:

- ``sanitize_strict`` — strips every HTML tag. Use for plain-string fields
  rendered as text where no markup is desired (e.g. ``title``).
- ``sanitize_markdown_html`` — applies the same allow-list as the Jinja
  render-time policy (``UdataCleaner``), so the input contract matches the
  output contract. Use for fields persisted as Markdown that may also
  contain inline HTML (e.g. ``description``, ``about``).
"""

import bleach
from flask import current_app


def sanitize_strict(value):
    """Remove all HTML tags from ``value``.

    Returns the original value when it is empty/falsy so callers do not have
    to special-case ``None``/``""``.
    """
    if not value:
        return value
    return bleach.clean(value, tags=[], strip=True)


def sanitize_markdown_html(value):
    """Sanitize ``value`` against the Markdown HTML allow-list.

    The allow-list is sourced from the application config
    (``MD_ALLOWED_TAGS`` / ``MD_ALLOWED_ATTRIBUTES`` /
    ``MD_ALLOWED_PROTOCOLS``), so input sanitization mirrors the render-time
    policy enforced by ``udata.frontend.markdown.UdataCleaner``.
    """
    if not value:
        return value
    return bleach.clean(
        value,
        tags=current_app.config["MD_ALLOWED_TAGS"],
        attributes=current_app.config["MD_ALLOWED_ATTRIBUTES"],
        protocols=current_app.config["MD_ALLOWED_PROTOCOLS"],
        strip=True,
    )
