"""
Upload file validation to prevent malicious file uploads.

This module provides centralized content validation for all uploaded files,
protecting against polyglot files, XSS via image metadata, XXE in XML files,
and files whose content does not match their claimed extension/MIME type.
"""

import logging
import os
import re

log = logging.getLogger(__name__)

# Magic bytes for common image formats
IMAGE_MAGIC = {
    "image/png": b"\x89PNG\r\n\x1a\n",
    "image/jpeg": b"\xff\xd8\xff",
    "image/gif": (b"GIF87a", b"GIF89a"),
    "image/webp": b"RIFF",  # Full check: RIFF....WEBP
    "image/bmp": b"BM",
    "image/tiff": (b"II\x2a\x00", b"MM\x00\x2a"),
}

# MIME types that are XML-based and need XML-specific scanning
XML_MIME_TYPES = {
    "application/xml",
    "text/xml",
    "application/rdf+xml",
    "image/svg+xml",
    "application/xhtml+xml",
}

XML_EXTENSIONS = {"xml", "svg", "svgz", "xhtml", "rdf"}

# Patterns that indicate active/dangerous content in any file
DANGEROUS_CONTENT_PATTERNS = [
    r"<script",
    r"javascript:",
    r"on\w+\s*=",
    r"<iframe",
    r"<object",
    r"<embed",
    r"<foreignobject",
]

# Additional patterns specific to XML files (XXE)
XML_DANGEROUS_PATTERNS = DANGEROUS_CONTENT_PATTERNS + [
    r"<!entity\s",
    r"<!doctype\s[^>]*\[",
    r"system\s+[\"']",
]

# Image MIME types where we should verify magic bytes
IMAGE_MIME_TYPES = {
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "image/bmp",
    "image/tiff",
}

# Extensions mapped to expected MIME prefixes for basic sanity checking
IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "jpe", "gif", "webp", "bmp", "tiff", "tif"}


def _check_magic_bytes(filepath, expected_mime):
    """Verify that the file's magic bytes match the expected MIME type."""
    magic = IMAGE_MAGIC.get(expected_mime)
    if magic is None:
        return True  # No magic check for this MIME type

    try:
        with open(filepath, "rb") as f:
            header = f.read(16)
    except OSError:
        return False

    if not header:
        return False

    if isinstance(magic, tuple):
        return any(header.startswith(m) for m in magic)

    if expected_mime == "image/webp":
        # RIFF....WEBP format
        return header[:4] == b"RIFF" and header[8:12] == b"WEBP"

    return header.startswith(magic)


def _scan_for_dangerous_content(filepath, patterns):
    """Scan file content for dangerous patterns (scripts, XXE, etc.)."""
    try:
        with open(filepath, "r", errors="ignore") as f:
            content = f.read().lower()
    except OSError:
        return None

    for pattern in patterns:
        if re.search(pattern, content):
            return pattern
    return None


def _validate_image_is_parseable(filepath, mime):
    """Use Pillow to verify the image is actually a valid image file."""
    try:
        from PIL import Image

        with Image.open(filepath) as img:
            img.verify()
        return True
    except Exception:
        return False


def validate_upload(filepath, mime, extension):
    """
    Validate an uploaded file for malicious content.

    Returns None if the file is safe, or an error message string if it should be rejected.
    Deletes the file from disk if it is rejected.
    """
    mime = (mime or "").lower()
    extension = (extension or "").lower()

    # 1. Block HTML MIME types
    if "html" in mime:
        _remove_file(filepath)
        return "Incorrect file content type: HTML"

    # 2. For image files: verify magic bytes match claimed type
    if mime in IMAGE_MIME_TYPES or extension in IMAGE_EXTENSIONS:
        if not _check_magic_bytes(filepath, mime):
            _remove_file(filepath)
            return "File content does not match the claimed image format"

        # Verify Pillow can parse it (catches polyglot files)
        if not _validate_image_is_parseable(filepath, mime):
            _remove_file(filepath)
            return "File is not a valid image"

        # Even for valid images, scan for embedded script content
        # (polyglot files can be valid images AND contain scripts in metadata)
        match = _scan_for_dangerous_content(filepath, DANGEROUS_CONTENT_PATTERNS)
        if match:
            _remove_file(filepath)
            return "Image file contains suspicious active content"

    # 3. For XML-based files: scan for XSS + XXE patterns
    elif mime in XML_MIME_TYPES or extension in XML_EXTENSIONS:
        match = _scan_for_dangerous_content(filepath, XML_DANGEROUS_PATTERNS)
        if match:
            _remove_file(filepath)
            return "XML-based files with active content or entity declarations are not allowed"

    # 4. For all other files: scan for HTML/script injection
    else:
        match = _scan_for_dangerous_content(filepath, DANGEROUS_CONTENT_PATTERNS)
        if match:
            _remove_file(filepath)
            return "File contains suspicious active content"

    return None


def validate_image_stream(file_storage):
    """
    Validate an image uploaded as a Werkzeug FileStorage stream.

    Used by parse_uploaded_image() for avatars, logos, reuse images, post images.
    Returns None if the file is safe, or an error message string if it should be rejected.
    The stream position is reset after validation.
    """
    mime = (file_storage.mimetype or "").lower()

    # 1. Check magic bytes from the stream
    header = file_storage.stream.read(16)
    file_storage.stream.seek(0)

    if not header:
        return "Uploaded file is empty"

    magic = IMAGE_MAGIC.get(mime)
    if magic is not None:
        if isinstance(magic, tuple):
            if not any(header.startswith(m) for m in magic):
                return "File content does not match the claimed image format"
        elif mime == "image/webp":
            if header[:4] != b"RIFF" or header[8:12] != b"WEBP":
                return "File content does not match the claimed image format"
        elif not header.startswith(magic):
            return "File content does not match the claimed image format"

    # 2. Verify Pillow can parse it
    try:
        from PIL import Image

        file_storage.stream.seek(0)
        with Image.open(file_storage.stream) as img:
            img.verify()
    except Exception:
        file_storage.stream.seek(0)
        return "File is not a valid image"

    # 3. Scan raw bytes for embedded script content
    file_storage.stream.seek(0)
    raw = file_storage.stream.read().lower()
    file_storage.stream.seek(0)

    # Decode as text for pattern matching (ignore binary noise)
    try:
        text = raw.decode("utf-8", errors="ignore")
    except Exception:
        text = raw.decode("latin-1", errors="ignore")

    for pattern in DANGEROUS_CONTENT_PATTERNS:
        if re.search(pattern, text):
            return "Image file contains suspicious active content"

    return None


def _remove_file(filepath):
    """Safely remove a file from disk."""
    try:
        os.remove(filepath)
    except OSError:
        log.warning(f"Could not remove rejected upload: {filepath}")
