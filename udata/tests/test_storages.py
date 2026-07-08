from datetime import UTC, datetime, timedelta
from io import BytesIO
from os.path import basename
from uuid import uuid4

import pytest
from flask import json, url_for
from werkzeug.test import EnvironBuilder
from werkzeug.wrappers import Request

from udata.core import storages
from udata.core.storages import utils
from udata.core.storages.api import META, chunk_filename
from udata.core.storages.tasks import purge_chunks
from udata.core.storages.validation import (
    _SCAN_CHUNK_SIZE,
    PLAIN_TEXT_DANGEROUS_PATTERNS,
    XML_DANGEROUS_PATTERNS,
    _scan_for_dangerous_content,
    validate_upload,
)
from udata.tests import PytestOnlyTestCase
from udata.tests.api import PytestOnlyAPITestCase
from udata.utils import faker

from .helpers import assert200, assert400


class StorageUtilsTest(PytestOnlyTestCase):
    """
    Perform all tests on a file of size 2 * CHUNCK_SIZE = 2 * (2 ** 16).
    Expected values are precomputed with shell `md5sum`, `sha1sum`...
    """

    @pytest.fixture(autouse=True)
    def write_file(self, tmpdir):
        tmpfile = tmpdir.join("test.txt")
        tmpfile.write_binary(b"a" * 2 * (2**16))
        self.file = self.filestorage(str(tmpfile))

    def filestorage(self, filename):
        data = open(filename, "rb")
        builder = EnvironBuilder(method="POST", data={"file": (data, basename(filename))})
        env = builder.get_environ()
        req = Request(env)
        return req.files["file"]

    def test_sha1(self):
        # Output of sha1sum
        expected = "ce5653590804baa9369f72d483ed9eba72f04d29"
        assert utils.sha1(self.file) == expected

    def test_md5(self):
        expected = "81615449a98aaaad8dc179b3bec87f38"  # Output of md5sum
        assert utils.md5(self.file) == expected

    def test_crc32(self):
        expected = "CA975130"  # Output of cksfv
        assert utils.crc32(self.file) == expected

    def test_mime(self):
        assert utils.mime("test.txt") == "text/plain"
        assert utils.mime("test") is None

    def test_extension_default(self, app):
        assert utils.extension("test.txt") == "txt"
        assert utils.extension("prefix/test.txt") == "txt"
        assert utils.extension("prefix.with.dot/test.txt") == "txt"

    def test_extension_compound(self, app):
        assert utils.extension("test.tar.gz") == "tar.gz"
        assert utils.extension("prefix.with.dot/test.tar.gz") == "tar.gz"

    def test_extension_compound_with_allowed_extension(self, app):
        assert utils.extension("test.2022.csv.tar.gz") == "csv.tar.gz"
        assert utils.extension("prefix.with.dot/test.2022.csv.tar.gz") == "csv.tar.gz"

    def test_extension_compound_without_allowed_extension(self, app):
        assert utils.extension("test.2022.tar.gz") == "tar.gz"
        assert utils.extension("prefix.with.dot/test.2022.tar.gz") == "tar.gz"

    def test_no_extension(self, app):
        assert utils.extension("test") is None
        assert utils.extension("prefix/test") is None

    def test_normalize_no_changes(self):
        assert utils.normalize("test.txt") == "test.txt"

    def test_normalize_spaces(self):
        expected = "test-with-spaces.txt"
        assert utils.normalize("test with  spaces.txt") == expected

    def test_normalize_to_lower(self):
        assert utils.normalize("Test.TXT") == "test.txt"

    def test_normalize_special_chars(self):
        assert utils.normalize("éàü@€.txt") == "eau-eur.txt"


class ConfigurableAllowedExtensionsTest(PytestOnlyTestCase):
    def test_has_default(self):
        assert "csv" in storages.CONFIGURABLE_AUTHORIZED_TYPES
        assert "xml" in storages.CONFIGURABLE_AUTHORIZED_TYPES
        assert "json" in storages.CONFIGURABLE_AUTHORIZED_TYPES
        assert "exe" not in storages.CONFIGURABLE_AUTHORIZED_TYPES
        assert "bat" not in storages.CONFIGURABLE_AUTHORIZED_TYPES

    @pytest.mark.options(ALLOWED_RESOURCES_EXTENSIONS=["csv", "json"])
    def test_with_config(self):
        assert "csv" in storages.CONFIGURABLE_AUTHORIZED_TYPES
        assert "json" in storages.CONFIGURABLE_AUTHORIZED_TYPES
        assert "xml" not in storages.CONFIGURABLE_AUTHORIZED_TYPES
        assert "exe" not in storages.CONFIGURABLE_AUTHORIZED_TYPES
        assert "bat" not in storages.CONFIGURABLE_AUTHORIZED_TYPES


@pytest.mark.usefixtures("instance_path")
class StorageUploadViewTest(PytestOnlyAPITestCase):
    def test_standard_upload(self):
        self.login()
        response = self.post(
            url_for("storage.upload", name="resources"),
            {"file": (BytesIO(b"aaa"), "Test with  spaces.TXT")},
            json=False,
        )

        assert200(response)
        assert response.json["success"]
        assert "url" in response.json
        assert "size" in response.json
        assert "sha1" in response.json
        assert "filename" in response.json
        filename = response.json["filename"]
        assert filename.endswith("test-with-spaces.txt")
        expected = storages.resources.url(filename, external=True)
        assert response.json["url"] == expected
        assert response.json["mime"] == "text/plain"

    def test_chunked_upload(self):
        self.login()
        url = url_for("storage.upload", name="tmp")
        uuid = str(uuid4())
        parts = 4

        for i in range(parts):
            response = self.post(
                url,
                {
                    "file": (BytesIO(b"a"), "blob"),
                    "uuid": uuid,
                    "filename": "Test with  spaces.TXT",
                    "partindex": i,
                    "partbyteoffset": 0,
                    "totalfilesize": parts,
                    "totalparts": parts,
                    "chunksize": 1,
                },
                json=False,
            )

            assert200(response)
            assert response.json["success"]
            assert "filename" not in response.json
            assert "url" not in response.json
            assert "size" not in response.json
            assert "sha1" not in response.json
            assert "url" not in response.json

        response = self.post(
            url,
            {
                "uuid": uuid,
                "filename": "Test with  spaces.TXT",
                "totalfilesize": parts,
                "totalparts": parts,
            },
            json=False,
        )
        assert "filename" in response.json
        assert "url" in response.json
        assert "size" in response.json
        assert response.json["size"] == parts
        assert "sha1" in response.json
        expected_filename = "test-with-spaces.txt"
        filename = response.json["filename"]
        assert filename.endswith(expected_filename)
        expected_url = storages.tmp.url(filename, external=True)
        assert response.json["url"] == expected_url
        assert response.json["mime"] == "text/plain"
        assert storages.tmp.read(filename) == b"aaaa"
        assert list(storages.chunks.list_files()) == []

    def test_chunked_upload_bad_chunk(self):
        self.login()
        url = url_for("storage.upload", name="tmp")
        uuid = str(uuid4())
        parts = 4

        response = self.post(
            url,
            {
                "file": (BytesIO(b"a"), "blob"),
                "uuid": uuid,
                "filename": "test.txt",
                "partindex": 0,
                "partbyteoffset": 0,
                "totalfilesize": parts,
                "totalparts": parts,
                "chunksize": 10,  # Does not match
            },
            json=False,
        )

        assert400(response)
        assert not response.json["success"]
        assert "filename" not in response.json
        assert "url" not in response.json
        assert "size" not in response.json
        assert "sha1" not in response.json
        assert "url" not in response.json

        assert list(storages.chunks.list_files()) == []

    @pytest.mark.options(RESOURCES_FILE_MAX_SIZE=2)
    def test_standard_upload_too_large(self):
        self.login()
        response = self.post(
            url_for("storage.upload", name="resources"),
            {"file": (BytesIO(b"aaa"), "test.txt")},  # 3 bytes > 2
            json=False,
        )

        assert response.status_code == 413
        # The oversized file must not be left behind.
        assert list(storages.resources.list_files()) == []

    @pytest.mark.options(RESOURCES_FILE_MAX_SIZE=2)
    def test_chunked_upload_too_large(self):
        self.login()
        url = url_for("storage.upload", name="tmp")
        uuid = str(uuid4())
        parts = 4  # 4 * 1 byte = 4 bytes > 2

        for i in range(parts):
            response = self.post(
                url,
                {
                    "file": (BytesIO(b"a"), "blob"),
                    "uuid": uuid,
                    "filename": "test.txt",
                    "partindex": i,
                    "partbyteoffset": 0,
                    "totalparts": parts,
                    "chunksize": 1,
                },
                json=False,
            )
            assert200(response)

        response = self.post(
            url,
            {"uuid": uuid, "filename": "test.txt", "totalparts": parts},
            json=False,
        )

        assert400(response)
        assert not response.json["success"]
        # Neither the combined file nor the chunk parts must be left behind.
        assert list(storages.tmp.list_files()) == []
        assert list(storages.chunks.list_files()) == []

    def test_upload_resource_bad_request(self):
        self.login()
        response = self.post(
            url_for("storage.upload", name="tmp"),
            {"bad": (BytesIO(b"aaa"), "test.txt")},
            json=False,
        )

        assert400(response)
        assert not response.json["success"]
        assert "error" in response.json


@pytest.mark.usefixtures("instance_path")
class ChunksRetentionTest(PytestOnlyTestCase):
    def create_chunks(self, uuid, nb=3, last=None):
        for i in range(nb):
            storages.chunks.write(chunk_filename(uuid, i), faker.word())
        storages.chunks.write(
            chunk_filename(uuid, META),
            json.dumps(
                {
                    "uuid": str(uuid),
                    "filename": faker.file_name(),
                    "totalparts": nb + 1,
                    "lastchunk": last or datetime.now(UTC),
                }
            ),
        )

    @pytest.mark.options(UPLOAD_MAX_RETENTION=0)
    def test_chunks_cleanup_after_max_retention(self, client):
        uuid = str(uuid4())
        self.create_chunks(uuid)
        purge_chunks.apply()
        assert list(storages.chunks.list_files()) == []
        assert not storages.chunks.exists(uuid)  # Directory should be removed too

    @pytest.mark.options(UPLOAD_MAX_RETENTION=60 * 60)  # 1 hour
    def test_chunks_kept_before_max_retention(self, client):
        not_expired = datetime.now(UTC)
        expired = datetime.now(UTC) - timedelta(hours=2)
        expired_uuid = str(uuid4())
        active_uuid = str(uuid4())
        parts = 3
        self.create_chunks(expired_uuid, nb=parts, last=expired)
        self.create_chunks(active_uuid, nb=parts, last=not_expired)
        purge_chunks.apply()
        expected = set([chunk_filename(active_uuid, i) for i in range(parts)])
        expected.add(chunk_filename(active_uuid, META))
        assert set(storages.chunks.list_files()) == expected
        assert not storages.chunks.exists(expired_uuid)  # Directory should be removed too


class DangerousContentScanTest(PytestOnlyTestCase):
    """Regression tests for the streaming dangerous-content scanner.

    A previous implementation read the whole file into memory (f.read().lower())
    and raised MemoryError on large resource uploads. The scanner now reads in
    fixed-size chunks with an overlap so boundary-straddling patterns are still
    caught while memory stays bounded.
    """

    def test_large_clean_file_is_not_flagged(self, tmpdir):
        # A few chunks worth of legitimate data must scan cleanly without
        # loading the whole file into memory.
        target = tmpdir.join("big.csv")
        with open(str(target), "w") as f:
            for _ in range(4 * _SCAN_CHUNK_SIZE // 12):
                f.write("a,b,c,d,e,f\n")
        assert _scan_for_dangerous_content(str(target), PLAIN_TEXT_DANGEROUS_PATTERNS) is None

    def test_pattern_straddling_chunk_boundary_is_detected(self, tmpdir):
        # A dangerous token split across the chunk boundary must still match.
        target = tmpdir.join("boundary.txt")
        with open(str(target), "w") as f:
            f.write("x" * (_SCAN_CHUNK_SIZE - 4))
            f.write("<script>alert(1)</script>")
        match = _scan_for_dangerous_content(str(target), PLAIN_TEXT_DANGEROUS_PATTERNS)
        assert match is not None
        assert match[0] == r"<script"

    def test_xxe_pattern_is_matched_case_insensitively(self, tmpdir):
        target = tmpdir.join("x.xml")
        with open(str(target), "w") as f:
            f.write("<!ENTITY foo SYSTEM 'file:///etc/passwd'>")
        match = _scan_for_dangerous_content(str(target), XML_DANGEROUS_PATTERNS)
        assert match is not None


class ValidateUploadDataFormatTest(PytestOnlyTestCase):
    """Inert data formats (CSV, JSON, …) are served as attachments and never
    rendered inline, so legitimate data that merely contains an HTML-looking
    substring must not be rejected as "dangerous". Only browser-renderable HTML
    documents and XML/SVG keep the HTML/script scan.
    """

    @pytest.mark.parametrize(
        ("name", "content"),
        [
            ("data.csv", "col1,col2\nvalue,<iframe src=x>\n"),
            ("data.csv", "url\nhttps://x?u=javascript:alert(1)\n"),
            ("data.json", '{"note": "use <script> to embed"}'),
            ("dump.sql", "INSERT INTO t VALUES ('<object data=x>');"),
            ("notes.txt", "example of an <embed> tag in prose"),
        ],
    )
    def test_data_file_with_html_substring_is_allowed(self, tmpdir, name, content):
        target = tmpdir.join(name)
        with open(str(target), "w") as f:
            f.write(content)
        ext = name.rsplit(".", 1)[-1]
        assert validate_upload(str(target), "", ext) is None
        # The file must be kept on disk (not deleted as a rejected upload).
        assert target.check(file=1)

    @pytest.mark.parametrize("ext", ["html", "htm", "shtml", "xht"])
    def test_html_document_with_script_is_rejected(self, tmpdir, ext):
        target = tmpdir.join(f"page.{ext}")
        with open(str(target), "w") as f:
            f.write("<html><body><script>alert(1)</script></body></html>")
        error = validate_upload(str(target), "", ext)
        assert error is not None
        # Rejected uploads are removed from disk.
        assert not target.check()

    def test_svg_with_script_is_still_rejected(self, tmpdir):
        target = tmpdir.join("logo.svg")
        with open(str(target), "w") as f:
            f.write('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>')
        error = validate_upload(str(target), "image/svg+xml", "svg")
        assert error is not None
        assert not target.check()
