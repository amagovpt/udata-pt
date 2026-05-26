"""Tests for the force-download behavior of `/api/1/datasets/r/<id>/` — LEDG-1765.

Covers both code paths of `ResourceRedirectAPI`:

- Hosted resources (`fs_filename` set) — served via `send_file(as_attachment=True)`
  with the stored mimetype and a sensible download name.
- Remote resources (only `url`) — proxied through `stream_as_attachment`, so
  they inherit the SSRF guard, byte cap and attachment headers from the
  LEDG-1214 download proxy.

The previous behavior (302 redirect to `resource.url`) was tested in
`test_datasets_api.py::test_resource_redirect_success`; that test was
updated to match the new contract.
"""

from __future__ import annotations

from io import BytesIO
from unittest.mock import MagicMock, patch
from uuid import uuid4

import requests
from flask import url_for

from udata.core.dataset.factories import DatasetFactory, ResourceFactory
from udata.tests.api import APITestCase


def _build_mock_upstream(body=b"hello", content_type="application/pdf"):
    """A `requests.Response`-shaped mock yielding `body` once via iter_content."""
    m = MagicMock()
    m.headers = {"Content-Type": content_type}
    m.status_code = 200
    m.iter_content = MagicMock(return_value=iter([body]))
    m.raise_for_status = MagicMock()
    return m


class ResourceRedirectForceDownloadTest(APITestCase):
    """Replay the LEDG-866 / LEDG-1026 user scenario against the new endpoint.

    All assertions are about the *attachment* contract: status 200 (no
    redirect), `Content-Disposition: attachment; filename="..."`,
    Content-Type propagated, body streamed.
    """

    def _hit(self, resource_id):
        return self.get(url_for("api.resource_redirect", id=resource_id))

    # ------------------------------------------------------------------
    # Hosted (fs_filename) path — `send_file(as_attachment=True)`
    # ------------------------------------------------------------------

    def test_hosted_resource_served_as_attachment_with_title(self):
        """Title preferred when set — UX-friendly download name."""
        resource = ResourceFactory(
            fs_filename="ds-slug/20260520-143015/file.pdf",
            mime="application/pdf",
            title="Report 2026.pdf",
        )
        DatasetFactory(resources=[resource])

        with patch(
            "udata.core.dataset.api.storages.resources.open",
            return_value=BytesIO(b"%PDF-1.4 dummy body"),
        ):
            response = self._hit(resource.id)

        assert response.status_code == 200
        cd = response.headers["Content-Disposition"]
        assert cd.startswith("attachment;")
        assert "Report 2026.pdf" in cd
        assert response.headers["Content-Type"].startswith("application/pdf")
        assert response.data == b"%PDF-1.4 dummy body"

    def test_hosted_resource_appends_extension_when_title_missing_it(self):
        """LEDG-1765 follow-up: title without extension + format → append it.

        Reported by Valentim Marcelino Pinto: a CSV resource was being
        downloaded with no extension because `title` omitted `.csv` even
        though `format` knew it was a CSV. Windows then treated the file
        as a generic "Arquivo".
        """
        resource = ResourceFactory(
            fs_filename="ds-slug/20260520-143015/abc123.csv",
            mime="text/csv",
            title="Lista de Apoios 2026",
            format="csv",
        )
        DatasetFactory(resources=[resource])

        with patch(
            "udata.core.dataset.api.storages.resources.open",
            return_value=BytesIO(b"a,b\n1,2\n"),
        ):
            response = self._hit(resource.id)

        assert response.status_code == 200
        assert "Lista de Apoios 2026.csv" in response.headers["Content-Disposition"]

    def test_hosted_resource_does_not_duplicate_existing_extension(self):
        """A title that already ends in `.csv` (any case) keeps a single extension."""
        for title in ("Report 2026.csv", "REPORT 2026.CSV"):
            resource = ResourceFactory(
                fs_filename="ds-slug/20260520-143015/abc.csv",
                mime="text/csv",
                title=title,
                format="csv",
            )
            DatasetFactory(resources=[resource])

            with patch(
                "udata.core.dataset.api.storages.resources.open",
                return_value=BytesIO(b"x"),
            ):
                response = self._hit(resource.id)

            cd = response.headers["Content-Disposition"]
            assert title in cd, cd
            # No double `.csv.csv` regardless of original case.
            assert ".csv.csv" not in cd.lower(), cd

    def test_hosted_resource_no_format_keeps_title_untouched(self):
        """Resources without `format` get the title as-is (no guessed extension)."""
        resource = ResourceFactory(
            fs_filename="ds-slug/20260520-143015/blob",
            mime=None,
            title="raw-dump",
            format=None,
        )
        DatasetFactory(resources=[resource])

        with patch(
            "udata.core.dataset.api.storages.resources.open",
            return_value=BytesIO(b"x"),
        ):
            response = self._hit(resource.id)

        assert response.status_code == 200
        assert "raw-dump" in response.headers["Content-Disposition"]
        assert "raw-dump." not in response.headers["Content-Disposition"]

    def test_remote_resource_appends_extension_when_title_missing_it(self):
        """Same fix on the remote path — filename_hint carries the extension."""
        resource = ResourceFactory(
            url="https://example.com/export",
            filetype="remote",
            fs_filename=None,
            title="Lista de Apoios 2026",
            format="csv",
        )
        DatasetFactory(resources=[resource])
        mock_upstream = _build_mock_upstream(body=b"a,b\n1,2\n", content_type="text/csv")

        with patch(
            "udata.core.dataset.download_proxy.requests.get",
            return_value=mock_upstream,
        ):
            response = self._hit(resource.id)

        assert response.status_code == 200
        assert "Lista de Apoios 2026.csv" in response.headers["Content-Disposition"]

    def test_hosted_resource_falls_back_to_basename_when_no_title(self):
        """No title → use the fs_filename basename (preserves extension)."""
        resource = ResourceFactory(
            fs_filename="ds-slug/20260520-143015/file.pdf",
            mime="application/pdf",
            title="",
        )
        DatasetFactory(resources=[resource])

        with patch(
            "udata.core.dataset.api.storages.resources.open",
            return_value=BytesIO(b"data"),
        ):
            response = self._hit(resource.id)

        assert response.status_code == 200
        assert "file.pdf" in response.headers["Content-Disposition"]

    def test_hosted_resource_default_mimetype_when_none(self):
        """`mime=None` → `application/octet-stream` fallback."""
        resource = ResourceFactory(
            fs_filename="ds-slug/20260520-143015/blob",
            mime=None,
            title="blob",
        )
        DatasetFactory(resources=[resource])

        with patch(
            "udata.core.dataset.api.storages.resources.open",
            return_value=BytesIO(b"raw"),
        ):
            response = self._hit(resource.id)

        assert response.status_code == 200
        assert response.headers["Content-Type"].startswith("application/octet-stream")

    # ------------------------------------------------------------------
    # Remote (url-only) path — `stream_as_attachment`
    # ------------------------------------------------------------------

    def test_remote_resource_proxied_with_attachment_header(self):
        resource = ResourceFactory(
            url="https://example.com/some/data.csv",
            filetype="remote",
            fs_filename=None,
            title="export.csv",
        )
        DatasetFactory(resources=[resource])
        mock_upstream = _build_mock_upstream(body=b"a,b\n1,2\n", content_type="text/csv")

        with patch(
            "udata.core.dataset.download_proxy.requests.get",
            return_value=mock_upstream,
        ) as g:
            response = self._hit(resource.id)

        assert response.status_code == 200
        cd = response.headers["Content-Disposition"]
        assert cd.startswith("attachment;")
        assert "export.csv" in cd  # resource.title used as filename_hint
        assert response.headers["Content-Type"].startswith("text/csv")
        # The outbound call must be streaming AND redirect-disabled
        # (LEDG-1214's SSRF defense in depth).
        _, kwargs = g.call_args
        assert kwargs.get("stream") is True
        assert kwargs.get("allow_redirects") is False

    def test_remote_resource_blocked_by_ssrf_guard(self):
        """A denylisted host returns 403 — guard inherited from LEDG-1214."""
        resource = ResourceFactory(
            url="http://canary.s.inty.io/probe",
            filetype="remote",
            fs_filename=None,
        )
        DatasetFactory(resources=[resource])

        response = self._hit(resource.id)

        assert response.status_code == 403

    def test_remote_resource_502_when_upstream_fails(self):
        resource = ResourceFactory(
            url="https://example.com/big.zip",
            filetype="remote",
            fs_filename=None,
        )
        DatasetFactory(resources=[resource])

        with patch(
            "udata.core.dataset.download_proxy.requests.get",
            side_effect=requests.exceptions.ConnectionError("boom"),
        ):
            response = self._hit(resource.id)

        assert response.status_code == 502

    # ------------------------------------------------------------------
    # 404 path — unchanged from the pre-LEDG-1765 behavior
    # ------------------------------------------------------------------

    def test_404_when_resource_missing(self):
        response = self._hit(uuid4())
        assert response.status_code == 404
