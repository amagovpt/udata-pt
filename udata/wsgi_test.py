"""
WSGI entry point for the disposable E2E test backend.

Mirrors `udata/wsgi.py` but pre-loads the test settings so the API and
plugins register against the disposable MongoDB on port 27018 rather than
the dev DB on 27017. Used by `scripts/start_test_backend.sh`.
"""

import os
from pathlib import Path

if "UDATA_SETTINGS" not in os.environ:
    os.environ["UDATA_SETTINGS"] = str(
        Path(__file__).resolve().parent.parent / "udata.test.cfg"
    )

from udata.app import create_app, standalone  # noqa: E402

app = standalone(create_app())
