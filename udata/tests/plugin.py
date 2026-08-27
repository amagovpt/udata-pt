import os

import pytest

DEFAULT_TEST_MONGO_PREFIX = "mongodb://localhost:27017/udata_test"


def pytest_configure(config):
    # Each xdist worker gets its own MongoDB database to avoid conflicts
    # when tests drop/recreate the database.
    #
    # UDATA_TEST_MONGO_PREFIX extends that isolation past a single run. `_clean_db` truncates
    # every collection before each test, so two runs sharing a database name wipe each
    # other's fixtures mid-test -- which is what happens when the same repository is checked
    # out twice (a git worktree per branch) and both run pytest. Exporting a distinct prefix
    # per checkout gives each one its own databases. Unset, nothing changes.
    prefix = os.environ.get("UDATA_TEST_MONGO_PREFIX")
    workerinput = getattr(config, "workerinput", None)
    from udata import settings

    if workerinput is not None:
        worker_id = workerinput["workerid"]
        settings.Testing.MONGODB_HOST_TEST = f"{prefix or DEFAULT_TEST_MONGO_PREFIX}_{worker_id}"
    elif prefix:
        # Without xdist there is no worker to distinguish, so the prefix is the whole name.
        settings.Testing.MONGODB_HOST_TEST = prefix


@pytest.fixture
def rmock():
    """A requests-mock fixture"""
    import requests_mock

    with requests_mock.Mocker() as m:
        m.ANY = requests_mock.ANY
        yield m


@pytest.fixture
def instance_path(app, tmpdir):
    """Use temporary application instance_path"""
    from udata.core import storages

    app.instance_path = str(tmpdir)
    app.config["FS_ROOT"] = str(tmpdir / "fs")
    # Force local storage:
    for s in "resources", "avatars", "logos", "images", "chunks", "tmp":
        key = "{0}_FS_{{0}}".format(s.upper())
        app.config[key.format("BACKEND")] = "local"
        app.config.pop(key.format("ROOT"), None)

    storages.init_app(app)

    return tmpdir
