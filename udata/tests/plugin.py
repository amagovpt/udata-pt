import os

import pytest

DEFAULT_TEST_MONGO_PREFIX = "mongodb://localhost:27017/udata_test"

# Short on purpose: this is a liveness check, not a query. The point is to
# answer in seconds instead of inheriting the 30-second default.
PREFLIGHT_TIMEOUT_MS = 3000


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

    # Only in the process that coordinates the run: the workers inherit the
    # same target, so pinging once is enough and pinging four times only
    # multiplies the wait when the answer is bad.
    if workerinput is None:
        _require_test_mongo(prefix or DEFAULT_TEST_MONGO_PREFIX)

    if workerinput is not None:
        worker_id = workerinput["workerid"]
        settings.Testing.MONGODB_HOST_TEST = f"{prefix or DEFAULT_TEST_MONGO_PREFIX}_{worker_id}"
    elif prefix:
        # Without xdist there is no worker to distinguish, so the prefix is the whole name.
        settings.Testing.MONGODB_HOST_TEST = prefix


def _require_test_mongo(uri):
    """Stop the run immediately when the test database is not answering.

    Without this the failure mode is silence, not an error. `MONGODB_CONNECT`
    is False (lazy connection, for fork safety) and nothing in this project
    sets `serverSelectionTimeoutMS`, so every attempt waits PyMongo's 30-second
    default -- and the `app` fixture and the `_clean_db` autouse fixture are
    both per-test, across roughly 3500 tests. A wrong or unreachable address
    therefore does not fail: it hangs for hours without ever saying why.

    So the ping is made explicitly, with a short timeout of its own, and the
    message names the command that fixes it. Deliberately not a fixture: by the
    time fixtures run, collection is done and the first test is already paying
    the 30 seconds.
    """
    import pymongo

    try:
        pymongo.MongoClient(uri, serverSelectionTimeoutMS=PREFLIGHT_TIMEOUT_MS).admin.command(
            "ping"
        )
    except Exception as exc:
        pytest.exit(
            f"The test MongoDB at {uri} is not answering ({type(exc).__name__}).\n"
            "Start it with:  docker compose -f docker-compose.test.yml up -d\n"
            "Or point the suite elsewhere with UDATA_TEST_MONGO_PREFIX.",
            returncode=pytest.ExitCode.USAGE_ERROR,
        )


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
