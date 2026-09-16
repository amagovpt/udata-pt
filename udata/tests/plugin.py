import os

import pytest

# 27019 is what docker-compose.test.yml publishes for `udata-mongodb-test`, the
# instance this repository declares for running tests. NOT 27017: that is the
# development stack's MongoDB, and pointing the suite there is what LEDG-2489
# was about -- see the comment in pytest_configure below.
DEFAULT_TEST_MONGO_PREFIX = "mongodb://localhost:27019/udata_test"

# Short on purpose: this is a liveness check, not a query. The point is to
# answer in seconds instead of inheriting the 30-second default.
PREFLIGHT_TIMEOUT_MS = 3000


def pytest_configure(config):
    # Each xdist worker gets its own MongoDB database to avoid conflicts
    # when tests drop/recreate the database.
    #
    # 🚩 The database this points AT is load-bearing, and getting it wrong does
    # not look like a configuration problem -- it looks like a flaky suite.
    # Until LEDG-2489 the default was the development stack's MongoDB, which
    # runs under `restart: unless-stopped` and comes back whenever that stack is
    # brought up. A restart mid-run closes every open connection, so whichever
    # tests happened to be running die with `pymongo.errors.AutoReconnect:
    # connection closed` -- different tests each time, in modules with nothing
    # in common, all passing when run alone. That reads exactly like shared
    # state between workers, and it is not: it is the server going away.
    #
    # So: a spread of AutoReconnect failures across unrelated modules is test
    # infrastructure, not a regression. Check that the test containers are up
    # (`docker compose -f docker-compose.test.yml up -d`) before reading the
    # list as a list of broken tests.
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
    else:
        # Without xdist there is no worker to distinguish, so the prefix is the whole name.
        # The default applies here too, and that is a fix rather than tidiness: left unset,
        # build_test_config (udata/mongo/__init__.py) derives the address from
        # settings.Defaults.MONGODB_HOST -- the development database again, by another route.
        settings.Testing.MONGODB_HOST_TEST = prefix or DEFAULT_TEST_MONGO_PREFIX


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
