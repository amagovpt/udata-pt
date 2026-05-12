import logging
from datetime import UTC, datetime

from udata.tests.api import PytestOnlyDBTestCase

from ..tasks import _report_orphan_dispatch, purge_harvest_jobs, purge_harvest_sources
from .factories import HarvestSourceFactory

log = logging.getLogger(__name__)


class HarvestActionsTest(PytestOnlyDBTestCase):
    def test_purge_sources(self, mocker):
        """It should purge from DB sources flagged as deleted"""
        mock = mocker.patch("udata.harvest.actions.purge_sources")
        purge_harvest_sources()
        mock.assert_called_once_with()

    def test_purge_jobs(self, mocker):
        """It should purge from DB jobs older than retention policy"""
        mock = mocker.patch("udata.harvest.actions.purge_jobs")
        purge_harvest_jobs()
        mock.assert_called_once_with()

    def test_orphan_dispatch_logs_warning_for_deleted_source(self, caplog):
        """LEDG-1727: a periodic task firing for a deleted source must emit a
        WARNING (not silent INFO) so ops can spot orphan PeriodicTask docs."""
        source = HarvestSourceFactory(deleted=datetime.now(UTC))

        with caplog.at_level(logging.WARNING, logger="udata.harvest.tasks"):
            _report_orphan_dispatch(source)

        assert any(
            record.levelno == logging.WARNING
            and str(source.id) in record.getMessage()
            and "deleted" in record.getMessage()
            for record in caplog.records
        ), [(r.levelname, r.getMessage()) for r in caplog.records]

    def test_orphan_dispatch_logs_warning_for_inactive_source(self, caplog):
        """LEDG-1727: same surface for inactive (active=False) sources."""
        source = HarvestSourceFactory(active=False)

        with caplog.at_level(logging.WARNING, logger="udata.harvest.tasks"):
            _report_orphan_dispatch(source)

        assert any(
            record.levelno == logging.WARNING
            and str(source.id) in record.getMessage()
            and "inactive" in record.getMessage()
            for record in caplog.records
        )
