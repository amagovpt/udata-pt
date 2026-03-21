"""
Create MetricEvent and MetricAggregation collections with indexes
"""

import logging

from udata.core.metrics.aggregations import MetricAggregation
from udata.core.metrics.events import MetricEvent

log = logging.getLogger(__name__)


def migrate(db):
    log.info("Creating MetricEvent indexes...")
    MetricEvent.ensure_indexes()

    log.info("Creating MetricAggregation indexes...")
    MetricAggregation.ensure_indexes()

    log.info("Metrics collections and indexes created successfully.")
