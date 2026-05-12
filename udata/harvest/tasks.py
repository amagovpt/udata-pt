from udata.tasks import get_logger, job, task

from . import backends
from .models import HarvestJob, HarvestSource

log = get_logger(__name__)


def _report_orphan_dispatch(source):
    """Notify ops that beat fired a task for an unusable source (LEDG-1727).

    Surfaces a class of wasted beat slots that used to be silent: PeriodicTask
    documents pointing at a deleted/inactive HarvestSource. The fix in
    `delete_source()` disables future dispatches, but old data may already be
    in flight. Sentry capture is best-effort and never blocks the worker.
    """
    state = "deleted" if source.deleted else "inactive"
    log.warning(
        'Periodic harvest task fired for %s source "%s" (slug=%s); '
        "the linked PeriodicTask should be disabled. "
        "Run `udata harvest orphans` to list affected schedules.",
        state,
        source.id,
        source.slug,
    )
    try:
        import sentry_sdk

        with sentry_sdk.push_scope() as scope:
            scope.set_tag("harvest.source_id", str(source.id))
            scope.set_tag("harvest.source_state", state)
            scope.set_extra("source_slug", source.slug)
            sentry_sdk.capture_message(
                f"Harvest periodic task fired for {state} source",
                level="warning",
            )
    except ImportError:
        pass


@job("harvest", route="low.harvest")
def harvest(self, ident):
    log.info('Launching harvest job for source "%s"', ident)

    source = HarvestSource.get(ident)
    if source.deleted or not source.active:
        _report_orphan_dispatch(source)
        return  # Ignore deleted and inactive sources
    Backend = backends.get_backend(source.backend)
    backend = Backend(source)

    backend.harvest()


@task(ignore_result=False, route="low.harvest")
def harvest_job_item(job_id, item_id):
    log.info('Harvesting item %s for job "%s"', item_id, job_id)

    job = HarvestJob.objects.get(pk=job_id)
    Backend = backends.get_backend(job.source.backend)
    backend = Backend(job)

    item = next(i for i in job.items if i.remote_id == item_id)

    backend.process_item(item)
    return item_id


@task(ignore_result=False, route="low.harvest")
def harvest_job_finalize(results, job_id):
    log.info('Finalize harvesting for job "%s"', job_id)
    job = HarvestJob.objects.get(pk=job_id)
    Backend = backends.get_backend(job.source.backend)
    backend = Backend(job)
    backend.finalize()


@job("purge-harvesters", route="low.harvest")
def purge_harvest_sources(self):
    log.info("Purging HarvestSources flagged as deleted")
    from .actions import purge_sources

    purge_sources()


@job("purge-harvest-jobs", route="low.harvest")
def purge_harvest_jobs(self):
    log.info("Purging HarvestJobs older than retention policy")
    from .actions import purge_jobs

    purge_jobs()
