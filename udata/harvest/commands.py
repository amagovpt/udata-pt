import json
import logging
from datetime import UTC, datetime

import click

from udata.commands import KO, OK, cli, green, red
from udata.harvest.backends import get_all_backends, is_backend_enabled
from udata.models import Dataset, PeriodicTask

from . import actions
from .models import HarvestSource

log = logging.getLogger(__name__)


@cli.group("harvest")
def grp():
    """Remote repositories harvesting operations"""
    pass


@grp.command()
@click.argument("backend")
@click.argument("url")
@click.argument("name")
@click.option("-f", "--frequency", default=None)
@click.option("-u", "--owner", default=None)
@click.option("-o", "--org", default=None)
def create(name, url, backend, frequency=None, owner=None, org=None):
    """Create a new harvest source"""
    log.info('Creating a new Harvest source "%s"', name)
    source = actions.create_source(
        name, url, backend, frequency=frequency, owner=owner, organization=org
    )
    log.info(
        """Created a new Harvest source:
    name: {0.name},
    slug: {0.slug},
    url: {0.url},
    backend: {0.backend},
    frequency: {0.frequency},
    owner: {0.owner},
    organization: {0.organization}""".format(source)
    )


@grp.command()
@click.argument("identifier")
def validate(identifier):
    """Validate a source given its identifier"""
    source = actions.validate_source(actions.get_source(identifier))
    log.info("Source %s (%s) has been validated", source.slug, str(source.id))


@grp.command()
def delete(identifier):
    """Delete a harvest source"""
    log.info('Deleting source "%s"', identifier)
    actions.delete_source(actions.get_source(identifier))
    log.info('Deleted source "%s"', identifier)


@grp.command()
@click.argument("identifier")
def clean(identifier):
    """Delete all datasets linked to a harvest source"""
    log.info(f'Cleaning source "{identifier}"')
    num_of_datasets = actions.clean_source(actions.get_source(identifier))
    log.info(f'Cleaned source "{identifier}" - deleted {num_of_datasets} dataset(s)')


@grp.command()
@click.option("-s", "--scheduled", is_flag=True, help="list only scheduled source")
def sources(scheduled=False):
    """List all harvest sources"""
    sources = actions.list_sources()
    if scheduled:
        sources = [s for s in sources if s.periodic_task]
    if sources:
        for source in sources:
            msg = "{source.name} ({source.backend}): {cron}"
            if source.periodic_task:
                cron = source.periodic_task.schedule_display
            else:
                cron = "not scheduled"
            log.info(msg.format(source=source, cron=cron))
    elif scheduled:
        log.info("No sources scheduled yet")
    else:
        log.info("No sources defined yet")


@grp.command()
def backends():
    """List available backends"""
    print("Available backends:")
    for backend in get_all_backends().values():
        status = green(OK) if is_backend_enabled(backend) else red(KO)
        click.echo("{0} {1} ({2})".format(status, backend.display_name, backend.name))


@grp.command()
@click.argument("identifier")
def launch(identifier):
    """Launch a source harvesting on the workers"""
    log.info('Launching harvest job for source "%s"', identifier)
    actions.launch(actions.get_source(identifier))


@grp.command()
@click.argument("identifier")
def run(identifier):
    """Run a harvester synchronously"""
    log.info('Harvesting source "%s"', identifier)
    actions.run(actions.get_source(identifier))


@grp.command()
@click.argument("identifier")
@click.option("-m", "--minute", default="*", help="The crontab expression for minute")
@click.option("-h", "--hour", default="*", help="The crontab expression for hour")
@click.option(
    "-d", "--day", "day_of_week", default="*", help="The crontab expression for day of week"
)
@click.option("-D", "--day-of-month", default="*", help="The crontab expression for day of month")
@click.option("-M", "--month-of-year", default="*", help="The crontab expression for month of year")
def schedule(identifier, **kwargs):
    """Schedule a harvest job to run periodically"""
    source = actions.schedule(actions.get_source(identifier), **kwargs)
    msg = "Scheduled {source.name} with the following crontab: {cron}"
    log.info(msg.format(source=source, cron=source.periodic_task.crontab))


@grp.command()
@click.argument("identifier")
def unschedule(identifier):
    """Unschedule a periodical harvest job"""
    source = actions.unschedule(actions.get_source(identifier))
    log.info('Unscheduled harvest source "%s"', source.name)


@grp.command()
def purge():
    """Permanently remove deleted harvest sources"""
    log.info("Purging deleted harvest sources")
    count = actions.purge_sources()
    log.info("Purged %s source(s)", count)


@grp.command()
@click.argument("filename")
@click.argument("domain")
def attach(domain, filename):
    """
    Attach existing datasets to their harvest remote id

    Mapping between identifiers should be in FILENAME CSV file.
    """
    log.info("Attaching datasets for domain %s", domain)
    result = actions.attach(domain, filename)
    log.info("Attached %s datasets to %s", result.success, domain)


@grp.command()
@click.argument("dataset_id")
def detach(dataset_id):
    """
    Detach a dataset_id from its harvest source

    The dataset will be cleaned from harvested information
    """
    log.info(f"Detaching dataset {dataset_id}")
    dataset = Dataset.get(dataset_id)
    actions.detach(dataset)
    log.info("Done")


def _humanize_age(dt):
    """Return a short human-readable age (e.g. '9h12m', '3d', '148d')."""
    if not dt:
        return "-"
    # Normalize to UTC-aware for arithmetic.
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    delta = datetime.now(UTC) - dt
    days = delta.days
    if days >= 1:
        return f"{days}d"
    hours, remainder = divmod(delta.seconds, 3600)
    minutes = remainder // 60
    if hours >= 1:
        return f"{hours}h{minutes:02d}m"
    return f"{minutes}m"


def _format_dt(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "(never)"


def _build_diagnose_row(source):
    """Collect diagnostic data for a single HarvestSource.

    Tolerant: missing periodic_task / no jobs / dereference failures all
    produce sentinel values rather than raising, so this command remains
    safe to run on a messy production database.
    """
    pt = source.periodic_task
    pt_enabled = pt.enabled if pt else None
    crontab_str = pt.schedule_display if pt else "(unscheduled)"
    last_run_at = pt.last_run_at if pt else None
    run_count = pt.total_run_count if pt else 0

    try:
        last_job = source.get_last_job(reduced=True)
    except Exception:
        last_job = None
    last_job_created = last_job.created if last_job else None
    last_job_status = last_job.status if last_job else "-"

    return {
        "slug": source.slug,
        "id": str(source.id),
        "backend": source.backend,
        "active": bool(source.active),
        "deleted": source.deleted is not None,
        "frequency": source.frequency,
        "periodic_task_enabled": pt_enabled,
        "crontab": crontab_str,
        "last_run_at": last_run_at.isoformat() if last_run_at else None,
        "total_run_count": run_count,
        "last_job_at": last_job_created.isoformat() if last_job_created else None,
        "last_job_status": last_job_status,
        "last_run_age": _humanize_age(last_run_at),
        "last_job_age": _humanize_age(last_job_created),
    }


@grp.command()
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Emit machine-readable JSON instead of the tabular default",
)
@click.option(
    "--include-deleted",
    is_flag=True,
    help="Include sources flagged as deleted (default: skip)",
)
def diagnose(as_json, include_deleted):
    """Print a snapshot of every HarvestSource for scheduling triage.

    Read-only. Surfaces: active flag, periodic_task.enabled, crontab,
    last_run_at + age, total_run_count, last HarvestJob + age. Use to
    quickly spot sources whose schedule has drifted or that are firing
    but not producing jobs.
    """
    sources = list(HarvestSource.objects)
    if not include_deleted:
        sources = [s for s in sources if s.deleted is None]

    rows = [_build_diagnose_row(s) for s in sources]

    if as_json:
        click.echo(json.dumps(rows, indent=2, default=str))
        return

    if not rows:
        click.echo("No harvest sources found.")
        return

    cols = [
        ("SLUG", "slug", 28),
        ("BACKEND", "backend", 10),
        ("ACTIVE", "active", 6),
        ("PT_ENABLED", "periodic_task_enabled", 10),
        ("CRONTAB", "crontab", 18),
        ("LAST_RUN_AT", "last_run_at", 25),
        ("LAST_RUN_AGE", "last_run_age", 12),
        ("RUNS", "total_run_count", 5),
        ("LAST_JOB_AGE", "last_job_age", 12),
        ("JOB_STATUS", "last_job_status", 12),
    ]
    header = "  ".join(label.ljust(width) for label, _, width in cols)
    click.echo(header)
    click.echo("-" * len(header))
    for row in rows:
        line = "  ".join(
            str(row.get(key, "") if row.get(key) is not None else "-").ljust(width)
            for _, key, width in cols
        )
        click.echo(line)

    # Summary.
    scheduled = [r for r in rows if r["periodic_task_enabled"]]
    active_scheduled = [r for r in scheduled if r["active"]]
    never_ran = [r for r in active_scheduled if r["last_run_at"] is None]
    click.echo("")
    click.echo(
        f"Total: {len(rows)} source(s) "
        f"({len(scheduled)} scheduled, {len(active_scheduled)} active+scheduled, "
        f"{len(never_ran)} never executed)"
    )


@grp.command()
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Emit machine-readable JSON instead of the tabular default",
)
def orphans(as_json):
    """List PeriodicTask documents whose harvest source is missing/deleted/inactive.

    Read-only. Surfaces beat-slot waste: PeriodicTask docs whose ``args[0]``
    does not resolve to a live HarvestSource. The beat scheduler still
    dispatches these, the worker enters the early-return in
    ``harvest()``, and nothing observable happens until you run this.
    """
    tasks = PeriodicTask.objects(task="harvest")
    orphan_rows = []
    for pt in tasks:
        ident = pt.args[0] if pt.args else None
        try:
            source = HarvestSource.objects(pk=ident).first() if ident else None
        except Exception:
            source = None

        if source is None:
            reason = "source not found"
        elif source.deleted is not None:
            reason = "source deleted"
        elif not source.active:
            reason = "source inactive"
        else:
            continue

        orphan_rows.append(
            {
                "periodic_task_id": str(pt.id),
                "name": pt.name,
                "source_id": ident,
                "enabled": pt.enabled,
                "last_run_at": pt.last_run_at.isoformat() if pt.last_run_at else None,
                "total_run_count": pt.total_run_count,
                "reason": reason,
            }
        )

    if as_json:
        click.echo(json.dumps(orphan_rows, indent=2, default=str))
        return

    if not orphan_rows:
        click.echo("No orphan harvest PeriodicTask documents found.")
        return

    cols = [
        ("PT_ID", "periodic_task_id", 26),
        ("NAME", "name", 50),
        ("ENABLED", "enabled", 8),
        ("RUNS", "total_run_count", 5),
        ("REASON", "reason", 20),
    ]
    header = "  ".join(label.ljust(width) for label, _, width in cols)
    click.echo(header)
    click.echo("-" * len(header))
    for row in orphan_rows:
        line = "  ".join(str(row.get(key, "-") or "-").ljust(width) for _, key, width in cols)
        click.echo(line)
    click.echo("")
    click.echo(f"{len(orphan_rows)} orphan PeriodicTask document(s) wasting beat slots.")


@grp.command()
@click.argument("identifier")
def detach_all_from_source(identifier):
    """
    Detach all datasets from a harvest source

    All the datasets will be cleaned from harvested information.
    Make sure the harvest source won't create new duplicate datasets,
    either by deactivating it or filtering its scope, etc.
    """
    log.info(f"Detaching datasets from harvest source {identifier}")
    count = actions.detach_all_from_source(actions.get_source(identifier))
    log.info(f"Detached {count} datasets")
    log.warning(
        "Make sure the harvest source won't create new duplicate datasets, either by deactivating it or filtering its scope, etc."
    )
