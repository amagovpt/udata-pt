"""Shared harness for the resource id stability tests (LEDG-2251).

Not a test module: it is imported by the per-backend ones.
"""

from udata.models import Dataset


def harvest(backend_class, source, remote_id, **kwargs):
    """Run a real harvest job processing a single dataset.

    Only `inner_harvest` is stubbed out; `process_dataset`, `get_dataset` and the
    save go through `BaseBackend` unchanged, which is where resource identity is
    decided — the point being tested.
    """
    backend = backend_class(source)
    backend.inner_harvest = lambda: backend.process_dataset(remote_id, **kwargs)
    job = backend.harvest()
    assert [item.status for item in job.items] == ["done"], [
        error.message for item in job.items for error in item.errors
    ]
    return job


def harvested_dataset(remote_id):
    dataset = Dataset.objects(__raw__={"harvest.remote_id": str(remote_id)}).first()
    assert dataset is not None, f"no dataset harvested for {remote_id}"
    return dataset


def resource_ids(remote_id):
    return [resource.id for resource in harvested_dataset(remote_id).resources]


def resource_urls(remote_id):
    return [resource.url for resource in harvested_dataset(remote_id).resources]
