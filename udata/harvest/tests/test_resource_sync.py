"""Resource reconciliation shared by the PT harvesters (LEDG-2251).

The harvesters used to wipe `dataset.resources` and rebuild every resource from
scratch on each run. Since `Resource.id` is auto-generated, that handed every
resource a new id — and therefore a new `/api/1/datasets/r/<id>` permalink —
every single night. `sync_resources` matches the harvested entries against the
resources already stored so the ids survive.
"""

from udata.models import Resource

from ..backends.tools.harvester_utils import sync_resources

CSV_URL = "https://example.pt/data/file.csv"
JSON_URL = "https://example.pt/data/file.json"
WMS_URL = "https://example.pt/wms?SERVICE=WMS&REQUEST=GetCapabilities"


class FakeDataset:
    """Stand-in for a dataset: `sync_resources` only touches `resources`."""

    def __init__(self, resources=None):
        self.resources = resources or []


def _entry(url, **kwargs):
    fields = {"title": "A resource", "url": url, "filetype": "remote", "format": "csv"}
    fields.update(kwargs)
    return fields


def _ids(dataset):
    return [resource.id for resource in dataset.resources]


class SyncResourcesTest:
    def test_resources_are_created_on_the_first_sync(self):
        dataset = FakeDataset()

        sync_resources(dataset, [_entry(CSV_URL), _entry(JSON_URL, format="json")])

        assert [r.url for r in dataset.resources] == [CSV_URL, JSON_URL]
        assert [r.format for r in dataset.resources] == ["csv", "json"]

    def test_ids_survive_a_second_sync(self):
        dataset = FakeDataset()
        sync_resources(dataset, [_entry(CSV_URL), _entry(JSON_URL, format="json")])
        before = _ids(dataset)

        sync_resources(dataset, [_entry(CSV_URL), _entry(JSON_URL, format="json")])

        assert _ids(dataset) == before

    def test_metadata_changes_land_on_the_existing_resource(self):
        dataset = FakeDataset()
        sync_resources(dataset, [_entry(CSV_URL, title="Old", format="unknown")])
        resource = dataset.resources[0]

        sync_resources(dataset, [_entry(CSV_URL, title="New", format="csv")])

        # Same object, hence same id and same permalink.
        assert dataset.resources[0] is resource
        assert resource.title == "New"
        assert resource.format == "csv"

    def test_resource_dropped_upstream_is_removed(self):
        dataset = FakeDataset()
        sync_resources(dataset, [_entry(CSV_URL), _entry(JSON_URL, format="json")])
        csv_id = dataset.resources[0].id

        sync_resources(dataset, [_entry(CSV_URL)])

        assert [r.url for r in dataset.resources] == [CSV_URL]
        assert dataset.resources[0].id == csv_id

    def test_new_entry_joins_the_kept_ones(self):
        dataset = FakeDataset()
        sync_resources(dataset, [_entry(CSV_URL)])
        csv_id = dataset.resources[0].id

        sync_resources(dataset, [_entry(CSV_URL), _entry(WMS_URL, format="wms")])

        assert _ids(dataset)[0] == csv_id
        assert dataset.resources[1].url == WMS_URL

    def test_stored_raw_url_matches_its_normalized_form(self):
        # `cswudata` and `inehvd` stored URLs verbatim; normalizing them now must
        # not count as a different resource, otherwise the first harvest after
        # the fix would break the very permalinks it is meant to preserve.
        stored = Resource(title="Stored", url="https://example.pt//data\\file.csv")
        dataset = FakeDataset([stored])

        sync_resources(dataset, [_entry(CSV_URL)])

        assert dataset.resources == [stored]
        assert stored.url == CSV_URL

    def test_url_repeated_in_the_source_yields_a_single_resource(self):
        dataset = FakeDataset()

        sync_resources(dataset, [_entry(CSV_URL, title="First"), _entry(CSV_URL, title="Second")])
        before = _ids(dataset)

        assert len(dataset.resources) == 1
        assert dataset.resources[0].title == "First"

        # Without deduplication the second copy would never match anything and
        # would be recreated — with a new id — on every run.
        sync_resources(dataset, [_entry(CSV_URL, title="First"), _entry(CSV_URL, title="Second")])
        assert _ids(dataset) == before

    def test_entry_without_a_url_is_ignored(self):
        dataset = FakeDataset()

        sync_resources(dataset, [_entry(CSV_URL), _entry(None), _entry("")])

        assert [r.url for r in dataset.resources] == [CSV_URL]

    def test_uploaded_resources_are_preserved(self):
        # Files uploaded through the portal never came from the harvester;
        # deleting them lost the file and orphaned it in storage.
        uploaded = Resource(
            title="Uploaded", url="https://example.pt/uploaded.csv", filetype="file"
        )
        dataset = FakeDataset([uploaded])

        sync_resources(dataset, [_entry(CSV_URL)])

        assert dataset.resources[-1] is uploaded
        assert [r.url for r in dataset.resources] == [CSV_URL, uploaded.url]

    def test_an_empty_payload_only_clears_the_harvested_resources(self):
        uploaded = Resource(
            title="Uploaded", url="https://example.pt/uploaded.csv", filetype="file"
        )
        dataset = FakeDataset()
        sync_resources(dataset, [_entry(CSV_URL)])
        dataset.resources.append(uploaded)

        sync_resources(dataset, [])

        assert dataset.resources == [uploaded]

    def test_order_follows_the_source(self):
        dataset = FakeDataset()
        sync_resources(dataset, [_entry(CSV_URL), _entry(JSON_URL, format="json")])
        csv_id, json_id = _ids(dataset)

        sync_resources(dataset, [_entry(JSON_URL, format="json"), _entry(CSV_URL)])

        assert _ids(dataset) == [json_id, csv_id]
