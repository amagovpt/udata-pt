"""The APAmbiente harvest sources move onto the generic CSW backend (LEDG-2492).

What the migration has to prove: the source survives as the same document -- its
id is what its periodic task and its datasets point at -- the producer tag it
used to hard-code follows it into the config the new backend actually reads, and
running twice changes nothing.
"""

import pytest

# `udata.models` is the aggregator: importing it first is what stops
# `udata.harvest.models` being reached mid-initialisation. `Harvest` is the
# alias it publishes for `HarvestSource`.
from udata.models import Harvest as HarvestSource
from udata.tests.api import PytestOnlyDBTestCase

from .factories import HarvestSourceFactory
from .test_ckanpt_migrations import extra_configs, load_migration

MIGRATION = "2026-09-22-apambiente-sources-to-cswudata.py"

CSW_URL = "https://sniambgeoportal.apambiente.pt/geoportal/csw"


@pytest.mark.usefixtures("app")
class ApambienteSourcesToCswudataMigrationTest(PytestOnlyDBTestCase):
    def _migrate(self):
        load_migration(MIGRATION).migrate(None)

    def _source(self, backend="apambiente", **kwargs):
        return HarvestSourceFactory(backend=backend, url=CSW_URL, **kwargs)

    def test_backend_and_default_tag_are_rewritten(self):
        source = self._source()

        self._migrate()

        source.reload()
        assert source.backend == "cswudata"
        assert extra_configs(source) == {"default_tag": "apambiente.pt"}

    def test_the_source_id_is_kept(self):
        # The periodic task and every harvested dataset point at this id.
        source = self._source()
        before = source.id

        self._migrate()

        source.reload()
        assert source.id == before

    def test_no_apambiente_source_is_left(self):
        self._source()
        self._source()

        self._migrate()

        assert HarvestSource.objects(backend="apambiente").count() == 0

    def test_is_idempotent(self):
        source = self._source()

        self._migrate()
        self._migrate()

        assert extra_configs(source) == {"default_tag": "apambiente.pt"}

    def test_an_existing_default_tag_wins(self):
        source = self._source(
            config={"extra_configs": [{"key": "default_tag", "value": "ambiente.pt"}]}
        )

        self._migrate()

        source.reload()
        assert source.backend == "cswudata"
        assert extra_configs(source) == {"default_tag": "ambiente.pt"}

    def test_other_backends_are_left_alone(self):
        other = self._source(backend="ckanpt")

        self._migrate()

        other.reload()
        assert other.backend == "ckanpt"
        assert extra_configs(other) == {}
