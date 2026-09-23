"""`HARVESTER_BACKENDS` in `udata.cfg` against the registered backends.

Nothing tied the two together: the suite runs on `settings.Testing`, which
enables only the `factory` backend, so a name left in the deployed config after
its backend was removed went unnoticed. `dgtIne` and `dadosGov` both survived
that way until they were found by hand (LEDG-2491), and an unmatched name is
silently ignored by `is_backend_enabled`, so nothing ever complains.

The file is read statically rather than executed: `udata.cfg` is a deployment
config that reads the environment, and this only needs one literal from it.
"""

import ast
from pathlib import Path

import pytest

from ..backends import get_all_backends

CONFIG = Path(__file__).resolve().parents[3] / "udata.cfg"


def configured_backends() -> list[str]:
    """The `HARVESTER_BACKENDS` literal of the repository's `udata.cfg`."""
    assert CONFIG.is_file(), f"udata.cfg not found at {CONFIG}"
    module = ast.parse(CONFIG.read_text(encoding="utf-8"), filename=str(CONFIG))
    for node in module.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "HARVESTER_BACKENDS"
            for target in node.targets
        ):
            return ast.literal_eval(node.value)
    pytest.fail(f"no HARVESTER_BACKENDS assignment in {CONFIG}")


class HarvesterBackendsConfigTest:
    def test_every_configured_name_is_a_registered_backend(self):
        registered = set(get_all_backends())
        unknown = sorted(set(configured_backends()) - registered)
        assert not unknown, (
            f"{unknown} enabled in udata.cfg but not registered as a harvester: "
            "a source on one of these fails its next run with "
            "`ValueError: Backend … unknown`"
        )

    def test_maaf_is_not_offered(self):
        # The upstream French backend: it stays in the tree, so an upstream sync
        # still applies cleanly, but it harvests nothing here and must not be
        # offered by `GET /api/1/harvest/backends/` (LEDG-2493).
        assert "maaf" not in configured_backends()
        assert "maaf" in get_all_backends()
