"""Periodicity mapping shared by the two INE harvesters (`ine`, `inehvd`).

Both backends read the same INE catalogue, which publishes the update frequency of every
indicator as free Portuguese text in `<periodicity>`. Until now `ine` ignored the element
entirely (every dataset was stored as `unknown`) and `inehvd` recognised five values with a
substring test. `map_ine_periodicity` is the shared replacement.

The parametrisation below is not a sample: it is every distinct value published by the full
catalogue (`xml_indic.jsp?opc=2`), enumerated on 2026-09-18 over 13154 indicators.
"""

import pytest

from udata.core.dataset.constants import UpdateFrequency

from ..backends.tools.harvester_utils import map_ine_periodicity

# Every distinct <periodicity> in the catalogue on 2026-09-18, with its occurrence count,
# and the frequency it must map to. A value dropping to UNKNOWN here is a regression.
OBSERVED_PERIODICITIES = [
    ("Anual", 7158, UpdateFrequency.ANNUAL),
    ("Decenal", 1786, UpdateFrequency.DECENNIAL),
    ("Mensal", 1420, UpdateFrequency.MONTHLY),
    ("Não periódica", 1025, UpdateFrequency.IRREGULAR),
    ("Trimestral", 605, UpdateFrequency.QUARTERLY),
    ("Bienal", 419, UpdateFrequency.BIENNIAL),
    ("Sexenal", 414, UpdateFrequency.OTHER),
    ("Quinquenal", 276, UpdateFrequency.QUINQUENNIAL),
    ("Semestral", 19, UpdateFrequency.SEMIANNUAL),
    ("Quadrienal", 11, UpdateFrequency.QUADRENNIAL),
    ("Mensal acumulado", 10, UpdateFrequency.MONTHLY),
    ("Trienal", 7, UpdateFrequency.TRIENNIAL),
    ("Semanal", 2, UpdateFrequency.WEEKLY),
    # Same two values as above in a different capitalisation: the feed really does publish
    # both, which is why the lookup case-folds instead of comparing raw text.
    ("Não Periódica", 1, UpdateFrequency.IRREGULAR),
    ("decenal", 1, UpdateFrequency.DECENNIAL),
]


@pytest.mark.parametrize(
    "text,expected",
    [(text, expected) for text, _count, expected in OBSERVED_PERIODICITIES],
)
def test_every_observed_value_maps_off_unknown(text, expected):
    assert map_ine_periodicity(text) == expected
    assert map_ine_periodicity(text) != UpdateFrequency.UNKNOWN


@pytest.mark.parametrize(
    "text,expected",
    [(f" {text}", expected) for text, _count, expected in OBSERVED_PERIODICITIES],
)
def test_leading_whitespace_is_stripped(text, expected):
    """13152 of the 13154 published values arrive as `<![CDATA[ Mensal]]>`.

    Without the strip, essentially the whole catalogue would keep falling through to
    `unknown` — which is the bug this mapping exists to fix.
    """
    assert map_ine_periodicity(text) == expected


def test_sexenal_maps_to_other_because_the_vocabulary_has_no_six_year_member():
    """`UpdateFrequency` jumps from QUINQUENNIAL straight to DECENNIAL.

    414 indicators are published as "Sexenal". They must not claim to be five- or
    ten-yearly, and they must not read as "no frequency given" either: the source does
    state one, so OTHER is the honest answer.
    """
    assert not [member for member in UpdateFrequency if "SEX" in member.name]
    assert map_ine_periodicity("Sexenal") == UpdateFrequency.OTHER
    assert map_ine_periodicity("Sexenal") != UpdateFrequency.UNKNOWN


@pytest.mark.parametrize("text", [None, "", "   ", "Bissexta", "n/a", "12"])
def test_unknown_and_empty_fall_back_to_unknown_without_raising(text):
    """An unnamed periodicity degrades; it never fails the item being harvested."""
    assert map_ine_periodicity(text) == UpdateFrequency.UNKNOWN


def test_compound_values_are_not_matched_by_substring():
    """The previous implementation used `"mensal" in text`.

    That is why the lookup is an exact match: "Mensal acumulado" has to be mapped
    deliberately rather than swallowed by the "Mensal" branch, and a future compound value
    must surface as unmapped instead of silently inheriting a neighbour's frequency.
    """
    assert map_ine_periodicity("Mensal acumulado") == UpdateFrequency.MONTHLY
    assert map_ine_periodicity("Decenal revista") == UpdateFrequency.UNKNOWN
