"""Bridge family lookup for the shipped 16-class open-default model.

The bridge re-derives ``family`` on ingest with ``normalize_family``. Six of
the open-default names (ask, psk, qam, fsk, msk, dsss) are not canonical
classes, so they used to come back "UNKNOWN" and could trip the
"Novel Signal Detected" alert rule.
"""

from __future__ import annotations

import pytest

from sigrift.bridge.class_map import (
    CANONICAL_CLASS_TO_FAMILY,
    CANONICAL_CLASSES,
    normalize_class,
    normalize_family,
)
from sigrift.lib.taxonomy_open import OPEN_DEFAULT_CLASSES

# Agreed family per open-default class, in model output order.
AGREED_FAMILY: dict[str, str] = {
    "noise": "NOISE",
    "tone": "ANALOG",
    "am": "ANALOG",
    "fm": "ANALOG",
    "ask": "ASK",
    "psk": "PSK",
    "qam": "QAM",
    "fsk": "FSK",
    "gfsk": "FSK",
    "msk": "FSK",
    "ofdm": "OFDM",
    "lora-css": "SPREAD_SPECTRUM",
    "dsss": "SPREAD_SPECTRUM",
    "adsb": "PULSED",
    "fpv-analog": "ANALOG",
    "pocsag": "FSK",
}

FIXED = ("ask", "psk", "qam", "fsk", "msk", "dsss")


def test_agreed_table_covers_the_model_classes_in_order():
    assert list(AGREED_FAMILY) == OPEN_DEFAULT_CLASSES


@pytest.mark.parametrize("name,family", list(AGREED_FAMILY.items()))
def test_open_default_class_maps_to_agreed_family(name: str, family: str):
    assert normalize_family(name) == family
    assert normalize_family(name) != "UNKNOWN"


@pytest.mark.parametrize("name", OPEN_DEFAULT_CLASSES)
def test_open_default_class_name_is_not_rewritten(name: str):
    # Only the family changes; the stored class name stays what the model said.
    assert normalize_class(name) == name


@pytest.mark.parametrize("name", FIXED)
def test_fixed_names_use_existing_family_vocabulary(name: str):
    assert normalize_family(name) in set(CANONICAL_CLASS_TO_FAMILY.values())


@pytest.mark.parametrize("name", FIXED)
def test_fixed_names_are_not_added_to_canonical_list(name: str):
    # The canonical list is mirrored in the Rust gateway and served by
    # /signals; the open-default names must not leak into it.
    assert name not in CANONICAL_CLASSES
    assert name not in CANONICAL_CLASS_TO_FAMILY


@pytest.mark.parametrize("name", FIXED)
def test_case_and_whitespace_variants_stay_exact_match(name: str):
    # The module promises exact, case-sensitive matching with no stripping.
    for variant in (name.upper(), name.capitalize(), f" {name}", f"{name} "):
        assert normalize_class(variant) == variant
        assert normalize_family(variant) == "UNKNOWN"


def test_unrecognised_name_still_unknown():
    assert normalize_family("not-a-real-class") == "UNKNOWN"
    assert normalize_family("") == "UNKNOWN"
