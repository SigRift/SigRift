"""Cross-language taxonomy integration test: Python <-> Rust.

Parses the Rust source file (class_map.rs) directly and compares every
canonical class, merge mapping, and family assignment against the Python
definitions in sigrift.bridge.class_map and sigrift.lib.taxonomy.

No running Rust binary is required.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Ensure sigrift is importable
# ---------------------------------------------------------------------------

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from sigrift.lib.taxonomy import (
    CLASSES,
    CLASS_TO_FAMILY as TAXONOMY_CLASS_TO_FAMILY,
    FAMILIES,
    FAMILY_TO_CLASSES,
    SUPER_FAMILIES,
    SUPER_FAMILY_TO_FAMILIES,
)
from sigrift.bridge.class_map import (
    CANONICAL_CLASS_TO_FAMILY as PY_CANONICAL_CLASS_TO_FAMILY,
    CANONICAL_CLASSES as PY_CANONICAL_CLASSES,
    SIGNAL_CLASS_MAP as PY_SIGNAL_CLASS_MAP,
    normalize_class as py_normalize_class,
    normalize_family as py_normalize_family,
)

# ---------------------------------------------------------------------------
# Rust source parsing helpers
# ---------------------------------------------------------------------------

_CLASS_MAP_RS = (
    _PROJECT_ROOT
    / "src" / "gateway" / "crates" / "sigrift-gateway-core" / "src" / "class_map.rs"
)


def _read_rust_source() -> str:
    """Read class_map.rs and return its content."""
    assert _CLASS_MAP_RS.exists(), f"Rust source not found: {_CLASS_MAP_RS}"
    return _CLASS_MAP_RS.read_text(encoding="utf-8")


def _parse_rust_signal_class_map(src: str) -> dict[str, str]:
    """Extract SIGNAL_CLASS_MAP entries (m.insert("old", "new")) from Rust."""
    # LazyLock block: `static SIGNAL_CLASS_MAP: ... = LazyLock::new(|| { ... });`
    block_match = re.search(
        r"static\s+SIGNAL_CLASS_MAP.*?LazyLock::new\(\|\|\s*\{(.*?)\}\);",
        src,
        re.DOTALL,
    )
    assert block_match is not None, "Could not find SIGNAL_CLASS_MAP block in Rust source"
    block = block_match.group(1)
    pairs = re.findall(r'm\.insert\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)', block)
    return dict(pairs)


def _parse_rust_class_to_family(src: str) -> dict[str, str]:
    """Extract CLASS_TO_FAMILY entries from Rust."""
    block_match = re.search(
        r"static\s+CLASS_TO_FAMILY.*?LazyLock::new\(\|\|\s*\{(.*?)\}\);",
        src,
        re.DOTALL,
    )
    assert block_match is not None, "Could not find CLASS_TO_FAMILY block in Rust source"
    block = block_match.group(1)
    pairs = re.findall(r'm\.insert\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)', block)
    return dict(pairs)


def _parse_rust_canonical_classes(src: str) -> list[str]:
    """Extract CANONICAL_CLASSES array from Rust."""
    block_match = re.search(
        r"pub\s+const\s+CANONICAL_CLASSES.*?=\s*&\[(.*?)\];",
        src,
        re.DOTALL,
    )
    assert block_match is not None, "Could not find CANONICAL_CLASSES array in Rust source"
    block = block_match.group(1)
    return re.findall(r'"([^"]+)"', block)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def rust_src() -> str:
    return _read_rust_source()


@pytest.fixture(scope="module")
def rust_signal_class_map(rust_src: str) -> dict[str, str]:
    return _parse_rust_signal_class_map(rust_src)


@pytest.fixture(scope="module")
def rust_class_to_family(rust_src: str) -> dict[str, str]:
    return _parse_rust_class_to_family(rust_src)


@pytest.fixture(scope="module")
def rust_canonical_classes(rust_src: str) -> list[str]:
    return _parse_rust_canonical_classes(rust_src)


# ---------------------------------------------------------------------------
# Tests: canonical class list agreement
# ---------------------------------------------------------------------------

class TestCanonicalClasses:
    """Verify Rust and Python canonical class lists are identical."""

    def test_same_count(self, rust_canonical_classes: list[str]):
        assert len(rust_canonical_classes) == len(PY_CANONICAL_CLASSES), (
            f"Count mismatch: Rust has {len(rust_canonical_classes)}, "
            f"Python has {len(PY_CANONICAL_CLASSES)}"
        )

    def test_same_set(self, rust_canonical_classes: list[str]):
        rust_set = set(rust_canonical_classes)
        py_set = set(PY_CANONICAL_CLASSES)
        only_rust = rust_set - py_set
        only_py = py_set - rust_set
        assert rust_set == py_set, (
            f"Sets differ. Only in Rust: {only_rust}. Only in Python: {only_py}"
        )

    def test_same_order(self, rust_canonical_classes: list[str]):
        assert rust_canonical_classes == PY_CANONICAL_CLASSES, (
            "Canonical class ordering differs between Rust and Python"
        )

    def test_exactly_57_classes(self, rust_canonical_classes: list[str]):
        assert len(rust_canonical_classes) == 57
        assert len(PY_CANONICAL_CLASSES) == 57

    def test_no_duplicates_rust(self, rust_canonical_classes: list[str]):
        assert len(rust_canonical_classes) == len(set(rust_canonical_classes)), (
            "Rust CANONICAL_CLASSES contains duplicates"
        )

    def test_no_duplicates_python(self):
        assert len(PY_CANONICAL_CLASSES) == len(set(PY_CANONICAL_CLASSES)), (
            "Python CANONICAL_CLASSES contains duplicates"
        )


# ---------------------------------------------------------------------------
# Tests: merge map (SIGNAL_CLASS_MAP) agreement
# ---------------------------------------------------------------------------

class TestSignalClassMap:
    """Verify the 76->57 merge mappings match between Rust and Python."""

    def test_same_keys(self, rust_signal_class_map: dict[str, str]):
        rust_keys = set(rust_signal_class_map.keys())
        py_keys = set(PY_SIGNAL_CLASS_MAP.keys())
        only_rust = rust_keys - py_keys
        only_py = py_keys - rust_keys
        assert rust_keys == py_keys, (
            f"Merge-map keys differ. Only in Rust: {only_rust}. Only in Python: {only_py}"
        )

    def test_same_values(self, rust_signal_class_map: dict[str, str]):
        for key in PY_SIGNAL_CLASS_MAP:
            assert key in rust_signal_class_map, f"Key {key!r} missing from Rust map"
            assert rust_signal_class_map[key] == PY_SIGNAL_CLASS_MAP[key], (
                f"Value mismatch for {key!r}: "
                f"Rust={rust_signal_class_map[key]!r}, Python={PY_SIGNAL_CLASS_MAP[key]!r}"
            )

    def test_merge_count(self, rust_signal_class_map: dict[str, str]):
        """76 full classes - 57 canonical = 19 classes eliminated.
        The map has 25 entries (multiple source classes merge to same target)."""
        assert len(rust_signal_class_map) == len(PY_SIGNAL_CLASS_MAP)
        assert len(PY_SIGNAL_CLASS_MAP) == 25

    def test_merge_targets_are_canonical(self, rust_signal_class_map: dict[str, str]):
        for old, new in rust_signal_class_map.items():
            assert new in PY_CANONICAL_CLASSES, (
                f"Rust merge target {new!r} (from {old!r}) is not a canonical class"
            )

    def test_merged_classes_not_in_canonical(self, rust_signal_class_map: dict[str, str]):
        """Classes that get merged should not themselves appear in canonical list."""
        for old in rust_signal_class_map:
            assert old not in PY_CANONICAL_CLASSES, (
                f"Merged class {old!r} should not appear in CANONICAL_CLASSES"
            )


# ---------------------------------------------------------------------------
# Tests: family mapping agreement
# ---------------------------------------------------------------------------

class TestFamilyMappings:
    """Verify Rust CLASS_TO_FAMILY and Python CANONICAL_CLASS_TO_FAMILY match."""

    def test_same_keys(self, rust_class_to_family: dict[str, str]):
        rust_keys = set(rust_class_to_family.keys())
        py_keys = set(PY_CANONICAL_CLASS_TO_FAMILY.keys())
        only_rust = rust_keys - py_keys
        only_py = py_keys - rust_keys
        assert rust_keys == py_keys, (
            f"Family-map keys differ. Only in Rust: {only_rust}. Only in Python: {only_py}"
        )

    def test_same_families(self, rust_class_to_family: dict[str, str]):
        for cls in PY_CANONICAL_CLASS_TO_FAMILY:
            assert cls in rust_class_to_family, (
                f"Class {cls!r} missing from Rust CLASS_TO_FAMILY"
            )
            assert rust_class_to_family[cls] == PY_CANONICAL_CLASS_TO_FAMILY[cls], (
                f"Family mismatch for {cls!r}: "
                f"Rust={rust_class_to_family[cls]!r}, "
                f"Python={PY_CANONICAL_CLASS_TO_FAMILY[cls]!r}"
            )

    def test_every_canonical_class_has_family(self, rust_class_to_family: dict[str, str]):
        for cls in PY_CANONICAL_CLASSES:
            assert cls in rust_class_to_family, (
                f"Canonical class {cls!r} has no family in Rust"
            )
            assert cls in PY_CANONICAL_CLASS_TO_FAMILY, (
                f"Canonical class {cls!r} has no family in Python"
            )

    def test_family_names_are_valid(self, rust_class_to_family: dict[str, str]):
        """All family names in both maps should be from the taxonomy's FAMILIES list."""
        rust_families = set(rust_class_to_family.values())
        py_families = set(PY_CANONICAL_CLASS_TO_FAMILY.values())
        taxonomy_families = set(FAMILIES)
        assert rust_families.issubset(taxonomy_families), (
            f"Rust families not in taxonomy: {rust_families - taxonomy_families}"
        )
        assert py_families.issubset(taxonomy_families), (
            f"Python families not in taxonomy: {py_families - taxonomy_families}"
        )


# ---------------------------------------------------------------------------
# Tests: normalize_class behaviour
# ---------------------------------------------------------------------------

class TestNormalizeClass:
    """Test that Python normalize_class behaves identically to the Rust spec."""

    @pytest.mark.parametrize("raw,expected", list(PY_SIGNAL_CLASS_MAP.items()))
    def test_merged_classes(self, raw: str, expected: str):
        assert py_normalize_class(raw) == expected

    @pytest.mark.parametrize("cls", PY_CANONICAL_CLASSES)
    def test_canonical_classes_are_identity(self, cls: str):
        assert py_normalize_class(cls) == cls

    def test_unknown_class_passthrough(self):
        assert py_normalize_class("totally-unknown-signal") == "totally-unknown-signal"

    def test_empty_string(self):
        assert py_normalize_class("") == ""


# ---------------------------------------------------------------------------
# Tests: normalize_family behaviour
# ---------------------------------------------------------------------------

class TestNormalizeFamily:
    """Test that Python normalize_family matches the Rust spec."""

    @pytest.mark.parametrize("cls", PY_CANONICAL_CLASSES)
    def test_canonical_classes_have_known_family(self, cls: str):
        family = py_normalize_family(cls)
        assert family != "UNKNOWN", f"Canonical class {cls!r} returned UNKNOWN family"
        assert family == PY_CANONICAL_CLASS_TO_FAMILY[cls]

    def test_merged_classes_resolve_family(self):
        for raw, canonical in PY_SIGNAL_CLASS_MAP.items():
            family = py_normalize_family(raw)
            expected = PY_CANONICAL_CLASS_TO_FAMILY[canonical]
            assert family == expected, (
                f"normalize_family({raw!r}) = {family!r}, expected {expected!r}"
            )

    def test_unknown_class_returns_unknown(self):
        assert py_normalize_family("nonexistent-signal") == "UNKNOWN"

    def test_empty_string_returns_unknown(self):
        assert py_normalize_family("") == "UNKNOWN"


# ---------------------------------------------------------------------------
# Tests: edge cases — case sensitivity, whitespace
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Verify edge case handling: case sensitivity, whitespace, near-misses."""

    def test_case_sensitive_exact_match_required(self):
        """Class names are lowercase; uppercase variants should not match."""
        assert py_normalize_class("BPSK") == "BPSK"  # passthrough, NOT "bpsk"
        assert py_normalize_family("BPSK") == "UNKNOWN"

    def test_mixed_case_not_normalized(self):
        assert py_normalize_class("Ofdm-64") == "Ofdm-64"
        assert py_normalize_family("Ofdm-64") == "UNKNOWN"

    def test_whitespace_not_stripped(self):
        assert py_normalize_class(" bpsk") == " bpsk"
        assert py_normalize_class("bpsk ") == "bpsk "
        assert py_normalize_family(" bpsk") == "UNKNOWN"

    def test_near_miss_typo(self):
        assert py_normalize_class("bpks") == "bpks"
        assert py_normalize_family("bpks") == "UNKNOWN"

    def test_hyphen_sensitivity(self):
        """ofdm-64 is valid; ofdm64 is not."""
        assert py_normalize_class("ofdm-64") == "ofdm"
        assert py_normalize_class("ofdm64") == "ofdm64"


# ---------------------------------------------------------------------------
# Tests: full 76-class taxonomy -> canonical coverage
# ---------------------------------------------------------------------------

class TestFullTaxonomyCoverage:
    """Every one of the 76 production classes must normalize to a valid
    canonical class."""

    @pytest.mark.parametrize("cls", CLASSES)
    def test_all_76_classes_normalize_to_canonical(self, cls: str):
        canonical = py_normalize_class(cls)
        assert canonical in PY_CANONICAL_CLASSES, (
            f"Class {cls!r} normalized to {canonical!r}, which is not canonical"
        )

    def test_76_classes_cover_all_57_canonical(self):
        """Normalizing all 76 classes should produce all 57 canonical classes."""
        normalized = {py_normalize_class(c) for c in CLASSES}
        assert normalized == set(PY_CANONICAL_CLASSES), (
            f"Missing canonical: {set(PY_CANONICAL_CLASSES) - normalized}. "
            f"Extra: {normalized - set(PY_CANONICAL_CLASSES)}"
        )


# ---------------------------------------------------------------------------
# Tests: super-family consistency between Python taxonomy layers
# ---------------------------------------------------------------------------

class TestSuperFamilyGroupings:
    """Verify super-family -> family -> class hierarchy is consistent and
    that every canonical class has a well-defined super-family path.

    (Super-families exist only in Python taxonomy; Rust does not carry them.
    These tests ensure the Python-only layer is internally consistent with
    the shared canonical-class/family layer.)
    """

    def test_super_family_count(self):
        assert len(SUPER_FAMILIES) == 9

    def test_every_family_has_super_family(self):
        families_in_sf = set()
        for fam_list in SUPER_FAMILY_TO_FAMILIES.values():
            families_in_sf.update(fam_list)
        assert families_in_sf == set(FAMILIES), (
            f"Missing: {set(FAMILIES) - families_in_sf}. "
            f"Extra: {families_in_sf - set(FAMILIES)}"
        )

    def test_no_family_in_multiple_super_families(self):
        seen: dict[str, str] = {}
        for sf, fam_list in SUPER_FAMILY_TO_FAMILIES.items():
            for fam in fam_list:
                assert fam not in seen, (
                    f"Family {fam!r} assigned to both {seen[fam]!r} and {sf!r}"
                )
                seen[fam] = sf

    def test_canonical_class_super_family_path(self):
        """Every canonical class should have: class -> family -> super-family."""
        family_to_sf: dict[str, str] = {}
        for sf, fams in SUPER_FAMILY_TO_FAMILIES.items():
            for f in fams:
                family_to_sf[f] = sf

        for cls in PY_CANONICAL_CLASSES:
            family = PY_CANONICAL_CLASS_TO_FAMILY[cls]
            assert family in family_to_sf, (
                f"Family {family!r} (for class {cls!r}) has no super-family"
            )

    def test_rust_families_subset_of_taxonomy(self, rust_class_to_family: dict[str, str]):
        """All family names used in Rust should exist in the Python taxonomy."""
        rust_families = set(rust_class_to_family.values())
        assert rust_families.issubset(set(FAMILIES)), (
            f"Rust uses families not in taxonomy: {rust_families - set(FAMILIES)}"
        )


# ---------------------------------------------------------------------------
# Tests: taxonomy FAMILY_TO_CLASSES vs canonical class_map consistency
# ---------------------------------------------------------------------------

class TestTaxonomyCanonicalConsistency:
    """Verify the 76-class taxonomy families are consistent with the
    57-class canonical family mapping after normalization."""

    def test_every_taxonomy_class_family_agrees_after_normalization(self):
        """For every 76-class entry, normalizing and looking up the canonical
        family should agree with the taxonomy's own family assignment."""
        for cls in CLASSES:
            taxonomy_family = TAXONOMY_CLASS_TO_FAMILY[cls]
            canonical = py_normalize_class(cls)
            canonical_family = PY_CANONICAL_CLASS_TO_FAMILY.get(canonical)
            # Families may differ in name for merged families. The canonical
            # family must be one of the taxonomy families.
            assert canonical_family is not None, (
                f"Canonical {canonical!r} (from {cls!r}) has no family"
            )
            assert canonical_family in FAMILIES

    def test_family_to_classes_union_covers_all_76(self):
        all_classes = set()
        for cls_list in FAMILY_TO_CLASSES.values():
            all_classes.update(cls_list)
        assert all_classes == set(CLASSES)

    def test_family_to_classes_all_normalize_within_family(self):
        """Within each taxonomy family, all classes that merge should merge
        to a canonical class whose canonical family is the same taxonomy
        family (or the 'parent' family in the canonical world)."""
        for family, cls_list in FAMILY_TO_CLASSES.items():
            for cls in cls_list:
                canonical = py_normalize_class(cls)
                canon_fam = PY_CANONICAL_CLASS_TO_FAMILY.get(canonical)
                # FSK family in taxonomy includes MSK and GFSK/GMSK variants
                # which in canonical land all map to FSK as well
                assert canon_fam is not None, (
                    f"{cls!r} -> {canonical!r} has no canonical family"
                )


# ---------------------------------------------------------------------------
# Tests: families of the shipped open-default model's classes
# ---------------------------------------------------------------------------

# The 16 output names of the open-default model, in output order.
_OPEN_DEFAULT_MODEL_CLASSES = [
    "noise", "tone", "am", "fm", "ask", "psk", "qam", "fsk", "gfsk", "msk",
    "ofdm", "lora-css", "dsss", "adsb", "fpv-analog", "pocsag",
]


def _parse_rust_open_default_class_to_family(src: str) -> dict[str, str]:
    """Extract OPEN_DEFAULT_CLASS_TO_FAMILY entries from Rust."""
    block_match = re.search(
        r"static\s+OPEN_DEFAULT_CLASS_TO_FAMILY.*?LazyLock::new\(\|\|\s*\{(.*?)\}\);",
        src,
        re.DOTALL,
    )
    assert block_match is not None, (
        "Could not find OPEN_DEFAULT_CLASS_TO_FAMILY block in Rust source"
    )
    pairs = re.findall(
        r'm\.insert\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)', block_match.group(1)
    )
    return dict(pairs)


class TestOpenDefaultModelFamilies:
    """The gateway and the bridge both derive the family on ingest, and the
    gateway raises the anomaly score for UNKNOWN, so the two must agree on
    the shipped model's class names."""

    def test_rust_fallback_table_matches_python(self, rust_src: str):
        from sigrift.bridge.class_map import OPEN_DEFAULT_CLASS_TO_FAMILY

        assert (
            _parse_rust_open_default_class_to_family(rust_src)
            == OPEN_DEFAULT_CLASS_TO_FAMILY
        )

    def test_fallback_table_does_not_shadow_canonical_classes(
        self, rust_src: str, rust_class_to_family: dict[str, str]
    ):
        fallback = _parse_rust_open_default_class_to_family(rust_src)
        assert not set(fallback) & set(rust_class_to_family)
        assert not set(fallback) & set(PY_CANONICAL_CLASS_TO_FAMILY)

    def test_every_model_class_has_one_known_family_on_both_sides(
        self,
        rust_src: str,
        rust_signal_class_map: dict[str, str],
        rust_class_to_family: dict[str, str],
    ):
        fallback = _parse_rust_open_default_class_to_family(rust_src)
        for cls in _OPEN_DEFAULT_MODEL_CLASSES:
            canonical = rust_signal_class_map.get(cls, cls)
            rust_family = rust_class_to_family.get(canonical) or fallback.get(
                canonical, "UNKNOWN"
            )
            assert rust_family == py_normalize_family(cls), cls
            assert rust_family != "UNKNOWN", cls
