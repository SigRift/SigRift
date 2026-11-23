"""Tests for the synthetic preset generator and the committed preset bundles."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from sigrift.bridge import bundles as B
from sigrift.lib import taxonomy_open

_REPO = Path(__file__).resolve().parents[2]
_GEN_PATH = _REPO / "training" / "generate_preset_bundles.py"
_PRESETS_DIR = _REPO / "src" / "sigrift" / "bridge" / "presets"


def _load_generator():
    spec = importlib.util.spec_from_file_location("gen_preset", _GEN_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gen = _load_generator()


# ---------------------------------------------------------------------------
# Profile validation
# ---------------------------------------------------------------------------


def test_profile_load_rejects_unknown_class():
    bad = {
        "profile": "bad",
        "seed": 1,
        "version": 1,
        "diurnal": "flat",
        "bands": [
            {
                "name": "b",
                "freq_start_hz": 433_000_000,
                "freq_step_hz": 100_000,
                "slots": 1,
                "detections_per_slot": [10, 20],
                "classes": {"tpms": 1.0},  # not a source class
                "snr_db": [10, 20],
            }
        ],
    }
    with pytest.raises(ValueError, match="tpms"):
        gen._validate_classes(bad)


def test_shipped_profiles_all_use_valid_classes():
    for pfile in (_REPO / "training" / "configs" / "presets").glob("*.json"):
        gen._validate_classes(json.loads(pfile.read_text()))


# ---------------------------------------------------------------------------
# Committed bundles
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "profile",
    ["urban-dense", "suburban-residential", "rural-quiet", "office-commercial"],
)
class TestCommittedBundles:
    def _bundle(self, profile):
        return _PRESETS_DIR / f"preset_{profile}_v1.sigrift.tar.gz"

    def test_bundle_present_and_validates(self, profile):
        path = self._bundle(profile)
        assert path.exists(), f"missing committed bundle for {profile}"
        report, manifest, members = B.validate_bundle(path, expect_kind="preset")
        assert report.valid, [
            c.model_dump() for c in report.checks if c.result == "fail"
        ]
        assert manifest.profile == profile
        assert manifest.generator.seed is not None

    def test_under_size_budget(self, profile):
        assert self._bundle(profile).stat().st_size <= 512 * 1024

    def test_baselines_open16_keyed_and_warm(self, profile):
        _, _, members = B.validate_bundle(self._bundle(profile))
        baselines, _ = B.load_rf_baselines_from_bytes(members["rf_baselines.json"])
        assert baselines, "preset has no baselines"
        open16 = set(taxonomy_open.OPEN_DEFAULT_CLASSES)
        for bl in baselines.values():
            assert set(bl.class_counts) <= open16
        # Hot slots must have exited the learning phase.
        assert any(not bl.is_learning() for bl in baselines.values())

    def test_no_mac_shaped_strings(self, profile):
        _, _, members = B.validate_bundle(self._bundle(profile))
        blob = members["rf_baselines.json"].decode()
        assert not B._MAC_RE.search(blob.replace('"', ""))

    def test_whitelist_entries_valid_and_have_collapsed_labels(self, profile):
        _, _, members = B.validate_bundle(self._bundle(profile))
        entries = B.load_whitelist_entries_from_bytes(members["signal_whitelist.json"])
        assert entries
        assert all(e.node_ids is None for e in entries)
        # FM broadcast entry should now include the open label 'fm'.
        fm = next(e for e in entries if e.freq_min_hz <= 100_000_000 <= e.freq_max_hz)
        assert "fm" in fm.expected_classes


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_regeneration_is_structurally_deterministic(tmp_path):
    # rural-quiet is the cheapest profile.
    a = gen.generate_profile("rural-quiet", tmp_path / "a", gen._DEFAULT_TIMESTAMP)
    b = gen.generate_profile("rural-quiet", tmp_path / "b", gen._DEFAULT_TIMESTAMP)
    _, _, ma = B.validate_bundle(a)
    _, _, mb = B.validate_bundle(b)
    bla, _ = B.load_rf_baselines_from_bytes(ma["rf_baselines.json"])
    blb, _ = B.load_rf_baselines_from_bytes(mb["rf_baselines.json"])
    assert set(bla) == set(blb)
    for f in bla:
        assert bla[f].total_detections == blb[f].total_detections
        assert abs(bla[f].power_ewma - blb[f].power_ewma) < 1e-6
        assert bla[f].hourly_counts == blb[f].hourly_counts
