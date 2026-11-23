"""Tests for the learned-state bundle format module (sigrift.bridge.bundles)."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from sigrift.bridge import bundles as B
from sigrift.bridge.anomaly.baseline import BaselineManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _warm_rf_manager(freqs=(433_920_000,), n=400) -> BaselineManager:
    mgr = BaselineManager()
    for f in freqs:
        for i in range(n):
            mgr.update(
                f,
                "ook",
                0.9,
                -60.0 + (i % 5),
                i % 24,
                snr_db=20.0,
                bandwidth_hz=25000.0,
            )
    return mgr


def _build_preset(tmp_path: Path, mgr: BaselineManager | None = None) -> Path:
    mgr = mgr or _warm_rf_manager()
    for bl in mgr.baselines.values():
        B.sanitize_rf_baseline(bl)
    rf_bytes = B.serialize_rf_manager(mgr)
    out = tmp_path / "preset_test_v1.sigrift.tar.gz"
    return B.build_bundle(
        out,
        kind="preset",
        component_bytes={"rf_baselines.json": rf_bytes},
        profile="test",
        name="Test preset",
        created_at="2026-07-01T00:00:00+00:00",
        mtime=0,
    )


def _write_tar(path: Path, members: list[tuple[str, bytes]]) -> None:
    """Write a raw .tar.gz with arbitrary members (for attack-vector tests)."""
    with tarfile.open(path, "w:gz") as tar:
        for name, data in members:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))


def _manifest_dict(components: list[dict], kind="preset", **over) -> dict:
    compat = B.compat_snapshot().model_dump()
    base = {
        "schema_version": 1,
        "kind": kind,
        "profile": "x",
        "name": "",
        "description": "",
        "created_at": "2026-07-01T00:00:00+00:00",
        "generator": {"tool": "test"},
        "compatibility": compat,
        "components": components,
        "extensions": {},
    }
    base.update(over)
    return base


def _component(fname: str, data: bytes, **over) -> dict:
    import hashlib

    c = {
        "file": fname,
        "type": B.COMPONENT_FILES[fname],
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "optional": False,
    }
    c.update(over)
    return c


# ---------------------------------------------------------------------------
# Round trip
# ---------------------------------------------------------------------------


class TestRoundTrip:
    def test_preset_builds_and_validates(self, tmp_path):
        path = _build_preset(tmp_path)
        report, manifest, members = B.validate_bundle(path, expect_kind="preset")
        assert report.valid, [
            c.model_dump() for c in report.checks if c.result == "fail"
        ]
        assert manifest.kind == "preset"
        assert "rf_baselines.json" in members

    def test_apply_restores_baseline_state(self, tmp_path):
        mgr = _warm_rf_manager()
        expected_bins = set(mgr.baselines)
        expected_total = sum(b.total_detections for b in mgr.baselines.values())
        path = _build_preset(tmp_path, mgr)
        _, _, members = B.validate_bundle(path)
        loaded, alpha = B.load_rf_baselines_from_bytes(members["rf_baselines.json"])
        assert set(loaded) == expected_bins
        assert sum(b.total_detections for b in loaded.values()) == expected_total

    def test_export_allows_wifi_member(self, tmp_path):
        out = tmp_path / "sigrift_export_x.sigrift.tar.gz"
        B.build_bundle(
            out,
            kind="export",
            component_bytes={
                "wifi_baselines.json": b'{"schema_version":1,"baselines":{}}'
            },
        )
        report, _, _ = B.validate_bundle(out, expect_kind="export")
        assert report.valid


# ---------------------------------------------------------------------------
# Sanitizer
# ---------------------------------------------------------------------------


class TestSanitizer:
    def test_transients_zeroed_and_hourly_neutral(self):
        mgr = _warm_rf_manager()
        bl = next(iter(mgr.baselines.values()))
        bl.cusum_pos = 5.0
        bl.last_detection_time = 123.0
        B.sanitize_rf_baseline(bl)
        assert bl.cusum_pos == 0.0
        assert bl.last_detection_time == 0.0
        assert bl.hourly_counts == B.expected_neutral_hourly(bl.class_counts)

    def test_buffers_truncated(self):
        mgr = _warm_rf_manager(n=600)
        bl = next(iter(mgr.baselines.values()))
        B.sanitize_rf_baseline(bl, buffer_cap=120)
        assert len(bl.power_samples) <= 120

    def test_variance_widened(self):
        mgr = _warm_rf_manager()
        bl = next(iter(mgr.baselines.values()))
        before = bl.power_var
        B.sanitize_rf_baseline(bl, variance_widening=2.0)
        # widened then rounded to 4 sig figs
        assert bl.power_var >= before

    def test_leak_assert_raises_on_planted_mac(self):
        mgr = _warm_rf_manager()
        bl = next(iter(mgr.baselines.values()))
        bl.class_counts["aa:bb:cc:dd:ee:ff"] = 3
        with pytest.raises(B.BundleError):
            B.sanitize_rf_baseline(bl)

    def test_sanitize_is_idempotent_for_validator(self, tmp_path):
        # Building twice from the same warmed state yields a preset that passes
        # the sanitized-fixpoint check.
        path = _build_preset(tmp_path)
        report, _, _ = B.validate_bundle(path)
        names = {c.check for c in report.checks if c.result == "pass"}
        assert "rf_baselines.json sanitized" in names


# ---------------------------------------------------------------------------
# Attack vectors — every one must be a failed check, never an exception
# ---------------------------------------------------------------------------


class TestAttackVectors:
    def test_path_traversal_member(self, tmp_path):
        p = tmp_path / "bad.tar.gz"
        _write_tar(p, [("../evil.json", b"{}"), ("manifest.json", b"{}")])
        report, _, _ = B.validate_bundle(p)
        assert not report.valid
        assert any(c.check == "archive_safety" for c in report.checks)

    def test_absolute_path_member(self, tmp_path):
        p = tmp_path / "bad.tar.gz"
        _write_tar(p, [("/etc/passwd", b"x"), ("manifest.json", b"{}")])
        report, _, _ = B.validate_bundle(p)
        assert not report.valid

    def test_symlink_member(self, tmp_path):
        p = tmp_path / "bad.tar.gz"
        with tarfile.open(p, "w:gz") as tar:
            info = tarfile.TarInfo(name="manifest.json")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            tar.addfile(info)
        report, _, _ = B.validate_bundle(p)
        assert not report.valid

    def test_manifest_not_first(self, tmp_path):
        p = tmp_path / "bad.tar.gz"
        _write_tar(p, [("rf_baselines.json", b"{}"), ("manifest.json", b"{}")])
        report, _, _ = B.validate_bundle(p)
        assert not report.valid
        assert any(c.check == "manifest_first" for c in report.checks)

    def test_sha256_mismatch(self, tmp_path):
        rf = b'{"schema_version":1,"alpha":0.01,"baselines":{}}'
        comp = _component("rf_baselines.json", rf, sha256="0" * 64)
        manifest = json.dumps(_manifest_dict([comp])).encode()
        p = tmp_path / "bad.tar.gz"
        _write_tar(p, [("manifest.json", manifest), ("rf_baselines.json", rf)])
        report, _, _ = B.validate_bundle(p)
        assert not report.valid
        fails = [c for c in report.checks if c.result == "fail"]
        assert any("sha256" in c.check for c in fails)
        assert all(c.fix for c in fails if "sha256" in c.check)  # fix text present

    def test_oversize_vs_declared_bytes(self, tmp_path):
        rf = b'{"schema_version":1,"alpha":0.01,"baselines":{}}'
        comp = _component("rf_baselines.json", rf, bytes=4)  # lie: declare 4 bytes
        manifest = json.dumps(_manifest_dict([comp])).encode()
        p = tmp_path / "bad.tar.gz"
        _write_tar(p, [("manifest.json", manifest), ("rf_baselines.json", rf)])
        report, _, _ = B.validate_bundle(p)
        assert not report.valid

    def test_nan_literal_rejected(self, tmp_path):
        rf = b'{"schema_version":1,"alpha":0.01,"baselines":{"1e8":{"power_ewma":NaN}}}'
        comp = _component("rf_baselines.json", rf)
        manifest = json.dumps(_manifest_dict([comp])).encode()
        p = tmp_path / "bad.tar.gz"
        _write_tar(p, [("manifest.json", manifest), ("rf_baselines.json", rf)])
        report, _, _ = B.validate_bundle(p)
        assert not report.valid

    def test_future_schema_version_rejected(self, tmp_path):
        rf = b'{"schema_version":1,"alpha":0.01,"baselines":{}}'
        comp = _component("rf_baselines.json", rf)
        manifest = json.dumps(_manifest_dict([comp], schema_version=99)).encode()
        p = tmp_path / "bad.tar.gz"
        _write_tar(p, [("manifest.json", manifest), ("rf_baselines.json", rf)])
        report, _, _ = B.validate_bundle(p)
        assert not report.valid
        assert any(
            c.check == "schema_version" and c.result == "fail" for c in report.checks
        )

    def test_unknown_optional_component_skipped(self, tmp_path):
        rf = b'{"schema_version":1,"alpha":0.01,"baselines":{}}'
        comp = _component("rf_baselines.json", rf, type="future_thing", optional=True)
        manifest = json.dumps(_manifest_dict([comp], kind="export")).encode()
        p = tmp_path / "b.tar.gz"
        _write_tar(p, [("manifest.json", manifest), ("rf_baselines.json", rf)])
        report, _, _ = B.validate_bundle(p)
        assert any(c.check == "optional_skipped" for c in report.checks)

    def test_unknown_nonoptional_component_rejected(self, tmp_path):
        rf = b'{"schema_version":1,"alpha":0.01,"baselines":{}}'
        comp = _component("rf_baselines.json", rf, type="future_thing", optional=False)
        manifest = json.dumps(_manifest_dict([comp], kind="export")).encode()
        p = tmp_path / "b.tar.gz"
        _write_tar(p, [("manifest.json", manifest), ("rf_baselines.json", rf)])
        report, _, _ = B.validate_bundle(p)
        assert not report.valid

    def test_preset_with_wifi_member_rejected(self, tmp_path):
        wifi = b'{"schema_version":1,"baselines":{}}'
        comp = _component("wifi_baselines.json", wifi)
        manifest = json.dumps(_manifest_dict([comp], kind="preset")).encode()
        p = tmp_path / "b.tar.gz"
        _write_tar(p, [("manifest.json", manifest), ("wifi_baselines.json", wifi)])
        report, _, _ = B.validate_bundle(p)
        assert not report.valid
        assert any("preset_forbidden" in c.check for c in report.checks)

    def test_bt_dimension_weights_reserved_rejected(self, tmp_path):
        cfg = json.dumps({"config": {"bt_dimension_weights": {"x": 0.5}}}).encode()
        comp = _component("detection_config.json", cfg)
        manifest = json.dumps(_manifest_dict([comp], kind="export")).encode()
        p = tmp_path / "b.tar.gz"
        _write_tar(p, [("manifest.json", manifest), ("detection_config.json", cfg)])
        report, _, _ = B.validate_bundle(p)
        assert not report.valid
        assert any("reserved" in c.check for c in report.checks)

    def test_weight_sum_bound(self, tmp_path):
        cfg = json.dumps(
            {"config": {"rf_dimension_weights": {"a": 0.9, "b": 0.9, "c": 0.9}}}
        ).encode()
        comp = _component("detection_config.json", cfg)
        manifest = json.dumps(_manifest_dict([comp], kind="export")).encode()
        p = tmp_path / "b.tar.gz"
        _write_tar(p, [("manifest.json", manifest), ("detection_config.json", cfg)])
        report, _, _ = B.validate_bundle(p)
        assert not report.valid

    @pytest.mark.parametrize(
        ("config", "kind", "problem"),
        [
            ({"rf_anomaly_insert_threshold": "abc"}, "preset", "rf_anomaly_insert"),
            ({"rf_anomaly_alert_threshold": None}, "preset", "rf_anomaly_alert"),
            ({"rf_auto_snooze_hours": 10**8}, "preset", "rf_auto_snooze_hours"),
            (
                {"rf_dimension_weights": {"a": "0.1"}},
                "preset",
                "rf_dimension_weights.a",
            ),
            ({"wifi_dimension_weights": [0.1]}, "export", "wifi_dimension_weights"),
            ({"protocol_detection": {"adsb": "off"}}, "export", "protocol_detection"),
            ({"auto_rescan": {"enabled": True, "max_retries": 0}}, "export", "auto_"),
            ({"auto_rescan": {"enabled": "true"}}, "export", "auto_rescan"),
            ({"iq_capture_enabled": 1}, "export", "iq_capture_enabled"),
            # The bounds of a whole object: 64 entries, a weight sum of 2.0.
            (
                {"wifi_dimension_weights": {"a": 1.0, "b": 1.0, "c": 0.5}},
                "export",
                "they would sum to 2.50",
            ),
            (
                {"rf_dimension_weights": {f"w{i}": 0.0 for i in range(65)}},
                "preset",
                "at most 64 weights",
            ),
            (
                {"protocol_detection": {f"p{i}": True for i in range(65)}},
                "export",
                "at most 64 true / false toggles",
            ),
        ],
    )
    def test_detection_config_values_are_checked(self, tmp_path, config, kind, problem):
        # The same value rules as PUT /api/admin/detection-config: a value of
        # the wrong type or range fails validation, so it is never applied.
        cfg = json.dumps({"config": config}).encode()
        comp = _component("detection_config.json", cfg)
        manifest = json.dumps(_manifest_dict([comp], kind=kind)).encode()
        p = tmp_path / "b.tar.gz"
        _write_tar(p, [("manifest.json", manifest), ("detection_config.json", cfg)])
        report, _, _ = B.validate_bundle(p)
        assert not report.valid
        [check] = [c for c in report.checks if c.result == "fail"]
        assert check.check == "detection_config.json detection_config"
        assert problem in check.detail

    def test_detection_config_must_be_an_object(self, tmp_path):
        cfg = json.dumps({"config": ["rf_anomaly_insert_threshold", 0.3]}).encode()
        comp = _component("detection_config.json", cfg)
        manifest = json.dumps(_manifest_dict([comp], kind="export")).encode()
        p = tmp_path / "b.tar.gz"
        _write_tar(p, [("manifest.json", manifest), ("detection_config.json", cfg)])
        report, _, _ = B.validate_bundle(p)
        assert not report.valid

    def test_export_detection_config_keeps_unknown_keys(self, tmp_path):
        # Another version's keys stay inert: an export bundle may carry them.
        cfg = json.dumps(
            {
                "config": {
                    "rf_anomaly_insert_threshold": 0.3,
                    "protocol_detection": {"future_proto": False},
                    "future_setting": "anything",
                }
            }
        ).encode()
        comp = _component("detection_config.json", cfg)
        manifest = json.dumps(_manifest_dict([comp], kind="export")).encode()
        p = tmp_path / "b.tar.gz"
        _write_tar(p, [("manifest.json", manifest), ("detection_config.json", cfg)])
        report, _, _ = B.validate_bundle(p)
        assert report.valid, [c for c in report.checks if c.result == "fail"]


# ---------------------------------------------------------------------------
# detection_config planning
# ---------------------------------------------------------------------------


class TestDetectionConfigPlan:
    def test_preset_subset_only(self):
        current = {
            "rf_anomaly_insert_threshold": 0.3,
            "protocol_detection": {"adsb": True},
        }
        bundle = {
            "config": {
                "rf_anomaly_insert_threshold": 0.5,
                "protocol_detection": {"adsb": False},
            }
        }
        merged = B.plan_detection_config(current, bundle, subset_only=True)
        assert merged["rf_anomaly_insert_threshold"] == 0.5
        # protocol_detection is NOT in the preset subset -> unchanged
        assert merged["protocol_detection"] == {"adsb": True}

    def test_export_full_deep_merge(self):
        current = {"rf_dimension_weights": {"a": 0.1, "b": 0.2}}
        bundle = {"config": {"rf_dimension_weights": {"a": 0.5}}}
        merged = B.plan_detection_config(current, bundle, subset_only=False)
        assert merged["rf_dimension_weights"] == {"a": 0.5, "b": 0.2}

    def test_merges_the_checked_values(self):
        bundle = {
            "config": {
                "rf_auto_snooze_seen_count": 120.0,
                "auto_rescan": {"enabled": True},
            }
        }
        merged = B.plan_detection_config({}, bundle, subset_only=False)
        assert type(merged["rf_auto_snooze_seen_count"]) is int
        assert merged["auto_rescan"] == {
            "enabled": True,
            "confidence_threshold": 0.5,
            "max_retries": 2,
        }

    @pytest.mark.parametrize(
        "config",
        [
            {"rf_anomaly_insert_threshold": "abc"},
            # auto_rescan is strict too: a string is refused, not converted.
            {"auto_rescan": {"enabled": "false"}},
            {"auto_rescan": {"confidence_threshold": "0.4"}},
            {"auto_rescan": {"max_retries": True}},
        ],
    )
    def test_refuses_a_value_validation_would_refuse(self, config):
        with pytest.raises(B.BundleError, match=next(iter(config))):
            B.plan_detection_config({}, {"config": config}, subset_only=False)

    def test_preset_keys_outside_the_subset_are_neither_checked_nor_merged(self):
        bundle = {
            "config": {
                "rf_anomaly_insert_threshold": 0.35,
                "protocol_detection": {"adsb": "off"},
                "bt_dimension_weights": "reserved",
            }
        }
        current = {"protocol_detection": {"adsb": True}}
        merged = B.plan_detection_config(current, bundle, subset_only=True)
        assert merged == {**current, "rf_anomaly_insert_threshold": 0.35}
        with pytest.raises(B.BundleError, match=r"protocol_detection\.adsb"):
            B.plan_detection_config(current, bundle, subset_only=False)

    def test_bounds_hold_for_the_weights_merged_into_the_current_ones(self):
        # A bundle's weights merge into the ones in force: what would be
        # stored keeps at most 64 weights summing to at most 2.0, so the
        # result can always be exported and imported again.
        current = {"rf_dimension_weights": {f"w{i}": 0.01 for i in range(14)}}
        fits = {"rf_dimension_weights": {f"x{i}": 0.0 for i in range(50)}}
        merged = B.plan_detection_config(current, {"config": fits}, False)
        assert len(merged["rf_dimension_weights"]) == 64
        over = {"rf_dimension_weights": {f"x{i}": 0.0 for i in range(51)}}
        with pytest.raises(B.BundleError, match="there would be 65"):
            B.plan_detection_config(current, {"config": over}, False)
        # Sums: the merged object's (1.0 + 13 * 0.01 + 0.88 = 2.01).
        heavy = {"rf_dimension_weights": {"w0": 1.0, "y": 0.88}}
        with pytest.raises(B.BundleError, match="would sum to 2.01"):
            B.plan_detection_config(current, {"config": heavy}, False)
        heavy["rf_dimension_weights"]["y"] = 0.87
        merged = B.plan_detection_config(current, {"config": heavy}, False)
        assert merged["rf_dimension_weights"]["y"] == 0.87
        # Protocol names stay free in a bundle, but not their number.
        toggles = {"protocol_detection": {f"p{i}": True for i in range(60)}}
        new = {"protocol_detection": {f"q{i}": False for i in range(5)}}
        with pytest.raises(B.BundleError, match="there would be 65"):
            B.plan_detection_config(toggles, {"config": new}, False)
        new["protocol_detection"].pop("q4")
        merged = B.plan_detection_config(toggles, {"config": new}, False)
        assert len(merged["protocol_detection"]) == 64


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestCLI:
    def test_validate_cli(self, tmp_path, capsys):
        path = _build_preset(tmp_path)
        rc = B.main(["validate", str(path)])
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["valid"] is True

    def test_extract_cli(self, tmp_path):
        path = _build_preset(tmp_path)
        out = tmp_path / "rf.json"
        rc = B.main(["extract", str(path), "--component", "rf", "-o", str(out)])
        assert rc == 0
        assert json.loads(out.read_text())["baselines"]

    def test_export_cli(self, tmp_path):
        # Seed a data dir with a baselines.json the CLI will pick up.
        mgr = _warm_rf_manager()
        (tmp_path / "baselines.json").write_bytes(B.serialize_rf_manager(mgr))
        out = tmp_path / "exp.sigrift.tar.gz"
        rc = B.main(
            [
                "export",
                "--data-dir",
                str(tmp_path),
                "-o",
                str(out),
                "--components",
                "rf",
            ]
        )
        assert rc == 0
        report, _, _ = B.validate_bundle(out)
        assert report.valid

    def test_import_live_bridge_guard(self, tmp_path):
        path = _build_preset(tmp_path)
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        # Simulate a running bridge via a fresh WAL file.
        (data_dir / "detections.db-wal").write_bytes(b"x")
        rc = B.main(["import", str(path), "--data-dir", str(data_dir)])
        assert rc == 1  # guard refuses without --force


# ---------------------------------------------------------------------------
# Review-hardening regressions
# ---------------------------------------------------------------------------


class TestNonFiniteAndBomb:
    def test_1e400_literal_becomes_inf_and_is_rejected(self, tmp_path):
        # parse_constant does NOT catch the numeric literal 1e400 (-> inf);
        # the full finite-scan must. Hand-write the JSON so the literal survives.
        rf = b'{"schema_version":1,"alpha":0.01,"baselines":{"433920000.0":{"class_ewma":{"ask":1e400},"power_samples":[1e400,-50.0],"total_detections":5}}}'
        comp = _component("rf_baselines.json", rf)
        manifest = json.dumps(_manifest_dict([comp], kind="export")).encode()
        p = tmp_path / "inf.tar.gz"
        _write_tar(p, [("manifest.json", manifest), ("rf_baselines.json", rf)])
        report, _, _ = B.validate_bundle(p)
        assert not report.valid
        assert any(c.check.endswith("finite") for c in report.checks)

    def test_legit_large_rf_values_still_accepted(self, tmp_path):
        # Bandwidth variance in Hz² and whitelist frequencies legitimately exceed
        # 1e9; they must NOT be rejected (guards against an over-strict fix).
        path = _build_preset(tmp_path, _warm_rf_manager(freqs=(2_450_000_000,)))
        report, _, _ = B.validate_bundle(path)
        assert report.valid, [
            c.model_dump() for c in report.checks if c.result == "fail"
        ]

    def test_oversized_declared_member_rejected_fast(self, tmp_path, monkeypatch):
        # A member whose declared uncompressed size exceeds the cap must be
        # rejected during header iteration, before its payload is decompressed.
        # Build a many-bin preset so the uncompressed rf member exceeds the
        # compressed archive, then set the cap between the two.
        path = _build_preset(
            tmp_path,
            _warm_rf_manager(freqs=tuple(433_000_000 + i * 25_000 for i in range(30))),
        )
        file_size = path.stat().st_size
        with tarfile.open(path, "r:gz") as t:
            member_max = max(m.size for m in t.getmembers())
        assert member_max > file_size  # JSON compresses, so this holds
        monkeypatch.setattr(B, "MAX_BUNDLE_BYTES", (file_size + member_max) // 2)
        report, _, _ = B.validate_bundle(path)
        assert not report.valid
        assert any(c.check == "member_size" for c in report.checks)
