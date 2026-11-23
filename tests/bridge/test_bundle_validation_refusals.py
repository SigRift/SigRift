"""Untrusted-bundle validation: every refusal the pipeline promises.

Complements ``test_bundles.py``: archive limits and member types, manifest
limits and parse failures, manifest/member mismatches, the structural RF /
whitelist / WiFi / BT / detection-config checks, the preset sanitation fixpoint,
compatibility warnings, manifest reads of packaged presets, and the CLI's
refusals (``python -m sigrift.bridge.bundles``).
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import logging
import os
import subprocess
import sys
import tarfile
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from sigrift.bridge import bundles as B
from sigrift.bridge.anomaly.bt_scorer import BtBaselineManager
from sigrift.bridge.anomaly.wifi_scorer import WifiBaselineManager

_ROOT = Path(__file__).resolve().parents[2]
_FREQ = "433920000.0"
_BIN = {"power_ewma": -60.0, "power_var": 4.0, "snr_ewma": 20.0, "snr_var": 1.0}
# A sanitized preset bin: class_counts {"ook": 48} -> 2 per hour.
_CLEAN_BIN = {
    **_BIN,
    "class_counts": {"ook": 48},
    "hourly_counts": {str(h): {"ook": 2} for h in range(24)},
}
_PACKAGED = {"office-commercial", "rural-quiet", "suburban-residential", "urban-dense"}


def _info(name: str, data: bytes = b"", **attrs) -> tuple[tarfile.TarInfo, bytes]:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    for key, value in attrs.items():
        setattr(info, key, value)
    return info, data


def _write(path: Path, members: list[tuple[tarfile.TarInfo, bytes]]) -> Path:
    with tarfile.open(path, "w:gz") as tar:
        for info, data in members:
            tar.addfile(info, io.BytesIO(data))
    return path


def _entry(fname: str, data: bytes) -> dict:
    return {
        "file": fname,
        "type": B.COMPONENT_FILES[fname],
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
    }


def _manifest(components: list[dict], **over) -> bytes:
    manifest = {
        "schema_version": 1,
        "kind": "export",
        "created_at": "2026-07-01T00:00:00+00:00",
        "generator": {"tool": "test"},
        "compatibility": B.compat_snapshot().model_dump(),
        "components": components,
    }
    manifest.update(over)
    return json.dumps(manifest).encode()


def _bundle(tmp_path: Path, components: dict[str, object], kind="export", **kw) -> Path:
    blobs = {fname: json.dumps(obj).encode() for fname, obj in components.items()}
    return B.build_bundle(
        tmp_path / f"{kind}.sigrift.tar.gz", kind=kind, component_bytes=blobs, **kw
    )


def _failed(report) -> list[tuple[str, str]]:
    return [(c.check, c.detail) for c in report.checks if c.result == "fail"]


def _warned(report) -> list[str]:
    return [c.check for c in report.checks if c.result == "warn"]


# ---------------------------------------------------------------------------
# Building
# ---------------------------------------------------------------------------


class TestBuildRefusals:
    def test_unknown_component_file_is_not_packaged(self, tmp_path):
        out = tmp_path / "x.sigrift.tar.gz"
        with pytest.raises(B.BundleError, match="unknown component file: 'notes.txt'"):
            B.build_bundle(out, kind="export", component_bytes={"notes.txt": b"hi"})
        assert list(tmp_path.iterdir()) == []

    def test_preset_refuses_mac_keyed_components(self, tmp_path):
        out = tmp_path / "x.sigrift.tar.gz"
        blobs = {"wifi_baselines.json": b"{}", "bt_baselines.json": b"{}"}
        with pytest.raises(
            B.BundleError,
            match=r"may not contain \['bt_baselines.json', 'wifi_baselines.json'\]",
        ):
            B.build_bundle(out, kind="preset", component_bytes=blobs)
        assert list(tmp_path.iterdir()) == []


# ---------------------------------------------------------------------------
# Archive level
# ---------------------------------------------------------------------------


class TestArchiveRefusals:
    def test_transport_size_cap(self, tmp_path, monkeypatch):
        path = _bundle(tmp_path, {"rf_baselines.json": {"baselines": {}}})
        monkeypatch.setattr(B, "MAX_BUNDLE_BYTES", 64)
        report, manifest, members = B.validate_bundle(path)
        assert (report.valid, manifest, members) == (False, None, {})
        [(check, detail)] = _failed(report)
        assert check == "transport_size"
        assert detail == f"{path.stat().st_size} bytes > 64 cap"

    @pytest.mark.parametrize(
        ("content", "reason"),
        [(b"", "empty file"), (b"PK\x03\x04 not a gzip", "not a gzip file")],
    )
    def test_unreadable_archive(self, tmp_path, content, reason):
        path = tmp_path / "x.sigrift.tar.gz"
        path.write_bytes(content)
        report, manifest, _ = B.validate_bundle(path)
        assert manifest is None
        assert _failed(report) == [("archive_open", f"cannot open archive: {reason}")]

    def test_tar_truncated_inside_a_complete_gzip(self, tmp_path):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w") as tar:
            for info, data in (
                _info("manifest.json", b"{}"),
                _info("rf_baselines.json", b"x" * 5000),
            ):
                tar.addfile(info, io.BytesIO(data))
        path = tmp_path / "x.sigrift.tar.gz"
        path.write_bytes(gzip.compress(raw.getvalue()[: 512 * 3 + 100]))
        report, manifest, _ = B.validate_bundle(path)
        assert manifest is None
        assert _failed(report) == [
            ("archive_read", "corrupt archive: unexpected end of data")
        ]

    def test_member_count_cap(self, tmp_path):
        members = [_info("manifest.json", b"{}")]
        members += [_info(f"extra{i}.json", b"{}") for i in range(B.MAX_MEMBERS)]
        report, _, _ = B.validate_bundle(_write(tmp_path / "x.tar.gz", members))
        assert _failed(report) == [("member_count", "> 16 members")]

    @pytest.mark.parametrize(
        "member",
        [
            _info("rf_baselines.json", type=tarfile.LNKTYPE, linkname="manifest.json"),
            _info("rf_baselines.json", type=tarfile.DIRTYPE),
            _info("rf_baselines.json", type=tarfile.FIFOTYPE),
            _info("rf_baselines.json", type=tarfile.CHRTYPE, devmajor=1, devminor=3),
            _info(".rf_baselines.json", b"{}"),
            _info("sub/rf_baselines.json", b"{}"),
            _info("rf..baselines.json", b"{}"),
        ],
        ids=["hardlink", "directory", "fifo", "device", "dotfile", "nested", "dots"],
    )
    def test_unsafe_members_are_refused(self, tmp_path, member):
        path = _write(tmp_path / "x.tar.gz", [_info("manifest.json", b"{}"), member])
        report, manifest, members = B.validate_bundle(path)
        assert (manifest, members) == (None, {})
        assert _failed(report) == [
            ("archive_safety", f"unsafe member {member[0].name!r}")
        ]

    def test_duplicate_member_is_refused(self, tmp_path):
        members = [_info("manifest.json", b"{}"), _info("rf_baselines.json", b"{}")]
        members.append(_info("rf_baselines.json", b'{"baselines": {}}'))
        report, _, _ = B.validate_bundle(_write(tmp_path / "x.tar.gz", members))
        assert _failed(report) == [
            ("archive_safety", "duplicate member 'rf_baselines.json'")
        ]


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------


class TestManifestRefusals:
    def test_manifest_size_cap(self, tmp_path):
        path = _bundle(
            tmp_path, {"rf_baselines.json": {"baselines": {}}}, description="x" * 70_000
        )
        report, manifest, _ = B.validate_bundle(path)
        assert manifest is None
        assert _failed(report) == [("manifest_size", "manifest too large")]

    @pytest.mark.parametrize(
        "raw",
        [
            b"{not json",
            b'{"schema_version": NaN}',
            _manifest([], operator_note="extra keys are refused"),
            _manifest([], kind="backup"),
        ],
        ids=["syntax", "nan", "extra-key", "kind"],
    )
    def test_unparseable_manifest(self, tmp_path, raw):
        path = _write(tmp_path / "x.tar.gz", [_info("manifest.json", raw)])
        report, manifest, members = B.validate_bundle(path)
        assert (manifest, members) == (None, {})
        [(check, detail)] = _failed(report)
        assert check == "manifest_parse"
        assert detail.startswith("invalid manifest: ")

    def test_wrong_kind_for_the_endpoint(self, tmp_path):
        path = _bundle(tmp_path, {"rf_baselines.json": {"baselines": {}}})
        report, _, _ = B.validate_bundle(path, expect_kind="preset")
        assert _failed(report) == [("kind", "expected kind=preset, got export")]

    def test_extensions_size_cap(self, tmp_path):
        path = _bundle(
            tmp_path,
            {"rf_baselines.json": {"baselines": {}}},
            manifest_extra={"blob": "x" * (B.MAX_EXTENSIONS_BYTES + 1)},
        )
        report, _, _ = B.validate_bundle(path)
        assert _failed(report) == [("extensions_size", "extensions object too large")]

    def test_member_missing_from_the_manifest(self, tmp_path):
        rf = b'{"baselines": {}}'
        members = [
            _info("manifest.json", _manifest([])),
            _info("rf_baselines.json", rf),
        ]
        report, _, kept = B.validate_bundle(_write(tmp_path / "x.tar.gz", members))
        assert _failed(report) == [
            ("orphan_member", "member 'rf_baselines.json' not in manifest")
        ]
        assert kept == {}

    def test_declared_member_absent_from_the_archive(self, tmp_path):
        rf = b'{"baselines": {}}'
        manifest = _manifest([_entry("rf_baselines.json", rf)])
        path = _write(tmp_path / "x.tar.gz", [_info("manifest.json", manifest)])
        report, _, _ = B.validate_bundle(path)
        assert _failed(report) == [
            ("missing_member", "'rf_baselines.json' declared but absent")
        ]


# ---------------------------------------------------------------------------
# Component structure
# ---------------------------------------------------------------------------


class TestRfStructure:
    @pytest.mark.parametrize(
        ("rf", "check", "detail"),
        [
            ({"alpha": 0, "baselines": {}}, "alpha", "alpha 0 not in (0, 1]"),
            ({"alpha": 1.5, "baselines": {}}, "alpha", "alpha 1.5 not in (0, 1]"),
            ({"alpha": "fast", "baselines": {}}, "alpha", "alpha fast not in (0, 1]"),
            ({"baselines": {"abc": _BIN}}, "freq_key", "non-numeric freq 'abc'"),
            ({"baselines": {"5000": _BIN}}, "freq_range", "freq 5000.0 out of range"),
            (
                {"baselines": {"2e10": _BIN}},
                "freq_range",
                "freq 20000000000.0 out of range",
            ),
            ({"baselines": {"nan": _BIN}}, "freq_range", "freq nan out of range"),
            ({"baselines": {"inf": _BIN}}, "freq_range", "freq inf out of range"),
            (
                {"baselines": {_FREQ: {**_BIN, "power_ewma": 5e9}}},
                "finite",
                f"bad float in bin {_FREQ}",
            ),
            (
                {"baselines": {_FREQ: {**_BIN, "snr_var": "high"}}},
                "finite",
                f"bad float in bin {_FREQ}",
            ),
            (
                {"baselines": {_FREQ: {**_BIN, "power_samples": [-60.0] * 501}}},
                "power_samples",
                "sample buffer too large",
            ),
            (
                {
                    "baselines": {
                        _FREQ: {
                            **_BIN,
                            "class_counts": {f"c{i}": 1 for i in range(129)},
                        }
                    }
                },
                "class_count",
                "too many classes in bin",
            ),
        ],
    )
    def test_out_of_bounds_rf_is_refused(self, tmp_path, rf, check, detail):
        report, _, _ = B.validate_bundle(_bundle(tmp_path, {"rf_baselines.json": rf}))
        assert _failed(report) == [(f"rf_baselines.json {check}", detail)]

    def test_bin_count_cap(self, tmp_path, monkeypatch):
        rf = {"baselines": {_FREQ: _BIN, "915000000.0": _BIN}}
        monkeypatch.setattr(B, "MAX_FREQ_BINS", 1)
        report, _, _ = B.validate_bundle(_bundle(tmp_path, {"rf_baselines.json": rf}))
        assert _failed(report) == [("rf_baselines.json bin_count", "2 > 1")]

    @pytest.mark.parametrize(
        ("rf", "detail"),
        [
            ([], "not a JSON object"),
            ({"baselines": [_BIN]}, "baselines is not an object"),
            ({"baselines": {_FREQ: 5}}, f"bin {_FREQ} is not an object"),
        ],
        ids=["list", "baselines-list", "bin-number"],
    )
    def test_rf_of_the_wrong_shape_fails_a_check(self, tmp_path, rf, detail):
        # A failed check (the import answers 422), never an exception (500).
        report, _, _ = B.validate_bundle(_bundle(tmp_path, {"rf_baselines.json": rf}))
        assert _failed(report) == [("rf_baselines.json structure", detail)]


class TestPresetSanitation:
    def test_a_sanitized_bin_passes(self, tmp_path):
        rf = {"baselines": {_FREQ: _CLEAN_BIN}}
        report, _, _ = B.validate_bundle(
            _bundle(tmp_path, {"rf_baselines.json": rf}, kind="preset"),
            expect_kind="preset",
        )
        assert report.valid, _failed(report)

    @pytest.mark.parametrize(
        ("bin_", "check", "detail"),
        [
            (
                {**_CLEAN_BIN, "cusum_pos": 1.5},
                "sanitized",
                f"transient cusum_pos not zeroed in bin {_FREQ}",
            ),
            (
                {**_CLEAN_BIN, "last_detection_time": 1763452800.0},
                "sanitized",
                f"transient last_detection_time not zeroed in bin {_FREQ}",
            ),
            (
                {
                    **_CLEAN_BIN,
                    "hourly_counts": {**_CLEAN_BIN["hourly_counts"], "12": {"ook": 40}},
                },
                "hourly_prior",
                f"hourly_counts is not the neutral prior in bin {_FREQ}",
            ),
            (
                {
                    **_BIN,
                    "class_counts": {"aa:bb:cc:dd:ee:ff": 48},
                    "hourly_counts": {
                        str(h): {"aa:bb:cc:dd:ee:ff": 2} for h in range(24)
                    },
                },
                "mac_leak",
                "MAC-shaped key 'aa:bb:cc:dd:ee:ff'",
            ),
        ],
        ids=["cusum", "last-seen", "real-hourly-pattern", "mac-key"],
    )
    def test_site_specific_state_in_a_preset_is_refused(
        self, tmp_path, bin_, check, detail
    ):
        rf = {"baselines": {_FREQ: bin_}}
        report, _, _ = B.validate_bundle(
            _bundle(tmp_path, {"rf_baselines.json": rf}, kind="preset")
        )
        assert _failed(report) == [(f"rf_baselines.json {check}", detail)]

    def test_preset_whitelist_entries_may_not_name_nodes(self, tmp_path):
        entry = {"freq_min_hz": 1e8, "freq_max_hz": 2e8, "node_ids": ["edge-7"]}
        path = _bundle(
            tmp_path, {"signal_whitelist.json": {"entries": [entry]}}, kind="preset"
        )
        report, _, _ = B.validate_bundle(path)
        assert _failed(report) == [
            (
                "signal_whitelist.json node_ids",
                "preset whitelist entries must have node_ids=null",
            )
        ]

    def test_preset_config_carries_only_the_transferable_subset(self, tmp_path):
        config = {
            "rf_anomaly_insert_threshold": 0.3,
            "protocol_detection": {"adsb": True},
            "iq_capture_enabled": True,
        }
        path = _bundle(
            tmp_path, {"detection_config.json": {"config": config}}, kind="preset"
        )
        report, _, _ = B.validate_bundle(path)
        assert _failed(report) == [
            (
                "detection_config.json preset_subset",
                "non-transferable keys in preset config: "
                "['iq_capture_enabled', 'protocol_detection']",
            )
        ]


class TestWhitelistStructure:
    def test_entry_count_cap(self, tmp_path, monkeypatch):
        entry = {"freq_min_hz": 1e8, "freq_max_hz": 2e8}
        monkeypatch.setattr(B, "MAX_WHITELIST_ENTRIES", 1)
        path = _bundle(tmp_path, {"signal_whitelist.json": {"entries": [entry, entry]}})
        report, _, _ = B.validate_bundle(path)
        assert _failed(report) == [
            ("signal_whitelist.json count", "too many whitelist entries")
        ]

    @pytest.mark.parametrize(
        "entry",
        [
            {"freq_min_hz": 1e8, "freq_max_hz": 2e8, "score_reduction": 5},
            {"freq_min_hz": 1e8, "freq_max_hz": 2e8, "lat": 51.5},
            {"freq_min_hz": 1e8},
        ],
        ids=["out-of-range", "unknown-key", "missing-key"],
    )
    def test_invalid_entry_is_refused(self, tmp_path, entry):
        path = _bundle(tmp_path, {"signal_whitelist.json": {"entries": [entry]}})
        report, _, _ = B.validate_bundle(path)
        [(check, detail)] = _failed(report)
        assert check == "signal_whitelist.json entry"
        assert detail.startswith("invalid whitelist entry: ")

    @pytest.mark.parametrize(
        ("whitelist", "check", "detail"),
        [
            ([], "structure", "not a JSON object"),
            ({"entries": {"a": 1}}, "structure", "entries is not a list"),
            ({"entries": [5]}, "entry", "invalid whitelist entry: "),
        ],
        ids=["list", "entries-object", "entry-number"],
    )
    def test_whitelist_of_the_wrong_shape_fails_a_check(
        self, tmp_path, whitelist, check, detail
    ):
        path = _bundle(tmp_path, {"signal_whitelist.json": whitelist})
        report, _, _ = B.validate_bundle(path)
        [(failed, message)] = _failed(report)
        assert failed == f"signal_whitelist.json {check}"
        assert message.startswith(detail)


_BSSID = "aa:bb:cc:dd:ee:01"
_ADDR = "11:22:33:44:55:66"
_NUMBER = "a number in [-1e+09, 1e+09]"


def _device_checks(tmp_path: Path, fname: str, obj) -> list[tuple[str, str]]:
    report, _, _ = B.validate_bundle(_bundle(tmp_path, {fname: obj}))
    return _failed(report)


class TestWifiBtStructure:
    """Checked against the serializers and the loaders the apply path runs."""

    def test_what_the_serializers_emit_passes(self, tmp_path):
        wifi = WifiBaselineManager()
        wifi.update(_BSSID, "CafeNet", 6, "WPA2", -55.0, 3, 0.01, 12)
        bt = BtBaselineManager()
        bt.update(_ADDR, {"device_name": "tag", "rssi_dbm": -61.0})
        bt.record_batch_size(3)
        blobs = {
            "wifi_baselines.json": B.serialize_wifi_manager(wifi),
            "bt_baselines.json": B.serialize_bt_manager(bt),
        }
        path = B.build_bundle(
            tmp_path / "x.sigrift.tar.gz", kind="export", component_bytes=blobs
        )
        report, _, _ = B.validate_bundle(path)
        assert report.valid, _failed(report)
        passed = {c.check for c in report.checks if c.result == "pass"}
        assert {
            "wifi_baselines.json structure",
            "bt_baselines.json structure",
        } <= passed

    @pytest.mark.parametrize(
        ("wifi", "check", "detail"),
        [
            ([], "structure", "not a JSON object"),
            ({"alpha": 0.02}, "structure", "baselines is missing or not an object"),
            ({"baselines": []}, "structure", "baselines is missing or not an object"),
            (
                {"alpha": -5, "baselines": {}},
                "alpha",
                "alpha must be a number in (0, 1]",
            ),
            (
                {"alpha": True, "baselines": {}},
                "alpha",
                "alpha must be a number in (0, 1]",
            ),
            (
                {"schema_version": "2", "baselines": {}},
                "schema_version",
                "schema_version must be a positive integer",
            ),
            (
                {"baselines": {}, "ssid_to_bssids": {"CafeNet": _BSSID}},
                "ssid_to_bssids",
                "ssid_to_bssids must be an object of BSSID lists",
            ),
            (
                {"baselines": {_BSSID: [1]}},
                "baseline",
                f"baseline {_BSSID!r} is not an object",
            ),
            (
                {"baselines": {_BSSID: {"alpha": 2}}},
                "baseline",
                f"baseline {_BSSID!r}: alpha must be a number in (0, 1]",
            ),
            (
                {"baselines": {_BSSID: {"expected_ssids": ["CafeNet", 7]}}},
                "baseline",
                f"baseline {_BSSID!r}: expected_ssids must be a list of strings",
            ),
            (
                {"baselines": {_BSSID: {"expected_channel": "6"}}},
                "baseline",
                f"baseline {_BSSID!r}: expected_channel must be an integer or null",
            ),
            (
                {"baselines": {_BSSID: {"seen_channels": [6, "11"]}}},
                "baseline",
                f"baseline {_BSSID!r}: seen_channels must be a list of integers",
            ),
            (
                {"baselines": {_BSSID: {"expected_vendor": None}}},
                "baseline",
                f"baseline {_BSSID!r}: expected_vendor must be a string",
            ),
            (
                {"baselines": {_BSSID: {"signal_ewma": "loud"}}},
                "baseline",
                f"baseline {_BSSID!r}: signal_ewma must be {_NUMBER}",
            ),
            (
                # An integer, so past the float scan: float() would overflow.
                {"baselines": {_BSSID: {"client_count_ewma": 10**400}}},
                "baseline",
                f"baseline {_BSSID!r}: client_count_ewma must be {_NUMBER}",
            ),
            (
                {"baselines": {_BSSID: {"signal_var": -1.0}}},
                "baseline",
                f"baseline {_BSSID!r}: signal_var must be a number in [0, 1e+09]",
            ),
            (
                {"baselines": {_BSSID: {"total_observations": 1.5}}},
                "baseline",
                f"baseline {_BSSID!r}: total_observations must be "
                "an integer in [0, 1e+09]",
            ),
        ],
    )
    def test_malformed_wifi_baselines_fail_a_check(self, tmp_path, wifi, check, detail):
        assert _device_checks(tmp_path, "wifi_baselines.json", wifi) == [
            (f"wifi_baselines.json {check}", detail)
        ]

    @pytest.mark.parametrize(
        ("bt", "check", "detail"),
        [
            ("tags", "structure", "not a JSON object"),
            (
                {"alpha": 0, "baselines": {}},
                "alpha",
                "alpha must be a number in (0, 1]",
            ),
            (
                {"baselines": {}, "batch_device_counts": [3, -1]},
                "batch_device_counts",
                "batch_device_counts must be a list of non-negative integers",
            ),
            (
                {"baselines": {}, "batch_device_counts": "3"},
                "batch_device_counts",
                "batch_device_counts must be a list of non-negative integers",
            ),
            (
                {"baselines": {_ADDR: 5}},
                "baseline",
                f"baseline {_ADDR!r} is not an object",
            ),
            (
                {"baselines": {_ADDR: {"expected_name": None}}},
                "baseline",
                f"baseline {_ADDR!r}: expected_name must be a string",
            ),
            (
                {"baselines": {_ADDR: {"expected_device_class": "phone"}}},
                "baseline",
                f"baseline {_ADDR!r}: expected_device_class must be an integer",
            ),
            (
                {"baselines": {_ADDR: {"expected_service_uuids": "180f"}}},
                "baseline",
                f"baseline {_ADDR!r}: expected_service_uuids must be a list of strings",
            ),
            (
                {"baselines": {_ADDR: {"rssi_m2": -0.5}}},
                "baseline",
                f"baseline {_ADDR!r}: rssi_m2 must be a number in [0, 1e+09]",
            ),
            (
                {"baselines": {_ADDR: {"last_seen": 1763452800}}},
                "baseline",
                f"baseline {_ADDR!r}: last_seen must be a string",
            ),
        ],
    )
    def test_malformed_bt_baselines_fail_a_check(self, tmp_path, bt, check, detail):
        assert _device_checks(tmp_path, "bt_baselines.json", bt) == [
            (f"bt_baselines.json {check}", detail)
        ]


# ---------------------------------------------------------------------------
# Compatibility
# ---------------------------------------------------------------------------


class TestCompatibility:
    def _compat(self, **update) -> B.Compatibility:
        return B.compat_snapshot().model_copy(update=update)

    def test_other_bin_strategy_is_refused(self, tmp_path):
        compat = self._compat(freq_bin_strategy="fixed_1mhz")
        path = _bundle(
            tmp_path, {"rf_baselines.json": {"baselines": {}}}, compatibility=compat
        )
        report, _, _ = B.validate_bundle(path)
        assert _failed(report) == [
            ("freq_bin_strategy", "bundle fixed_1mhz != running adaptive_v1")
        ]
        # Bins would not align: nothing further is compared.
        assert "taxonomy_overlap" not in {c.check for c in report.checks}

    def test_informational_differences_only_warn(self, tmp_path):
        running = list(B.compat_snapshot().class_set)
        compat = self._compat(
            class_set=running[:4] + ["future_class"],
            bands_sha256="0" * 64,
            min_learning_detections=100,
        )
        path = _bundle(
            tmp_path, {"rf_baselines.json": {"baselines": {}}}, compatibility=compat
        )
        report, _, _ = B.validate_bundle(
            path, running_compat=self._compat(min_learning_detections=50)
        )
        assert report.valid, _failed(report)
        assert _warned(report) == [
            "taxonomy_overlap",
            "bands",
            "min_learning_detections",
        ]
        overlap = next(c for c in report.checks if c.check == "taxonomy_overlap")
        assert overlap.detail == "overlap 0.80; unknown classes: ['future_class']"


# ---------------------------------------------------------------------------
# Detection config: planning and propagation
# ---------------------------------------------------------------------------


class _Scorer:
    def __init__(self) -> None:
        self.weights: list[dict] = []
        self.config = SimpleNamespace(min_learning_detections=50)

    def update_weights(self, weights: dict) -> None:
        self.weights.append(weights)


class TestDetectionConfigApply:
    def test_plan_refuses_a_config_that_is_not_an_object(self):
        with pytest.raises(
            B.BundleError, match="detection_config: .*must be an object"
        ):
            B.plan_detection_config(
                {}, {"config": ["rf_anomaly_insert_threshold"]}, False
            )

    def test_each_key_reaches_only_its_scorer(self):
        rf, wifi = _Scorer(), _Scorer()
        B.apply_detection_config_to_scorers(
            rf, wifi, {"rf_min_learning_detections": 25.0}
        )
        assert (rf.weights, wifi.weights) == ([], [])
        assert rf.config.min_learning_detections == 25
        assert type(rf.config.min_learning_detections) is int

        B.apply_detection_config_to_scorers(
            rf, None, {"rf_dimension_weights": {"a": 0.1}}
        )
        assert rf.weights == [{"a": 0.1}]
        assert rf.config.min_learning_detections == 25

        B.apply_detection_config_to_scorers(
            None, wifi, {"wifi_dimension_weights": {"b": 0.2}}
        )
        assert wifi.weights == [{"b": 0.2}]


# ---------------------------------------------------------------------------
# Packaged presets and manifest reads
# ---------------------------------------------------------------------------


class TestPackagedPresets:
    def test_shipped_presets_validate_and_match_their_checksums(self):
        listed = B.list_packaged_presets()
        assert {p["profile"] for p in listed} == _PACKAGED
        for preset in listed:
            path = B._presets_dir() / preset["file"]
            sidecar = path.with_name(path.name + ".sha256").read_text().split()[0]
            assert preset["sha256"] == sidecar
            report, _, _ = B.validate_bundle(path, expect_kind="preset")
            assert report.valid, (preset["file"], _failed(report))
            assert B.resolve_preset(preset["profile"]) == path

    def test_missing_presets_dir_lists_nothing(self, tmp_path, monkeypatch):
        monkeypatch.setattr(B, "_presets_dir", lambda: tmp_path / "absent")
        assert B.list_packaged_presets() == []

    def test_unreadable_preset_is_skipped(self, tmp_path, monkeypatch, caplog):
        (tmp_path / "aaa_broken.sigrift.tar.gz").write_bytes(b"garbage")
        _bundle(
            tmp_path,
            {"rf_baselines.json": {"baselines": {}}},
            kind="preset",
            profile="calm",
        )
        monkeypatch.setattr(B, "_presets_dir", lambda: tmp_path)
        with caplog.at_level(logging.WARNING, logger=B.logger.name):
            listed = B.list_packaged_presets()
        assert [p["profile"] for p in listed] == ["calm"]
        assert "Skipping unreadable preset aaa_broken.sigrift.tar.gz" in caplog.text
        assert B.resolve_preset("calm") == tmp_path / "preset.sigrift.tar.gz"
        assert B.resolve_preset("stormy") is None

    def test_manifest_read_refusals(self, tmp_path):
        as_dir = _write(
            tmp_path / "dir.tar.gz", [_info("manifest.json", type=tarfile.DIRTYPE)]
        )
        with pytest.raises(
            B.BundleError, match="'manifest.json' is not a regular file"
        ):
            B.read_manifest(as_dir)
        second = _write(
            tmp_path / "second.tar.gz",
            [_info("rf_baselines.json", b"{}"), _info("manifest.json", _manifest([]))],
        )
        with pytest.raises(
            B.BundleError, match="manifest.json is not the first member"
        ):
            B.read_manifest(second)
        garbage = tmp_path / "garbage.tar.gz"
        garbage.write_bytes(b"garbage")
        with pytest.raises(B.BundleError, match="cannot read manifest from"):
            B.read_manifest(garbage)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _cli_bundle(tmp_path: Path) -> Path:
    return _bundle(
        tmp_path,
        {
            "rf_baselines.json": {"alpha": 0.01, "baselines": {}},
            "signal_whitelist.json": {"entries": []},
        },
    )


def _tampered(tmp_path: Path) -> Path:
    rf = b'{"baselines": {}}'
    manifest = _manifest([{**_entry("rf_baselines.json", rf), "sha256": "0" * 64}])
    return _write(
        tmp_path / "tampered.tar.gz",
        [_info("manifest.json", manifest), _info("rf_baselines.json", rf)],
    )


class TestCliExport:
    def test_unknown_selector_exits_2_and_writes_nothing(self, tmp_path, caplog):
        (tmp_path / "baselines.json").write_text('{"baselines": {}}')
        out = tmp_path / "out.sigrift.tar.gz"
        argv = ["export", "--data-dir", str(tmp_path), "-o", str(out)]
        assert B.main(argv + ["--components", "rf", "secrets"]) == 2
        assert not out.exists()
        assert "Unknown component selector: secrets" in caplog.text

    def test_nothing_on_disk_exits_1_and_writes_nothing(self, tmp_path, caplog):
        out = tmp_path / "out.sigrift.tar.gz"
        argv = ["export", "--data-dir", str(tmp_path / "data"), "-o", str(out)]
        assert B.main(argv) == 1
        assert not out.exists()
        assert "No components to export" in caplog.text


class TestCliExtract:
    def test_refuses_to_extract_from_an_invalid_bundle(self, tmp_path, caplog):
        out = tmp_path / "rf.json"
        argv = [
            "extract",
            str(_tampered(tmp_path)),
            "--component",
            "rf",
            "-o",
            str(out),
        ]
        assert B.main(argv) == 1
        assert not out.exists()
        assert "refusing to extract" in caplog.text

    def test_component_not_in_the_bundle(self, tmp_path):
        out = tmp_path / "bt.json"
        argv = [
            "extract",
            str(_cli_bundle(tmp_path)),
            "--component",
            "bt",
            "-o",
            str(out),
        ]
        assert B.main(argv) == 1
        assert not out.exists()

    def test_extract_to_stdout(self, tmp_path, capsysbinary):
        path = _cli_bundle(tmp_path)
        assert B.main(["extract", str(path), "--component", "whitelist"]) == 0
        assert json.loads(capsysbinary.readouterr().out) == {"entries": []}


class TestCliImport:
    def test_dry_run_reports_and_writes_nothing(self, tmp_path, capsys):
        data = tmp_path / "data"
        argv = ["import", str(_cli_bundle(tmp_path)), "--data-dir", str(data)]
        assert B.main(argv + ["--dry-run"]) == 0
        assert json.loads(capsys.readouterr().out)["valid"] is True
        assert not data.exists()

    def test_invalid_bundle_is_reported_and_not_written(self, tmp_path, capsys):
        data = tmp_path / "data"
        argv = ["import", str(_tampered(tmp_path)), "--data-dir", str(data)]
        assert B.main(argv + ["--force"]) == 1
        assert json.loads(capsys.readouterr().out)["valid"] is False
        assert not data.exists()

    def test_force_overrides_the_live_bridge_guard(self, tmp_path, capsys):
        data = tmp_path / "data"
        data.mkdir()
        (data / "detections.db-wal").write_bytes(b"wal")
        argv = ["import", str(_cli_bundle(tmp_path)), "--data-dir", str(data)]
        assert B.main(argv + ["--force"]) == 0
        # rf_baselines.json lands under the name the bridge loads.
        written = ["baselines.json", "signal_whitelist.json"]
        assert json.loads(capsys.readouterr().out) == {"applied": written}
        assert sorted(p.name for p in data.iterdir()) == sorted(
            written + ["detections.db-wal"]
        )
        assert json.loads((data / "baselines.json").read_text())["alpha"] == 0.01

    def test_a_stale_wal_does_not_block_the_import(self, tmp_path):
        data = tmp_path / "data"
        data.mkdir()
        wal = data / "detections.db-wal"
        wal.write_bytes(b"wal")
        stale = time.time() - 3600
        os.utime(wal, (stale, stale))
        argv = ["import", str(_cli_bundle(tmp_path)), "--data-dir", str(data)]
        assert B.main(argv) == 0
        assert (data / "baselines.json").exists()

    def test_import_into_a_new_data_dir(self, tmp_path):
        # No bridge has run here (no WAL at all): the directory is created.
        data = tmp_path / "fresh" / "data"
        argv = ["import", str(_cli_bundle(tmp_path)), "--data-dir", str(data)]
        assert B.main(argv) == 0
        assert sorted(p.name for p in data.iterdir()) == [
            "baselines.json",
            "signal_whitelist.json",
        ]

    def test_list_presets(self, tmp_path, monkeypatch, capsys):
        _bundle(
            tmp_path,
            {"rf_baselines.json": {"baselines": {}}},
            kind="preset",
            profile="calm",
        )
        monkeypatch.setattr(B, "_presets_dir", lambda: tmp_path)
        assert B.main(["list-presets"]) == 0
        assert [p["profile"] for p in json.loads(capsys.readouterr().out)] == ["calm"]

    @pytest.mark.timeout(180)
    def test_module_entry_point_exits_non_zero_on_an_invalid_bundle(self, tmp_path):
        env = {
            **os.environ,
            # No empty entry: that would put the working directory on the path.
            "PYTHONPATH": os.pathsep.join(
                filter(None, [str(_ROOT / "src"), os.environ.get("PYTHONPATH")])
            ),
        }
        result = subprocess.run(
            [sys.executable, "-m", "sigrift.bridge.bundles", "validate"]
            + [str(_tampered(tmp_path))],
            capture_output=True,
            text=True,
            env=env,
            timeout=170,
        )
        assert result.returncode == 1, result.stderr
        assert json.loads(result.stdout)["valid"] is False
