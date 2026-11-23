"""Learned-state bundle API: what is exported, what an import may apply,
and what it must refuse.

Complements ``test_bundle_endpoints.py`` with the paths it leaves out: the
upload size cap and owner-only staging, ``force`` never overriding an
integrity failure, selective ``?components=`` imports, every component
kind applied and persisted, scorers that are not running, packaged presets
that fail validation, dry runs, and the download containment checks.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from sigrift.bridge import bundles as B
from sigrift.bridge.anomaly.baseline import BaselineManager
from sigrift.bridge.anomaly.bt_scorer import BtBaselineManager
from sigrift.bridge.anomaly.wifi_scorer import WifiBaselineManager
from sigrift.bridge.routers import maintenance as maint

_IMPORT = "/api/admin/baselines/import"
_BSSID = "aa:bb:cc:dd:ee:01"
_BT_ADDR = "11:22:33:44:55:66"
_WHITELIST = [
    {"freq_min_hz": 433_050_000.0, "freq_max_hz": 434_790_000.0, "description": "ISM"}
]


def _rf_manager() -> BaselineManager:
    mgr = BaselineManager()
    for i in range(60):
        mgr.update(
            433_920_000,
            "ook",
            0.9,
            -60.0 + i % 3,
            i % 24,
            snr_db=20.0,
            bandwidth_hz=25e3,
        )
    return mgr


def _wifi_bytes() -> bytes:
    mgr = WifiBaselineManager()
    mgr.update(_BSSID, "CafeNet", 6, "WPA2", -55.0, 3, 0.01, 12)
    return B.serialize_wifi_manager(mgr)


def _bt_bytes() -> bytes:
    mgr = BtBaselineManager()
    mgr.update(_BT_ADDR, {"device_name": "tag", "rssi_dbm": -61.0})
    mgr.record_batch_size(3)
    mgr.record_batch_size(5)
    return B.serialize_bt_manager(mgr)


def _all_components() -> dict[str, bytes]:
    return {
        "rf_baselines.json": B.serialize_rf_manager(_rf_manager()),
        "wifi_baselines.json": _wifi_bytes(),
        "bt_baselines.json": _bt_bytes(),
        "signal_whitelist.json": json.dumps({"entries": _WHITELIST}).encode(),
        "detection_config.json": json.dumps(
            {"config": {"rf_anomaly_insert_threshold": 0.35}}
        ).encode(),
    }


def _export(tmp_path: Path, components: dict[str, bytes]) -> Path:
    out = tmp_path / "in" / "sigrift_export_t.sigrift.tar.gz"
    return B.build_bundle(out, kind="export", component_bytes=components)


def _preset(directory: Path, profile: str, components: dict[str, bytes]) -> Path:
    return B.build_bundle(
        directory / f"preset_{profile}_v1.sigrift.tar.gz",
        kind="preset",
        component_bytes=components,
        profile=profile,
        name=f"{profile} preset",
    )


def _sanitized_rf_bytes() -> bytes:
    mgr = _rf_manager()
    for bl in mgr.baselines.values():
        B.sanitize_rf_baseline(bl)
    return B.serialize_rf_manager(mgr)


def _upload(client, path: Path, query: str = ""):
    return client.post(
        _IMPORT + query,
        files={"file": (path.name, path.read_bytes(), "application/gzip")},
    )


def _data_dir(app) -> Path:
    return Path(app.state.rf_baselines_path).parent


def _failed_checks(resp) -> set[str]:
    return {
        c["check"] for c in resp.json()["detail"]["checks"] if c["result"] == "fail"
    }


# ---------------------------------------------------------------------------
# Export / list / download
# ---------------------------------------------------------------------------


class TestExport:
    def test_export_carries_the_live_bt_whitelist_and_config(
        self, client, bridge_app, detection_store
    ):
        bridge_app.state.bt_baseline_mgr.update(_BT_ADDR, {"device_name": "tag"})
        resp = client.post(
            "/api/admin/baselines/export",
            json={"components": ["bt", "whitelist", "detection_config"]},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["components"] == [
            "bt_baselines.json",
            "detection_config.json",
            "signal_whitelist.json",
        ]
        exports = _data_dir(bridge_app) / "exports"
        sidecar = (exports / (body["file"] + ".sha256")).read_text()
        assert sidecar == f"{body['sha256']}  {body['file']}\n"
        report, _, members = B.validate_bundle(
            exports / body["file"], expect_kind="export"
        )
        assert report.valid
        assert json.loads(members["signal_whitelist.json"])["entries"] == [
            e.model_dump() for e in bridge_app.state.signal_whitelist.entries
        ]
        assert json.loads(members["detection_config.json"]) == {
            "config": bridge_app.state.persistence.get_detection_config()
        }
        assert list(json.loads(members["bt_baselines.json"])["baselines"]) == [_BT_ADDR]
        [entry] = detection_store.get_audit_log(action="admin_baseline_export")
        assert body["file"] in entry["note"]

    def test_unknown_component_is_refused_before_anything_is_written(
        self, client, bridge_app
    ):
        resp = client.post(
            "/api/admin/baselines/export", json={"components": ["rf", "secrets"]}
        )
        assert (resp.status_code, resp.json()["detail"]) == (
            400,
            "Unknown components: ['secrets']",
        )
        assert not (_data_dir(bridge_app) / "exports").exists()

    def test_nothing_to_export_is_refused(self, client, bridge_app):
        bridge_app.state.signal_whitelist = None
        resp = client.post(
            "/api/admin/baselines/export", json={"components": ["whitelist"]}
        )
        assert (resp.status_code, resp.json()["detail"]) == (
            400,
            "No components available to export",
        )
        assert not (_data_dir(bridge_app) / "exports").exists()

    def test_listing_before_any_export_is_empty(self, client):
        assert client.get("/api/admin/baselines/exports").json() == {
            "count": 0,
            "exports": [],
        }

    def test_download_stays_inside_the_exports_dir(self, client, bridge_app, tmp_path):
        exports = _data_dir(bridge_app) / "exports"
        exports.mkdir()
        outside = tmp_path / "outside.sigrift.tar.gz"
        outside.write_bytes(b"not for download")
        (exports / "link.sigrift.tar.gz").symlink_to(outside)
        (exports / "folder.sigrift.tar.gz").mkdir()
        for name in ("link", "folder", "absent"):
            resp = client.get(f"/api/admin/baselines/exports/{name}.sigrift.tar.gz")
            assert (resp.status_code, resp.json()["detail"]) == (
                404,
                "Export not found",
            )


class TestComponentHelpers:
    def test_absent_subsystems_serialize_to_nothing(self):
        request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace()))
        selectors = ["rf", "wifi", "bt", "whitelist", "detection_config", "other"]
        assert [maint._serialize_component(request, s) for s in selectors] == [None] * 6

    def test_data_dir_follows_the_rf_baselines_path(self, tmp_path):
        state = SimpleNamespace(
            rf_baselines_path=str(tmp_path / "d" / "baselines.json")
        )
        request = SimpleNamespace(app=SimpleNamespace(state=state))
        assert maint._data_dir(request) == tmp_path / "d"
        del state.rf_baselines_path
        packaged = Path(maint.__file__).resolve().parent.parent / "data"
        assert maint._data_dir(request) == packaged

    def test_apply_skips_every_subsystem_that_is_not_running(self, tmp_path):
        data = tmp_path / "data"
        data.mkdir()
        report, manifest, members = B.validate_bundle(
            _export(tmp_path, _all_components())
        )
        assert report.valid
        state = SimpleNamespace(rf_baselines_path=str(data / "baselines.json"))
        request = SimpleNamespace(app=SimpleNamespace(state=state))
        applied = maint._apply_members(request, members, manifest, None, {"x": 1})
        assert applied == []
        # Only the provenance marker is written, and it says nothing applied.
        assert [p.name for p in data.iterdir()] == ["bundle_provenance.json"]
        provenance = json.loads((data / "bundle_provenance.json").read_text())
        assert (provenance["kind"], provenance["components"]) == ("export", [])

    def test_a_component_that_cannot_be_loaded_applies_nothing(
        self, bridge_app, tmp_path, monkeypatch
    ):
        # Behind validation: every component is decoded before the first is
        # swapped in, so a loader failure leaves no live state changed.
        live_whitelist = list(bridge_app.state.signal_whitelist.entries)
        components = {
            "signal_whitelist.json": json.dumps({"entries": _WHITELIST}).encode(),
            "wifi_baselines.json": _wifi_bytes(),
        }
        report, manifest, members = B.validate_bundle(_export(tmp_path, components))
        assert report.valid

        def _unloadable(data: bytes):
            raise ValueError("cannot be loaded")

        monkeypatch.setattr(B, "load_wifi_baselines_from_bytes", _unloadable)
        request = SimpleNamespace(app=bridge_app)
        with pytest.raises(ValueError, match="cannot be loaded"):
            maint._apply_members(request, members, manifest, None, None)
        assert bridge_app.state.signal_whitelist.entries == live_whitelist
        assert bridge_app.state.wifi_baseline_mgr.baselines == {}
        data = _data_dir(bridge_app)
        assert not (data / "signal_whitelist.json").exists()
        assert not (data / "bundle_provenance.json").exists()


# ---------------------------------------------------------------------------
# Import
# ---------------------------------------------------------------------------


class TestImportRefusals:
    def test_upload_over_the_size_cap_is_413_and_leaves_no_file(
        self, client, bridge_app, monkeypatch
    ):
        monkeypatch.setenv("BRIDGE_BUNDLE_MAX_BYTES", "1024")
        resp = client.post(
            _IMPORT + "?dry_run=false",
            files={
                "file": ("big.sigrift.tar.gz", os.urandom(4096), "application/gzip")
            },
        )
        assert (resp.status_code, resp.json()["detail"]) == (
            413,
            "Bundle exceeds 1024 bytes",
        )
        assert list((_data_dir(bridge_app) / "tmp_bundles").iterdir()) == []

    def test_upload_is_validated_from_an_owner_only_file_then_removed(
        self, client, tmp_path, monkeypatch
    ):
        seen = []
        original = B.validate_bundle

        def _spy(path, **kwargs):
            seen.append((Path(path), os.stat(path).st_mode & 0o777))
            return original(path, **kwargs)

        monkeypatch.setattr(B, "validate_bundle", _spy)
        resp = _upload(client, _export(tmp_path, {"rf_baselines.json": b"{}"}))
        assert resp.status_code == 200, resp.text
        [(staged, mode)] = seen
        assert mode == 0o600
        assert not staged.exists()

    def test_force_never_overrides_an_integrity_failure(
        self, client, bridge_app, tmp_path
    ):
        # Disjoint taxonomy (overridable) AND a wrong checksum (not).
        rf = b'{"schema_version":1,"alpha":0.01,"baselines":{}}'
        compat = B.compat_snapshot(class_set=["zzz_a", "zzz_b"]).model_dump()
        manifest = {
            "schema_version": 1,
            "kind": "export",
            "created_at": "2026-07-01T00:00:00+00:00",
            "generator": {"tool": "test"},
            "compatibility": compat,
            "components": [
                {
                    "file": "rf_baselines.json",
                    "type": "rf_baselines",
                    "sha256": hashlib.sha256(b"something else").hexdigest(),
                    "bytes": len(rf),
                }
            ],
        }
        path = tmp_path / "tampered.sigrift.tar.gz"
        with tarfile.open(path, "w:gz") as tar:
            for name, data in (
                ("manifest.json", json.dumps(manifest).encode()),
                ("rf_baselines.json", rf),
            ):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        resp = _upload(client, path, "?dry_run=false&force=true")
        assert resp.status_code == 422
        failed = {
            c["check"] for c in resp.json()["detail"]["checks"] if c["result"] == "fail"
        }
        assert failed == {"rf_baselines.json sha256", "taxonomy_overlap"}
        assert not (_data_dir(bridge_app) / "bundle_provenance.json").exists()

    @pytest.mark.parametrize(
        ("fname", "data", "check"),
        [
            ("wifi_baselines.json", b"[]", "wifi_baselines.json structure"),
            (
                "bt_baselines.json",
                json.dumps({"baselines": {_BT_ADDR: 5}}).encode(),
                "bt_baselines.json baseline",
            ),
            ("rf_baselines.json", b"[]", "rf_baselines.json structure"),
        ],
        ids=["wifi-list", "bt-bin-number", "rf-list"],
    )
    def test_a_malformed_member_is_refused_before_anything_is_applied(
        self, client, bridge_app, tmp_path, detection_store, fname, data, check
    ):
        live_whitelist = list(bridge_app.state.signal_whitelist.entries)
        whitelist = json.dumps({"entries": _WHITELIST}).encode()
        path = _export(tmp_path, {"signal_whitelist.json": whitelist, fname: data})
        for query in ("", "?dry_run=false"):
            resp = _upload(client, path, query)
            assert resp.status_code == 422, resp.text
            assert _failed_checks(resp) == {check}
        # Not even the valid whitelist was swapped in or saved.
        assert bridge_app.state.signal_whitelist.entries == live_whitelist
        data_dir = _data_dir(bridge_app)
        assert not (data_dir / "signal_whitelist.json").exists()
        assert not (data_dir / "bundle_provenance.json").exists()
        assert detection_store.get_audit_log(action="admin_bundle_import") == []

    @pytest.mark.parametrize(
        ("fname", "attr"),
        [
            ("wifi_baselines.json", "wifi_baseline_mgr"),
            ("bt_baselines.json", "bt_baseline_mgr"),
        ],
    )
    def test_an_out_of_range_alpha_is_not_applied(
        self, client, bridge_app, tmp_path, fname, attr
    ):
        mgr = getattr(bridge_app.state, attr)
        alpha = mgr.alpha
        member = json.dumps({"alpha": -5, "baselines": {}}).encode()
        resp = _upload(client, _export(tmp_path, {fname: member}), "?dry_run=false")
        assert resp.status_code == 422, resp.text
        assert _failed_checks(resp) == {f"{fname} alpha"}
        assert mgr.alpha == alpha
        assert not (_data_dir(bridge_app) / fname).exists()


class TestImportApply:
    def test_every_component_is_applied_live_and_persisted(
        self, client, bridge_app, tmp_path, detection_store
    ):
        resp = _upload(client, _export(tmp_path, _all_components()), "?dry_run=false")
        assert resp.status_code == 200, resp.text
        assert sorted(resp.json()["applied"]) == [
            "bt",
            "detection_config",
            "rf",
            "whitelist",
            "wifi",
        ]
        state = bridge_app.state
        assert set(state.rf_baseline_mgr.baselines) == set(_rf_manager().baselines)
        assert set(state.wifi_baseline_mgr.baselines) == {_BSSID}
        assert state.wifi_baseline_mgr.get_bssids_for_ssid("CafeNet") == {_BSSID}
        assert set(state.bt_baseline_mgr.baselines) == {_BT_ADDR}
        assert state.bt_baseline_mgr.avg_batch_device_count() == 4.0
        assert [
            e.model_dump(exclude_defaults=True) for e in state.signal_whitelist.entries
        ] == _WHITELIST
        assert (
            state.persistence.get_detection_config()["rf_anomaly_insert_threshold"]
            == 0.35
        )
        assert state.detection_config["rf_anomaly_insert_threshold"] == 0.35

        data = _data_dir(bridge_app)
        assert set(
            json.loads((data / "wifi_baselines.json").read_text())["baselines"]
        ) == {_BSSID}
        bt_saved = json.loads((data / "bt_baselines.json").read_text())
        assert (list(bt_saved["baselines"]), bt_saved["batch_device_counts"]) == (
            [_BT_ADDR],
            [3, 5],
        )
        assert (
            json.loads((data / "signal_whitelist.json").read_text())["entries"][0][
                "description"
            ]
            == "ISM"
        )
        provenance = json.loads((data / "bundle_provenance.json").read_text())
        assert provenance["kind"] == "export"
        assert sorted(provenance["components"]) == sorted(resp.json()["applied"])
        [entry] = detection_store.get_audit_log(action="admin_bundle_import")
        assert "kind=export" in entry["note"]

        status = client.get("/api/admin/baselines/status").json()
        assert status["provenance"] == provenance
        assert (status["wifi"]["count"], status["bt"]["count"]) == (1, 1)

    def test_components_selector_applies_only_what_was_asked(
        self, client, bridge_app, tmp_path
    ):
        before = bridge_app.state.persistence.get_detection_config()
        default_whitelist = list(bridge_app.state.signal_whitelist.entries)
        path = _export(tmp_path, _all_components())
        resp = _upload(client, path, "?dry_run=false&components=rf,%20wifi")
        assert resp.status_code == 200, resp.text
        assert sorted(resp.json()["applied"]) == ["rf", "wifi"]
        state = bridge_app.state
        assert set(state.wifi_baseline_mgr.baselines) == {_BSSID}
        assert state.bt_baseline_mgr.baselines == {}
        assert state.signal_whitelist.entries == default_whitelist
        assert state.persistence.get_detection_config() == before
        data = _data_dir(bridge_app)
        assert not (data / "bt_baselines.json").exists()
        assert not (data / "signal_whitelist.json").exists()

    def test_preset_without_a_running_rf_scorer_applies_the_rest(
        self, client, bridge_app, tmp_path
    ):
        bridge_app.state.rf_baseline_mgr = None
        path = _preset(
            tmp_path,
            "quiet",
            {
                "rf_baselines.json": _sanitized_rf_bytes(),
                "detection_config.json": json.dumps(
                    {"config": {"rf_anomaly_insert_threshold": 0.45}}
                ).encode(),
            },
        )
        resp = _upload(client, path, "?dry_run=false")
        assert resp.status_code == 200, resp.text
        assert resp.json()["applied"] == ["detection_config"]
        assert (
            bridge_app.state.persistence.get_detection_config()[
                "rf_anomaly_insert_threshold"
            ]
            == 0.45
        )
        assert not (_data_dir(bridge_app) / "baselines.json").exists()
        status = client.get("/api/admin/baselines/status").json()
        assert status["rf"] == {"present": False}
        assert (status["provenance"]["kind"], status["provenance"]["profile"]) == (
            "preset",
            "quiet",
        )

    def test_unreadable_provenance_is_reported_as_none(self, client, bridge_app):
        (_data_dir(bridge_app) / "bundle_provenance.json").write_text("{truncated")
        assert client.get("/api/admin/baselines/status").json()["provenance"] is None


# ---------------------------------------------------------------------------
# Packaged presets
# ---------------------------------------------------------------------------


class TestPresetApply:
    def test_a_packaged_preset_that_fails_validation_is_500_and_applies_nothing(
        self, client, bridge_app, tmp_path, monkeypatch
    ):
        presets = tmp_path / "presets"
        _preset(presets, "broken", {"rf_baselines.json": _sanitized_rf_bytes()})
        bundle = presets / "preset_broken_v1.sigrift.tar.gz"
        # Rebuild the archive with the RF member altered after packaging.
        with tarfile.open(bundle, "r:gz") as tar:
            manifest = tar.extractfile("manifest.json").read()
            rf = tar.extractfile("rf_baselines.json").read()
        with tarfile.open(bundle, "w:gz") as tar:
            for name, data in (
                ("manifest.json", manifest),
                ("rf_baselines.json", rf.replace(b'"ook"', b'"fsk"')),
            ):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        monkeypatch.setattr(B, "_presets_dir", lambda: presets)
        resp = client.post("/api/admin/presets/broken/apply")
        assert resp.status_code == 500
        detail = resp.json()["detail"]
        assert (detail["error"], detail["valid"]) == (
            "packaged preset failed validation",
            False,
        )
        assert {c["check"] for c in detail["checks"] if c["result"] == "fail"} == {
            "rf_baselines.json sha256"
        }
        assert bridge_app.state.rf_baseline_mgr.baselines == {}

    def test_dry_run_reports_and_applies_nothing_even_over_learned_state(
        self, client, bridge_app, tmp_path, monkeypatch
    ):
        presets = tmp_path / "presets"
        _preset(presets, "calm", {"rf_baselines.json": _sanitized_rf_bytes()})
        monkeypatch.setattr(B, "_presets_dir", lambda: presets)
        live = bridge_app.state.rf_baseline_mgr
        for i in range(1100):  # past the 1000-detection guard
            live.update(915_000_000, "lora", 0.9, -70.0, i % 24, snr_db=10.0)
        before = {f: b.total_detections for f, b in live.baselines.items()}
        resp = client.post("/api/admin/presets/calm/apply?dry_run=true")
        assert resp.status_code == 200, resp.text
        assert (resp.json()["valid"], resp.json()["would_apply"]) == (
            True,
            ["rf_baselines"],
        )
        assert {f: b.total_detections for f, b in live.baselines.items()} == before
        assert not (_data_dir(bridge_app) / "bundle_provenance.json").exists()
