"""Endpoint tests for the learned-state bundle API (/api/admin/*)."""

from __future__ import annotations

import io
import json
from pathlib import Path

from fastapi.testclient import TestClient

from sigrift.bridge import bundles as B
from sigrift.bridge.anomaly.baseline import BaselineManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _warm(mgr: BaselineManager, freq=433_920_000, n=400) -> None:
    for i in range(n):
        mgr.update(
            freq, "ook", 0.9, -60.0 + (i % 5), i % 24, snr_db=20.0, bandwidth_hz=25000.0
        )


def _detection_config_bundle(tmp_path, weights):
    cfg = json.dumps({"config": {"rf_dimension_weights": weights}}).encode()
    out = tmp_path / "sigrift_export_cfg.sigrift.tar.gz"
    return B.build_bundle(
        out, kind="export", component_bytes={"detection_config.json": cfg}
    )


def _preset_bundle(tmp_path, profile="urban-dense"):
    mgr = BaselineManager()
    _warm(mgr)
    for bl in mgr.baselines.values():
        B.sanitize_rf_baseline(bl)
    out = tmp_path / f"preset_{profile}_v1.sigrift.tar.gz"
    return B.build_bundle(
        out,
        kind="preset",
        component_bytes={"rf_baselines.json": B.serialize_rf_manager(mgr)},
        profile=profile,
        name=f"{profile} preset",
        created_at="2026-07-01T00:00:00+00:00",
        mtime=0,
    )


def _upload(client, path, url):
    with open(path, "rb") as f:
        return client.post(url, files={"file": (path.name, f, "application/gzip")})


# ---------------------------------------------------------------------------
# Auth / gating
# ---------------------------------------------------------------------------


class TestGating:
    def test_status_requires_admin(self, bridge_app):
        anon = TestClient(bridge_app)  # no X-API-Key
        resp = anon.get("/api/admin/baselines/status")
        assert resp.status_code in (401, 403)

    def test_status_ok_for_admin(self, client):
        resp = client.get("/api/admin/baselines/status")
        assert resp.status_code == 200
        body = resp.json()
        assert "rf" in body and "autosave" in body


# ---------------------------------------------------------------------------
# Export → list → download
# ---------------------------------------------------------------------------


class TestExport:
    def test_export_then_list_and_download(self, client, bridge_app):
        _warm(bridge_app.state.rf_baseline_mgr)
        resp = client.post("/api/admin/baselines/export", json={"components": ["rf"]})
        assert resp.status_code == 200, resp.text
        fname = resp.json()["file"]
        assert fname.endswith(".sigrift.tar.gz")

        listing = client.get("/api/admin/baselines/exports").json()
        assert any(e["filename"] == fname for e in listing["exports"])

        dl = client.get(f"/api/admin/baselines/exports/{fname}")
        assert dl.status_code == 200
        # Downloaded bytes validate as a real bundle.
        report, _, _ = B.validate_bundle(io_to_tmp(dl.content))
        assert report.valid

    def test_download_rejects_bad_filename(self, client):
        resp = client.get("/api/admin/baselines/exports/..%2Fescape")
        assert resp.status_code in (400, 404)

    def test_download_refuses_a_trailing_newline(self, client, bridge_app):
        """The whole name must match, even when such a file exists."""
        _warm(bridge_app.state.rf_baseline_mgr)
        fname = client.post(
            "/api/admin/baselines/export", json={"components": ["rf"]}
        ).json()["file"]
        exports = Path(bridge_app.state.rf_baselines_path).parent / "exports"
        (exports / (fname + "\n")).write_bytes((exports / fname).read_bytes())
        resp = client.get(f"/api/admin/baselines/exports/{fname}%0A")
        assert (resp.status_code, resp.json()["detail"]) == (400, "Invalid filename")
        assert client.get(f"/api/admin/baselines/exports/{fname}").status_code == 200


# ---------------------------------------------------------------------------
# Import
# ---------------------------------------------------------------------------


class TestImport:
    def test_dry_run_is_default_and_applies_nothing(self, client, bridge_app, tmp_path):
        before = dict(getattr(bridge_app.state.rf_scorer.config, "weights", {}) or {})
        path = _detection_config_bundle(tmp_path, {"signature_match": 0.9})
        resp = _upload(client, path, "/api/admin/baselines/import")
        assert resp.status_code == 200
        assert resp.json()["valid"] is True
        # No mutation on a dry run.
        after = dict(getattr(bridge_app.state.rf_scorer.config, "weights", {}) or {})
        assert before == after

    def test_apply_hot_reloads_scorer_weights(self, client, bridge_app, tmp_path):
        path = _detection_config_bundle(tmp_path, {"signature_match": 0.42})
        resp = _upload(client, path, "/api/admin/baselines/import?dry_run=false")
        assert resp.status_code == 200, resp.text
        assert "detection_config" in resp.json()["applied"]
        # Live scorer picked up the new weight.
        cfg = bridge_app.state.persistence.get_detection_config()
        assert cfg["rf_dimension_weights"]["signature_match"] == 0.42

    def test_weights_that_merged_break_their_bounds_apply_nothing(
        self, client, bridge_app, tmp_path
    ):
        # Valid alone (sum 2.0), but merged into the weights in force (the
        # defaults, which sum to 1.18) they would sum to 2.84: a dry run
        # reports it, and the import is refused before any component, the
        # RF baselines included, is applied.
        mgr = BaselineManager()
        _warm(mgr)
        cfg = {"rf_dimension_weights": {"novel_class": 1.0, "rare_class": 1.0}}
        out = tmp_path / "sigrift_export_heavy.sigrift.tar.gz"
        B.build_bundle(
            out,
            kind="export",
            component_bytes={
                "rf_baselines.json": B.serialize_rf_manager(mgr),
                "detection_config.json": json.dumps({"config": cfg}).encode(),
            },
        )
        live = bridge_app.state.rf_baseline_mgr
        before = (
            len(live.baselines),
            bridge_app.state.persistence.get_detection_config(),
        )
        for url in (
            "/api/admin/baselines/import",
            "/api/admin/baselines/import?dry_run=false",
            "/api/admin/baselines/import?dry_run=false&force=true",
        ):
            resp = _upload(client, out, url)
            assert resp.status_code == 422, (url, resp.text)
            detail = resp.json()["detail"]
            [check] = [c for c in detail["checks"] if c["result"] == "fail"]
            assert check["check"] == "detection_config.json detection_config merge"
            assert "rf_dimension_weights" in check["detail"]
            assert "would sum to 2.84" in check["detail"]
        after = (
            len(live.baselines),
            bridge_app.state.persistence.get_detection_config(),
        )
        assert after == before

        # The same weights over the whole RF object, as an export carries
        # it, fit: the bundle applies.
        whole = {k: 0.0 for k in before[1]["rf_dimension_weights"]}
        cfg["rf_dimension_weights"] = {**whole, **cfg["rf_dimension_weights"]}
        out.unlink()
        B.build_bundle(
            out,
            kind="export",
            component_bytes={
                "rf_baselines.json": B.serialize_rf_manager(mgr),
                "detection_config.json": json.dumps({"config": cfg}).encode(),
            },
        )
        resp = _upload(client, out, "/api/admin/baselines/import?dry_run=false")
        assert resp.status_code == 200, resp.text
        assert set(resp.json()["applied"]) == {"rf", "detection_config"}
        stored = bridge_app.state.persistence.get_detection_config()
        assert stored["rf_dimension_weights"] == cfg["rf_dimension_weights"]

    def test_tampered_bundle_returns_422_report(self, client, tmp_path):
        # Hand-build a bundle whose declared sha256 is wrong.
        rf = b'{"schema_version":1,"alpha":0.01,"baselines":{}}'
        import tarfile

        manifest = {
            "schema_version": 1,
            "kind": "export",
            "created_at": "2026-07-01T00:00:00+00:00",
            "generator": {"tool": "test"},
            "compatibility": B.compat_snapshot().model_dump(),
            "components": [
                {
                    "file": "rf_baselines.json",
                    "type": "rf_baselines",
                    "sha256": "0" * 64,
                    "bytes": len(rf),
                }
            ],
            "extensions": {},
        }
        p = tmp_path / "bad.sigrift.tar.gz"
        with tarfile.open(p, "w:gz") as tar:
            for name, data in (
                ("manifest.json", json.dumps(manifest).encode()),
                ("rf_baselines.json", rf),
            ):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        resp = _upload(client, p, "/api/admin/baselines/import?dry_run=false")
        assert resp.status_code == 422
        detail = resp.json()["detail"]
        assert detail["valid"] is False
        assert any("sha256" in c["check"] for c in detail["checks"])


# ---------------------------------------------------------------------------
# Presets
# ---------------------------------------------------------------------------


class TestPresets:
    def test_list_presets(self, client, monkeypatch, tmp_path):
        # Point the preset dir at a tmp dir with one generated preset.
        _preset_bundle(tmp_path, "urban-dense")
        monkeypatch.setattr(B, "_presets_dir", lambda: tmp_path)
        resp = client.get("/api/admin/presets")
        assert resp.status_code == 200
        profiles = [p["profile"] for p in resp.json()["presets"]]
        assert "urban-dense" in profiles

    def test_unknown_preset_404(self, client, monkeypatch, tmp_path):
        monkeypatch.setattr(B, "_presets_dir", lambda: tmp_path)
        resp = client.post("/api/admin/presets/nope/apply")
        assert resp.status_code == 404

    def test_apply_preset_applies_rf(self, client, bridge_app, monkeypatch, tmp_path):
        _preset_bundle(tmp_path, "rural-quiet")
        monkeypatch.setattr(B, "_presets_dir", lambda: tmp_path)
        assert len(bridge_app.state.rf_baseline_mgr.baselines) == 0
        resp = client.post("/api/admin/presets/rural-quiet/apply")
        assert resp.status_code == 200, resp.text
        assert "rf" in resp.json()["applied"]
        assert len(bridge_app.state.rf_baseline_mgr.baselines) > 0

    def test_preset_whose_weights_merged_break_their_bounds_applies_nothing(
        self, client, bridge_app, monkeypatch, tmp_path
    ):
        # A valid preset's weights (sum 2.0) merged into the defaults would
        # sum to 2.84: a dry run and an apply are both refused (422, not the
        # 500 of a packaged preset that fails validation), and nothing is
        # applied.
        mgr = BaselineManager()
        _warm(mgr)
        for bl in mgr.baselines.values():
            B.sanitize_rf_baseline(bl)
        cfg = {"rf_dimension_weights": {"novel_class": 1.0, "rare_class": 1.0}}
        B.build_bundle(
            tmp_path / "preset_heavy_v1.sigrift.tar.gz",
            kind="preset",
            component_bytes={
                "rf_baselines.json": B.serialize_rf_manager(mgr),
                "detection_config.json": json.dumps({"config": cfg}).encode(),
            },
            profile="heavy",
            name="heavy preset",
            created_at="2026-07-01T00:00:00+00:00",
            mtime=0,
        )
        monkeypatch.setattr(B, "_presets_dir", lambda: tmp_path)
        before = bridge_app.state.persistence.get_detection_config()
        for url in (
            "/api/admin/presets/heavy/apply?dry_run=true",
            "/api/admin/presets/heavy/apply",
        ):
            resp = client.post(url)
            assert resp.status_code == 422, (url, resp.text)
            checks = resp.json()["detail"]["checks"]
            [check] = [c for c in checks if c["result"] == "fail"]
            assert check["check"] == "detection_config.json detection_config merge"
            assert "would sum to 2.84" in check["detail"]
        assert len(bridge_app.state.rf_baseline_mgr.baselines) == 0
        assert bridge_app.state.persistence.get_detection_config() == before

    def test_apply_preset_409_guard_over_learned_state(
        self, client, bridge_app, monkeypatch, tmp_path
    ):
        _preset_bundle(tmp_path, "urban-dense")
        monkeypatch.setattr(B, "_presets_dir", lambda: tmp_path)
        # Warm past the 1000-detection guard threshold.
        _warm(bridge_app.state.rf_baseline_mgr, n=1500)
        resp = client.post("/api/admin/presets/urban-dense/apply")
        assert resp.status_code == 409
        # force=true overrides.
        forced = client.post("/api/admin/presets/urban-dense/apply?force=true")
        assert forced.status_code == 200


def io_to_tmp(content: bytes):
    import tempfile
    from pathlib import Path

    p = Path(tempfile.mkstemp(suffix=".sigrift.tar.gz")[1])
    p.write_bytes(content)
    return p


# ---------------------------------------------------------------------------
# Review-hardening regressions
# ---------------------------------------------------------------------------


class TestImportHardening:
    def test_import_preset_over_learned_state_409(self, client, bridge_app, tmp_path):
        # The >1000-learned-detection guard must fire on the generic import
        # path too, not only /presets/{profile}/apply.
        _warm(bridge_app.state.rf_baseline_mgr, n=1500)
        path = _preset_bundle(tmp_path, "urban-dense")
        resp = _upload(client, path, "/api/admin/baselines/import?dry_run=false")
        assert resp.status_code == 409
        forced = _upload(
            client, path, "/api/admin/baselines/import?dry_run=false&force=true"
        )
        assert forced.status_code == 200

    def test_export_does_not_reset_wifi_dirty(self, client, bridge_app):
        mgr = bridge_app.state.wifi_baseline_mgr
        mgr.update("aa:bb:cc:dd:ee:ff", "net", 6, "WPA2", -50.0, 1, 0.0, 12)
        assert mgr.dirty is True
        resp = client.post("/api/admin/baselines/export", json={"components": ["wifi"]})
        assert resp.status_code == 200
        # Export must not clear the crash-durability dirty flag.
        assert mgr.dirty is True

    def test_import_taxonomy_force_override(self, client, tmp_path):
        # A bundle whose taxonomy is disjoint from the running model fails
        # without force, and applies with force=true.
        rf = _EMPTY_RF_BYTES
        out = tmp_path / "sigrift_export_disjoint.sigrift.tar.gz"
        B.build_bundle(
            out,
            kind="export",
            component_bytes={"rf_baselines.json": rf},
            compatibility=B.compat_snapshot(class_set=["zzz_a", "zzz_b", "zzz_c"]),
        )
        no_force = _upload(client, out, "/api/admin/baselines/import?dry_run=false")
        assert no_force.status_code == 422
        assert any(
            "taxonomy_overlap" in c["check"]
            for c in no_force.json()["detail"]["checks"]
        )
        forced = _upload(
            client, out, "/api/admin/baselines/import?dry_run=false&force=true"
        )
        assert forced.status_code == 200


_EMPTY_RF_BYTES = b'{"schema_version":1,"alpha":0.01,"baselines":{}}'
