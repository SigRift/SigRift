"""Tests for training run viewer and operations endpoints."""

import time
from unittest.mock import patch

import pytest

SAMPLE_LOG = """2026-02-13 19:30:05,506 [INFO] __main__: ======================================================================
2026-02-13 19:30:05,508 [INFO] __main__: GEN3 HIERARCHICAL TRAINING v1
2026-02-13 19:30:05,509 [INFO] __main__: ======================================================================
2026-02-13 19:30:05,511 [INFO] __main__: Args: {'epochs': 50, 'batch_size': 256, 'lr': 0.001, 'weight_decay': 0.0001, 'gamma': 1.5}
2026-02-13 19:30:05,625 [INFO] __main__: GPU: NVIDIA GeForce RTX 3090
2026-02-13 19:30:05,626 [INFO] __main__: VRAM: 25.8 GB
2026-02-13 19:30:05,757 [INFO] __main__: Model parameters: 11,741,752
2026-02-13 19:30:07,242 [INFO] sigrift.lib.training.trainer: Starting training: 50 epochs, batch_size=256, lr=1.0e-03, device=cuda
2026-02-13 19:34:33,015 [INFO] sigrift.lib.training.trainer: Epoch   1/50 | train_loss=3.500 train_acc=0.1700 | val_loss=2.0589 val_acc=0.3904 | lr=3.00e-04 | 54.5s
2026-02-13 19:34:33,025 [INFO] sigrift.lib.training.trainer:   New best val_acc=0.3904 at epoch 1
2026-02-13 19:35:27,794 [INFO] sigrift.lib.training.trainer: Epoch   2/50 | train_loss=2.6113 train_acc=0.2448 | val_loss=1.8163 val_acc=0.4106 | lr=2.99e-04 | 54.8s
2026-02-13 19:35:27,804 [INFO] sigrift.lib.training.trainer:   New best val_acc=0.4106 at epoch 2
2026-02-13 19:36:22,342 [INFO] sigrift.lib.training.trainer: Epoch   3/50 | train_loss=2.3984 train_acc=0.2472 | val_loss=1.6513 val_acc=0.4513 | lr=2.97e-04 | 54.5s
2026-02-13 19:36:22,353 [INFO] sigrift.lib.training.trainer:   New best val_acc=0.4513 at epoch 3
"""


@pytest.fixture
def tmp_checkpoints(tmp_path):
    """Create a temporary checkpoints directory with sample logs."""
    ckpt_dir = tmp_path / "nightrun" / "checkpoints"
    run_dir = ckpt_dir / "sigrift_v1"
    run_dir.mkdir(parents=True)
    log_file = run_dir / "sigrift_train_20260213_193005.log"
    log_file.write_text(SAMPLE_LOG)
    return ckpt_dir


@pytest.fixture
def training_client(bridge_app, tmp_checkpoints):
    """Add training router to the bridge app with mocked checkpoints."""
    from fastapi.testclient import TestClient
    from sigrift.bridge.routers import training

    with patch.object(training, "_CHECKPOINTS_DIR", tmp_checkpoints):
        bridge_app.include_router(training.router, prefix="/api/training", tags=["training"])
        yield TestClient(bridge_app, headers={"X-API-Key": "test-key"})


# ---- Unit tests for parsing functions ----

class TestLogParsing:
    """Unit tests for log parsing functions."""

    def test_parse_metrics_from_sample(self, tmp_checkpoints):
        from sigrift.bridge.routers.training import _parse_metrics
        log_path = tmp_checkpoints / "sigrift_v1" / "sigrift_train_20260213_193005.log"
        metrics = _parse_metrics(log_path)
        assert len(metrics) == 3
        assert metrics[0]["epoch"] == 1
        assert metrics[0]["val_acc"] == pytest.approx(0.3904)
        assert metrics[2]["epoch"] == 3
        assert metrics[2]["val_acc"] == pytest.approx(0.4513)

    def test_parse_metrics_has_all_fields(self, tmp_checkpoints):
        from sigrift.bridge.routers.training import _parse_metrics
        log_path = tmp_checkpoints / "sigrift_v1" / "sigrift_train_20260213_193005.log"
        epoch = _parse_metrics(log_path)[0]
        assert epoch["epoch"] == 1
        assert epoch["total_epochs"] == 50
        assert epoch["train_loss"] == pytest.approx(3.5)
        assert epoch["train_acc"] == pytest.approx(0.17)
        assert epoch["val_loss"] == pytest.approx(2.0589)
        assert epoch["val_acc"] == pytest.approx(0.3904)
        assert epoch["lr"] == pytest.approx(3.0e-04)
        assert epoch["time_s"] == pytest.approx(54.5)

    def test_parse_metadata_from_sample(self, tmp_checkpoints):
        from sigrift.bridge.routers.training import _parse_run_metadata
        with patch("sigrift.bridge.routers.training._PROJECT_ROOT", tmp_checkpoints.parent):
            log_path = tmp_checkpoints / "sigrift_v1" / "sigrift_train_20260213_193005.log"
            meta = _parse_run_metadata(log_path)
            assert meta["gpu"] == "NVIDIA GeForce RTX 3090"
            assert meta["epochs"] == 50
            assert meta["batch_size"] == 256
            assert meta["lr"] == 0.001
            assert meta["gamma"] == 1.5
            assert meta["current_epoch"] == 3
            assert meta["best_val_acc"] == pytest.approx(0.4513, abs=0.001)
            assert meta["status"] == "active"  # 3/50 epochs

    def test_find_log_files(self, tmp_checkpoints):
        with patch("sigrift.bridge.routers.training._CHECKPOINTS_DIR", tmp_checkpoints):
            from sigrift.bridge.routers.training import _find_log_files
            logs = _find_log_files()
            assert len(logs) == 1
            assert logs[0].name == "sigrift_train_20260213_193005.log"

    def test_empty_checkpoints_dir(self, tmp_path):
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        with patch("sigrift.bridge.routers.training._CHECKPOINTS_DIR", empty_dir):
            from sigrift.bridge.routers.training import _find_log_files
            logs = _find_log_files()
            assert logs == []

    def test_nonexistent_checkpoints_dir(self, tmp_path):
        with patch("sigrift.bridge.routers.training._CHECKPOINTS_DIR", tmp_path / "nope"):
            from sigrift.bridge.routers.training import _find_log_files
            logs = _find_log_files()
            assert logs == []

    def test_inf_train_loss_parsed_as_none(self, tmp_path):
        ckpt_dir = tmp_path / "checkpoints"
        run_dir = ckpt_dir / "test_run"
        run_dir.mkdir(parents=True)
        log = run_dir / "sigrift_train_20260213_000000.log"
        log.write_text(
            "2026-02-13 19:34:33,015 [INFO] trainer: "
            "Epoch   1/10 | train_loss=inf train_acc=0.1000 | "
            "val_loss=3.0 val_acc=0.2000 | lr=1.00e-03 | 10.0s\n"
        )
        from sigrift.bridge.routers.training import _parse_metrics
        metrics = _parse_metrics(log)
        assert len(metrics) == 1
        assert metrics[0]["train_loss"] is None
        assert metrics[0]["val_acc"] == pytest.approx(0.2)

    def test_completed_run_status(self, tmp_path):
        """A run with epoch == total_epochs should be 'completed'."""
        ckpt_dir = tmp_path / "checkpoints"
        run_dir = ckpt_dir / "done_run"
        run_dir.mkdir(parents=True)
        log = run_dir / "sigrift_train_20260213_000000.log"
        log.write_text(
            "2026-02-13 19:30:00,000 [INFO] __main__: Args: {'epochs': 2}\n"
            "2026-02-13 19:31:00,000 [INFO] trainer: Epoch   1/2 | train_loss=2.0 train_acc=0.3 | val_loss=1.5 val_acc=0.4 | lr=1.00e-03 | 30.0s\n"
            "2026-02-13 19:32:00,000 [INFO] trainer: Epoch   2/2 | train_loss=1.5 train_acc=0.5 | val_loss=1.0 val_acc=0.6 | lr=1.00e-03 | 30.0s\n"
        )
        with patch("sigrift.bridge.routers.training._PROJECT_ROOT", tmp_path):
            from sigrift.bridge.routers.training import _parse_run_metadata
            meta = _parse_run_metadata(log)
            assert meta["status"] == "completed"
            assert meta["current_epoch"] == 2
            assert meta["best_val_acc"] == pytest.approx(0.6)

    def test_multiple_run_dirs(self, tmp_path):
        """Multiple subdirs under checkpoints should all be found."""
        ckpt_dir = tmp_path / "checkpoints"
        for name in ["run_a", "run_b"]:
            d = ckpt_dir / name
            d.mkdir(parents=True)
            (d / "sigrift_train_20260213_000000.log").write_text(
                "2026-02-13 19:30:00,000 [INFO] test\n"
            )
        with patch("sigrift.bridge.routers.training._CHECKPOINTS_DIR", ckpt_dir):
            from sigrift.bridge.routers.training import _find_log_files
            logs = _find_log_files()
            assert len(logs) == 2


# ---- Security tests ----

class TestPathTraversal:
    """Security tests for path traversal prevention."""

    def test_dot_dot_in_run_dir_rejected(self, tmp_checkpoints):
        """Ensure path traversal via run_dir is blocked."""
        from sigrift.bridge.routers.training import router
        # The validator checks for ".." in path components
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from sigrift.bridge.dependencies import set_rate_limiter, RateLimiter
        set_rate_limiter(RateLimiter(max_requests=1000, window_seconds=60.0))

        app = FastAPI()
        app.include_router(router, prefix="/api/training")

        # Minimal state setup for auth
        from sigrift.lib.security.credentials import generate_api_key, hash_credential
        from sigrift.bridge.persistence import PersistenceManager
        from sigrift.bridge.state import AppState
        mk = generate_api_key(length=32)
        pm = PersistenceManager(data_dir=tmp_checkpoints.parent / "data", auto_save_interval=0)
        pm.load_all()
        hash_hex, salt = hash_credential(mk)
        pm.set_key("master", hash_hex, salt)
        app.state.persistence = pm
        app.state.app_state = AppState()

        client = TestClient(app, headers={"X-API-Key": mk})
        r = client.get("/api/training/runs/..%2F..%2Fetc/passwd/log")
        # Should be rejected — 400, 404, or 422 are all acceptable
        assert r.status_code in (400, 404, 422)


# ---- Stalled / failed detection tests ----

class TestStatusDetection:
    """Tests for stalled/failed run detection."""

    def test_stalled_run_detected(self, tmp_path):
        """A run whose log hasn't been modified in >5min should be 'stalled'."""
        ckpt_dir = tmp_path / "checkpoints"
        run_dir = ckpt_dir / "stale_run"
        run_dir.mkdir(parents=True)
        log = run_dir / "sigrift_train_20260213_000000.log"
        log.write_text(
            "2026-02-13 19:30:00,000 [INFO] __main__: Args: {'epochs': 50}\n"
            "2026-02-13 19:31:00,000 [INFO] trainer: Epoch   1/50 | "
            "train_loss=2.0 train_acc=0.3 | val_loss=1.5 val_acc=0.4 | "
            "lr=1.00e-03 | 30.0s\n"
        )
        # Make the file look old
        import os
        old_time = time.time() - 600  # 10 minutes ago
        os.utime(log, (old_time, old_time))

        with patch("sigrift.bridge.routers.training._PROJECT_ROOT", tmp_path):
            from sigrift.bridge.routers.training import _parse_run_metadata
            meta = _parse_run_metadata(log)
            assert meta["status"] == "stalled"
            assert meta["last_activity_s"] > 300

    def test_failed_run_no_epochs(self, tmp_path):
        """A run with no epochs and old mtime should be 'failed'."""
        ckpt_dir = tmp_path / "checkpoints"
        run_dir = ckpt_dir / "fail_run"
        run_dir.mkdir(parents=True)
        log = run_dir / "sigrift_train_20260213_000000.log"
        log.write_text(
            "2026-02-13 19:30:00,000 [INFO] __main__: Starting...\n"
        )
        import os
        old_time = time.time() - 600
        os.utime(log, (old_time, old_time))

        with patch("sigrift.bridge.routers.training._PROJECT_ROOT", tmp_path):
            from sigrift.bridge.routers.training import _parse_run_metadata
            meta = _parse_run_metadata(log)
            assert meta["status"] == "failed"

    def test_active_run_recent_mtime(self, tmp_path):
        """A run with recent mtime and incomplete epochs is 'active'."""
        ckpt_dir = tmp_path / "checkpoints"
        run_dir = ckpt_dir / "active_run"
        run_dir.mkdir(parents=True)
        log = run_dir / "sigrift_train_20260213_000000.log"
        log.write_text(
            "2026-02-13 19:30:00,000 [INFO] __main__: Args: {'epochs': 50}\n"
            "2026-02-13 19:31:00,000 [INFO] trainer: Epoch   1/50 | "
            "train_loss=2.0 train_acc=0.3 | val_loss=1.5 val_acc=0.4 | "
            "lr=1.00e-03 | 30.0s\n"
        )
        # mtime is now (just written), so it should be active
        with patch("sigrift.bridge.routers.training._PROJECT_ROOT", tmp_path):
            from sigrift.bridge.routers.training import _parse_run_metadata
            meta = _parse_run_metadata(log)
            assert meta["status"] == "active"
            assert meta["last_activity_s"] < 60


# ---- Training operations endpoint tests ----

class TestTrainingOperations:
    """Tests for training operation audit endpoints."""

    @pytest.fixture
    def ops_client(self, tmp_path):
        """Create a test client with training router and detection store."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from sigrift.bridge.routers import training
        from sigrift.bridge.dependencies import set_rate_limiter, RateLimiter
        from sigrift.lib.security.credentials import generate_api_key, hash_credential
        from sigrift.bridge.persistence import PersistenceManager
        from sigrift.bridge.state import AppState
        from sigrift.bridge.detection_store import DetectionStore

        set_rate_limiter(RateLimiter(max_requests=1000, window_seconds=60.0))

        # Set up checkpoints with a sample log
        ckpt_dir = tmp_path / "nightrun" / "checkpoints"
        run_dir = ckpt_dir / "test_gpu0"
        run_dir.mkdir(parents=True)
        log = run_dir / "sigrift_train_20260213_193005.log"
        log.write_text(SAMPLE_LOG)

        app = FastAPI()

        with patch.object(training, "_CHECKPOINTS_DIR", ckpt_dir), \
             patch.object(training, "_PROJECT_ROOT", tmp_path):
            app.include_router(training.router, prefix="/api/training")

            mk = generate_api_key(length=32)
            data_dir = tmp_path / "data"
            data_dir.mkdir(parents=True, exist_ok=True)
            pm = PersistenceManager(data_dir=data_dir, auto_save_interval=0)
            pm.load_all()
            hash_hex, salt = hash_credential(mk)
            pm.set_key("master", hash_hex, salt)
            app.state.persistence = pm
            app.state.app_state = AppState()

            db_path = data_dir / "test.db"
            store = DetectionStore(str(db_path))
            app.state.detection_store = store

            yield TestClient(app, headers={"X-API-Key": mk})

    def test_log_training_start(self, ops_client):
        r = ops_client.post(
            "/api/training/runs/test_gpu0/sigrift_train_20260213_193005/start",
            json={"note": "Started GPU 0 training"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["action"] == "training_start"
        assert "test_gpu0" in data["target_id"]

    def test_log_training_stop(self, ops_client):
        r = ops_client.post(
            "/api/training/runs/test_gpu0/sigrift_train_20260213_193005/stop",
            json={"note": "Manual stop"},
        )
        assert r.status_code == 200
        assert r.json()["action"] == "training_stop"

    def test_log_training_resume(self, ops_client):
        r = ops_client.post(
            "/api/training/runs/test_gpu0/sigrift_train_20260213_193005/resume",
            json={},
        )
        assert r.status_code == 200
        assert r.json()["action"] == "training_resume"

    def test_list_operations_returns_training_events(self, ops_client):
        # Create some training events
        ops_client.post(
            "/api/training/runs/test_gpu0/sigrift_train_20260213_193005/start",
            json={"note": "test"},
        )
        ops_client.post(
            "/api/training/runs/test_gpu0/sigrift_train_20260213_193005/stop",
            json={"note": "done"},
        )
        r = ops_client.get("/api/training/operations")
        assert r.status_code == 200
        data = r.json()
        actions = [e["action"] for e in data]
        assert "training_start" in actions
        assert "training_stop" in actions

    def test_training_health_endpoint(self, ops_client):
        r = ops_client.get("/api/training/health")
        assert r.status_code == 200
        data = r.json()
        assert "runs" in data
        assert isinstance(data["runs"], list)
        assert "checked_at" in data
        assert isinstance(data["checked_at"], str)
        assert len(data["runs"]) > 0

    def test_operations_nonexistent_run_404(self, ops_client):
        r = ops_client.post(
            "/api/training/runs/nonexistent/fake_run/start",
            json={},
        )
        assert r.status_code == 404

    def test_operations_path_traversal_blocked(self, ops_client):
        r = ops_client.post(
            "/api/training/runs/..%2F..%2Fetc/passwd/start",
            json={},
        )
        assert r.status_code in (400, 404, 422)
