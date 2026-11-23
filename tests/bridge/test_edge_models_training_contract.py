"""Edge model training, status and distribution: the router's own contract.

The router finds its model files next to itself (``bridge/data``). Each test
points the module's ``__file__`` at a temporary tree, so nothing is written to
the source checkout, and the trainer is a small fake: the router's job here is
the status transitions, the model swap and the files it hands to edge nodes.
"""

from __future__ import annotations

import errno
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from sigrift.bridge.routers import edge_models
from sigrift.lib.dsp import family_classifier
from sigrift.lib.dsp.family_classifier import LightweightClassifier


@pytest.fixture
def model_dir(tmp_path, monkeypatch) -> Path:
    """The router's ``data`` directory, under tmp_path instead of the checkout."""
    routers = tmp_path / "bridge" / "routers"
    routers.mkdir(parents=True)
    monkeypatch.setattr(edge_models, "__file__", str(routers / "edge_models.py"))
    data = tmp_path / "bridge" / "data"
    data.mkdir()
    return data.resolve()


#: What an export or a save fails with on a full disk.
DISK_FULL = OSError(errno.ENOSPC, "No space left on device")


def fake_trainer(
    monkeypatch, *, history, error=None, onnx=b"exported-onnx-graph", fail=None
):
    """Replace FamilyTrainer; returns the calls the router made and the models built.

    The export writes *onnx* and the save a state dict named after it. *fail*
    ("save" or "export") makes that step write only part of its file and then
    fail with DISK_FULL, as an interrupted writer would.
    """
    made = SimpleNamespace(calls=[], models=[])

    def write(step, path, data):
        made.calls.append((step, Path(path)))
        if fail == step:
            Path(path).write_bytes(data[:5])
            raise DISK_FULL
        Path(path).write_bytes(data)

    class Trainer:
        def __init__(self, *, epochs, batch_size, lr):
            made.calls.append(("init", epochs, batch_size, lr))
            self.model = LightweightClassifier()
            made.models.append(self.model)

        def prepare_data(self, *, samples_per_class):
            made.calls.append(("prepare", samples_per_class))
            return samples_per_class * 7

        def train(self, *, verbose):
            made.calls.append(("train", verbose))
            if error is not None:
                raise error
            return history

        def save_model(self, path):
            write("save", path, b"state-dict of " + onnx)

        def export_onnx(self, path):
            write("export", path, onnx)

    monkeypatch.setattr(family_classifier, "FamilyTrainer", Trainer)
    return made


def test_training_swaps_in_the_new_model_and_distributes_exactly_its_export(
    client, bridge_app, model_dir, monkeypatch
):
    made = fake_trainer(monkeypatch, history=[{"loss": 0.9}, {"loss": 0.25}])
    assert client.get("/api/edge-models/model/status").json() == {
        "status": "idle",
        "message": "No training job has been run.",
    }
    body = {"epochs": 3, "samples_per_class": 20, "batch_size": 16, "lr": 0.05}
    response = client.post("/api/edge-models/model/train", json=body)
    assert response.status_code == 200, response.text
    assert response.json() == {
        "status": "completed",
        "total_samples": 140,
        "final_loss": 0.25,
    }
    pth, onnx = (
        model_dir / "family_classifier.pth",
        model_dir / "family_classifier.onnx",
    )
    assert made.calls[:3] == [("init", 3, 16, 0.05), ("prepare", 20), ("train", False)]
    assert [call[0] for call in made.calls[3:]] == ["save", "export"]
    # Both files are written under temporary names beside the files they
    # replace, named so that nothing takes them for a model ...
    for _, written in made.calls[3:]:
        assert written.parent == model_dir
        assert not written.name.endswith((".onnx", ".pth"))
    # ... and renamed into place once complete: no temporary file is left.
    assert sorted(model_dir.iterdir()) == [onnx, pth]
    # The trained model is the one now serving /classify, not a copy.
    assert bridge_app.state.family_classifier is made.models[0]
    assert client.get("/api/edge-models/model/info").json()["loaded"] is True
    status = client.get("/api/edge-models/model/status").json()
    assert status == {
        "status": "completed",
        "total_samples": 140,
        "final_loss": 0.25,
        "pth_path": str(pth),
        "onnx_path": str(onnx),
    }
    # Edge nodes get the exported bytes and a digest of exactly those bytes.
    download = client.get("/api/edge-models/model/download")
    assert download.status_code == 200
    assert download.content == b"exported-onnx-graph"
    assert (
        download.headers["x-model-sha256"]
        == hashlib.sha256(b"exported-onnx-graph").hexdigest()
    )
    assert download.headers["content-type"] == "application/octet-stream"


def test_training_without_history_reports_no_final_loss(client, model_dir, monkeypatch):
    fake_trainer(monkeypatch, history=[])
    response = client.post("/api/edge-models/model/train", json={"epochs": 1})
    assert response.status_code == 200
    assert response.json()["final_loss"] is None
    assert response.json()["total_samples"] == 500 * 7  # the default per class


def test_failed_training_keeps_the_serving_model_and_allows_a_retry(
    client, bridge_app, model_dir, monkeypatch
):
    serving = LightweightClassifier()
    bridge_app.state.family_classifier = serving
    fake_trainer(monkeypatch, history=[], error=RuntimeError("loss diverged"))
    response = client.post("/api/edge-models/model/train", json={"epochs": 2})
    assert response.status_code == 500
    assert response.json()["detail"] == "loss diverged"
    assert bridge_app.state.family_classifier is serving
    assert client.get("/api/edge-models/model/status").json() == {
        "status": "failed",
        "error": "loss diverged",
    }
    # Training failed before anything was saved: no file is offered to edges.
    assert list(model_dir.iterdir()) == []
    assert client.get("/api/edge-models/model/download").status_code == 404
    # A failure does not leave the job "running": a retry is accepted.
    retry = fake_trainer(monkeypatch, history=[{"loss": 0.5}])
    assert client.post("/api/edge-models/model/train", json={}).status_code == 200
    assert bridge_app.state.family_classifier is retry.models[0]


def train_and_download(client, monkeypatch, onnx):
    """One successful training run; returns its trainer and the download."""
    made = fake_trainer(monkeypatch, history=[{"loss": 0.4}], onnx=onnx)
    assert client.post("/api/edge-models/model/train", json={}).status_code == 200
    download = client.get("/api/edge-models/model/download")
    assert download.content == onnx
    assert download.headers["x-model-sha256"] == hashlib.sha256(onnx).hexdigest()
    return made, download


@pytest.mark.parametrize("step", ["save", "export"])
def test_a_failed_save_or_export_keeps_the_previous_model_served(
    client, bridge_app, model_dir, monkeypatch, step
):
    first, served = train_and_download(client, monkeypatch, b"good-onnx-graph" * 100)
    files = {path.name: path.read_bytes() for path in model_dir.iterdir()}
    assert sorted(files) == ["family_classifier.onnx", "family_classifier.pth"]
    fake_trainer(monkeypatch, history=[], onnx=b"newer-onnx-graph" * 100, fail=step)
    response = client.post("/api/edge-models/model/train", json={})
    assert response.status_code == 500
    assert response.json()["detail"] == str(DISK_FULL)
    assert client.get("/api/edge-models/model/status").json() == {
        "status": "failed",
        "error": str(DISK_FULL),
    }
    assert bridge_app.state.family_classifier is first.models[0]
    # The ONNX that edges download and the .pth the next start loads are
    # byte for byte the previous ones, and the partial write is gone.
    assert {path.name: path.read_bytes() for path in model_dir.iterdir()} == files
    download = client.get("/api/edge-models/model/download")
    assert download.status_code == 200
    assert download.content == served.content
    assert download.headers["x-model-sha256"] == served.headers["x-model-sha256"]


@pytest.mark.parametrize("busy", ["family_classifier.pth", "family_classifier.onnx"])
def test_the_new_model_serves_only_once_its_export_is_in_place(
    client, bridge_app, model_dir, monkeypatch, busy
):
    first, served = train_and_download(client, monkeypatch, b"good-onnx-graph")
    fake_trainer(monkeypatch, history=[], onnx=b"newer-onnx-graph")
    real_replace = os.replace

    def replace(src, dst):
        if Path(dst) == model_dir / busy:
            raise OSError(errno.EBUSY, "Device or resource busy")
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", replace)
    response = client.post("/api/edge-models/model/train", json={})
    assert response.status_code == 500
    # A file could not be put in place, either one (the ONNX goes last): the
    # model it came from does not serve /classify, edges still get the
    # previous bytes and digest, and no temporary file is left behind.
    assert bridge_app.state.family_classifier is first.models[0]
    download = client.get("/api/edge-models/model/download")
    assert download.content == served.content == b"good-onnx-graph"
    assert download.headers["x-model-sha256"] == served.headers["x-model-sha256"]
    assert sorted(path.name for path in model_dir.iterdir()) == [
        "family_classifier.onnx",
        "family_classifier.pth",
    ]


def test_second_training_job_is_refused_while_one_runs(
    client, bridge_app, model_dir, monkeypatch
):
    made = fake_trainer(monkeypatch, history=[])
    running = {"status": "running", "epochs": 30, "samples_per_class": 500}
    bridge_app.state.family_training_status = running
    response = client.post("/api/edge-models/model/train", json={"epochs": 1})
    assert response.status_code == 409
    assert response.json()["detail"] == "A training job is already running"
    assert made.calls == []
    assert bridge_app.state.family_training_status == running
    assert list(model_dir.iterdir()) == []


def test_download_without_an_export_is_404_not_an_error(client, model_dir):
    response = client.get("/api/edge-models/model/download")
    assert response.status_code == 404
    assert "No ONNX model file found" in response.json()["detail"]
    assert "x-model-sha256" not in response.headers


def test_mismatched_iq_channels_are_refused_before_inference(client, bridge_app):
    # Any attribute access on this sentinel would fail the request with 500.
    bridge_app.state.family_classifier = SimpleNamespace()
    response = client.post(
        "/api/edge-models/classify/iq",
        json={"iq_real": [0.1, 0.2, 0.3, 0.4], "iq_imag": [0.1, 0.2, 0.3]},
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "iq_real and iq_imag must have the same length"


@pytest.mark.parametrize(
    "raw,limit",
    [("", 2), ("   ", 2), ("abc", 2), ("2.5", 2), ("0", 1), ("-4", 1), (" 6 ", 6)],
)
def test_inference_concurrency_setting_is_bounded(monkeypatch, raw, limit):
    monkeypatch.setenv("BRIDGE_CLASSIFY_MAX_CONCURRENCY", raw)
    assert edge_models._inference_limit() == limit
