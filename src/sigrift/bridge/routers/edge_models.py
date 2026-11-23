"""Edge model management endpoints.

Provides family classification, model info, download, and training
endpoints for the LightweightClassifier used on edge nodes.
"""

from __future__ import annotations

import asyncio
import logging
import os
import secrets
from pathlib import Path
from typing import Any

import torch
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from sigrift.lib.dsp.family_classifier import (
    SIGNAL_FAMILIES,
    LightweightClassifier,
    get_family,
    get_family_names,
)
from sigrift.lib.dsp.spectral_features import compute_dsp_features
from sigrift.bridge.dependencies import Role, require_role

logger = logging.getLogger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


#: Longest feature vector accepted (the model takes 54; the bound only
#: keeps a request from carrying megabytes of floats).
_MAX_FEATURES = 1024
#: Most IQ samples per channel accepted by /classify/iq (64 Ki, like an edge
#: capture); DSP features over more would hold a worker for seconds.
_MAX_IQ_SAMPLES = 65536


class ClassifyFeaturesRequest(BaseModel):
    features: list[float] = Field(..., min_length=1, max_length=_MAX_FEATURES)


class ClassifyIQRequest(BaseModel):
    iq_real: list[float] = Field(..., min_length=2, max_length=_MAX_IQ_SAMPLES)
    iq_imag: list[float] = Field(..., min_length=2, max_length=_MAX_IQ_SAMPLES)


class TrainRequest(BaseModel):
    epochs: int = Field(30, ge=1, le=500)
    samples_per_class: int = Field(500, ge=10, le=10_000)
    batch_size: int = Field(256, ge=1, le=8192)
    lr: float = Field(1e-2, gt=0.0, le=1.0)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_family_model(request: Request) -> LightweightClassifier | None:
    """Get the family classifier from app state, or None."""
    return getattr(request.app.state, "family_classifier", None)


def _inference_limit() -> int:
    raw = os.environ.get("BRIDGE_CLASSIFY_MAX_CONCURRENCY", "").strip()
    try:
        return max(1, int(raw)) if raw else 2
    except ValueError:
        return 2


#: Bounds concurrent classifier inference (each runs in a worker thread):
#: ``BRIDGE_CLASSIFY_MAX_CONCURRENCY`` (default 2).  Requests over the
#: limit get 503 instead of queueing without bound.
_inference_slots = asyncio.Semaphore(_inference_limit())


async def _run_inference(fn: Any, *args: Any) -> Any:
    """Run blocking torch/DSP work *fn* in a thread, within the slot limit."""
    if _inference_slots.locked():
        raise HTTPException(
            status_code=503,
            detail="Classifier busy, retry shortly",
            headers={"Retry-After": "1"},
        )
    async with _inference_slots:
        return await asyncio.to_thread(fn, *args)


def _classify(model: LightweightClassifier, features: torch.Tensor) -> dict[str, Any]:
    """Family prediction plus every family's probability (blocking)."""
    family_name, confidence = model.predict(features)
    model.eval()
    with torch.no_grad():
        logits = model(features)
        probs = torch.softmax(logits, dim=-1).squeeze(0)
    family_names = get_family_names()
    return {
        "family": family_name,
        "confidence": round(confidence, 4),
        "all_families": {
            name: round(probs[i].item(), 4) for i, name in enumerate(family_names)
        },
    }


def _classify_features(
    model: LightweightClassifier, values: list[float]
) -> dict[str, Any]:
    return _classify(model, torch.tensor([values], dtype=torch.float32))


def _classify_iq(
    model: LightweightClassifier, iq_real: list[float], iq_imag: list[float]
) -> dict[str, Any]:
    i_vals = torch.tensor(iq_real, dtype=torch.float32).unsqueeze(0)
    q_vals = torch.tensor(iq_imag, dtype=torch.float32).unsqueeze(0)
    x = torch.stack([i_vals, q_vals], dim=1)  # [1, 2, N]
    return _classify(model, compute_dsp_features(x))  # features [1, 54]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/families")
async def list_families(
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """List signal family definitions."""
    return {
        "families": SIGNAL_FAMILIES,
        "family_names": get_family_names(),
        "total_families": len(SIGNAL_FAMILIES),
        "total_classes": sum(len(v) for v in SIGNAL_FAMILIES.values()),
    }


@router.get("/family/{class_name}")
async def get_class_family(
    class_name: str,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, str]:
    """Get the family for a specific modulation class."""
    try:
        family = get_family(class_name)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Unknown class: {class_name}")
    return {"class_name": class_name, "family": family}


@router.post("/classify")
async def classify_features(
    body: ClassifyFeaturesRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Classify 49-dim features into a signal family."""
    model = _get_family_model(request)
    if model is None:
        raise HTTPException(
            status_code=503,
            detail="No family classifier model loaded. Train one first.",
        )

    if len(body.features) != model.input_dim:
        raise HTTPException(
            status_code=400,
            detail=f"Expected {model.input_dim} features, got {len(body.features)}",
        )

    return await _run_inference(_classify_features, model, body.features)


@router.post("/classify/iq")
async def classify_iq(
    body: ClassifyIQRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Classify raw IQ samples into a signal family."""
    model = _get_family_model(request)
    if model is None:
        raise HTTPException(
            status_code=503,
            detail="No family classifier model loaded. Train one first.",
        )

    if len(body.iq_real) != len(body.iq_imag):
        raise HTTPException(
            status_code=400,
            detail="iq_real and iq_imag must have the same length",
        )

    # DSP features + inference off the event loop
    return await _run_inference(_classify_iq, model, body.iq_real, body.iq_imag)


@router.get("/model/info")
async def model_info(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Get model info (params, families, accuracy)."""
    model = _get_family_model(request)
    if model is None:
        return {
            "loaded": False,
            "message": "No family classifier model loaded.",
            "families": get_family_names(),
            "n_families": len(get_family_names()),
        }

    param_count = sum(p.numel() for p in model.parameters())
    return {
        "loaded": True,
        "input_dim": model.input_dim,
        "hidden_dim": model.hidden_dim,
        "n_families": model.n_families,
        "param_count": param_count,
        "families": get_family_names(),
    }


@router.get("/model/download")
async def download_model(
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> FileResponse:
    """Download the ONNX model file."""
    data_dir = Path(__file__).resolve().parent.parent / "data"
    onnx_path = data_dir / "family_classifier.onnx"
    if not onnx_path.exists():
        raise HTTPException(
            status_code=404,
            detail="No ONNX model file found. Train and export first.",
        )
    import hashlib

    sha256 = hashlib.sha256(onnx_path.read_bytes()).hexdigest()
    resp = FileResponse(
        path=str(onnx_path),
        filename="family_classifier.onnx",
        media_type="application/octet-stream",
    )
    resp.headers["X-Model-SHA256"] = sha256
    return resp


@router.post("/model/train")
async def train_model(
    body: TrainRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ADMIN)),
) -> dict[str, Any]:
    """Trigger a training job for the family classifier (one at a time)."""
    current = getattr(request.app.state, "family_training_status", None) or {}
    if current.get("status") == "running":
        raise HTTPException(status_code=409, detail="A training job is already running")
    # Store training status
    request.app.state.family_training_status = {
        "status": "running",
        "epochs": body.epochs,
        "samples_per_class": body.samples_per_class,
    }

    try:
        from sigrift.lib.dsp.family_classifier import FamilyTrainer

        trainer = FamilyTrainer(
            epochs=body.epochs,
            batch_size=body.batch_size,
            lr=body.lr,
        )

        # Run training in a thread to not block the event loop
        def _train_sync():
            total = trainer.prepare_data(samples_per_class=body.samples_per_class)
            history = trainer.train(verbose=False)

            data_dir = Path(__file__).resolve().parent.parent / "data"
            pth_path = data_dir / "family_classifier.pth"
            onnx_path = data_dir / "family_classifier.onnx"
            # Both files are written under unique temporary names beside the
            # served ones and renamed into place only once both are complete,
            # the ONNX last.  A failed save or export leaves the model edges
            # download, and the one the next start loads, as they were.
            pth_tmp, onnx_tmp = (
                path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
                for path in (pth_path, onnx_path)
            )
            try:
                trainer.save_model(pth_tmp)
                trainer.export_onnx(onnx_tmp)
                os.replace(pth_tmp, pth_path)
                os.replace(onnx_tmp, onnx_path)
            except BaseException:
                for tmp in (pth_tmp, onnx_tmp):
                    try:
                        os.unlink(tmp)
                    except OSError:
                        pass
                raise

            return {
                "total_samples": total,
                "final_loss": history[-1]["loss"] if history else None,
                "pth_path": str(pth_path),
                "onnx_path": str(onnx_path),
                "model": trainer.model,
            }

        result = await asyncio.to_thread(_train_sync)

        # Update app state with the new model
        request.app.state.family_classifier = result.pop("model")
        request.app.state.family_training_status = {
            "status": "completed",
            **result,
        }

        return {
            "status": "completed",
            "total_samples": result["total_samples"],
            "final_loss": result["final_loss"],
        }

    except Exception as exc:
        request.app.state.family_training_status = {
            "status": "failed",
            "error": str(exc),
        }
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/model/status")
async def training_status(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Get training status."""
    status = getattr(request.app.state, "family_training_status", None)
    if status is None:
        return {"status": "idle", "message": "No training job has been run."}
    return status
