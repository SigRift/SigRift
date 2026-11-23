"""Signal browser endpoints for the signal-class taxonomy.

Provides endpoints to browse the class/family/super-family hierarchy,
generate synthetic waveforms, extract DSP features, and compare
multiple signal classes side-by-side.
"""

from __future__ import annotations

import html
import logging
from typing import Any

import numpy as np
from fastapi import APIRouter, Depends, HTTPException, Query, status

from sigrift.lib.shiny.dependencies import rate_limit
from sigrift.lib.shiny.models import SignalClass, WaveformData
from sigrift.lib.taxonomy import (
    CLASSES,
    CLASS_TO_FAMILY,
    CLASS_TO_MT,
    CLASS_TO_SF,
    FAMILIES,
    FAMILY_TO_CLASSES,
    SUPER_FAMILIES,
    SUPER_FAMILY_TO_FAMILIES,
)

logger = logging.getLogger(__name__)
router = APIRouter()

# -- Optional heavy imports (graceful degradation) --------------------------

try:
    from sigrift.lib.training.signal_factory import generate_signal as _factory_generate

    _HAS_FACTORY = True
except ImportError:
    _HAS_FACTORY = False
    _factory_generate = None  # type: ignore[assignment]

try:
    import torch
    from sigrift.lib.dsp.spectral_features import compute_dsp_features as _torch_dsp

    _HAS_DSP = True
except ImportError:
    _HAS_DSP = False
    _torch_dsp = None  # type: ignore[assignment]

_MAX_SAMPLES = 32768
_MAX_COMPARE = 6

# -- Helpers ----------------------------------------------------------------


def _generate_iq(class_name: str, snr: float, n: int) -> np.ndarray:
    """Generate IQ samples, using the factory if available."""
    if _HAS_FACTORY and _factory_generate is not None:
        return _factory_generate(class_name=class_name, n_samples=n, snr_db=snr)
    # Fallback: basic synthetic generation
    rng = np.random.RandomState()
    t = np.arange(n, dtype=np.float32)
    name = class_name.lower()
    if "bpsk" in name:
        sig = rng.choice([-1.0, 1.0], size=n).astype(np.complex64)
    elif "qpsk" in name:
        k = rng.randint(0, 4, size=n)
        sig = np.exp(1j * np.pi / 4 * (2 * k + 1)).astype(np.complex64)
    elif "psk" in name:
        order = 8
        sig = np.exp(1j * 2 * np.pi * rng.randint(0, order, n) / order).astype(
            np.complex64
        )
    elif "qam" in name:
        k = rng.randint(0, 4, size=n)
        sig = ((2 * (k // 2) - 1) + 1j * (2 * (k % 2) - 1)).astype(np.complex64)
    elif "fsk" in name or "msk" in name:
        phase = np.cumsum(2 * np.pi * rng.choice([-0.1, 0.1], size=n))
        sig = np.exp(1j * phase).astype(np.complex64)
    elif "fm" in name:
        sig = np.exp(
            1j * np.cumsum(2 * np.pi * 0.05 * np.sin(2 * np.pi * 0.01 * t))
        ).astype(np.complex64)
    elif "am" in name:
        sig = (
            (1 + 0.5 * np.sin(2 * np.pi * 0.01 * t)) * np.exp(1j * 2 * np.pi * 0.1 * t)
        ).astype(np.complex64)
    else:
        sig = (rng.randn(n) + 1j * rng.randn(n)).astype(np.complex64)
    # Normalize and add noise
    power = np.mean(np.abs(sig) ** 2)
    if power > 0:
        sig = sig / np.sqrt(power)
    noise_power = 10.0 ** (-snr / 10.0)
    noise = np.sqrt(noise_power / 2) * (rng.randn(n) + 1j * rng.randn(n))
    return (sig + noise).astype(np.complex64)


def _compute_psd(iq: np.ndarray) -> tuple[list[float], list[float]]:
    """Compute PSD via Welch-style averaged periodogram."""
    fft_size = min(1024, len(iq))
    n_seg = max(1, len(iq) // fft_size)
    psd_acc = np.zeros(fft_size)
    for i in range(n_seg):
        seg = iq[i * fft_size : (i + 1) * fft_size]
        if len(seg) < fft_size:
            break
        spec = np.fft.fftshift(np.fft.fft(seg * np.hanning(fft_size)))
        psd_acc += np.abs(spec) ** 2
    psd_db = 10.0 * np.log10(psd_acc / max(n_seg, 1) + 1e-12)
    freqs = np.fft.fftshift(np.fft.fftfreq(fft_size))
    return psd_db.tolist(), freqs.tolist()


def _extract_constellation(
    iq: np.ndarray, max_pts: int = 512
) -> tuple[list[float], list[float]]:
    """Downsample IQ for constellation display."""
    step = max(1, len(iq) // max_pts)
    pts = iq[::step][:max_pts]
    return pts.real.tolist(), pts.imag.tolist()


def _compute_features(iq: np.ndarray) -> list[float]:
    """Compute DSP feature vector from IQ data."""
    if _HAS_DSP and _torch_dsp is not None:
        iq_tensor = torch.tensor(
            np.stack([iq.real, iq.imag], axis=0),
            dtype=torch.float32,
        ).unsqueeze(0)
        return _torch_dsp(iq_tensor).squeeze(0).tolist()
    return [
        float(np.mean(np.abs(iq) ** 2)),
        float(np.var(np.abs(iq))),
        float(np.mean(iq.real)),
        float(np.mean(iq.imag)),
    ]


def _validate_class_name(class_name: str) -> str:
    """Validate and sanitize a class name against the taxonomy."""
    cleaned = class_name.strip().lower()
    if cleaned not in CLASS_TO_FAMILY:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown signal class: {html.escape(class_name)}",
        )
    return cleaned


def _build_waveform(class_name: str, snr: float, n: int) -> WaveformData:
    """Generate full waveform data for a validated class name."""
    try:
        iq = _generate_iq(class_name, snr, n)
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Signal generation failed: {html.escape(str(exc))}",
        )
    psd_db, psd_freq = _compute_psd(iq)
    cx, cy = _extract_constellation(iq)
    return WaveformData(
        signal_class=class_name,
        snr_db=snr,
        iq_real=iq.real.tolist(),
        iq_imag=iq.imag.tolist(),
        constellation_x=cx,
        constellation_y=cy,
        psd_db=psd_db,
        psd_freq_hz=psd_freq,
        dsp_features=_compute_features(iq),
    )


# -- Endpoints --------------------------------------------------------------


@router.get("/classes")
async def list_classes(
    _key_id: str = Depends(rate_limit),
) -> list[SignalClass]:
    """List all signal classes with hierarchy info."""
    return [
        SignalClass(
            name=c,
            mod_type=CLASS_TO_MT.get(c, ""),
            family=CLASS_TO_FAMILY.get(c, ""),
            super_family=CLASS_TO_SF.get(c, ""),
        )
        for c in CLASSES
    ]


@router.get("/families")
async def list_families(
    _key_id: str = Depends(rate_limit),
) -> list[dict[str, Any]]:
    """List families with their member classes."""
    return [{"family": f, "classes": FAMILY_TO_CLASSES.get(f, [])} for f in FAMILIES]


@router.get("/super-families")
async def list_super_families(
    _key_id: str = Depends(rate_limit),
) -> list[dict[str, Any]]:
    """List 6 super-families with their member families."""
    return [
        {"super_family": sf, "families": SUPER_FAMILY_TO_FAMILIES.get(sf, [])}
        for sf in SUPER_FAMILIES
    ]


@router.get("/generate")
async def generate_waveform(
    signal_class: str = Query(..., alias="class"),
    snr: float = Query(15.0, ge=-20.0, le=40.0),
    n: int = Query(4096, ge=64, le=_MAX_SAMPLES),
    _key_id: str = Depends(rate_limit),
) -> WaveformData:
    """Generate a waveform sample for a given signal class."""
    return _build_waveform(_validate_class_name(signal_class), snr, n)


@router.get("/dsp-features")
async def get_dsp_features(
    signal_class: str = Query(..., alias="class"),
    snr: float = Query(15.0, ge=-20.0, le=40.0),
    _key_id: str = Depends(rate_limit),
) -> dict[str, Any]:
    """Return DSP feature vector for a given class and SNR."""
    class_name = _validate_class_name(signal_class)
    try:
        iq = _generate_iq(class_name, snr, 4096)
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Signal generation failed: {html.escape(str(exc))}",
        )
    features = _compute_features(iq)
    return {
        "signal_class": class_name,
        "snr_db": snr,
        "features": features,
        "feature_count": len(features),
    }


@router.post("/compare")
async def compare_signals(
    classes: list[str],
    snr: float = Query(15.0, ge=-20.0, le=40.0),
    n: int = Query(4096, ge=64, le=_MAX_SAMPLES),
    _key_id: str = Depends(rate_limit),
) -> list[WaveformData]:
    """Generate side-by-side comparison data for multiple classes."""
    if len(classes) > _MAX_COMPARE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Maximum {_MAX_COMPARE} classes for comparison",
        )
    if not classes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one class is required",
        )
    return [_build_waveform(_validate_class_name(cls), snr, n) for cls in classes]
