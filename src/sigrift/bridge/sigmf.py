"""SigMF (Signal Metadata Format) metadata generator for IQ captures.

Produces valid SigMF 1.0.0 metadata dicts and saves them as
``{detection_id}.sigmf-meta`` sidecar files alongside ``.iq.gz`` data.

Reference: https://github.com/gnuradio/SigMF/blob/main/sigmf-spec.md
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sigrift.bridge.iq_store import capture_stem

logger = logging.getLogger(__name__)

_SIGMF_VERSION = "1.0.0"
_DEFAULT_BASE_DIR = Path(__file__).resolve().parent / "data" / "iq_captures"


def generate_sigmf_meta(
    detection_id: str,
    detection_record: dict[str, Any],
    sample_rate: float,
    data_type: str = "cf32_le",
    **kwargs: Any,
) -> dict[str, Any]:
    """Generate a SigMF metadata dict for an IQ capture.

    Parameters
    ----------
    detection_id : str
        Detection identifier.
    detection_record : dict
        Detection record with keys like freq_hz, signal_class, timestamp,
        node_id, bandwidth_hz, etc.
    sample_rate : float
        Sample rate in Hz.
    data_type : str
        SigMF datatype string. Default ``cf32_le`` (complex float32 little-endian).
    **kwargs
        Additional fields merged into the global section (e.g. ``hw``).

    Returns
    -------
    dict
        Valid SigMF metadata dict with global, captures, and annotations sections.
    """
    freq_hz = detection_record.get("freq_hz", 0.0)
    signal_class = detection_record.get("signal_class", "unknown")
    node_id = detection_record.get("node_id", "")
    bandwidth_hz = detection_record.get("bandwidth_hz")
    sample_count = detection_record.get("sample_count")

    # Parse timestamp from detection record
    ts_raw = detection_record.get("timestamp")
    if isinstance(ts_raw, str):
        capture_datetime = ts_raw
    elif isinstance(ts_raw, datetime):
        capture_datetime = ts_raw.isoformat()
    else:
        capture_datetime = datetime.now(timezone.utc).isoformat()

    # -- global section --
    global_section: dict[str, Any] = {
        "core:datatype": data_type,
        "core:sample_rate": sample_rate,
        "core:version": _SIGMF_VERSION,
        "core:description": (
            f"IQ capture for detection {detection_id} (signal_class={signal_class})"
        ),
    }

    # Hardware info from node_id or explicit kwarg
    hw = kwargs.pop("hw", None)
    if hw:
        global_section["core:hw"] = hw
    elif node_id:
        global_section["core:hw"] = f"node:{node_id}"

    # Merge any extra kwargs into global
    for key, value in kwargs.items():
        global_section[key] = value

    # -- captures section --
    capture: dict[str, Any] = {
        "core:sample_start": 0,
        "core:frequency": freq_hz,
        "core:datetime": capture_datetime,
    }

    # -- annotations section --
    annotation: dict[str, Any] = {
        "core:sample_start": 0,
        "core:label": signal_class,
    }

    if sample_count is not None:
        annotation["core:sample_count"] = sample_count

    if bandwidth_hz is not None and freq_hz:
        half_bw = bandwidth_hz / 2.0
        annotation["core:freq_lower_edge"] = freq_hz - half_bw
        annotation["core:freq_upper_edge"] = freq_hz + half_bw

    return {
        "global": global_section,
        "captures": [capture],
        "annotations": [annotation],
    }


def save_sigmf_meta(
    detection_id: str,
    meta_dict: dict[str, Any],
    base_dir: str | Path | None = None,
) -> Path:
    """Save SigMF metadata as a ``.sigmf-meta`` JSON file.

    Parameters
    ----------
    detection_id : str
        Detection identifier (used as filename stem).
    meta_dict : dict
        SigMF metadata dict (from :func:`generate_sigmf_meta`).
    base_dir : str or Path or None
        Directory to write into. Defaults to ``data/iq_captures/``.

    Returns
    -------
    Path
        Path to the written ``.sigmf-meta`` file.
    """
    base = Path(base_dir or _DEFAULT_BASE_DIR)
    base.mkdir(parents=True, exist_ok=True)

    # Same injective id -> file-stem mapping as the capture itself, so the
    # sidecar sits next to ``{stem}.iq.gz`` and is deleted with it.
    path = (base / f"{capture_stem(detection_id)}.sigmf-meta").resolve()
    if not path.is_relative_to(base.resolve()):
        raise ValueError("Path traversal detected")

    path.write_text(json.dumps(meta_dict, indent=2))
    logger.debug("SigMF metadata saved: %s", path)
    return path
