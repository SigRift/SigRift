"""Generate synthetic environment-preset bundles from the signal factory.

Each preset is a site-transferable, fully synthetic starting point for the RF
anomaly baselines so a fresh SigRift install starts warm instead of spending
~300 detections/bin in learning mode. Nothing here reads real deployment data:
detections are synthesized by ``signal_factory`` (the same generator the
open-default classifier was trained on), measured, collapsed to the open-16
taxonomy the shipped model emits, fed through the real ``BaselineManager``, then
sanitized of all site-coupled state.

Usage::

    python training/generate_preset_bundles.py --profile all
    python training/generate_preset_bundles.py --profile rural-quiet --check

Profiles live in ``training/configs/presets/<profile>.json``; bundles are
written to ``src/sigrift/bridge/presets/preset_<profile>_v1.sigrift.tar.gz``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
from pathlib import Path

import numpy as np

# Ensure the package is importable when run as a script from the repo root.
_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO / "src"))

from sigrift.bridge import bundles  # noqa: E402
from sigrift.bridge.anomaly.baseline import BaselineManager  # noqa: E402
from sigrift.bridge.anomaly.whitelist import (  # noqa: E402
    _DEFAULT_ENTRIES,
    WhitelistEntry,
)
from sigrift.lib import taxonomy_open  # noqa: E402
from sigrift.lib.training import signal_factory  # noqa: E402

logger = logging.getLogger("generate_preset_bundles")

_PROFILE_DIR = _REPO / "training" / "configs" / "presets"
_OUT_DIR = _REPO / "src" / "sigrift" / "bridge" / "presets"
_MEASURE_SAMPLES = 4096
_SAMPLE_RATE = 2_048_000.0
_MAX_BUNDLE_BYTES = 512 * 1024
_DEFAULT_TIMESTAMP = "2026-07-01T00:00:00+00:00"

# 24-hour arrival-rate envelopes. Presets neutralize hourly_counts at packaging,
# but the diurnal shape still drives realistic inter-arrival statistics.
_DIURNAL = {
    "flat": [1.0] * 24,
    "business_hours": [0.2] * 8 + [1.0] * 10 + [0.3] * 6,
    "evening_peak": [0.3] * 17 + [1.0, 1.0, 1.0, 0.8, 0.5, 0.3, 0.3][:7],
    "quiet_night": [1.0] * 6 + [0.4] * 12 + [0.8] * 6,
}


def _diurnal_weights(name: str) -> np.ndarray:
    w = np.asarray(_DIURNAL.get(name, _DIURNAL["flat"]), dtype=float)
    return w / w.sum()


def _measure_signal(source_class: str, snr_db: float, seed: int) -> tuple[float, float]:
    """Return (relative_power_dbfs, occupied_bandwidth_hz) for a class at an SNR.

    Deterministic in (source_class, snr_bucket, seed) and independent of draw
    order, so regeneration is reproducible.
    """
    rng = np.random.RandomState(seed % (2**32))
    iq = signal_factory.generate_signal(
        source_class, n_samples=_MEASURE_SAMPLES, snr_db=snr_db, rng=rng
    )
    power = float(np.mean(np.abs(iq) ** 2)) + 1e-12
    power_dbfs = 10.0 * np.log10(power)
    # 99%-occupied bandwidth from the magnitude PSD.
    psd = np.abs(np.fft.fftshift(np.fft.fft(iq))) ** 2
    total = psd.sum() + 1e-12
    order = np.argsort(psd)[::-1]
    csum = np.cumsum(psd[order])
    n_bins = int(np.searchsorted(csum, 0.99 * total)) + 1
    occupied_frac = min(1.0, n_bins / len(psd))
    bandwidth_hz = occupied_frac * _SAMPLE_RATE
    return power_dbfs, bandwidth_hz


def _validate_classes(profile: dict) -> None:
    valid = set(taxonomy_open.SOURCE_TO_OPEN_DEFAULT)
    for band in profile["bands"]:
        for cls in band["classes"]:
            if cls not in valid:
                raise ValueError(
                    f"profile '{profile['profile']}' band '{band['name']}': "
                    f"class {cls!r} is not a source class in SOURCE_TO_OPEN_DEFAULT"
                )


def _build_manager(profile: dict, class_idx: dict[str, int]) -> BaselineManager:
    rng = np.random.RandomState(profile["seed"])
    mgr = BaselineManager()
    offset = float(profile.get("rx_power_offset_db", -45))
    diurnal = _diurnal_weights(profile["diurnal"])
    hours = np.arange(24)
    t0 = 1_767_225_600.0  # 2026-01-01T00:00:00Z; fixed base for inter-arrival

    measure_cache: dict[tuple[str, int], tuple[float, float]] = {}

    for band in profile["bands"]:
        classes = list(band["classes"])
        probs = np.asarray([band["classes"][c] for c in classes], dtype=float)
        probs = probs / probs.sum()
        lo, hi = band["detections_per_slot"]
        snr_lo, snr_hi = band["snr_db"]
        for slot in range(band["slots"]):
            freq_hz = band["freq_start_hz"] + slot * band["freq_step_hz"]
            n_det = int(rng.randint(lo, hi + 1))
            for _ in range(n_det):
                source = classes[int(rng.choice(len(classes), p=probs))]
                snr = float(rng.uniform(snr_lo, snr_hi))
                bucket = int(round(snr / 2.0) * 2)
                key = (source, bucket)
                if key not in measure_cache:
                    mseed = profile["seed"] * 100003 + class_idx[source] * 997 + bucket
                    measure_cache[key] = _measure_signal(source, float(bucket), mseed)
                power_dbfs, bw = measure_cache[key]
                power_dbm = power_dbfs + offset
                hour = int(rng.choice(hours, p=diurnal))
                ts = t0 + hour * 3600.0 + float(rng.uniform(0, 3600))
                open_label = taxonomy_open.SOURCE_TO_OPEN_DEFAULT[source]
                mgr.update(
                    freq_hz,
                    open_label,
                    0.9,
                    power_dbm,
                    hour,
                    snr_db=snr,
                    bandwidth_hz=bw,
                    timestamp_epoch=ts,
                )
    return mgr


def _build_whitelist_bytes(profile: dict) -> bytes:
    """Seeded band entries, augmented with the open-16 collapse labels."""
    entries = []
    for raw in _DEFAULT_ENTRIES:
        e = dict(raw)
        expanded = set(e.get("expected_classes", []))
        for src, dst in taxonomy_open.SOURCE_TO_OPEN_DEFAULT.items():
            if src in expanded:
                expanded.add(dst)
        e["expected_classes"] = sorted(expanded)
        e["node_ids"] = None
        entries.append(WhitelistEntry(**e).model_dump())
    return json.dumps({"entries": entries}, indent=2).encode()


def _detection_config_bytes(profile: dict) -> bytes:
    cfg = {
        k: v
        for k, v in profile.get("detection_config", {}).items()
        if k in bundles.PRESET_DETECTION_CONFIG_KEYS
    }
    return json.dumps({"config": cfg}, indent=2).encode()


def generate_profile(name: str, out_dir: Path, timestamp: str) -> Path:
    profile_path = _PROFILE_DIR / f"{name}.json"
    raw = profile_path.read_bytes()
    profile = json.loads(raw)
    _validate_classes(profile)

    class_idx = {
        c: i for i, c in enumerate(sorted(taxonomy_open.SOURCE_TO_OPEN_DEFAULT))
    }
    mgr = _build_manager(profile, class_idx)
    widen = float(profile.get("variance_widening", bundles.PRESET_VARIANCE_WIDENING))
    for bl in mgr.baselines.values():
        bundles.sanitize_rf_baseline(bl, variance_widening=widen)

    component_bytes = {
        "rf_baselines.json": bundles.serialize_rf_manager(mgr),
        "signal_whitelist.json": _build_whitelist_bytes(profile),
        "detection_config.json": _detection_config_bytes(profile),
    }

    generator = bundles.GeneratorInfo(
        tool="training/generate_preset_bundles.py",
        git_sha=_git_sha(),
        sigrift_version=_sigrift_version(),
        seed=profile["seed"],
        profile_config_sha256=hashlib.sha256(raw).hexdigest(),
        numpy_version=np.__version__,
    )
    out = out_dir / f"preset_{name}_v{profile['version']}.sigrift.tar.gz"
    bundles.build_bundle(
        out,
        kind="preset",
        component_bytes=component_bytes,
        profile=name,
        name=f"{name} preset",
        description=profile.get("description", ""),
        generator=generator,
        compatibility=bundles.compat_snapshot(),
        created_at=timestamp,
        mtime=0,
    )
    size = out.stat().st_size
    if size > _MAX_BUNDLE_BYTES:
        out.unlink(missing_ok=True)
        raise ValueError(
            f"{out.name} is {size} bytes > {_MAX_BUNDLE_BYTES} budget — "
            "reduce slots/detections or buffer cap"
        )
    sha = hashlib.sha256(out.read_bytes()).hexdigest()
    out.with_suffix(out.suffix + ".sha256").write_text(f"{sha}  {out.name}\n")
    logger.info(
        "Generated %s: %d bins, %d detections, %d bytes",
        out.name,
        len(mgr.baselines),
        sum(b.total_detections for b in mgr.baselines.values()),
        size,
    )
    return out


def _git_sha() -> str | None:
    import subprocess

    try:
        return (
            subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=_REPO)
            .decode()
            .strip()
        )
    except Exception:
        return None


def _sigrift_version() -> str | None:
    try:
        import sigrift

        return getattr(sigrift, "__version__", None)
    except Exception:
        return None


def _check(name: str, out_dir: Path, timestamp: str) -> bool:
    """Regenerate to a temp dir and compare structural invariants."""
    import tempfile

    committed = out_dir / f"preset_{name}_v1.sigrift.tar.gz"
    if not committed.exists():
        logger.error("No committed bundle for %s", name)
        return False
    with tempfile.TemporaryDirectory() as td:
        fresh = generate_profile(name, Path(td), timestamp)
        rep_c, _, mem_c = bundles.validate_bundle(committed, expect_kind="preset")
        rep_f, _, mem_f = bundles.validate_bundle(fresh, expect_kind="preset")
        if not (rep_c.valid and rep_f.valid):
            logger.error("%s: validation failed", name)
            return False
        bl_c, _ = bundles.load_rf_baselines_from_bytes(mem_c["rf_baselines.json"])
        bl_f, _ = bundles.load_rf_baselines_from_bytes(mem_f["rf_baselines.json"])
        if set(bl_c) != set(bl_f):
            logger.error("%s: bin sets differ", name)
            return False
        for freq in bl_c:
            if bl_c[freq].total_detections != bl_f[freq].total_detections:
                logger.error("%s: total_detections differ at %s", name, freq)
                return False
            if abs(bl_c[freq].power_ewma - bl_f[freq].power_ewma) > 1e-6:
                logger.error("%s: power_ewma drift at %s", name, freq)
                return False
    logger.info("%s: structural invariants match committed bundle", name)
    return True


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--profile", default="all", help="profile name or 'all'")
    p.add_argument("--timestamp", default=_DEFAULT_TIMESTAMP)
    p.add_argument("--out", default=str(_OUT_DIR))
    p.add_argument("--check", action="store_true", help="regenerate + compare only")
    args = p.parse_args(argv)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    names = (
        [f.stem for f in sorted(_PROFILE_DIR.glob("*.json"))]
        if args.profile == "all"
        else [args.profile]
    )
    ok = True
    for name in names:
        if args.check:
            ok = _check(name, out_dir, args.timestamp) and ok
        else:
            generate_profile(name, out_dir, args.timestamp)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
