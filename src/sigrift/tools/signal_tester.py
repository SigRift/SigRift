#!/usr/bin/env python3
"""Signal Test Transmission Tool — generate, TX, inject, RX, and compare.

Full-loop RF testing: generate synthetic signals, transmit via HackRF,
capture via RTL-SDR, inject into SigRift, and compare TX vs RX results.

Usage:
    # === INJECT (software pipeline testing) ===
    python tools/signal_tester.py --class adsb --inject
    python tools/signal_tester.py --family FSK --inject
    python tools/signal_tester.py --band ism_2_4ghz --inject
    python tools/signal_tester.py --all --inject
    python tools/signal_tester.py --representatives --inject
    python tools/signal_tester.py --list

    # === RF TRANSMIT (HackRF) ===
    python tools/signal_tester.py --class pocsag --tx
    python tools/signal_tester.py --class adsb --tx --tx-gain 20 --tx-repeat 3
    python tools/signal_tester.py --family TRUNKED --tx --tx-dwell 2.0

    # === SAVE IQ FILES ===
    python tools/signal_tester.py --class p25 --save-iq /tmp/p25.cf32         # complex64
    python tools/signal_tester.py --class p25 --save-hackrf /tmp/p25.cs8      # int8 (hackrf_transfer)
    python tools/signal_tester.py --family PULSED --save-hackrf-dir /tmp/iq/  # batch export

    # === LOOPBACK TEST (TX via HackRF + RX via RTL-SDR, compare) ===
    python tools/signal_tester.py --class pocsag --loopback
    python tools/signal_tester.py --family PULSED --loopback --loopback-dwell 3.0
    python tools/signal_tester.py --representatives --loopback

    # === OPTIONS ===
    --snr 20                    # SNR in dB
    --samples 8192              # IQ sample count
    --sample-rate 2048000       # Sample rate Hz
    --tx-freq 433.92e6          # Override TX center frequency
    --tx-gain 20                # HackRF TX gain (0-47 dB)
    --tx-repeat 3               # Repeat TX N times
    --tx-dwell 1.0              # Seconds per signal when cycling multiple classes
    --tx-dry-run                # Print hackrf_transfer command without executing
    --rx-gain 30                # RTL-SDR RX gain (for loopback)
    --loopback-dwell 3.0        # Seconds to capture per loopback signal
    --json                      # Output results as JSON

    # === TLS (--inject) ===
    # The bridge certificate is verified. For a self-signed/private-CA bridge
    # set MLRF_CA_CERT=/path/to/ca.pem; MLRF_INSECURE_TLS=1 skips verification.
"""

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

# Add project root to path
_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))

from sigrift.lib.taxonomy import (  # noqa: E402
    CLASSES,
    CLASS_TO_FAMILY,
    FAMILY_TO_CLASSES,
    SUPER_FAMILIES,
    FAMILY_TO_SF,
)
from sigrift.lib.training.signal_factory import generate_signal, list_classes  # noqa: E402
from sigrift.bridge.class_map import normalize_class  # noqa: E402

logger = logging.getLogger("signal_tester")

# ---------------------------------------------------------------------------
# Protocol frequency map
# ---------------------------------------------------------------------------
PROTOCOL_FREQUENCIES: dict[str, int] = {
    "adsb": 1_090_000_000,
    "uat": 978_000_000,
    "tpms": 433_920_000,
    "p25": 155_000_000,
    "dmr": 446_000_000,
    "tetra": 390_000_000,
    "dect": 1_890_000_000,
    "zwave": 908_420_000,
    "wisun": 915_000_000,
    "scada-fsk": 450_000_000,
    "pocsag": 153_350_000,
    "nrf24": 2_426_000_000,
    "ais": 161_975_000,
    "dstar": 145_000_000,
    "gsm": 935_000_000,
    "ofdm-64": 2_437_000_000,
    "ofdm-128": 2_437_000_000,
    "ofdm-256": 2_437_000_000,
    "ofdm-512": 5_180_000_000,
    "ofdm-1024": 5_220_000_000,
    "ofdm-2048": 5_745_000_000,
    "dji-ofdm": 5_785_000_000,
    "nbiot": 900_000_000,
    "halow": 915_000_000,
    "am-dsb": 1_000_000,
    "am-ssb": 7_200_000,
    "fm": 100_000_000,
    "tone": 1_000_000,
    "fpv-analog": 5_800_000_000,
    "analog-video-24": 2_400_000_000,
    "pmr446": 446_006_250,
    "wireless-mic": 600_000_000,
    "lora-css": 868_000_000,
    "elrs": 915_000_000,
    "sigfox": 868_200_000,
    "sidewalk": 915_000_000,
    "oqpsk-dsss": 2_405_000_000,
    "wireless-hart": 2_405_000_000,
    "isa100": 2_405_000_000,
    "bpsk": 1_200_000_000,
    "qpsk": 1_200_000_000,
    "8psk": 1_200_000_000,
    "16psk": 1_200_000_000,
    "32psk": 1_200_000_000,
    "16qam": 2_437_000_000,
    "32qam": 2_437_000_000,
    "64qam": 2_437_000_000,
    "128qam": 2_437_000_000,
    "256qam": 2_437_000_000,
    "16apsk": 12_000_000_000,
    "32apsk": 12_000_000_000,
    "64apsk": 12_000_000_000,
    "128apsk": 12_000_000_000,
    "ook": 433_920_000,
    "4ask": 433_920_000,
    "8ask": 433_920_000,
    "16ask": 433_920_000,
    "4pam": 1_000_000_000,
    "8pam": 1_000_000_000,
    "16pam": 1_000_000_000,
    "2fsk": 433_920_000,
    "4fsk": 433_920_000,
    "2gfsk": 2_441_000_000,
    "4gfsk": 2_441_000_000,
    "2msk": 1_200_000_000,
    "4msk": 1_200_000_000,
    "2gmsk": 900_000_000,
    "4gmsk": 900_000_000,
    "ism433": 433_920_000,
    "uhf-rfid": 915_000_000,
    "gps-jammer": 1_575_420_000,
    "iridium": 1_621_000_000,
    "noise": 1_000_000_000,
    "lora-meshtastic": 906_000_000,
    "lora-meshcore": 906_000_000,
    "lora-lorawan": 868_000_000,
}

BANDS: dict[str, tuple[float, float]] = {
    "hf": (3e6, 30e6),
    "vhf": (30e6, 300e6),
    "uhf": (300e6, 1e9),
    "l_band": (1e9, 2e9),
    "s_band": (2e9, 4e9),
    "c_band": (4e9, 8e9),
    "sub_1ghz": (0, 1e9),
    "ism_433": (433e6, 435e6),
    "ism_868": (863e6, 870e6),
    "ism_915": (902e6, 928e6),
    "ism_2_4ghz": (2.4e9, 2.5e9),
    "ism_5ghz": (5.15e9, 5.85e9),
    "gps_l1": (1.57e9, 1.58e9),
    "satellite": (1.6e9, 1.66e9),
    "dect": (1.88e9, 1.9e9),
    "public_safety": (136e6, 174e6),
}

FAMILY_REPRESENTATIVE: dict[str, str] = {
    "ASK": "ook",
    "PAM": "4pam",
    "PSK": "bpsk",
    "QAM": "16qam",
    "APSK": "16apsk",
    "FSK": "2gfsk",
    "OFDM": "ofdm-256",
    "ANALOG": "fm",
    "SPREAD_SPECTRUM": "lora-css",
    "NOISE": "noise",
    "PULSED": "adsb",
    "802154": "oqpsk-dsss",
    "SATELLITE": "iridium",
    "INTERFERENCE": "gps-jammer",
    "TRUNKED": "p25",
    "NARROWBAND_FM": "pmr446",
}


# ---------------------------------------------------------------------------
# Selection helpers
# ---------------------------------------------------------------------------


def get_classes_for_band(band_name: str) -> list[str]:
    if band_name not in BANDS:
        return []
    lo, hi = BANDS[band_name]
    cs = set(CLASSES)
    return [c for c, f in PROTOCOL_FREQUENCIES.items() if lo <= f <= hi and c in cs]


def get_classes_for_family(family: str) -> list[str]:
    return FAMILY_TO_CLASSES.get(family, [])


def get_classes_for_super_family(sf: str) -> list[str]:
    out: list[str] = []
    for fam, s in FAMILY_TO_SF.items():
        if s == sf:
            out.extend(FAMILY_TO_CLASSES.get(fam, []))
    return out


# ---------------------------------------------------------------------------
# IQ format conversion
# ---------------------------------------------------------------------------


def complex64_to_hackrf_int8(iq: np.ndarray) -> bytes:
    """Convert complex64 IQ → interleaved int8 (HackRF native format).

    HackRF expects signed 8-bit I,Q,I,Q... samples.
    Normalize to [-127, 127] range.
    """
    # Normalize peak to ±1
    peak = np.max(np.abs(iq))
    if peak > 0:
        iq = iq / peak
    # Interleave I/Q as float then scale to int8
    interleaved = np.empty(len(iq) * 2, dtype=np.float32)
    interleaved[0::2] = iq.real
    interleaved[1::2] = iq.imag
    return (interleaved * 127).clip(-127, 127).astype(np.int8).tobytes()


def complex64_to_raw_iq(iq: np.ndarray) -> bytes:
    """Convert complex64 IQ → raw binary (GNU Radio .cf32 / SigMF)."""
    return iq.astype(np.complex64).tobytes()


# ---------------------------------------------------------------------------
# Signal generation
# ---------------------------------------------------------------------------


def generate_test_signal(
    class_name: str,
    snr_db: float = 15.0,
    n_samples: int = 4096,
    sample_rate: float = 2_048_000.0,
    message: str | None = None,
) -> dict:
    """Generate a test signal and return metadata + IQ data."""
    rng = np.random.RandomState(int(time.time() * 1000) % 2**31)
    signal = generate_signal(
        class_name, n_samples=n_samples, sample_rate=sample_rate, snr_db=snr_db, rng=rng
    )
    freq_hz = PROTOCOL_FREQUENCIES.get(class_name, 1_000_000_000)
    family = CLASS_TO_FAMILY.get(class_name, "UNKNOWN")
    power_dbm = float(10 * np.log10(np.mean(np.abs(signal) ** 2) + 1e-30) + 30)
    return {
        "class_name": class_name,
        "canonical": normalize_class(class_name),
        "family": family,
        "freq_hz": freq_hz,
        "snr_db": snr_db,
        "power_dbm": round(power_dbm, 1),
        "n_samples": n_samples,
        "sample_rate": sample_rate,
        "bandwidth_hz": sample_rate * 0.8,
        "message": message,
        "iq_data": signal,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# HackRF TX
# ---------------------------------------------------------------------------


def find_hackrf_transfer() -> str | None:
    """Find hackrf_transfer binary."""
    return shutil.which("hackrf_transfer")


def build_hackrf_cmd(
    iq_file: str,
    freq_hz: int,
    sample_rate: int = 2_048_000,
    tx_gain: int = 20,
    amp_enable: bool = False,
) -> list[str]:
    """Build hackrf_transfer TX command."""
    cmd = [
        "hackrf_transfer",
        "-t",
        iq_file,
        "-f",
        str(int(freq_hz)),
        "-s",
        str(int(sample_rate)),
        "-x",
        str(tx_gain),
    ]
    if amp_enable:
        cmd.extend(["-a", "1"])
    return cmd


def transmit_hackrf(
    iq: np.ndarray,
    freq_hz: int,
    sample_rate: int = 2_048_000,
    tx_gain: int = 20,
    repeat: int = 1,
    dry_run: bool = False,
) -> dict:
    """Transmit IQ data via HackRF.

    Returns dict with status, command, duration.
    """
    hackrf = find_hackrf_transfer()
    if not hackrf and not dry_run:
        return {"status": "error", "error": "hackrf_transfer not found in PATH"}

    # Write int8 IQ to temp file
    iq_bytes = complex64_to_hackrf_int8(iq)
    # Repeat the signal in the file for longer TX
    if repeat > 1:
        iq_bytes = iq_bytes * repeat

    with tempfile.NamedTemporaryFile(suffix=".cs8", delete=False) as f:
        f.write(iq_bytes)
        iq_file = f.name

    try:
        cmd = build_hackrf_cmd(iq_file, freq_hz, sample_rate, tx_gain)
        cmd_str = " ".join(cmd)

        if dry_run:
            return {
                "status": "dry_run",
                "command": cmd_str,
                "iq_file": iq_file,
                "iq_bytes": len(iq_bytes),
                "duration_s": len(iq_bytes) / 2 / sample_rate,
            }

        logger.info("TX: %s", cmd_str)
        t0 = time.monotonic()
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        elapsed = time.monotonic() - t0

        if proc.returncode != 0:
            return {
                "status": "error",
                "command": cmd_str,
                "error": proc.stderr.strip(),
                "returncode": proc.returncode,
            }

        return {
            "status": "transmitted",
            "command": cmd_str,
            "duration_s": round(elapsed, 2),
            "iq_bytes": len(iq_bytes),
            "samples": len(iq_bytes) // 2,
        }
    finally:
        try:
            os.unlink(iq_file)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# RTL-SDR RX capture (for loopback testing)
# ---------------------------------------------------------------------------


def capture_rtlsdr(
    freq_hz: int,
    sample_rate: int = 2_048_000,
    duration_s: float = 2.0,
    gain: int = 30,
) -> np.ndarray | None:
    """Capture IQ samples from RTL-SDR.

    Returns complex64 array or None on failure.
    """
    rtl_sdr = shutil.which("rtl_sdr")
    if not rtl_sdr:
        logger.error("rtl_sdr not found in PATH")
        return None

    n_bytes = int(
        sample_rate * duration_s * 2
    )  # 2 bytes per sample (uint8 I + uint8 Q)

    with tempfile.NamedTemporaryFile(suffix=".raw", delete=False) as f:
        rx_file = f.name

    try:
        cmd = [
            rtl_sdr,
            "-f",
            str(int(freq_hz)),
            "-s",
            str(int(sample_rate)),
            "-g",
            str(gain),
            "-n",
            str(n_bytes // 2),
            rx_file,
        ]
        logger.info("RX: %s", " ".join(cmd))
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=duration_s + 10
        )

        if not os.path.exists(rx_file) or os.path.getsize(rx_file) == 0:
            logger.error("RTL-SDR capture failed: %s", proc.stderr.strip())
            return None

        # RTL-SDR outputs unsigned 8-bit I/Q
        raw = np.fromfile(rx_file, dtype=np.uint8)
        iq = (raw[0::2].astype(np.float32) - 127.5) + 1j * (
            raw[1::2].astype(np.float32) - 127.5
        )
        return (iq / 127.5).astype(np.complex64)
    finally:
        try:
            os.unlink(rx_file)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Loopback comparison
# ---------------------------------------------------------------------------


def compare_tx_rx(tx_iq: np.ndarray, rx_iq: np.ndarray) -> dict:
    """Compare TX and RX IQ signals.

    Returns correlation metrics for verifying signal integrity.
    """
    # Normalize both
    tx_norm = tx_iq / (np.max(np.abs(tx_iq)) + 1e-10)
    rx_norm = rx_iq / (np.max(np.abs(rx_iq)) + 1e-10)

    # Cross-correlation peak
    min_len = min(len(tx_norm), len(rx_norm))
    tx_trim = tx_norm[:min_len]
    rx_trim = rx_norm[:min_len]

    xcorr = np.abs(np.correlate(tx_trim, rx_trim, mode="valid"))
    peak_corr = float(np.max(xcorr)) / min_len if min_len > 0 else 0.0

    # Power comparison
    tx_power = float(10 * np.log10(np.mean(np.abs(tx_trim) ** 2) + 1e-30))
    rx_power = float(10 * np.log10(np.mean(np.abs(rx_trim) ** 2) + 1e-30))

    # Spectral similarity (magnitude spectrum correlation)
    tx_fft = np.abs(np.fft.fft(tx_trim))
    rx_fft = np.abs(np.fft.fft(rx_trim))
    if np.std(tx_fft) > 0 and np.std(rx_fft) > 0:
        spectral_corr = float(np.corrcoef(tx_fft, rx_fft)[0, 1])
    else:
        spectral_corr = 0.0

    return {
        "peak_correlation": round(peak_corr, 4),
        "spectral_correlation": round(spectral_corr, 4),
        "tx_power_db": round(tx_power, 1),
        "rx_power_db": round(rx_power, 1),
        "power_delta_db": round(rx_power - tx_power, 1),
        "tx_samples": len(tx_iq),
        "rx_samples": len(rx_iq),
        "match_quality": (
            "excellent"
            if spectral_corr > 0.9
            else "good"
            if spectral_corr > 0.7
            else "fair"
            if spectral_corr > 0.5
            else "poor"
        ),
    }


def run_loopback_test(
    result: dict,
    tx_gain: int = 20,
    rx_gain: int = 30,
    dwell_s: float = 3.0,
    repeat: int = 3,
    dry_run: bool = False,
) -> dict:
    """Run TX → RX loopback test for a single signal.

    1. TX signal via HackRF
    2. RX via RTL-SDR simultaneously (or sequentially)
    3. Compare TX vs RX
    """
    iq = result["iq_data"]
    freq_hz = result["freq_hz"]
    sample_rate = int(result["sample_rate"])
    cls = result["class_name"]

    # Step 1: TX
    tx_result = transmit_hackrf(
        iq, freq_hz, sample_rate, tx_gain, repeat=repeat, dry_run=dry_run
    )
    if dry_run:
        return {"class": cls, "tx": tx_result, "rx": None, "comparison": None}

    if tx_result["status"] != "transmitted":
        return {"class": cls, "tx": tx_result, "rx": None, "comparison": None}

    # Step 2: Brief pause then RX
    time.sleep(0.2)
    rx_iq = capture_rtlsdr(freq_hz, sample_rate, duration_s=dwell_s, gain=rx_gain)
    if rx_iq is None:
        return {
            "class": cls,
            "tx": tx_result,
            "rx": {"status": "failed"},
            "comparison": None,
        }

    rx_result = {
        "status": "captured",
        "samples": len(rx_iq),
        "power_db": round(float(10 * np.log10(np.mean(np.abs(rx_iq) ** 2) + 1e-30)), 1),
    }

    # Step 3: Compare
    comparison = compare_tx_rx(iq, rx_iq)

    return {
        "class": cls,
        "family": result["family"],
        "freq_mhz": freq_hz / 1e6,
        "tx": tx_result,
        "rx": rx_result,
        "comparison": comparison,
    }


# ---------------------------------------------------------------------------
# Bridge injection
# ---------------------------------------------------------------------------


def _bridge_ssl_context():
    """TLS context for bridge injection.

    Verifies the bridge certificate by default: against MLRF_CA_CERT /
    MLRF_CA_BUNDLE when set (e.g. a self-signed dev bridge), otherwise the
    system trust store. Verification is skipped only when
    MLRF_INSECURE_TLS=1 is set explicitly, with a loud warning -- the API
    key is sent on this connection.
    """
    import ssl

    for var in ("MLRF_CA_CERT", "MLRF_CA_BUNDLE"):
        ca_bundle = os.environ.get(var, "").strip()
        if not ca_bundle:
            continue
        if Path(ca_bundle).is_file():
            return ssl.create_default_context(cafile=ca_bundle)
        logger.error(
            "%s=%s does not exist, falling back to the system trust store",
            var,
            ca_bundle,
        )

    ctx = ssl.create_default_context()
    if os.environ.get("MLRF_INSECURE_TLS", "").strip() == "1":
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        logger.warning(
            "TLS verification DISABLED via MLRF_INSECURE_TLS=1 -- the bridge is "
            "NOT authenticated and the API key can be intercepted"
        )
    return ctx


def inject_to_bridge(
    results: list[dict],
    bridge_url: str,
    api_key: str,
    node_id: str = "test-transmitter",
) -> dict:
    import urllib.request

    ctx = _bridge_ssl_context()

    now = datetime.now(timezone.utc).isoformat()
    detections = [
        {
            "node_id": node_id,
            "freq_hz": r["freq_hz"],
            "signal_class": r["class_name"],
            "confidence": 0.95,
            "power_dbm": r["power_dbm"],
            "snr_db": r["snr_db"],
            "bandwidth_hz": r["bandwidth_hz"],
            "timestamp": r["timestamp"],
        }
        for r in results
    ]

    payload = json.dumps(
        {
            "node_id": node_id,
            "period_start": now,
            "period_end": now,
            "detections": detections,
        }
    ).encode()

    req = urllib.request.Request(
        f"{bridge_url}/api/detections/batch",
        data=payload,
        headers={"Content-Type": "application/json", "X-API-Key": api_key},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            return {
                "status": "ok",
                "response": json.loads(resp.read()),
                "count": len(detections),
            }
    except Exception as e:
        return {"status": "error", "error": str(e), "count": len(detections)}


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------


def format_result_table(results: list[dict]) -> str:
    lines = [
        f"{'Class':<20} {'Family':<16} {'Freq':>12} {'SNR':>6} {'Power':>8} {'Samples':>8}",
        "-" * 74,
    ]
    for r in results:
        lines.append(
            f"{r['class_name']:<20} {r['family']:<16} {r['freq_hz'] / 1e6:>10.1f} MHz "
            f"{r['snr_db']:>5.0f}  {r['power_dbm']:>7.1f}  {r['n_samples']:>7d}"
        )
    lines.append(f"\nTotal: {len(results)} signals generated")
    return "\n".join(lines)


def format_loopback_table(loopback_results: list[dict]) -> str:
    lines = [
        f"{'Class':<18} {'Freq':>10} {'TX':>10} {'RX Power':>10} {'Δ Power':>8} "
        f"{'Spectral':>9} {'Quality':<10}",
        "-" * 80,
    ]
    for r in loopback_results:
        c = r.get("comparison") or {}
        tx = r.get("tx", {})
        lines.append(
            f"{r['class']:<18} {r.get('freq_mhz', 0):>8.1f}MHz "
            f"{tx.get('status', '?'):>10} "
            f"{c.get('rx_power_db', 0):>8.1f}dB "
            f"{c.get('power_delta_db', 0):>7.1f}dB "
            f"{c.get('spectral_correlation', 0):>8.3f} "
            f"{c.get('match_quality', '?'):<10}"
        )
    lines.append(f"\nTotal: {len(loopback_results)} loopback tests")
    return "\n".join(lines)


def list_available():
    print("=== FAMILIES (16) ===")
    for fam in sorted(FAMILY_TO_CLASSES.keys()):
        classes = FAMILY_TO_CLASSES[fam]
        rep = FAMILY_REPRESENTATIVE.get(fam, classes[0] if classes else "?")
        print(f"  {fam:<20} ({len(classes):2d} classes)  rep: {rep}")
    print(f"\n=== SUPER-FAMILIES ({len(SUPER_FAMILIES)}) ===")
    for sf in sorted(SUPER_FAMILIES):
        families = [f for f, s in FAMILY_TO_SF.items() if s == sf]
        print(f"  {sf:<24} families: {', '.join(families)}")
    print(f"\n=== BANDS ({len(BANDS)}) ===")
    for band, (lo, hi) in sorted(BANDS.items(), key=lambda x: x[1][0]):
        classes = get_classes_for_band(band)
        print(
            f"  {band:<16} {lo / 1e6:>8.1f} - {hi / 1e6:>8.1f} MHz  ({len(classes)} classes)"
        )
    print(f"\n=== ALL CLASSES ({len(CLASSES)}) ===")
    for cls in sorted(CLASSES):
        fam = CLASS_TO_FAMILY.get(cls, "?")
        freq = PROTOCOL_FREQUENCIES.get(cls, 0)
        print(f"  {cls:<20} {fam:<16} {freq / 1e6:>10.1f} MHz")


# ---------------------------------------------------------------------------
# API key resolution
# ---------------------------------------------------------------------------


def resolve_api_key(explicit: str) -> str:
    api_key = explicit or os.environ.get("BRIDGE_API_KEY", "")
    if not api_key:
        key_file = (
            Path(__file__).resolve().parent.parent
            / "bridge"
            / "data"
            / "master_key.txt"
        )
        if key_file.exists():
            api_key = key_file.read_text().strip()
    return api_key


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Signal Test Transmission Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Selection
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument("--class", dest="signal_class", help="Single signal class")
    grp.add_argument("--family", help="All classes in a family")
    grp.add_argument("--super-family", dest="super_family", help="All in super-family")
    grp.add_argument("--band", help="All classes in a band")
    grp.add_argument("--all", action="store_true", help="ALL 76 classes")
    grp.add_argument("--representatives", action="store_true", help="One per family")
    grp.add_argument("--list", action="store_true", help="List available")

    # Generation
    parser.add_argument("--snr", type=float, default=15.0, help="SNR dB (default: 15)")
    parser.add_argument("--samples", type=int, default=4096, help="Sample count")
    parser.add_argument(
        "--sample-rate", type=float, default=2_048_000, help="Sample rate Hz"
    )
    parser.add_argument("--message", help="Message content (protocol-aware)")

    # Inject
    parser.add_argument("--inject", action="store_true", help="Inject into SigRift")
    parser.add_argument("--bridge-url", default="https://localhost:8444")
    parser.add_argument("--api-key", default="")
    parser.add_argument("--node-id", default="test-transmitter")

    # TX
    parser.add_argument("--tx", action="store_true", help="Transmit via HackRF")
    parser.add_argument("--tx-freq", type=float, help="Override TX frequency Hz")
    parser.add_argument(
        "--tx-gain", type=int, default=20, help="HackRF TX gain 0-47 (default: 20)"
    )
    parser.add_argument(
        "--tx-repeat", type=int, default=1, help="Repeat signal N times"
    )
    parser.add_argument(
        "--tx-dwell", type=float, default=1.0, help="Seconds per signal when cycling"
    )
    parser.add_argument(
        "--tx-dry-run", action="store_true", help="Print command without TX"
    )

    # Save
    parser.add_argument("--save-iq", help="Save complex64 IQ (.cf32)")
    parser.add_argument("--save-hackrf", help="Save HackRF int8 IQ (.cs8)")
    parser.add_argument(
        "--save-hackrf-dir", help="Save all classes as .cs8 in directory"
    )

    # Loopback
    parser.add_argument("--loopback", action="store_true", help="TX + RX loopback test")
    parser.add_argument(
        "--rx-gain", type=int, default=30, help="RTL-SDR RX gain (default: 30)"
    )
    parser.add_argument(
        "--loopback-dwell", type=float, default=3.0, help="RX capture seconds"
    )

    # Output
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-q", "--quiet", action="store_true")

    args = parser.parse_args()

    level = (
        logging.DEBUG
        if args.verbose
        else (logging.WARNING if args.quiet else logging.INFO)
    )
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
        stream=sys.stderr,
    )

    if args.list:
        list_available()
        return 0

    # Resolve classes
    classes: list[str] = []
    if args.signal_class:
        if args.signal_class not in set(CLASSES) and args.signal_class not in set(
            list_classes()
        ):
            logger.error("Unknown class: %s", args.signal_class)
            return 2
        classes = [args.signal_class]
    elif args.family:
        classes = get_classes_for_family(args.family.upper())
    elif args.super_family:
        classes = get_classes_for_super_family(args.super_family.upper())
    elif args.band:
        classes = get_classes_for_band(args.band.lower())
    elif args.representatives:
        classes = list(FAMILY_REPRESENTATIVE.values())
    elif args.all:
        classes = list(CLASSES)
    else:
        parser.print_help()
        return 2

    if not classes:
        logger.error("No classes matched")
        return 2

    # Generate
    results = []
    for cls in sorted(classes):
        try:
            r = generate_test_signal(
                cls,
                snr_db=args.snr,
                n_samples=args.samples,
                sample_rate=args.sample_rate,
                message=args.message,
            )
            if args.tx_freq:
                r["freq_hz"] = int(args.tx_freq)
            results.append(r)
            logger.info(
                "Generated %s (%s) @ %.1f MHz", cls, r["family"], r["freq_hz"] / 1e6
            )
        except Exception as e:
            logger.error("Failed to generate %s: %s", cls, e)

    if not results:
        logger.error("No signals generated")
        return 1

    # Display
    if args.json and not args.loopback:
        print(
            json.dumps(
                [{k: v for k, v in r.items() if k != "iq_data"} for r in results],
                indent=2,
            )
        )
    elif not args.loopback:
        print(format_result_table(results))

    # Save IQ
    if args.save_iq and len(results) == 1:
        data = complex64_to_raw_iq(results[0]["iq_data"])
        Path(args.save_iq).write_bytes(data)
        logger.info("Saved %d bytes to %s (complex64)", len(data), args.save_iq)

    if args.save_hackrf and len(results) == 1:
        data = complex64_to_hackrf_int8(results[0]["iq_data"])
        Path(args.save_hackrf).write_bytes(data)
        logger.info("Saved %d bytes to %s (int8 hackrf)", len(data), args.save_hackrf)
        print(
            f"\nReplay: hackrf_transfer -t {args.save_hackrf} "
            f"-f {results[0]['freq_hz']} -s {int(args.sample_rate)} -x {args.tx_gain}"
        )

    if args.save_hackrf_dir:
        out_dir = Path(args.save_hackrf_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        for r in results:
            fname = out_dir / f"{r['class_name']}_{int(r['freq_hz'] / 1e6)}mhz.cs8"
            fname.write_bytes(complex64_to_hackrf_int8(r["iq_data"]))
        logger.info("Saved %d .cs8 files to %s", len(results), out_dir)
        print(
            f"\nReplay any: hackrf_transfer -t <file.cs8> -f <freq> -s {int(args.sample_rate)}"
        )

    # TX via HackRF
    if args.tx:
        for i, r in enumerate(results):
            logger.info(
                "TX [%d/%d] %s @ %.1f MHz",
                i + 1,
                len(results),
                r["class_name"],
                r["freq_hz"] / 1e6,
            )
            tx_res = transmit_hackrf(
                r["iq_data"],
                r["freq_hz"],
                int(r["sample_rate"]),
                args.tx_gain,
                repeat=args.tx_repeat,
                dry_run=args.tx_dry_run,
            )
            r["tx_result"] = tx_res
            if tx_res["status"] == "dry_run":
                print(f"  [DRY RUN] {tx_res['command']}")
            elif tx_res["status"] == "transmitted":
                logger.info(
                    "  TX OK: %.2fs, %d bytes", tx_res["duration_s"], tx_res["iq_bytes"]
                )
            else:
                logger.error("  TX FAIL: %s", tx_res.get("error"))
            if i < len(results) - 1:
                time.sleep(args.tx_dwell)

    # Loopback test
    if args.loopback:
        loopback_results = []
        for i, r in enumerate(results):
            logger.info(
                "Loopback [%d/%d] %s @ %.1f MHz",
                i + 1,
                len(results),
                r["class_name"],
                r["freq_hz"] / 1e6,
            )
            lb = run_loopback_test(
                r,
                tx_gain=args.tx_gain,
                rx_gain=args.rx_gain,
                dwell_s=args.loopback_dwell,
                repeat=args.tx_repeat,
                dry_run=args.tx_dry_run,
            )
            loopback_results.append(lb)
            if i < len(results) - 1:
                time.sleep(args.tx_dwell)

        if args.json:
            print(json.dumps(loopback_results, indent=2, default=str))
        else:
            print(format_loopback_table(loopback_results))

    # Inject into SigRift
    if args.inject:
        api_key = resolve_api_key(args.api_key)
        if not api_key:
            logger.error("No API key. Use --api-key or BRIDGE_API_KEY env var")
            return 1
        logger.info("Injecting %d signals into %s ...", len(results), args.bridge_url)
        resp = inject_to_bridge(results, args.bridge_url, api_key, args.node_id)
        if resp["status"] == "ok":
            logger.info("Injected %d detections: %s", resp["count"], resp["response"])
        else:
            logger.error("Injection failed: %s", resp["error"])
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
