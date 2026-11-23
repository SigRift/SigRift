#!/usr/bin/env python3
"""Edge spectrum sweep module for SigRift.

Performs wideband spectrum sweeps using RTL-SDR (``rtl_power``) or HackRF
(``hackrf_sweep``), collects power spectral density (PSD) data across
configurable frequency bands, detects peaks above the noise floor, and
POSTs spectrum snapshot batches to the Bridge controller's
``/api/spectrum/snapshots`` endpoint.

Requires:
  - Linux with rtl-sdr or hackrf tools installed
  - RTL-SDR dongle or HackRF One
  - Python 3.10+

Usage:
    # Standalone
    python3 -m sigrift.bridge.spectrum_sweeper \
        --server-url https://bridge:8444 \
        --api-key KEY --node-id node-01

    # Integrated with detection_reporter
    sweeper = SpectrumSweeper(server_url, api_key, node_id)
    sweeper.start()   # launches background sweep thread
    sweeper.stop()

Environment variables:
    MLRF_BRIDGE_URL, MLRF_API_KEY, MLRF_NODE_ID,
    MLRF_SWEEP_ENABLED (default: 0, set to 1 to enable),
    MLRF_SWEEP_INTERVAL (default: 60 seconds),
    MLRF_SWEEP_FREQ_START (default: 70e6 Hz),
    MLRF_SWEEP_FREQ_END (default: 6e9 Hz),
    MLRF_SWEEP_BIN_SIZE (default: 100000 Hz),
    MLRF_SWEEP_BACKEND (default: auto — tries rtl_power then hackrf_sweep)
"""

from __future__ import annotations

import argparse
import csv
import gzip
import io
import json
import logging
import math
import os
import signal
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_SWEEP_INTERVAL = 60  # seconds between sweeps
_DEFAULT_FREQ_START = 70e6  # 70 MHz
_DEFAULT_FREQ_END = 6e9  # 6 GHz
_DEFAULT_BIN_SIZE = 100_000  # 100 kHz per FFT bin
_UPLOAD_TIMEOUT = 30  # seconds
_MAX_PSD_BINS = 200_000  # safety limit on total bins per snapshot
_RTL_POWER_MAX_FREQ = 1.766e9  # rtl_power caps at ~1.766 GHz

# rtl_power splits wide sweeps into sub-ranges internally; each sub-range
# produces a CSV block with center_freq and per-bin power values.  We stitch
# them into contiguous PSD arrays and POST each sub-sweep as one snapshot.

# hackrf_sweep outputs binary frames (little-endian) when using -r flag,
# or CSV-like text on stdout.  We prefer the text output for simplicity.


class SweepBackend:
    """Enumeration of supported SDR sweep backends."""

    RTL_POWER = "rtl_power"
    HACKRF_SWEEP = "hackrf_sweep"
    AUTO = "auto"


# ---------------------------------------------------------------------------
# PSD parsing helpers
# ---------------------------------------------------------------------------


def _estimate_noise_floor(psd: list[float]) -> float:
    """Estimate noise floor as the median of PSD values."""
    if not psd:
        return -120.0
    values = sorted(psd)
    mid = len(values) // 2
    if len(values) % 2 == 0:
        return (values[mid - 1] + values[mid]) / 2
    return values[mid]


def _detect_peaks(
    psd: list[float],
    start_freq_hz: float,
    bin_width_hz: float,
    threshold_db: float = 10.0,
) -> list[dict[str, Any]]:
    """Detect peaks that exceed the noise floor by threshold_db.

    Returns a list of dicts with keys: freq_hz, power_dbm, snr_db.
    """
    noise_floor = _estimate_noise_floor(psd)
    peaks: list[dict[str, Any]] = []
    for i, power in enumerate(psd):
        if power - noise_floor >= threshold_db:
            peaks.append(
                {
                    "freq_hz": start_freq_hz + i * bin_width_hz,
                    "power_dbm": round(power, 2),
                    "snr_db": round(power - noise_floor, 2),
                }
            )
    return peaks


# ---------------------------------------------------------------------------
# rtl_power output parser
# ---------------------------------------------------------------------------


def _parse_rtl_power_csv(output: str) -> list[dict[str, Any]]:
    """Parse rtl_power CSV output into a list of snapshot dicts.

    rtl_power CSV format (one line per frequency step):
        date, time, hz_low, hz_high, hz_step, num_samples, dB, dB, dB, ...

    We group lines with the same timestamp into a single sweep and stitch
    adjacent frequency blocks into contiguous PSD arrays.  Each resulting
    dict contains: center_freq_hz, bandwidth_hz, fft_size, psd_dbm.
    """
    if not output.strip():
        return []

    # Parse all rows grouped by timestamp
    sweeps: dict[str, list[tuple[float, float, float, list[float]]]] = {}
    reader = csv.reader(io.StringIO(output))
    for row in reader:
        if len(row) < 7:
            continue
        try:
            ts_key = f"{row[0].strip()} {row[1].strip()}"
            hz_low = float(row[2].strip())
            hz_high = float(row[3].strip())
            hz_step = float(row[4].strip())
            # Columns 6+ are dB power values
            db_values = []
            for val_str in row[6:]:
                val_str = val_str.strip()
                if val_str:
                    try:
                        db_values.append(float(val_str))
                    except ValueError:
                        continue

            if db_values and hz_step > 0:
                sweeps.setdefault(ts_key, []).append(
                    (hz_low, hz_high, hz_step, db_values)
                )
        except (ValueError, IndexError):
            continue

    if not sweeps:
        return []

    # Take the most recent sweep (last timestamp)
    ts_key = list(sweeps.keys())[-1]
    blocks = sweeps[ts_key]

    # Sort blocks by start frequency
    blocks.sort(key=lambda b: b[0])

    # Stitch into contiguous PSD
    all_psd: list[float] = []
    freq_start = blocks[0][0]
    bin_width = blocks[0][2]
    for hz_low, hz_high, hz_step, db_values in blocks:
        all_psd.extend(db_values)
        # Use the finest bin width
        if hz_step < bin_width:
            bin_width = hz_step

    freq_end = blocks[-1][1]
    bandwidth = freq_end - freq_start
    center_freq = freq_start + bandwidth / 2

    if len(all_psd) > _MAX_PSD_BINS:
        # Downsample by averaging adjacent bins
        factor = math.ceil(len(all_psd) / _MAX_PSD_BINS)
        downsampled = []
        for i in range(0, len(all_psd), factor):
            chunk = all_psd[i : i + factor]
            downsampled.append(sum(chunk) / len(chunk))
        all_psd = downsampled
        bin_width *= factor

    return [
        {
            "center_freq_hz": center_freq,
            "bandwidth_hz": bandwidth,
            "fft_size": len(all_psd),
            "bin_width_hz": bin_width,
            "psd_dbm": [round(v, 2) for v in all_psd],
            "freq_start_hz": freq_start,
            "freq_end_hz": freq_end,
        }
    ]


# ---------------------------------------------------------------------------
# hackrf_sweep output parser
# ---------------------------------------------------------------------------


def _parse_hackrf_sweep_output(output: str) -> list[dict[str, Any]]:
    """Parse hackrf_sweep text output into snapshot dicts.

    hackrf_sweep text output format (one line per frequency step):
        timestamp, hz_low, hz_high, hz_bin_width, num_samples, dB, dB, ...

    Similar to rtl_power but with slightly different column layout.
    """
    if not output.strip():
        return []

    # Parse all rows, group by first timestamp seen
    blocks: list[tuple[float, float, float, list[float]]] = []
    first_ts = None
    for line in output.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        if len(parts) < 6:
            continue
        try:
            ts_str = parts[0].strip()
            if first_ts is None:
                first_ts = ts_str

            # Only take the first complete sweep
            if ts_str != first_ts and blocks:
                break

            hz_low = float(parts[1].strip())
            hz_high = float(parts[2].strip())
            hz_bin_width = float(parts[3].strip())

            db_values = []
            for val_str in parts[5:]:
                val_str = val_str.strip()
                if val_str:
                    try:
                        db_values.append(float(val_str))
                    except ValueError:
                        continue

            if db_values and hz_bin_width > 0:
                blocks.append((hz_low, hz_high, hz_bin_width, db_values))
        except (ValueError, IndexError):
            continue

    if not blocks:
        return []

    # Sort by start frequency and stitch
    blocks.sort(key=lambda b: b[0])

    all_psd: list[float] = []
    freq_start = blocks[0][0]
    bin_width = blocks[0][2]
    for hz_low, hz_high, hz_bin_width, db_values in blocks:
        all_psd.extend(db_values)
        if hz_bin_width < bin_width:
            bin_width = hz_bin_width

    freq_end = blocks[-1][1]
    bandwidth = freq_end - freq_start
    center_freq = freq_start + bandwidth / 2

    if len(all_psd) > _MAX_PSD_BINS:
        factor = math.ceil(len(all_psd) / _MAX_PSD_BINS)
        downsampled = []
        for i in range(0, len(all_psd), factor):
            chunk = all_psd[i : i + factor]
            downsampled.append(sum(chunk) / len(chunk))
        all_psd = downsampled
        bin_width *= factor

    return [
        {
            "center_freq_hz": center_freq,
            "bandwidth_hz": bandwidth,
            "fft_size": len(all_psd),
            "bin_width_hz": bin_width,
            "psd_dbm": [round(v, 2) for v in all_psd],
            "freq_start_hz": freq_start,
            "freq_end_hz": freq_end,
        }
    ]


# ---------------------------------------------------------------------------
# SpectrumSweeper
# ---------------------------------------------------------------------------


class SpectrumSweeper:
    """Edge spectrum sweeper that performs wideband PSD sweeps and reports
    snapshots to the SigRift controller.

    Supports RTL-SDR (via ``rtl_power``) and HackRF (via ``hackrf_sweep``)
    backends.  When backend is set to ``auto``, the sweeper probes for
    available tools at startup.
    """

    def __init__(
        self,
        server_url: str,
        api_key: str,
        node_id: str,
        *,
        freq_start_hz: float = _DEFAULT_FREQ_START,
        freq_end_hz: float = _DEFAULT_FREQ_END,
        bin_size_hz: float = _DEFAULT_BIN_SIZE,
        sweep_interval: int = _DEFAULT_SWEEP_INTERVAL,
        backend: str = SweepBackend.AUTO,
        ca_bundle: str | None = None,
        peak_threshold_db: float = 10.0,
    ) -> None:
        self.server_url = server_url.rstrip("/")
        self.api_key = api_key
        self.node_id = node_id
        self.freq_start_hz = freq_start_hz
        self.freq_end_hz = freq_end_hz
        self.bin_size_hz = bin_size_hz
        self.sweep_interval = sweep_interval
        self.peak_threshold_db = peak_threshold_db

        self._backend = self._resolve_backend(backend)
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

        # Stats
        self._sweep_count = 0
        self._upload_count = 0
        self._error_count = 0
        self._total_peaks_detected = 0
        self._last_sweep_duration: float = 0.0

        # SSL context
        self._ssl_ctx = ssl.create_default_context()
        if ca_bundle:
            self._ssl_ctx.load_verify_locations(ca_bundle)

    # -- Backend resolution ------------------------------------------------

    @staticmethod
    def _resolve_backend(backend: str) -> str:
        """Resolve 'auto' backend to a concrete tool, or validate the given one."""
        if backend == SweepBackend.AUTO:
            # Prefer hackrf_sweep (wider frequency range)
            for tool in (SweepBackend.HACKRF_SWEEP, SweepBackend.RTL_POWER):
                if _check_tool(tool):
                    logger.info("Auto-detected sweep backend: %s", tool)
                    return tool
            logger.warning(
                "No sweep backend found (tried hackrf_sweep, rtl_power). "
                "Sweeps will fail until a tool is installed."
            )
            return SweepBackend.RTL_POWER  # default, will error on first sweep
        if backend not in (SweepBackend.RTL_POWER, SweepBackend.HACKRF_SWEEP):
            raise ValueError(f"Unknown sweep backend: {backend!r}")
        return backend

    # -- Lifecycle ---------------------------------------------------------

    def start(self) -> None:
        """Start the background sweep thread."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._sweep_loop,
            daemon=True,
            name="spectrum-sweeper",
        )
        self._thread.start()
        logger.info(
            "Spectrum sweeper started (backend=%s, range=%.1f-%.1f MHz, "
            "bin=%.0f kHz, interval=%ds)",
            self._backend,
            self.freq_start_hz / 1e6,
            self.freq_end_hz / 1e6,
            self.bin_size_hz / 1e3,
            self.sweep_interval,
        )

    def stop(self) -> None:
        """Stop the background sweep thread."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=30)
            self._thread = None
        logger.info(
            "Spectrum sweeper stopped: %d sweeps, %d uploads, %d errors, "
            "%d peaks detected",
            self._sweep_count,
            self._upload_count,
            self._error_count,
            self._total_peaks_detected,
        )

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def stats(self) -> dict[str, Any]:
        """Return current sweeper statistics."""
        return {
            "running": self.is_running,
            "backend": self._backend,
            "freq_start_hz": self.freq_start_hz,
            "freq_end_hz": self.freq_end_hz,
            "bin_size_hz": self.bin_size_hz,
            "sweep_interval": self.sweep_interval,
            "sweep_count": self._sweep_count,
            "upload_count": self._upload_count,
            "error_count": self._error_count,
            "total_peaks_detected": self._total_peaks_detected,
            "last_sweep_duration_s": round(self._last_sweep_duration, 2),
        }

    # -- Sweep loop --------------------------------------------------------

    def _sweep_loop(self) -> None:
        """Main sweep loop — runs until stop event is set."""
        while not self._stop_event.is_set():
            try:
                t0 = time.monotonic()
                snapshots = self._sweep()
                self._last_sweep_duration = time.monotonic() - t0
                self._sweep_count += 1

                if snapshots:
                    for snapshot in snapshots:
                        # Detect peaks for logging
                        peaks = _detect_peaks(
                            snapshot["psd_dbm"],
                            snapshot["center_freq_hz"] - snapshot["bandwidth_hz"] / 2,
                            snapshot.get("bin_width_hz", self.bin_size_hz),
                            self.peak_threshold_db,
                        )
                        self._total_peaks_detected += len(peaks)
                        if peaks:
                            logger.info(
                                "Sweep found %d peaks above noise+%.0f dB "
                                "(range %.1f-%.1f MHz)",
                                len(peaks),
                                self.peak_threshold_db,
                                snapshot.get("freq_start_hz", 0) / 1e6,
                                snapshot.get("freq_end_hz", 0) / 1e6,
                            )

                        self._upload(snapshot)
                        self._upload_count += 1

                    logger.info(
                        "Sweep complete: %d snapshot(s), %.1fs elapsed",
                        len(snapshots),
                        self._last_sweep_duration,
                    )
                else:
                    logger.warning("Sweep produced no data")

            except Exception as exc:
                self._error_count += 1
                logger.warning("Spectrum sweep error: %s", exc, exc_info=True)

            self._stop_event.wait(timeout=self.sweep_interval)

    # -- Sweep execution ---------------------------------------------------

    def _sweep(self) -> list[dict[str, Any]]:
        """Execute a spectrum sweep using the configured backend.

        Returns a list of snapshot dicts ready for upload.
        """
        if self._backend == SweepBackend.RTL_POWER:
            return self._sweep_rtl_power()
        elif self._backend == SweepBackend.HACKRF_SWEEP:
            return self._sweep_hackrf()
        else:
            raise RuntimeError(f"Unknown backend: {self._backend}")

    def _sweep_rtl_power(self) -> list[dict[str, Any]]:
        """Run rtl_power and parse its CSV output.

        rtl_power supports frequencies up to ~1.766 GHz.  If the configured
        range exceeds this, we clamp to the rtl_power maximum and log a
        warning.
        """
        freq_end = min(self.freq_end_hz, _RTL_POWER_MAX_FREQ)
        if freq_end < self.freq_start_hz:
            logger.error(
                "rtl_power: start freq %.1f MHz exceeds rtl_power max %.1f MHz",
                self.freq_start_hz / 1e6,
                _RTL_POWER_MAX_FREQ / 1e6,
            )
            return []

        if self.freq_end_hz > _RTL_POWER_MAX_FREQ:
            logger.warning(
                "rtl_power max frequency is %.1f MHz; clamping from %.1f MHz",
                _RTL_POWER_MAX_FREQ / 1e6,
                self.freq_end_hz / 1e6,
            )

        # rtl_power -f start:end:bin_size -1 (single sweep) -c 20%
        # -1 flag: single shot, exit after one sweep
        cmd = [
            "rtl_power",
            "-f",
            f"{int(self.freq_start_hz)}:{int(freq_end)}:{int(self.bin_size_hz)}",
            "-1",  # single sweep
            "-c",
            "20%",  # crop percentage (exclude band edges)
        ]

        logger.debug("Running: %s", " ".join(cmd))

        # Estimate timeout: rtl_power takes roughly 1 second per MHz of span
        span_mhz = (freq_end - self.freq_start_hz) / 1e6
        timeout = max(120, int(span_mhz * 2) + 60)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            logger.error("rtl_power timed out after %ds", timeout)
            return []
        except FileNotFoundError:
            logger.error("rtl_power not found — install rtl-sdr package")
            return []
        except OSError as exc:
            logger.error("rtl_power execution failed: %s", exc)
            return []

        if result.returncode != 0:
            stderr = result.stderr.strip()[:500] if result.stderr else ""
            logger.warning(
                "rtl_power exited with code %d: %s", result.returncode, stderr
            )
            # rtl_power may still produce partial output
            if not result.stdout.strip():
                return []

        return _parse_rtl_power_csv(result.stdout)

    def _sweep_hackrf(self) -> list[dict[str, Any]]:
        """Run hackrf_sweep and parse its output.

        hackrf_sweep supports 1 MHz to 6 GHz.  It outputs CSV-format text
        to stdout with per-bin power levels.
        """
        # hackrf_sweep -f start_mhz:end_mhz -w bin_size_hz -1 (single sweep)
        start_mhz = int(self.freq_start_hz / 1e6)
        end_mhz = int(self.freq_end_hz / 1e6)

        cmd = [
            "hackrf_sweep",
            "-f",
            f"{start_mhz}:{end_mhz}",
            "-w",
            str(int(self.bin_size_hz)),
            "-1",  # single sweep
        ]

        logger.debug("Running: %s", " ".join(cmd))

        # hackrf_sweep is faster than rtl_power for wide spans
        span_mhz = end_mhz - start_mhz
        timeout = max(120, int(span_mhz * 0.5) + 60)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            logger.error("hackrf_sweep timed out after %ds", timeout)
            return []
        except FileNotFoundError:
            logger.error("hackrf_sweep not found — install hackrf package")
            return []
        except OSError as exc:
            logger.error("hackrf_sweep execution failed: %s", exc)
            return []

        if result.returncode != 0:
            stderr = result.stderr.strip()[:500] if result.stderr else ""
            logger.warning(
                "hackrf_sweep exited with code %d: %s",
                result.returncode,
                stderr,
            )
            if not result.stdout.strip():
                return []

        return _parse_hackrf_sweep_output(result.stdout)

    # -- Upload ------------------------------------------------------------

    def _upload(self, snapshot: dict[str, Any]) -> None:
        """Upload a spectrum snapshot to the Bridge controller.

        POSTs gzip-compressed JSON to ``/api/spectrum/snapshots`` matching
        the expected ingest format: node_id, center_freq_hz, bandwidth_hz,
        fft_size, psd_dbm.
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        payload = {
            "node_id": self.node_id,
            "timestamp": timestamp,
            "center_freq_hz": snapshot["center_freq_hz"],
            "bandwidth_hz": snapshot["bandwidth_hz"],
            "fft_size": snapshot["fft_size"],
            "psd_dbm": snapshot["psd_dbm"],
        }

        body = json.dumps(payload).encode("utf-8")
        compressed = gzip.compress(body)

        url = f"{self.server_url}/api/spectrum/snapshots"
        req = urllib.request.Request(
            url,
            data=compressed,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
                "X-API-Key": self.api_key,
            },
        )

        try:
            resp = urllib.request.urlopen(
                req,
                timeout=_UPLOAD_TIMEOUT,
                context=self._ssl_ctx,
            )
            data = json.loads(resp.read().decode())
            logger.info(
                "Spectrum snapshot uploaded: node=%s, center=%.1f MHz, "
                "bw=%.1f MHz, %d bins, id=%s",
                self.node_id,
                snapshot["center_freq_hz"] / 1e6,
                snapshot["bandwidth_hz"] / 1e6,
                snapshot["fft_size"],
                data.get("id", "?"),
            )
        except urllib.error.HTTPError as exc:
            body_text = ""
            try:
                body_text = exc.read().decode()[:300]
            except Exception:
                pass
            logger.warning(
                "Spectrum upload HTTP %d: %s — %s",
                exc.code,
                exc.reason,
                body_text,
            )
            self._error_count += 1
        except Exception as exc:
            logger.warning("Spectrum upload failed: %s", exc)
            self._error_count += 1


# ---------------------------------------------------------------------------
# Tool availability check
# ---------------------------------------------------------------------------


def _check_tool(tool_name: str) -> bool:
    """Check if an SDR sweep tool is available on the system."""
    try:
        result = subprocess.run(
            ["which", tool_name],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return False


def check_backend(backend: str = SweepBackend.AUTO) -> str | None:
    """Check which sweep backend is available.

    Returns the name of the available backend, or None if none found.
    """
    if backend == SweepBackend.AUTO:
        for tool in (SweepBackend.HACKRF_SWEEP, SweepBackend.RTL_POWER):
            if _check_tool(tool):
                return tool
        return None
    if _check_tool(backend):
        return backend
    return None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    """Standalone CLI entry point for spectrum sweeper."""
    parser = argparse.ArgumentParser(
        description="Edge spectrum sweeper for SigRift",
    )
    parser.add_argument(
        "--server-url",
        default=os.environ.get("MLRF_BRIDGE_URL", "https://localhost:8444"),
        help="The Bridge server URL",
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("MLRF_API_KEY", ""),
        help="API key for authentication",
    )
    parser.add_argument(
        "--node-id",
        default=os.environ.get("MLRF_NODE_ID", "node-01"),
        help="Edge node identifier",
    )
    parser.add_argument(
        "--freq-start",
        type=float,
        default=float(
            os.environ.get("MLRF_SWEEP_FREQ_START", str(_DEFAULT_FREQ_START))
        ),
        help=f"Sweep start frequency in Hz (default: {_DEFAULT_FREQ_START:.0f})",
    )
    parser.add_argument(
        "--freq-end",
        type=float,
        default=float(os.environ.get("MLRF_SWEEP_FREQ_END", str(_DEFAULT_FREQ_END))),
        help=f"Sweep end frequency in Hz (default: {_DEFAULT_FREQ_END:.0f})",
    )
    parser.add_argument(
        "--bin-size",
        type=float,
        default=float(os.environ.get("MLRF_SWEEP_BIN_SIZE", str(_DEFAULT_BIN_SIZE))),
        help=f"FFT bin size in Hz (default: {_DEFAULT_BIN_SIZE})",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=int(
            os.environ.get("MLRF_SWEEP_INTERVAL", str(_DEFAULT_SWEEP_INTERVAL))
        ),
        help=f"Sweep interval in seconds (default: {_DEFAULT_SWEEP_INTERVAL})",
    )
    parser.add_argument(
        "--backend",
        choices=["auto", "rtl_power", "hackrf_sweep"],
        default=os.environ.get("MLRF_SWEEP_BACKEND", SweepBackend.AUTO),
        help="SDR sweep backend (default: auto)",
    )
    parser.add_argument(
        "--peak-threshold",
        type=float,
        default=10.0,
        help="Peak detection threshold above noise floor in dB (default: 10)",
    )
    parser.add_argument(
        "--ca-bundle",
        default=os.environ.get("MLRF_CA_BUNDLE"),
        help="Path to CA bundle for TLS verification",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single sweep and exit (useful for testing)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    if not args.api_key:
        logger.error("No API key provided (--api-key or MLRF_API_KEY)")
        sys.exit(1)

    # Check backend availability
    available = check_backend(args.backend)
    if available is None:
        logger.error(
            "No sweep backend available. Install rtl-sdr (rtl_power) "
            "or hackrf (hackrf_sweep)."
        )
        sys.exit(1)
    logger.info("Using sweep backend: %s", available)

    sweeper = SpectrumSweeper(
        server_url=args.server_url,
        api_key=args.api_key,
        node_id=args.node_id,
        freq_start_hz=args.freq_start,
        freq_end_hz=args.freq_end,
        bin_size_hz=args.bin_size,
        sweep_interval=args.interval,
        backend=args.backend,
        ca_bundle=args.ca_bundle,
        peak_threshold_db=args.peak_threshold,
    )

    if args.once:
        # Single sweep mode
        logger.info("Running single sweep...")
        snapshots = sweeper._sweep()
        if snapshots:
            for snap in snapshots:
                noise_floor = _estimate_noise_floor(snap["psd_dbm"])
                peaks = _detect_peaks(
                    snap["psd_dbm"],
                    snap["center_freq_hz"] - snap["bandwidth_hz"] / 2,
                    snap.get("bin_width_hz", args.bin_size),
                    args.peak_threshold,
                )
                logger.info(
                    "Snapshot: center=%.1f MHz, bw=%.1f MHz, %d bins, "
                    "noise_floor=%.1f dBm, %d peaks",
                    snap["center_freq_hz"] / 1e6,
                    snap["bandwidth_hz"] / 1e6,
                    snap["fft_size"],
                    noise_floor,
                    len(peaks),
                )
                for peak in peaks[:20]:
                    logger.info(
                        "  Peak: %.3f MHz @ %.1f dBm (SNR %.1f dB)",
                        peak["freq_hz"] / 1e6,
                        peak["power_dbm"],
                        peak["snr_db"],
                    )
                if len(peaks) > 20:
                    logger.info("  ... and %d more peaks", len(peaks) - 20)
                sweeper._upload(snap)
        else:
            logger.warning("No data from sweep")
        logger.info("Stats: %s", json.dumps(sweeper.stats(), indent=2))
        return

    # Continuous sweep mode
    stop_event = threading.Event()

    def handle_signal(signum: int, frame: Any) -> None:
        logger.info("Signal %d received, stopping...", signum)
        stop_event.set()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    sweeper.start()
    logger.info("Spectrum sweeper running. Press Ctrl+C to stop.")

    stop_event.wait()
    sweeper.stop()

    logger.info("Final stats: %s", json.dumps(sweeper.stats(), indent=2))


if __name__ == "__main__":
    main()
