"""Filesystem-backed IQ capture storage with visualization computation.

Stores gzip-compressed IQ captures on disk at ``data/iq_captures/``
and provides FFT-based visualization (constellation, PSD, DSP features)
matching the ``/api/signals/generate`` response format so the dashboard
canvas renderers work unchanged.

Each file is named ``{stem}.iq.gz`` (see :func:`capture_stem`) and
contains float32 interleaved I/Q pairs.  Sidecars ``{stem}.quality.json``
and ``{stem}.sigmf-meta`` live next to it and are deleted with it.

Decompression is bounded: a capture may hold at most
``BRIDGE_IQ_MAX_SAMPLES`` complex samples (default 32 Mi, i.e. 64 Mi
float32 values / 256 MiB), so a small gzip "bomb" cannot inflate into
gigabytes of memory.

Analysis is bounded too.  All-zero IQ compresses about 1000:1, so a
~260 KB upload can still hold a cap-sized capture; the consumers that
run FFTs over a capture (visualization, spectrogram, modulation
parameters, protocol decoding) therefore inflate and analyse only its
first ``BRIDGE_IQ_ANALYSIS_MAX_SAMPLES`` samples (default 2 Mi, which
covers every capture a 10 MB upload of real, noisy IQ holds), and their
outputs have a fixed size: the PSD has at most :data:`VIZ_PSD_BINS`
bins, a spectrogram at most :data:`SPECTROGRAM_MAX_CELLS` cells, and
the STFT work is capped at :data:`SPECTROGRAM_MAX_FFT_CELLS` FFT bins
(the hop between segments is raised when a request asks for more).
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import zlib
from pathlib import Path
from typing import Any, Callable

import numpy as np

logger = logging.getLogger(__name__)

_DEFAULT_BASE_DIR = Path(__file__).resolve().parent / "data" / "iq_captures"

# -- Decompression limits ------------------------------------------------------

#: Default cap on complex IQ samples per capture: 32 Mi samples = 64 Mi
#: float32 values = 256 MiB decompressed.
DEFAULT_MAX_IQ_SAMPLES = 32 * 1024 * 1024
_MAX_SAMPLES_ENV = "BRIDGE_IQ_MAX_SAMPLES"
_BYTES_PER_SAMPLE = 8  # complex64: float32 I + float32 Q
# Inflation work bounds (see decompress_iq): input slice fed to zlib per
# call, output inflated per call, and concatenated gzip members accepted.
_INFLATE_INPUT_CHUNK = 64 * 1024
_INFLATE_OUTPUT_STEP = 1024 * 1024
_MAX_GZIP_MEMBERS = 64

# Quality validation runs an FFT over the capture; bound it so a capture
# near the sample cap cannot cost gigabytes of FFT buffers.  2 Mi samples
# covers every capture the 10 MB upload limit allows uncompressed.
_QUALITY_MAX_SAMPLES = 2 * 1024 * 1024

# -- Analysis limits -------------------------------------------------------------

#: Default number of samples (from the start of a capture) that the
#: analysis consumers inflate and process; see the module docstring.
DEFAULT_ANALYSIS_MAX_SAMPLES = _QUALITY_MAX_SAMPLES
_ANALYSIS_MAX_SAMPLES_ENV = "BRIDGE_IQ_ANALYSIS_MAX_SAMPLES"
#: PSD bins returned by :meth:`IQStore.compute_visualization` at most
#: (Welch average of segments of this length).
VIZ_PSD_BINS = 2048
#: Cells (time rows x frequency bins) a spectrogram returns at most when
#: the caller does not ask for fewer rows; consecutive segments are
#: averaged down to fit.
SPECTROGRAM_MAX_CELLS = 1024 * 1024
#: FFT bins a spectrogram computes at most (segments x nfft); the hop
#: between segments is raised (the overlap lowered) to stay under it.
SPECTROGRAM_MAX_FFT_CELLS = 16 * 1024 * 1024
#: Segments transformed per batch, so the STFT buffers stay small.
_STFT_BATCH_CELLS = 1024 * 1024
#: Sample rates an IQ capture may declare (the upload's ``X-Sample-Rate``).
#: Every SDR the edges drive runs within it (61.44 MHz at most).  The
#: rate sizes work done on the capture later (protocol decoding resamples
#: by it), so an absurd one is refused at upload.
MIN_IQ_SAMPLE_RATE_HZ = 1_000.0
MAX_IQ_SAMPLE_RATE_HZ = 250_000_000.0

# Sidecar files stored next to ``{stem}.iq.gz``.
_SIDECAR_SUFFIXES = (".quality.json", ".sigmf-meta")
# The orphan sweep leaves very recent sidecars alone (store() in progress).
_ORPHAN_GRACE_SECONDS = 60.0


class IQDecompressionError(ValueError):
    """The payload is not a valid gzip stream of complex64 IQ samples."""


class IQSampleLimitError(IQDecompressionError):
    """The payload decompresses to more samples than the configured cap."""


def max_iq_samples() -> int:
    """Return the configured per-capture sample cap (``BRIDGE_IQ_MAX_SAMPLES``)."""
    raw = os.environ.get(_MAX_SAMPLES_ENV, "").strip()
    if not raw:
        return DEFAULT_MAX_IQ_SAMPLES
    try:
        value = int(raw)
    except ValueError:
        value = 0
    if value <= 0:
        logger.warning(
            "Invalid %s=%r (must be a positive integer); using %d",
            _MAX_SAMPLES_ENV,
            raw,
            DEFAULT_MAX_IQ_SAMPLES,
        )
        return DEFAULT_MAX_IQ_SAMPLES
    return value


def analysis_max_samples() -> int:
    """Samples an analysis consumer processes at most (``BRIDGE_IQ_ANALYSIS_MAX_SAMPLES``).

    Never more than :func:`max_iq_samples`.
    """
    raw = os.environ.get(_ANALYSIS_MAX_SAMPLES_ENV, "").strip()
    value = DEFAULT_ANALYSIS_MAX_SAMPLES
    if raw:
        try:
            value = int(raw)
        except ValueError:
            value = 0
        if value <= 0:
            logger.warning(
                "Invalid %s=%r (must be a positive integer); using %d",
                _ANALYSIS_MAX_SAMPLES_ENV,
                raw,
                DEFAULT_ANALYSIS_MAX_SAMPLES,
            )
            value = DEFAULT_ANALYSIS_MAX_SAMPLES
    return min(value, max_iq_samples())


def decompress_iq(
    data: bytes, max_samples: int | None = None, *, truncate: bool = False
) -> np.ndarray:
    """Decompress gzip float32-interleaved IQ into a complex64 array, bounded.

    Work and memory are bounded independently of the compression ratio:

    * the input is fed to zlib in slices of at most ``_INFLATE_INPUT_CHUNK``
      bytes (a zero-copy ``memoryview``), so zlib's per-call copies of the
      unconsumed input stay small and the total work is linear;
    * output is inflated ``_INFLATE_OUTPUT_STEP`` bytes per call straight
      into one buffer, and inflation stops as soon as it would exceed
      *max_samples* complex samples (default :func:`max_iq_samples`), so
      the peak is about the cap plus one step;
    * at most ``_MAX_GZIP_MEMBERS`` concatenated gzip members are accepted
      (the edge agents send one), so a payload of thousands of tiny
      members cannot cost a decompressor setup each.

    Concatenated gzip members and zero padding between / after them are
    accepted, as ``gzip.decompress`` accepts them.

    With ``truncate=True`` a payload over *max_samples* is not an error:
    its first *max_samples* samples are returned, and inflation stops
    there (the rest of the payload is not read).

    Raises
    ------
    IQSampleLimitError
        The payload holds more than *max_samples* samples (and *truncate*
        is false).
    IQDecompressionError
        The payload is not valid gzip, is truncated, has too many members,
        or does not hold a whole number of complex64 samples.
    """
    limit = max_iq_samples() if max_samples is None else int(max_samples)
    view = memoryview(data).cast("B")
    if not len(view):
        raise IQDecompressionError("empty IQ payload")
    out = bytearray()
    try:
        _inflate_into(out, view, limit, truncate)
    except zlib.error as exc:
        raise IQDecompressionError(f"invalid gzip data: {exc}") from exc
    if len(out) % _BYTES_PER_SAMPLE:
        raise IQDecompressionError(
            f"decompressed size {len(out)} is not a whole number of "
            "complex64 (interleaved float32 I/Q) samples"
        )
    # Interleaved float32 I, Q is exactly the memory layout of complex64.
    return np.frombuffer(out, dtype=np.complex64)


def _inflate_into(out: bytearray, view: memoryview, limit: int, truncate: bool) -> None:
    """Inflate the gzip member(s) in *view* into *out*, at most *limit* samples.

    Over the limit: raise :class:`IQSampleLimitError`, or with *truncate*
    cut *out* to the limit and stop.  See :func:`decompress_iq`.
    """
    limit_bytes = limit * _BYTES_PER_SAMPLE
    total = len(view)
    pos = 0  # offset of the first input byte zlib has not consumed yet
    members = 0
    while True:
        pos = _skip_zero_padding(view, pos)
        if pos >= total:
            return
        members += 1
        if members > _MAX_GZIP_MEMBERS:
            raise IQDecompressionError(
                f"IQ payload has more than {_MAX_GZIP_MEMBERS} gzip members"
            )
        inflater = zlib.decompressobj(wbits=31)  # gzip container only
        while not inflater.eof:
            if pos >= total:
                raise IQDecompressionError("truncated gzip stream")
            end = min(pos + _INFLATE_INPUT_CHUNK, total)
            pending: bytes | memoryview = view[pos:end]
            while True:
                # Ask for one byte more than the room left: getting it
                # proves the payload is over the cap without inflating
                # more.
                want = min(_INFLATE_OUTPUT_STEP, limit_bytes - len(out) + 1)
                produced = inflater.decompress(pending, want)
                out += produced
                if len(out) > limit_bytes:
                    if truncate:
                        del out[limit_bytes:]
                        return
                    raise IQSampleLimitError(
                        f"IQ payload exceeds the limit of {limit} samples "
                        f"({limit_bytes} bytes decompressed); raise "
                        f"{_MAX_SAMPLES_ENV} to accept larger captures"
                    )
                if inflater.eof:
                    # The member ended inside this slice: the next one
                    # starts where zlib stopped consuming.
                    pos = end - len(inflater.unused_data)
                    break
                pending = inflater.unconsumed_tail
                if not pending and len(produced) < want:
                    # Slice consumed and no output held back: next slice.
                    # (A call cut short by ``want`` may leave output
                    # buffered in zlib; the loop drains it with b"".)
                    pos = end
                    break


class _CountingSink:
    """Stands in for the output buffer of :func:`_inflate_into`: counts bytes."""

    def __init__(self) -> None:
        self.size = 0

    def __iadd__(self, chunk: bytes) -> _CountingSink:
        self.size += len(chunk)
        return self

    def __len__(self) -> int:
        return self.size


def _count_samples(data: bytes, limit: int) -> int:
    """Complex samples in gzip IQ *data*, inflated in steps and discarded."""
    view = memoryview(data).cast("B")
    if not len(view):
        raise IQDecompressionError("empty IQ payload")
    sink = _CountingSink()
    try:
        _inflate_into(sink, view, limit, False)  # type: ignore[arg-type]
    except zlib.error as exc:
        raise IQDecompressionError(f"invalid gzip data: {exc}") from exc
    if sink.size % _BYTES_PER_SAMPLE:
        raise IQDecompressionError(
            f"decompressed size {sink.size} is not a whole number of samples"
        )
    return sink.size // _BYTES_PER_SAMPLE


def _skip_zero_padding(view: memoryview, pos: int) -> int:
    """Return the offset of the first non-zero byte at or after *pos*."""
    total = len(view)
    while pos < total and view[pos] == 0:
        chunk = bytes(view[pos : pos + _INFLATE_INPUT_CHUNK])
        stripped = len(chunk) - len(chunk.lstrip(b"\x00"))
        pos += stripped
        if stripped < len(chunk):
            break
    return pos


_PLAIN_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,200}")
_MAX_ENCODED_ID_LEN = 200


def capture_stem(detection_id: str) -> str:
    """Return the file stem for *detection_id*: injective and traversal-free.

    Ids made only of ``[A-Za-z0-9_-]`` (every id the platform generates:
    hex, UUIDs) map to themselves, so existing captures keep their file
    names.  Any other id is hex-encoded behind a ``~`` prefix, which plain
    ids cannot contain, so ``"a.b"`` and ``"ab"`` no longer share a file
    (the old sanitizer just stripped the dot).  Raises ``ValueError`` for
    an empty or over-long id.
    """
    if not isinstance(detection_id, str) or not detection_id:
        raise ValueError("Invalid detection_id")
    if _PLAIN_ID_RE.fullmatch(detection_id):
        return detection_id
    encoded = detection_id.encode("utf-8", "surrogatepass").hex()
    if len(encoded) > _MAX_ENCODED_ID_LEN:
        raise ValueError("Invalid detection_id: too long")
    return "~" + encoded


# Thresholds for quality checks
_CLIP_FRACTION_THRESHOLD = 0.05  # >5% clipped samples = clipped
_SNR_FLOOR_DB = -5.0  # Below this = noise-dominated
_DC_OFFSET_THRESHOLD = 0.05  # Mean magnitude relative to RMS


def validate_iq_quality(iq: np.ndarray) -> dict[str, Any]:
    """Validate quality of an IQ capture.

    Checks:
      - Clipping: >5% of samples at max/min magnitude (ADC saturation)
      - SNR floor: estimated SNR below -5 dB (noise-dominated)
      - DC offset: mean significantly non-zero relative to RMS
      - Phase coherence: I/Q channels correlated (incoherent = bad capture)

    Parameters
    ----------
    iq : np.ndarray
        Complex64 IQ samples.

    Returns
    -------
    dict
        {score: 0-1.0, clipped: bool, snr_db: float,
         dc_offset: bool, phase_coherent: bool}
    """
    n = len(iq)
    if n == 0:
        return {
            "score": 0.0,
            "clipped": False,
            "snr_db": float("-inf"),
            "dc_offset": False,
            "phase_coherent": False,
        }

    # --- Clipping detection ---
    magnitudes = np.abs(iq)
    max_mag = float(np.max(magnitudes))
    if max_mag > 0:
        clip_threshold = max_mag * 0.99
        clipped_fraction = float(np.sum(magnitudes >= clip_threshold)) / n
    else:
        clipped_fraction = 0.0
    clipped = clipped_fraction > _CLIP_FRACTION_THRESHOLD

    # --- SNR estimation (signal power / noise power) ---
    # Use PSD: signal is the peak, noise is the median
    fft_vals = np.fft.fft(iq)
    psd = np.abs(fft_vals) ** 2 / n
    signal_power = float(np.max(psd))
    noise_power = float(np.median(psd))
    if noise_power > 0:
        snr_db = float(10.0 * np.log10(signal_power / noise_power))
    else:
        snr_db = float("inf") if signal_power > 0 else 0.0

    # --- DC offset detection ---
    rms = float(np.sqrt(np.mean(magnitudes**2)))
    mean_abs = float(np.abs(np.mean(iq)))
    if rms > 0:
        dc_ratio = mean_abs / rms
    else:
        dc_ratio = 0.0
    dc_offset = dc_ratio > _DC_OFFSET_THRESHOLD

    # --- Phase coherence (I/Q correlation) ---
    i_vals = iq.real
    q_vals = iq.imag
    i_std = float(np.std(i_vals))
    q_std = float(np.std(q_vals))
    if i_std > 1e-12 and q_std > 1e-12:
        corr = float(np.abs(np.corrcoef(i_vals, q_vals)[0, 1]))
        # Coherent signals have moderate correlation (not 0 and not 1)
        # Incoherent = correlation very close to 0 or very close to 1
        # For real signals, some correlation is expected
        phase_coherent = corr < 0.99  # Perfect correlation = I==Q (bad)
    else:
        phase_coherent = False  # One channel is dead

    # --- Composite quality score ---
    score = 1.0
    if clipped:
        score -= 0.3
    if snr_db < _SNR_FLOOR_DB:
        score -= 0.3
    if dc_offset:
        score -= 0.2
    if not phase_coherent:
        score -= 0.2
    score = max(0.0, min(1.0, score))

    return {
        "score": round(score, 3),
        "clipped": clipped,
        "snr_db": round(snr_db, 2),
        "dc_offset": dc_offset,
        "phase_coherent": phase_coherent,
    }


class IQStore:
    """Filesystem storage for IQ waveform captures.

    Parameters
    ----------
    base_dir : str or Path or None
        Directory for ``.iq.gz`` files.  Created if it does not exist.
        Defaults to ``sigrift/bridge/data/iq_captures/``.
    """

    def __init__(self, base_dir: str | Path | None = None) -> None:
        self._base_dir = Path(base_dir or _DEFAULT_BASE_DIR)
        self._base_dir.mkdir(parents=True, exist_ok=True)
        logger.info("IQStore initialised: %s", self._base_dir)
        # Older releases deleted only the .iq.gz and left its sidecars
        # behind forever; clear those once at startup.
        try:
            self.sweep_orphan_sidecars()
        except OSError as exc:
            logger.warning("IQ orphan sidecar sweep failed: %s", exc)

    # -- Write ------------------------------------------------------------------

    def store(self, detection_id: str, data: bytes) -> Path:
        """Write compressed IQ data to disk and run quality validation.

        Parameters
        ----------
        detection_id : str
            Detection identifier (used as filename).
        data : bytes
            Gzip-compressed float32 interleaved IQ data.

        Returns
        -------
        Path
            Path to the stored file.

        Raises
        ------
        IQSampleLimitError
            *data* decompresses to more than ``BRIDGE_IQ_MAX_SAMPLES``
            samples; nothing is written.  (Data that is not valid gzip is
            still stored, without quality metadata, as before.)

        Blocking (decompression and an FFT): async callers should run it
        with ``asyncio.to_thread``.
        """
        path = self._path_for(detection_id)
        iq: np.ndarray | None = None
        try:
            iq = decompress_iq(data)
        except IQSampleLimitError:
            logger.warning(
                "IQ capture %s refused: over the %d-sample limit",
                detection_id,
                max_iq_samples(),
            )
            raise
        except IQDecompressionError as exc:
            logger.warning("IQ quality validation failed for %s: %s", detection_id, exc)

        path.write_bytes(data)
        logger.debug("IQ capture stored: %s (%d bytes)", detection_id, len(data))

        # Run quality validation and save metadata
        try:
            if iq is not None:
                quality = validate_iq_quality(iq[:_QUALITY_MAX_SAMPLES])
                self._save_quality_metadata(detection_id, quality)
                logger.debug(
                    "IQ quality for %s: score=%.2f clipped=%s snr=%.1f",
                    detection_id,
                    quality["score"],
                    quality["clipped"],
                    quality["snr_db"],
                )
        except Exception as e:
            logger.warning("IQ quality validation failed for %s: %s", detection_id, e)

        return path

    # -- Read -------------------------------------------------------------------

    def load_raw(self, detection_id: str) -> bytes | None:
        """Return compressed bytes, or None if not found."""
        path = self._path_for(detection_id)
        if not path.exists():
            return None
        return path.read_bytes()

    def load_iq(
        self, detection_id: str, max_samples: int | None = None
    ) -> np.ndarray | None:
        """Decompress and return complex64 IQ array, or None.

        Decompression is capped at ``BRIDGE_IQ_MAX_SAMPLES`` samples; a
        file over the cap (e.g. stored by an older release) is not loaded.
        With *max_samples*, only the first *max_samples* samples are
        inflated and returned (no error when the capture is longer): the
        analysis consumers pass :func:`analysis_max_samples`.
        """
        raw = self.load_raw(detection_id)
        if raw is None:
            return None
        try:
            if max_samples is None:
                return decompress_iq(raw)
            return decompress_iq(
                raw, min(int(max_samples), max_iq_samples()), truncate=True
            )
        except IQDecompressionError as e:
            logger.warning("Failed to decompress IQ for %s: %s", detection_id, e)
            return None

    def load_iq_for_analysis(self, detection_id: str) -> np.ndarray | None:
        """The first :func:`analysis_max_samples` samples of a capture, or None."""
        return self.load_iq(detection_id, max_samples=analysis_max_samples())

    def sample_count(self, detection_id: str) -> int | None:
        """Number of complex samples in a capture without holding them, or None.

        Inflates in bounded steps and discards the output, so counting a
        cap-sized capture costs one inflation step of memory.  ``None``
        when the capture is missing, unreadable or over the sample cap.
        """
        raw = self.load_raw(detection_id)
        if raw is None:
            return None
        try:
            return _count_samples(raw, max_iq_samples())
        except (IQDecompressionError, zlib.error) as e:
            logger.warning("Failed to read IQ for %s: %s", detection_id, e)
            return None

    # -- Query ------------------------------------------------------------------

    def exists(self, detection_id: str) -> bool:
        """Check if an IQ capture exists for this detection.

        An id that cannot name a capture file (empty, over-long) has none.
        """
        try:
            path = self._path_for(detection_id)
        except ValueError:
            return False
        return path.exists()

    def delete(self, detection_id: str) -> bool:
        """Delete an IQ capture and its sidecars.  True if the capture existed."""
        path = self._path_for(detection_id)
        existed = False
        try:
            path.unlink()
            existed = True
        except FileNotFoundError:
            pass
        self._remove_sidecars(path)
        return existed

    # -- Cleanup ----------------------------------------------------------------

    def cleanup(self, max_age_days: int = 7) -> int:
        """Delete IQ files older than *max_age_days*.

        Returns
        -------
        int
            Number of files deleted.
        """
        cutoff = time.time() - (max_age_days * 86400)
        deleted = 0
        for path in self._base_dir.glob("*.iq.gz"):
            try:
                if path.stat().st_mtime < cutoff:
                    path.unlink()
                    deleted += 1
                    self._remove_sidecars(path)
            except OSError:
                pass
        self.sweep_orphan_sidecars()
        if deleted > 0:
            logger.info(
                "IQ cleanup: removed %d files older than %d days", deleted, max_age_days
            )
        return deleted

    def sweep_orphan_sidecars(self) -> int:
        """Delete ``.quality.json`` / ``.sigmf-meta`` files whose capture is gone.

        Returns the number of sidecars removed.  Sidecars modified in the
        last minute are left alone (their capture may be mid-``store()``).
        """
        removed = 0
        grace_cutoff = time.time() - _ORPHAN_GRACE_SECONDS
        for suffix in _SIDECAR_SUFFIXES:
            for sidecar in self._base_dir.glob(f"*{suffix}"):
                stem = sidecar.name[: -len(suffix)]
                if (self._base_dir / f"{stem}.iq.gz").exists():
                    continue
                try:
                    if sidecar.stat().st_mtime >= grace_cutoff:
                        continue
                    sidecar.unlink()
                    removed += 1
                except OSError:
                    pass
        if removed:
            logger.info("IQ cleanup: removed %d orphaned sidecar files", removed)
        return removed

    @staticmethod
    def _remove_sidecars(capture_path: Path) -> None:
        """Delete the sidecars that belong to *capture_path* (``{stem}.iq.gz``)."""
        stem = capture_path.name[: -len(".iq.gz")]
        for suffix in _SIDECAR_SUFFIXES:
            try:
                (capture_path.parent / f"{stem}{suffix}").unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                logger.warning(
                    "Failed to delete IQ sidecar %s%s: %s", stem, suffix, exc
                )

    # -- Visualization ----------------------------------------------------------

    def _load_for_analysis(self, detection_id: str) -> tuple[np.ndarray, bool] | None:
        """``(first analysis_max_samples() samples, capture was longer)`` or None."""
        cap = analysis_max_samples()
        iq = self.load_iq(detection_id, max_samples=cap + 1)
        if iq is None:
            return None
        if len(iq) > cap:
            return iq[:cap], True
        return iq, False

    def compute_visualization(self, detection_id: str) -> dict | None:
        """Compute visualization data matching ``/api/signals/generate`` format.

        Bounded (see the module docstring): only the first
        :func:`analysis_max_samples` samples are analysed, and the PSD has
        at most :data:`VIZ_PSD_BINS` bins — a capture up to that length
        gets its full-resolution periodogram as before, a longer one a
        Welch average (Hann-windowed segments of ``VIZ_PSD_BINS``).

        Returns
        -------
        dict or None
            Keys: constellation_x, constellation_y, psd_db, psd_freq_hz,
            dsp_features.  None if IQ data not found.
        """
        iq = self.load_iq_for_analysis(detection_id)
        if iq is None:
            return None
        n = len(iq)

        # --- Constellation (subsample to max 2048 points) ---
        stride = max(1, n // 2048)
        subset = iq[::stride]
        constellation_x = subset.real.tolist()
        constellation_y = subset.imag.tolist()

        # --- PSD ---
        psd_linear, psd_freq = _bounded_psd(iq, VIZ_PSD_BINS)
        psd_db = (10 * np.log10(psd_linear + 1e-12)).tolist()
        psd_freq_hz = psd_freq.tolist()

        # --- DSP features (16-element vector matching signals.js bar chart) ---
        dsp_features = self._compute_dsp_features(iq) if n else [0.0] * 16

        return {
            "constellation_x": constellation_x,
            "constellation_y": constellation_y,
            "psd_db": psd_db,
            "psd_freq_hz": psd_freq_hz,
            "dsp_features": dsp_features,
        }

    # -- Spectrogram ------------------------------------------------------------

    def compute_spectrogram(
        self,
        detection_id: str,
        nfft: int = 256,
        overlap: int = 128,
        window: str = "hann",
        max_segments: int | None = None,
        db_decimals: int | None = None,
    ) -> dict[str, Any] | None:
        """Compute spectrogram from IQ capture for waterfall display.

        Bounded for every request (see the module docstring): the first
        :func:`analysis_max_samples` samples are analysed; at most
        :data:`SPECTROGRAM_MAX_FFT_CELLS` FFT bins are computed (when the
        requested overlap would need more, the hop between segments is
        raised and ``overlap`` in the result reports the one used); the
        STFT runs in batches; and the result has at most *max_segments*
        rows (default: as many as fit in :data:`SPECTROGRAM_MAX_CELLS`).
        Segments are detrended (mean removed), windowed and scaled as
        ``scipy.signal.spectrogram`` does.

        Parameters
        ----------
        max_segments : int or None
            When the capture yields more time segments, consecutive
            segments are averaged (in linear power) down to at most this
            many rows, so the waterfall keeps its full time span.
            ``n_segments`` reports the returned row count.
        db_decimals : int or None
            When set, dB values are rounded to this many decimals, which
            shrinks the JSON form about threefold (the values span 60 dB,
            so 0.1 dB is far below display resolution).

        Returns
        -------
        dict or None
            Keys: spectrogram (2D list, time x freq, dB), time_axis,
            freq_axis (normalised -0.5..0.5), nfft, n_segments, overlap
            (the one used), n_samples (samples analysed) and truncated.
            None if IQ data not found.

        Raises
        ------
        ValueError
            *overlap* is not in ``[0, nfft)`` or *window* is unknown.
        """
        from scipy.signal import get_window

        nfft = int(nfft)
        overlap = int(overlap)
        if nfft < 1 or not 0 <= overlap < nfft:
            raise ValueError("nfft must be positive and 0 <= overlap < nfft")
        loaded = self._load_for_analysis(detection_id)
        if loaded is None:
            return None
        iq, truncated = loaded
        n = len(iq)
        if max_segments is not None and max_segments > 0:
            max_rows = int(max_segments)
        else:
            max_rows = max(1, SPECTROGRAM_MAX_CELLS // nfft)

        seg_len = min(nfft, n)  # scipy shortens nperseg the same way
        hop = nfft - overlap
        if seg_len < nfft:
            n_seg = 1 if n else 0
        else:
            n_seg = 1 + (n - nfft) // hop
            max_computed = max(2, SPECTROGRAM_MAX_FFT_CELLS // nfft)
            if n_seg > max_computed:
                hop = -(-(n - nfft) // (max_computed - 1))  # ceil division
                n_seg = 1 + (n - nfft) // hop

        if n_seg == 0:
            Sxx = np.zeros((0, 0))
            t = np.zeros(0)
            f = np.zeros(0)
        else:
            win = get_window(window, seg_len).astype(np.float64)
            Sxx, t = _stft_power_rows(iq, seg_len, hop, n_seg, win, max_rows)
            # Centre the spectrum for display (-0.5 .. 0.5)
            Sxx = np.fft.fftshift(Sxx, axes=1)
            f = np.fft.fftshift(np.fft.fftfreq(seg_len, d=1.0))

        # Convert to dB, normalise to 0 dB peak, clamp
        Sxx_db = 10 * np.log10(np.maximum(Sxx, 1e-12))
        if Sxx_db.size:
            Sxx_db -= float(np.max(Sxx_db))
        Sxx_db = np.clip(Sxx_db, -60, 0)
        if db_decimals is not None:
            Sxx_db = np.round(Sxx_db, db_decimals)

        return {
            "spectrogram": Sxx_db.tolist(),  # time x freq
            "time_axis": t.tolist(),
            "freq_axis": f.tolist(),
            "nfft": nfft,
            "n_segments": int(Sxx_db.shape[0]),
            "overlap": max(0, nfft - hop),
            "n_samples": n,
            "truncated": truncated,
        }

    # -- Quality metadata -------------------------------------------------------

    def _quality_path_for(self, detection_id: str) -> Path:
        """Return path for quality metadata JSON."""
        return self._file_for(detection_id, ".quality.json")

    def _save_quality_metadata(
        self, detection_id: str, quality: dict[str, Any]
    ) -> None:
        """Save quality metadata as a JSON sidecar file."""
        path = self._quality_path_for(detection_id)
        path.write_text(json.dumps(quality))

    def get_quality(self, detection_id: str) -> dict[str, Any] | None:
        """Load quality metadata for a detection, or None if not found."""
        path = self._quality_path_for(detection_id)
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return None

    @staticmethod
    def _decompress(data: bytes) -> np.ndarray | None:
        """Decompress gzip IQ data to complex64 array (bounded), or None."""
        try:
            return decompress_iq(data)
        except IQDecompressionError:
            return None

    # -- Internal ---------------------------------------------------------------

    def _path_for(self, detection_id: str) -> Path:
        """Return filesystem path for a detection's IQ capture."""
        return self._file_for(detection_id, ".iq.gz")

    def _file_for(self, detection_id: str, suffix: str) -> Path:
        """Return ``base_dir/{capture_stem(detection_id)}{suffix}``."""
        path = (self._base_dir / f"{capture_stem(detection_id)}{suffix}").resolve()
        if not path.is_relative_to(self._base_dir.resolve()):
            raise ValueError("Path traversal detected")
        return path

    @staticmethod
    def _compute_dsp_features(iq: np.ndarray) -> list[float]:
        """Compute a 16-element DSP feature vector from IQ samples.

        Features (matching the labels in detections.js _drawDDFeatures):
            0-2: N2pk, N4pk, N8pk — peak values of Nth-power spectra
            3-7: CP64, CP256, CP512, CP1K, CP2K — cyclic prefix correlation at offsets
            8-15: |C20|, aC20, |C40|, aC40, |C41|, C42, rC40, rC41 — higher-order cumulants
        """
        n = len(iq)
        features = [0.0] * 16

        # Nth-power spectral peaks
        for idx, power in enumerate([2, 4, 8]):
            raised = iq**power
            spec = np.abs(np.fft.fft(raised))
            features[idx] = float(np.max(spec) / (np.mean(spec) + 1e-12))

        # Cyclic prefix correlation at different offsets
        for idx, offset in enumerate([64, 256, 512, 1024, 2048]):
            if offset < n:
                corr = np.abs(np.mean(iq[: n - offset] * np.conj(iq[offset:])))
                features[3 + idx] = float(corr)

        # Higher-order statistics (cumulant approximations)
        iq_norm = iq / (np.sqrt(np.mean(np.abs(iq) ** 2)) + 1e-12)
        c20 = np.mean(iq_norm**2)
        c40 = np.mean(iq_norm**4) - 3 * c20**2
        c41 = (
            np.mean(np.abs(iq_norm) ** 2 * iq_norm**2)
            - 3 * np.mean(np.abs(iq_norm) ** 2) * c20
        )
        c42 = (
            np.mean(np.abs(iq_norm) ** 4)
            - np.abs(c20) ** 2
            - 2 * np.mean(np.abs(iq_norm) ** 2) ** 2
        )

        features[8] = float(np.abs(c20))
        features[9] = float(np.angle(c20))
        features[10] = float(np.abs(c40))
        features[11] = float(np.angle(c40))
        features[12] = float(np.abs(c41))
        features[13] = float(np.real(c42))
        # Ratios
        features[14] = float(np.abs(c40) / (np.abs(c20) ** 2 + 1e-12))
        features[15] = float(np.abs(c41) / (np.abs(c20) ** 2 + 1e-12))

        return features


# -- Bounded spectral estimates --------------------------------------------------


def _bounded_psd(iq: np.ndarray, max_bins: int) -> tuple[np.ndarray, np.ndarray]:
    """Linear PSD (fftshift-ed) and normalised frequencies, at most *max_bins*.

    Up to *max_bins* samples: the plain periodogram ``|FFT|^2 / n``.
    Longer: the average of Hann-windowed, non-overlapping segments of
    *max_bins* samples, normalised by the window energy (the same scale
    for white noise), computed in batches.
    """
    n = len(iq)
    if n <= max_bins:
        fft_vals = np.fft.fftshift(np.fft.fft(iq))
        psd = np.abs(fft_vals) ** 2 / max(n, 1)
        return psd, np.fft.fftshift(np.fft.fftfreq(n, d=1.0))
    n_seg = n // max_bins
    win = np.hanning(max_bins)
    norm = float(np.sum(win**2))
    acc = np.zeros(max_bins)
    batch = max(1, _STFT_BATCH_CELLS // max_bins)
    frames = iq[: n_seg * max_bins].reshape(n_seg, max_bins)
    for start in range(0, n_seg, batch):
        spec = np.fft.fft(frames[start : start + batch] * win, axis=1)
        acc += np.sum(spec.real**2 + spec.imag**2, axis=0)
    psd = np.fft.fftshift(acc / (n_seg * norm))
    return psd, np.fft.fftshift(np.fft.fftfreq(max_bins, d=1.0))


def _stft_power_rows(
    iq: np.ndarray,
    nfft: int,
    hop: int,
    n_seg: int,
    win: np.ndarray,
    max_rows: int,
) -> tuple[np.ndarray, np.ndarray]:
    """Two-sided PSD of *n_seg* segments, averaged down to <= *max_rows* rows.

    Returns ``(power[rows, nfft], time[rows])`` (time = segment centres in
    samples, averaged per row).  Matches ``scipy.signal.spectrogram``
    (constant detrend, density scaling, ``fs=1``) segment by segment, but
    transforms the segments in batches of about ``_STFT_BATCH_CELLS``.
    """
    from numpy.lib.stride_tricks import sliding_window_view

    factor = -(-n_seg // max_rows)  # segments per row (ceil division)
    n_rows = -(-n_seg // factor)
    scale = 1.0 / float(np.sum(win**2))
    frames = sliding_window_view(iq[: (n_seg - 1) * hop + nfft], nfft)[::hop]
    power = np.zeros((n_rows, nfft))
    batch = max(1, _STFT_BATCH_CELLS // nfft)
    for start in range(0, n_seg, batch):
        seg = np.array(frames[start : start + batch], dtype=np.complex128)
        seg -= seg.mean(axis=1, keepdims=True)
        spec = np.fft.fft(seg * win, axis=1)
        cells = (spec.real**2 + spec.imag**2) * scale
        # Sum this batch's segments into their rows (a row may span batches).
        rows = (start + np.arange(len(cells))) // factor
        edges = np.concatenate(([0], np.flatnonzero(np.diff(rows)) + 1))
        power[rows[edges]] += np.add.reduceat(cells, edges, axis=0)
    counts = np.full(n_rows, factor, dtype=np.float64)
    counts[-1] = n_seg - factor * (n_rows - 1)
    power /= counts[:, None]
    first = np.arange(n_rows) * factor
    last = first + counts - 1
    times = nfft / 2 + hop * (first + last) / 2
    return power, times


# -- Analysis-job handler -------------------------------------------------------

#: nfft range a job-queue spectrogram accepts (requests are clamped to it).
SPECTROGRAM_JOB_NFFT_RANGE = (16, 4096)
#: Job-queue spectrograms hold at most this many cells (time rows x
#: frequency bins).  With dB values rounded to 0.1 a cell costs at most
#: 6 bytes of JSON, so a result stays near 1.5 MB for every nfft, well
#: under the job queue's default 8 MiB result cap.
SPECTROGRAM_JOB_CELL_BUDGET = 256 * 1024
_SPECTROGRAM_JOB_MAX_SEGMENTS_ENV = "BRIDGE_JOB_SPECTROGRAM_MAX_SEGMENTS"
_SPECTROGRAM_JOB_DEFAULT_MAX_SEGMENTS = 512


def spectrogram_job_handler(
    iq_store: IQStore,
    *,
    max_result_bytes: int | None = None,
    max_segments: int | None = None,
) -> Callable[[str, dict], dict]:
    """Build the ``spectrogram`` analysis-job handler for *iq_store*.

    The result is bounded for every accepted request: nfft is clamped to
    :data:`SPECTROGRAM_JOB_NFFT_RANGE`, consecutive time segments are
    averaged down to at most ``min(max_segments, cells // nfft)`` rows
    (``max_segments`` defaults to ``BRIDGE_JOB_SPECTROGRAM_MAX_SEGMENTS``,
    512; ``cells`` is :data:`SPECTROGRAM_JOB_CELL_BUDGET`, lowered to fit
    *max_result_bytes* when that is small) and dB values are rounded to
    0.1 dB.  The handler is synchronous (the job queue runs it in a
    worker thread).
    """
    if max_segments is None:
        from sigrift.bridge.job_queue import env_int

        max_segments = env_int(
            _SPECTROGRAM_JOB_MAX_SEGMENTS_ENV,
            _SPECTROGRAM_JOB_DEFAULT_MAX_SEGMENTS,
            minimum=1,
        )
    max_segments = max(1, int(max_segments))
    cell_budget = SPECTROGRAM_JOB_CELL_BUDGET
    if max_result_bytes is not None:
        # ~6 bytes per cell plus the axes: keep a wide margin.
        cell_budget = min(cell_budget, max(1, int(max_result_bytes) // 16))
    lo, hi = SPECTROGRAM_JOB_NFFT_RANGE

    def _spectrogram_handler(job_id: str, params: dict) -> dict:
        detection_id = params.get("detection_id")
        if not detection_id:
            raise ValueError("detection_id is required")
        try:
            nfft = int(params.get("nfft", 256))
        except (TypeError, ValueError):
            raise ValueError("nfft must be an integer") from None
        nfft = max(lo, min(nfft, hi))
        result = iq_store.compute_spectrogram(
            detection_id,
            nfft=nfft,
            overlap=nfft // 2,
            max_segments=max(1, min(max_segments, cell_budget // nfft)),
            db_decimals=1,
        )
        if result is None:
            raise ValueError(f"No IQ data found for detection {detection_id}")
        return result

    return _spectrogram_handler
