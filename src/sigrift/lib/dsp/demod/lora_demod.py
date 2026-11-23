"""LoRa CSS (Chirp Spread Spectrum) demodulator.

Demodulates LoRa signals from raw IQ samples by dechirping with a
conjugate base chirp, then extracting symbol values via FFT peak
detection.

Algorithm pipeline:
1. Bandwidth detection via PSD analysis, snap to standard LoRa BWs
2. Spreading factor detection: try SF 7-12, pick highest preamble
   correlation (N consecutive identical dechirped symbols)
3. Generate base up-chirp for the detected SF/BW pair
4. Dechirp: multiply IQ by conjugate of base chirp per symbol period
5. FFT each 2^SF-sample block, peak bin = symbol value
6. Preamble detection: 8+ consecutive identical symbols
7. Sync word extraction: 2 symbols following the preamble
8. CFO estimation from fractional preamble symbol offset
9. SNR estimation from preamble peak-to-floor ratio
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import numpy as np

logger = logging.getLogger(__name__)

# Standard LoRa bandwidths (Hz)
_STANDARD_BANDWIDTHS = [125_000.0, 250_000.0, 500_000.0]

# Well-known LoRa sync words
SYNC_WORD_PUBLIC = 0x34  # Public LoRaWAN / Meshtastic
SYNC_WORD_PRIVATE = 0x12  # Private networks

# Valid spreading factor range
_SF_MIN = 7
_SF_MAX = 12


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class LoRaDemodResult:
    """Result of LoRa CSS demodulation."""

    symbols: np.ndarray
    sf: int
    bw_hz: float
    cr: int
    cfo_hz: float
    snr_estimate_db: float
    n_symbols: int
    preamble_detected: bool
    sync_word: int
    confidence: float


# ---------------------------------------------------------------------------
# Demodulator
# ---------------------------------------------------------------------------


class LoRaCSSDemodulator:
    """LoRa chirp spread spectrum demodulator.

    Parameters
    ----------
    sample_rate : float
        IQ sample rate in Hz.
    """

    def __init__(self, sample_rate: float = 2_048_000.0) -> None:
        self.sample_rate = sample_rate

    # -- Bandwidth detection ------------------------------------------------

    def detect_bandwidth(self, iq: np.ndarray) -> float:
        """Measure occupied bandwidth via PSD and snap to standard LoRa BW.

        Parameters
        ----------
        iq : np.ndarray
            Complex IQ samples.

        Returns
        -------
        float
            Detected bandwidth in Hz (125e3, 250e3, or 500e3).
        """
        n = len(iq)
        if n < 64:
            return _STANDARD_BANDWIDTHS[0]

        nfft = min(n, 2048)
        window = np.hanning(nfft)
        n_segments = max(1, n // nfft)

        psd_sum = np.zeros(nfft)
        for i in range(n_segments):
            start = i * nfft
            seg = iq[start : start + nfft]
            if len(seg) < nfft:
                break
            windowed = seg * window
            spectrum = np.fft.fftshift(np.fft.fft(windowed))
            psd_sum += np.abs(spectrum) ** 2

        psd_db = 10.0 * np.log10(np.maximum(psd_sum / n_segments, 1e-12))
        peak_db = float(np.max(psd_db))
        freqs = np.fft.fftshift(np.fft.fftfreq(nfft, d=1.0 / self.sample_rate))

        # -20 dB bandwidth
        mask = psd_db >= (peak_db - 20.0)
        if not np.any(mask):
            return _STANDARD_BANDWIDTHS[0]

        indices = np.where(mask)[0]
        occupied_bw = float(freqs[indices[-1]] - freqs[indices[0]])

        # Snap to nearest standard LoRa bandwidth
        best_bw = min(_STANDARD_BANDWIDTHS, key=lambda b: abs(b - occupied_bw))
        return best_bw

    # -- Chirp generation ---------------------------------------------------

    def generate_base_chirp(self, sf: int, bw: float) -> np.ndarray:
        """Generate a base up-chirp for dechirp correlation.

        Parameters
        ----------
        sf : int
            Spreading factor (7-12).
        bw : float
            Bandwidth in Hz.

        Returns
        -------
        np.ndarray
            Complex up-chirp of length 2^SF samples.
        """
        n_fft = 2**sf
        t = np.arange(n_fft) / self.sample_rate
        chirp_rate = bw / (n_fft / self.sample_rate)
        phase = 2.0 * np.pi * ((-bw / 2.0) * t + (chirp_rate / 2.0) * t * t)
        return np.exp(1j * phase)

    # -- Dechirp ------------------------------------------------------------

    def dechirp(self, iq: np.ndarray, sf: int, bw: float) -> np.ndarray:
        """Dechirp IQ samples by multiplying with conjugate base chirp.

        Parameters
        ----------
        iq : np.ndarray
            Complex IQ samples.
        sf : int
            Spreading factor.
        bw : float
            Bandwidth in Hz.

        Returns
        -------
        np.ndarray
            Dechirped complex samples (same length as input).
        """
        base_chirp = self.generate_base_chirp(sf, bw)
        n_fft = len(base_chirp)
        conj_chirp = np.conj(base_chirp)

        # Tile conjugate chirp to cover full IQ length
        n_full_tiles = len(iq) // n_fft
        remainder = len(iq) % n_fft

        parts = []
        if n_full_tiles > 0:
            tiled = np.tile(conj_chirp, n_full_tiles)
            parts.append(iq[: n_full_tiles * n_fft] * tiled)
        if remainder > 0:
            parts.append(iq[n_full_tiles * n_fft :] * conj_chirp[:remainder])

        return np.concatenate(parts) if parts else np.array([], dtype=complex)

    # -- Symbol extraction --------------------------------------------------

    def extract_symbols(self, dechirped: np.ndarray, sf: int) -> np.ndarray:
        """Extract symbol values via FFT peak detection.

        Each 2^SF-sample block is FFT'd; the peak bin index is the
        symbol value (0 to 2^SF - 1).

        Parameters
        ----------
        dechirped : np.ndarray
            Dechirped complex samples.
        sf : int
            Spreading factor.

        Returns
        -------
        np.ndarray
            Integer symbol values, dtype int32.
        """
        n_fft = 2**sf
        n_symbols = len(dechirped) // n_fft
        if n_symbols == 0:
            return np.array([], dtype=np.int32)

        symbols = np.empty(n_symbols, dtype=np.int32)
        for i in range(n_symbols):
            block = dechirped[i * n_fft : (i + 1) * n_fft]
            spectrum = np.abs(np.fft.fft(block))
            symbols[i] = int(np.argmax(spectrum))

        return symbols

    # -- Preamble detection -------------------------------------------------

    @staticmethod
    def detect_preamble(symbols: np.ndarray, n_preamble: int = 8) -> bool:
        """Detect LoRa preamble: N consecutive identical symbols.

        Parameters
        ----------
        symbols : np.ndarray
            Demodulated symbol values.
        n_preamble : int
            Minimum number of consecutive identical symbols required.

        Returns
        -------
        bool
            True if preamble detected.
        """
        if len(symbols) < n_preamble:
            return False

        run = 1
        for i in range(1, len(symbols)):
            if symbols[i] == symbols[i - 1]:
                run += 1
                if run >= n_preamble:
                    return True
            else:
                run = 1

        return False

    # -- Sync word detection ------------------------------------------------

    @staticmethod
    def detect_sync_word(symbols: np.ndarray) -> int:
        """Extract sync word from the two symbols following the preamble.

        Scans for the end of the preamble run (first value change after
        8+ identical symbols) and reads the next two symbols. The sync
        word is encoded as (sym0_hi_nibble << 4) | sym1_hi_nibble.

        Parameters
        ----------
        symbols : np.ndarray
            Demodulated symbol values.

        Returns
        -------
        int
            Sync word (8-bit), or 0 if not detected.
        """
        if len(symbols) < 10:
            return 0

        # Find end of preamble run
        run = 1
        preamble_end = -1
        for i in range(1, len(symbols)):
            if symbols[i] == symbols[i - 1]:
                run += 1
            else:
                if run >= 8:
                    preamble_end = i
                    break
                run = 1

        if preamble_end < 0 or preamble_end + 1 >= len(symbols):
            return 0

        # Sync word from two symbols after preamble
        s0 = int(symbols[preamble_end])
        s1 = int(symbols[preamble_end + 1])
        sync_word = ((s0 & 0xF0) >> 4) | (s1 & 0xF0)

        return sync_word

    # -- CFO estimation -----------------------------------------------------

    def estimate_cfo(self, iq: np.ndarray, sf: int, bw: float) -> float:
        """Estimate carrier frequency offset from preamble symbol offset.

        Dechirps the first few symbols and measures the fractional bin
        offset of the preamble peak from bin 0. A non-zero offset
        indicates CFO proportional to the bin resolution.

        Parameters
        ----------
        iq : np.ndarray
            Complex IQ samples.
        sf : int
            Spreading factor.
        bw : float
            Bandwidth in Hz.

        Returns
        -------
        float
            Estimated CFO in Hz.
        """
        n_fft = 2**sf
        if len(iq) < n_fft:
            return 0.0

        base_chirp = self.generate_base_chirp(sf, bw)
        conj_chirp = np.conj(base_chirp)

        # Average several preamble symbols for robustness
        n_avg = min(4, len(iq) // n_fft)
        if n_avg == 0:
            return 0.0

        sum_spectrum = np.zeros(n_fft)
        for i in range(n_avg):
            block = iq[i * n_fft : (i + 1) * n_fft] * conj_chirp
            sum_spectrum += np.abs(np.fft.fft(block))

        # Peak bin (coarse)
        peak_bin = int(np.argmax(sum_spectrum))

        # Parabolic interpolation for fractional bin offset
        if 0 < peak_bin < n_fft - 1:
            alpha = sum_spectrum[peak_bin - 1]
            beta = sum_spectrum[peak_bin]
            gamma = sum_spectrum[peak_bin + 1]
            denom = alpha - 2.0 * beta + gamma
            if abs(denom) > 1e-12:
                frac_offset = 0.5 * (alpha - gamma) / denom
            else:
                frac_offset = 0.0
        else:
            frac_offset = 0.0

        # Convert bin offset to Hz
        # Each bin = bw / 2^SF Hz
        bin_resolution = bw / n_fft
        # Preamble symbols should land on bin 0; offset = CFO
        # Wrap around: if peak_bin > n_fft/2, it's negative offset
        if peak_bin > n_fft // 2:
            peak_bin -= n_fft

        cfo = (peak_bin + frac_offset) * bin_resolution
        return float(cfo)

    # -- SNR estimation -----------------------------------------------------

    @staticmethod
    def _estimate_snr(symbols_spectrum: np.ndarray) -> float:
        """Estimate SNR from FFT peak-to-noise floor ratio.

        Parameters
        ----------
        symbols_spectrum : np.ndarray
            FFT magnitude spectrum of a dechirped symbol.

        Returns
        -------
        float
            SNR estimate in dB.
        """
        if len(symbols_spectrum) < 4:
            return 0.0

        peak = float(np.max(symbols_spectrum))
        peak_idx = int(np.argmax(symbols_spectrum))

        # Noise floor: median of all bins excluding peak neighbourhood
        mask = np.ones(len(symbols_spectrum), dtype=bool)
        exclude_start = max(0, peak_idx - 2)
        exclude_end = min(len(symbols_spectrum), peak_idx + 3)
        mask[exclude_start:exclude_end] = False

        noise_bins = symbols_spectrum[mask]
        if len(noise_bins) == 0:
            return 0.0

        noise_floor = float(np.median(noise_bins))
        if noise_floor < 1e-12:
            return 30.0

        # SNR = peak_power / noise_power
        snr_linear = (peak**2) / (noise_floor**2)
        snr_db = float(10.0 * np.log10(max(snr_linear, 1e-6)))
        return max(-10.0, min(40.0, snr_db))

    # -- SF detection -------------------------------------------------------

    def _detect_sf(self, iq: np.ndarray, bw: float) -> int:
        """Auto-detect spreading factor by trying SF 7-12.

        For each candidate SF, dechirps one preamble-worth of symbols
        and scores by preamble symbol consistency (identical values).

        Parameters
        ----------
        iq : np.ndarray
            Complex IQ samples.
        bw : float
            Bandwidth in Hz.

        Returns
        -------
        int
            Best spreading factor (7-12).
        """
        best_sf = _SF_MIN
        best_score = -1.0

        for sf in range(_SF_MIN, _SF_MAX + 1):
            n_fft = 2**sf
            if len(iq) < n_fft * 8:
                continue

            dechirped = self.dechirp(iq, sf, bw)
            symbols = self.extract_symbols(dechirped, sf)
            if len(symbols) < 8:
                continue

            # Score: length of longest run of identical symbols in first 16
            check = symbols[: min(16, len(symbols))]
            max_run = 1
            run = 1
            for i in range(1, len(check)):
                if check[i] == check[i - 1]:
                    run += 1
                    max_run = max(max_run, run)
                else:
                    run = 1

            # Also consider FFT peak sharpness for the first symbol
            block = dechirped[:n_fft]
            spectrum = np.abs(np.fft.fft(block))
            peak = float(np.max(spectrum))
            median_floor = float(np.median(spectrum))
            sharpness = peak / median_floor if median_floor > 1e-12 else 0.0

            score = max_run + sharpness * 0.1

            if score > best_score:
                best_score = score
                best_sf = sf

        return best_sf

    # -- Full pipeline ------------------------------------------------------

    def demodulate(
        self,
        iq: np.ndarray,
        sf: int | None = None,
        bw: float | None = None,
    ) -> LoRaDemodResult:
        """Full LoRa CSS demodulation pipeline.

        Parameters
        ----------
        iq : np.ndarray
            Complex IQ samples.
        sf : int or None
            Spreading factor (7-12). Auto-detected if None.
        bw : float or None
            Bandwidth in Hz. Auto-detected if None.

        Returns
        -------
        LoRaDemodResult
            Demodulated symbols and metadata.
        """
        if len(iq) < 128:
            logger.warning(
                "IQ capture too short for LoRa demodulation (%d samples)", len(iq)
            )
            return LoRaDemodResult(
                symbols=np.array([], dtype=np.int32),
                sf=sf or _SF_MIN,
                bw_hz=bw or _STANDARD_BANDWIDTHS[0],
                cr=1,
                cfo_hz=0.0,
                snr_estimate_db=0.0,
                n_symbols=0,
                preamble_detected=False,
                sync_word=0,
                confidence=0.0,
            )

        # --- Bandwidth detection ---
        if bw is None:
            bw = self.detect_bandwidth(iq)
            logger.debug("Auto-detected BW: %.0f Hz", bw)

        # --- Spreading factor detection ---
        if sf is None:
            sf = self._detect_sf(iq, bw)
            logger.debug("Auto-detected SF: %d", sf)

        sf = max(_SF_MIN, min(_SF_MAX, sf))

        # --- CFO estimation and correction ---
        cfo_hz = self.estimate_cfo(iq, sf, bw)
        if abs(cfo_hz) > 1.0:
            t = np.arange(len(iq)) / self.sample_rate
            iq = iq * np.exp(-1j * 2.0 * np.pi * cfo_hz * t)

        # --- Dechirp and extract symbols ---
        dechirped = self.dechirp(iq, sf, bw)
        symbols = self.extract_symbols(dechirped, sf)

        if len(symbols) == 0:
            return LoRaDemodResult(
                symbols=symbols,
                sf=sf,
                bw_hz=bw,
                cr=1,
                cfo_hz=cfo_hz,
                snr_estimate_db=0.0,
                n_symbols=0,
                preamble_detected=False,
                sync_word=0,
                confidence=0.0,
            )

        # --- Preamble detection ---
        preamble_detected = self.detect_preamble(symbols)

        # --- Sync word ---
        sync_word = self.detect_sync_word(symbols) if preamble_detected else 0

        # --- SNR estimation from first dechirped block ---
        n_fft = 2**sf
        first_spectrum = (
            np.abs(np.fft.fft(dechirped[:n_fft]))
            if len(dechirped) >= n_fft
            else np.array([])
        )
        snr_db = self._estimate_snr(first_spectrum)

        # --- Coding rate (default; header parsing would refine) ---
        cr = 1

        # --- Confidence: sigmoid of SNR, boosted by preamble ---
        base_conf = float(1.0 / (1.0 + np.exp(-0.3 * (snr_db - 3.0))))
        if preamble_detected:
            base_conf = min(1.0, base_conf + 0.15)
        confidence = max(0.0, min(1.0, base_conf))

        return LoRaDemodResult(
            symbols=symbols,
            sf=sf,
            bw_hz=bw,
            cr=cr,
            cfo_hz=round(cfo_hz, 2),
            snr_estimate_db=round(snr_db, 2),
            n_symbols=len(symbols),
            preamble_detected=preamble_detected,
            sync_word=sync_word,
            confidence=round(confidence, 4),
        )
