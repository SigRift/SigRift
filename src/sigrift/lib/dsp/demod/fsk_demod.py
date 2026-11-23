"""Generalized FSK/GFSK demodulator for land-mobile radio protocols.

Demodulates M-ary FSK signals (2FSK, 4FSK) from raw IQ samples using
quadrature (arctan) discrimination, with symbol timing recovery via
Mueller-Muller TED.

Algorithm pipeline:
1. Quadrature demodulation: instantaneous frequency via arctan
   discriminator (angle of conjugate-delayed product)
2. Deviation estimation: histogram peak detection on the frequency
   signal to find M levels
3. Symbol rate estimation: autocorrelation of the magnitude signal
   to find the symbol period
4. Symbol timing recovery: Mueller-Muller timing error detector
   with first-order loop filter and linear interpolation
5. M-level adaptive threshold slicing with decision boundaries at
   midpoints between estimated deviation levels
6. Gray-coded bit mapping (DMR dibit convention for 4FSK:
   +3->00, +1->01, -1->10, -3->11)

Includes presets for DMR, P25 C4FM, and DECT.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import numpy as np

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


@dataclass
class FSKDemodResult:
    """Result of FSK/GFSK demodulation."""

    symbols: np.ndarray
    bits: list[int]
    deviation_hz: float
    symbol_rate: float
    bt: float
    modulation_index: float
    snr_estimate_db: float
    n_symbols: int
    confidence: float


@dataclass
class FSKPreset:
    """Pre-configured parameters for a known FSK protocol."""

    name: str
    m: int
    symbol_rate: float
    deviation_hz: float
    bt: float
    sample_rate: float


# ---------------------------------------------------------------------------
# Protocol presets
# ---------------------------------------------------------------------------

DMR_PRESET = FSKPreset("dmr", 4, 4800.0, 1944.0, 0.2, 2_048_000.0)
P25_PRESET = FSKPreset("p25_c4fm", 4, 4800.0, 1800.0, 0.2, 2_048_000.0)
DECT_PRESET = FSKPreset("dect", 2, 1_152_000.0, 288_000.0, 0.5, 2_048_000.0)


# ---------------------------------------------------------------------------
# 4FSK Gray decode (DMR dibit mapping)
# ---------------------------------------------------------------------------

# DMR dibit mapping: deviation level -> bits
# +3 -> 01, +1 -> 00, -1 -> 10, -3 -> 11
_DMR_4FSK_GRAY: dict[int, tuple[int, int]] = {
    3: (0, 0),
    1: (0, 1),
    -1: (1, 0),
    -3: (1, 1),
}

# Reverse for general M-ary: symbol index (0..M-1) -> Gray code
_GRAY_TABLE_4 = [0b00, 0b01, 0b11, 0b10]


# ---------------------------------------------------------------------------
# Demodulator
# ---------------------------------------------------------------------------


class FSKDemodulator:
    """Generalized M-ary FSK/GFSK demodulator.

    Parameters
    ----------
    sample_rate : float
        IQ sample rate in Hz.
    """

    def __init__(self, sample_rate: float = 2_048_000.0) -> None:
        self.sample_rate = sample_rate

    # -- Quadrature demodulation --------------------------------------------

    def quadrature_demod(self, iq: np.ndarray) -> np.ndarray:
        """Arctan discriminator: instantaneous frequency from IQ.

        Computes the angle of the conjugate-delayed product:
            freq[n] = angle(iq[n] * conj(iq[n-1]))

        The output is in radians/sample; scale by fs/(2*pi) for Hz.

        Parameters
        ----------
        iq : np.ndarray
            Complex IQ samples.

        Returns
        -------
        np.ndarray
            Instantaneous frequency signal (radians/sample).
        """
        if len(iq) < 2:
            return np.array([], dtype=np.float64)

        # Conjugate product with one-sample delay
        product = iq[1:] * np.conj(iq[:-1])
        return np.angle(product)

    # -- Deviation estimation -----------------------------------------------

    def estimate_deviation(self, freq_signal: np.ndarray) -> float:
        """Estimate peak frequency deviation using histogram analysis.

        Builds a histogram of the frequency signal and finds the two
        outermost peaks, corresponding to +/- max deviation.

        Parameters
        ----------
        freq_signal : np.ndarray
            Instantaneous frequency signal (radians/sample).

        Returns
        -------
        float
            Estimated deviation in Hz.
        """
        if len(freq_signal) < 32:
            return 0.0

        # Convert to Hz for analysis
        freq_hz = freq_signal * self.sample_rate / (2.0 * np.pi)

        # Histogram with enough bins to resolve deviation levels
        n_bins = min(256, max(64, len(freq_hz) // 32))
        counts, bin_edges = np.histogram(freq_hz, bins=n_bins)
        bin_centers = (bin_edges[:-1] + bin_edges[1:]) / 2.0

        # Smooth histogram to reduce noise
        kernel = np.ones(5) / 5.0
        if len(counts) > len(kernel):
            counts_smooth = np.convolve(counts, kernel, mode="same")
        else:
            counts_smooth = counts.astype(float)

        # Find peaks: local maxima above median
        threshold = np.median(counts_smooth) * 1.5
        peak_indices = []
        for i in range(1, len(counts_smooth) - 1):
            if (
                counts_smooth[i] > counts_smooth[i - 1]
                and counts_smooth[i] > counts_smooth[i + 1]
                and counts_smooth[i] > threshold
            ):
                peak_indices.append(i)

        if len(peak_indices) < 2:
            # Fallback: use robust percentile spread
            p5 = float(np.percentile(freq_hz, 5))
            p95 = float(np.percentile(freq_hz, 95))
            return abs(p95 - p5) / 2.0

        # Outermost peaks give the full deviation spread
        peak_freqs = [float(bin_centers[i]) for i in peak_indices]
        peak_freqs.sort()
        deviation = (peak_freqs[-1] - peak_freqs[0]) / 2.0

        return abs(deviation)

    # -- Symbol rate estimation ---------------------------------------------

    def estimate_symbol_rate(self, freq_signal: np.ndarray) -> float:
        """Estimate symbol rate via autocorrelation of magnitude signal.

        The magnitude of the FM signal has periodicity at the symbol
        rate due to inter-symbol transitions. The first strong
        autocorrelation peak (excluding lag 0) gives the symbol period.

        Parameters
        ----------
        freq_signal : np.ndarray
            Instantaneous frequency signal (radians/sample).

        Returns
        -------
        float
            Estimated symbol rate in Hz.
        """
        n = len(freq_signal)
        if n < 64:
            return 0.0

        # Work with the magnitude (captures transitions)
        sig = np.abs(freq_signal)
        sig = sig - np.mean(sig)

        # Use FFT-based autocorrelation for efficiency
        n_fft = 1
        while n_fft < 2 * n:
            n_fft *= 2

        fft_sig = np.fft.fft(sig, n=n_fft)
        autocorr = np.real(np.fft.ifft(fft_sig * np.conj(fft_sig)))
        autocorr = autocorr[:n]

        # Normalise
        if autocorr[0] > 1e-12:
            autocorr = autocorr / autocorr[0]
        else:
            return 0.0

        # Find first peak after initial decorrelation
        # Skip lags shorter than ~10 samples (too fast to be a symbol)
        min_lag = max(10, int(self.sample_rate / 100_000))
        max_lag = min(n - 1, int(self.sample_rate / 100))  # min ~100 sym/s

        best_lag = 0
        best_val = 0.0
        for i in range(min_lag + 1, min(max_lag, len(autocorr) - 1)):
            if (
                autocorr[i] > autocorr[i - 1]
                and autocorr[i] > autocorr[i + 1]
                and autocorr[i] > best_val
            ):
                best_val = autocorr[i]
                best_lag = i
                break  # First strong peak

        if best_lag == 0:
            return 0.0

        return self.sample_rate / best_lag

    # -- Mueller-Muller timing recovery ------------------------------------

    def recover_timing(
        self,
        freq_signal: np.ndarray,
        symbol_rate: float,
    ) -> np.ndarray:
        """Mueller-Muller timing error detector for symbol recovery.

        Recovers symbol-rate samples from the oversampled frequency
        signal using the M&M TED with a first-order loop filter.

        Parameters
        ----------
        freq_signal : np.ndarray
            Instantaneous frequency signal (radians/sample).
        symbol_rate : float
            Symbol rate in Hz.

        Returns
        -------
        np.ndarray
            Symbol-spaced frequency samples.
        """
        if symbol_rate <= 0 or len(freq_signal) < 4:
            return freq_signal

        sps = self.sample_rate / symbol_rate
        if sps < 1.5:
            # Already near symbol rate; just return as-is
            return freq_signal

        n = len(freq_signal)

        # Loop filter parameters
        bn_ts = 0.01
        damping = 1.0
        theta = bn_ts / (damping + 1.0 / (4.0 * damping))
        kp = 2.0 * damping * theta
        ki = theta**2

        symbols = []
        idx = float(sps)  # Start one symbol in
        loop_state = 0.0
        prev_sample = 0.0
        prev_decision = 0.0

        while idx < n - 1:
            base = int(idx)
            frac = idx - base
            if base + 1 < n:
                sample = freq_signal[base] * (1.0 - frac) + freq_signal[base + 1] * frac
            else:
                sample = float(freq_signal[base])

            symbols.append(sample)

            # M&M TED
            if len(symbols) >= 2:
                decision = np.sign(sample)
                timing_error = float(prev_decision * sample - decision * prev_sample)
                timing_error = max(-1.0, min(1.0, timing_error))

                loop_state += ki * timing_error
                adjust = kp * timing_error + loop_state
            else:
                adjust = 0.0

            prev_sample = sample
            prev_decision = np.sign(sample)
            idx += sps + adjust

        return np.array(symbols, dtype=np.float64)

    # -- Symbol slicing -----------------------------------------------------

    @staticmethod
    def slice_symbols(
        samples: np.ndarray,
        m: int,
        deviation: float,
    ) -> np.ndarray:
        """Adaptive M-level threshold slicing.

        Places decision boundaries at midpoints between M uniformly
        spaced deviation levels from -deviation to +deviation.

        For 2FSK: levels = [-dev, +dev], threshold at 0.
        For 4FSK: levels = [-3h, -h, +h, +3h] where h = dev/3.

        Parameters
        ----------
        samples : np.ndarray
            Symbol-spaced frequency samples.
        m : int
            Modulation order (2 or 4).
        deviation : float
            Peak deviation (in same units as samples).

        Returns
        -------
        np.ndarray
            Integer symbol values. For 4FSK: +3, +1, -1, -3.
            For 2FSK: +1, -1.
        """
        if len(samples) == 0:
            return np.array([], dtype=np.int32)

        if m == 2:
            # Binary: positive = +1, negative = -1
            return np.where(samples >= 0, 1, -1).astype(np.int32)

        if m == 4:
            # 4FSK levels: -3, -1, +1, +3 (normalised to deviation)
            # Decision boundaries at -2h, 0, +2h where h = deviation/3
            if deviation > 1e-12:
                h = deviation / 3.0
            else:
                # Fallback: estimate from sample distribution
                h = float(np.std(samples)) / 2.0
                if h < 1e-12:
                    h = 1.0

            thresholds = [-2.0 * h, 0.0, 2.0 * h]
            result = np.empty(len(samples), dtype=np.int32)
            for i, s in enumerate(samples):
                if s < thresholds[0]:
                    result[i] = -3
                elif s < thresholds[1]:
                    result[i] = -1
                elif s < thresholds[2]:
                    result[i] = 1
                else:
                    result[i] = 3
            return result

        # General M-ary: uniform levels
        levels = np.linspace(-(m - 1), m - 1, m)
        result = np.empty(len(samples), dtype=np.int32)
        for i, s in enumerate(samples):
            idx = int(np.argmin(np.abs(levels - s)))
            result[i] = int(levels[idx])
        return result

    # -- Bit mapping --------------------------------------------------------

    @staticmethod
    def symbols_to_bits(symbols: np.ndarray, m: int) -> list[int]:
        """Convert symbol values to bits using Gray decoding.

        For 4FSK, uses DMR dibit mapping:
            +3 -> 00, +1 -> 01, -1 -> 10, -3 -> 11

        For 2FSK:
            +1 -> 0, -1 -> 1

        Parameters
        ----------
        symbols : np.ndarray
            Integer symbol values (+3/+1/-1/-3 for 4FSK, +1/-1 for 2FSK).
        m : int
            Modulation order (2 or 4).

        Returns
        -------
        list[int]
            Decoded bit sequence.
        """
        bits: list[int] = []

        if m == 2:
            for s in symbols:
                bits.append(0 if s > 0 else 1)
            return bits

        if m == 4:
            for s in symbols:
                s_int = int(s)
                if s_int in _DMR_4FSK_GRAY:
                    b0, b1 = _DMR_4FSK_GRAY[s_int]
                else:
                    # Nearest valid level
                    nearest = min(_DMR_4FSK_GRAY.keys(), key=lambda k: abs(k - s_int))
                    b0, b1 = _DMR_4FSK_GRAY[nearest]
                bits.extend([b0, b1])
            return bits

        # General M-ary: log2(M) bits per symbol via Gray code
        bits_per_symbol = int(np.log2(m))
        levels = np.linspace(-(m - 1), m - 1, m)
        for s in symbols:
            idx = int(np.argmin(np.abs(levels - float(s))))
            # Gray encode the index
            gray = idx ^ (idx >> 1)
            for b in range(bits_per_symbol - 1, -1, -1):
                bits.append((gray >> b) & 1)
        return bits

    # -- SNR estimation -----------------------------------------------------

    @staticmethod
    def _estimate_snr(
        samples: np.ndarray,
        m: int,
        deviation: float,
    ) -> float:
        """Estimate SNR from symbol decision distances.

        Measures the mean squared distance from each sample to its
        nearest ideal level, compared to the signal power.

        Parameters
        ----------
        samples : np.ndarray
            Symbol-spaced frequency samples.
        m : int
            Modulation order.
        deviation : float
            Peak deviation (same units as samples).

        Returns
        -------
        float
            Estimated SNR in dB.
        """
        if len(samples) < 4 or deviation < 1e-12:
            return 0.0

        if m == 4:
            h = deviation / 3.0
            levels = np.array([-3.0 * h, -1.0 * h, 1.0 * h, 3.0 * h])
        elif m == 2:
            levels = np.array([-deviation, deviation])
        else:
            levels = np.linspace(-deviation, deviation, m)

        # Signal power
        signal_power = float(np.mean(levels**2))
        if signal_power < 1e-12:
            return 0.0

        # Noise: distance from nearest ideal level
        errors = np.empty(len(samples))
        for i, s in enumerate(samples):
            dists = (s - levels) ** 2
            errors[i] = float(np.min(dists))

        noise_power = float(np.mean(errors))
        if noise_power < 1e-12:
            return 30.0

        snr_db = float(10.0 * np.log10(signal_power / noise_power))
        return max(-10.0, min(40.0, snr_db))

    # -- Full pipeline ------------------------------------------------------

    def demodulate(
        self,
        iq: np.ndarray,
        preset: FSKPreset | None = None,
    ) -> FSKDemodResult:
        """Full FSK/GFSK demodulation pipeline.

        If a preset is provided, uses its parameters directly.
        Otherwise auto-detects deviation, symbol rate, and assumes
        2FSK (override by providing a preset with the correct M).

        Parameters
        ----------
        iq : np.ndarray
            Complex IQ samples.
        preset : FSKPreset or None
            Protocol preset (DMR_PRESET, P25_PRESET, DECT_PRESET, etc.).

        Returns
        -------
        FSKDemodResult
            Demodulated symbols, bits, and metadata.
        """
        if len(iq) < 16:
            logger.warning(
                "IQ capture too short for FSK demodulation (%d samples)", len(iq)
            )
            return FSKDemodResult(
                symbols=np.array([], dtype=np.int32),
                bits=[],
                deviation_hz=0.0,
                symbol_rate=0.0,
                bt=0.0,
                modulation_index=0.0,
                snr_estimate_db=0.0,
                n_symbols=0,
                confidence=0.0,
            )

        # --- Quadrature demodulation ---
        freq_signal = self.quadrature_demod(iq)

        if preset is not None:
            m = preset.m
            symbol_rate = preset.symbol_rate
            deviation_hz = preset.deviation_hz
            bt = preset.bt
            # Convert deviation to radians/sample for slicing
            deviation_rad = 2.0 * np.pi * deviation_hz / self.sample_rate
        else:
            m = 2  # Default to binary FSK for auto-detect

            # --- Auto-detect deviation ---
            deviation_hz = self.estimate_deviation(freq_signal)
            deviation_rad = 2.0 * np.pi * deviation_hz / self.sample_rate

            # --- Auto-detect symbol rate ---
            symbol_rate = self.estimate_symbol_rate(freq_signal)
            if symbol_rate <= 0:
                # Fallback: assume ~10 samples per symbol
                symbol_rate = self.sample_rate / 10.0
                logger.warning(
                    "Symbol rate auto-detection failed; using fallback %.1f Hz",
                    symbol_rate,
                )

            bt = 0.0  # Unknown for auto-detect

        # --- Timing recovery ---
        recovered = self.recover_timing(freq_signal, symbol_rate)

        if len(recovered) == 0:
            return FSKDemodResult(
                symbols=np.array([], dtype=np.int32),
                bits=[],
                deviation_hz=deviation_hz,
                symbol_rate=symbol_rate,
                bt=bt,
                modulation_index=0.0,
                snr_estimate_db=0.0,
                n_symbols=0,
                confidence=0.0,
            )

        # --- Symbol slicing ---
        symbols = self.slice_symbols(recovered, m, deviation_rad)

        # --- Bit decoding ---
        bits = self.symbols_to_bits(symbols, m)

        # --- SNR estimation ---
        snr_db = self._estimate_snr(recovered, m, deviation_rad)

        # --- Modulation index: h = 2*deviation / symbol_rate ---
        if symbol_rate > 0:
            mod_index = 2.0 * deviation_hz / symbol_rate
        else:
            mod_index = 0.0

        # --- Confidence: sigmoid mapping of SNR ---
        confidence = float(1.0 / (1.0 + np.exp(-0.25 * (snr_db - 5.0))))
        confidence = max(0.0, min(1.0, confidence))

        return FSKDemodResult(
            symbols=symbols,
            bits=bits,
            deviation_hz=round(deviation_hz, 2),
            symbol_rate=round(symbol_rate, 2),
            bt=bt,
            modulation_index=round(mod_index, 4),
            snr_estimate_db=round(snr_db, 2),
            n_symbols=len(symbols),
            confidence=round(confidence, 4),
        )
