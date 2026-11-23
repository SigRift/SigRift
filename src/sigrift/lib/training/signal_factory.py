"""Single authoritative signal generation for all 76 classes.

CRITICAL FIX: gen2 had generate_signal() duplicated across 8+ files with
inconsistent implementations. This module is the ONE place signals are generated.

FIX: Non-square QAM constellation (gen2 used 6x6 grid for "32qam" producing
36 points -- incorrect). Use proper cross-QAM constellation for 32-QAM.

v4.15.0: Added 35 protocol signal generators for TSCM, IoT, SCADA, satellite,
and ICS domains.  Wired optional channel_config into generate_signal() pipeline.

All signals:
1. Apply RRC pulse shaping where appropriate (PSK, QAM, APSK, ASK, PAM)
   using sigrift.lib.dsp.pulse_shaping
2. Normalize to unit power before noise addition
3. Optionally apply channel impairments (when channel_config provided)
4. Add AWGN at specified SNR
"""

from __future__ import annotations

import logging
from typing import Callable

import numpy as np
from scipy.signal import hilbert

logger = logging.getLogger(__name__)

# Lazy import to avoid circular dependency through sigrift.lib.dsp.__init__
# (dsp.__init__ -> fingerprint_trainer -> training.signal_factory)
_generate_ofdm_signal = None


def _get_ofdm_generator():
    global _generate_ofdm_signal
    if _generate_ofdm_signal is None:
        from sigrift.lib.dsp.ofdm import generate_ofdm_signal

        _generate_ofdm_signal = generate_ofdm_signal
    return _generate_ofdm_signal


# Default samples per symbol for digital modulations.  Used as the fallback
# when generator functions are called directly without an explicit ``sps``
# parameter.  In normal training, ``generate_signal()`` randomises SPS in
# [4, 32] and passes it explicitly -- this constant is NOT mutated at runtime.
_SPS = 8


# ---------------------------------------------------------------------------
# RRC pulse shaping (inline to avoid dependency on sigrift.lib.dsp.pulse_shaping
# which may not be written yet -- mirrors the canonical implementation)
# ---------------------------------------------------------------------------


def _rrc_taps(sps: int, alpha: float, span: int = 10) -> np.ndarray:
    """Compute root-raised cosine FIR filter taps.

    Parameters
    ----------
    sps : int
        Samples per symbol.
    alpha : float
        Roll-off factor in (0, 1].
    span : int
        Filter span in symbol periods (total length = span*sps + 1).
    """
    N = span * sps
    t = (np.arange(N + 1) - N / 2) / sps  # in symbol periods

    with np.errstate(divide="ignore", invalid="ignore"):
        num = np.sin(np.pi * t * (1 - alpha)) + 4 * alpha * t * np.cos(
            np.pi * t * (1 + alpha)
        )
        den = np.pi * t * (1 - (4 * alpha * t) ** 2)
        h = num / den

    # t == 0
    zero_mask = t == 0.0
    h[zero_mask] = 1.0 - alpha + 4.0 * alpha / np.pi

    # |t| == 1/(4*alpha) -- denominator singularity
    if alpha > 0:
        sing_mask = np.abs(np.abs(t) - 1.0 / (4.0 * alpha)) < 1e-8
        h[sing_mask] = (alpha / np.sqrt(2.0)) * (
            (1.0 + 2.0 / np.pi) * np.sin(np.pi / (4.0 * alpha))
            + (1.0 - 2.0 / np.pi) * np.cos(np.pi / (4.0 * alpha))
        )

    h = h / np.sqrt(np.sum(h**2))  # unit energy
    return h


def _apply_rrc(
    signal: np.ndarray,
    sps: int,
    alpha: float = 0.35,
) -> np.ndarray:
    """Apply RRC pulse shaping to an upsampled signal."""
    taps = _rrc_taps(sps, alpha)
    return np.convolve(signal, taps, mode="same")


def _apply_filter(
    signal: np.ndarray,
    rng: np.random.RandomState,
    sps: int,
    family: str = "",
) -> np.ndarray:
    """Apply RRC with family-specific roll-off factor range."""
    if "psk" in family:
        alpha = rng.uniform(0.2, 0.35)
    elif "qam" in family:
        alpha = rng.uniform(0.35, 0.5)
    elif "apsk" in family:
        alpha = rng.uniform(0.3, 0.45)
    else:
        alpha = rng.uniform(0.15, 0.5)
    return _apply_rrc(signal, sps=sps, alpha=alpha)


# ---------------------------------------------------------------------------
# Noise addition and power normalisation
# ---------------------------------------------------------------------------


def _normalize_power(signal: np.ndarray) -> np.ndarray:
    """Normalize signal to unit average power."""
    power = np.mean(np.abs(signal) ** 2)
    if power > 0:
        signal = signal / np.sqrt(power)
    return signal


def _add_awgn(
    signal: np.ndarray,
    snr_db: float,
    rng: np.random.RandomState,
) -> np.ndarray:
    """Add AWGN at the specified SNR (assumes signal is already unit-power)."""
    noise_power = 10.0 ** (-snr_db / 10.0)
    noise = np.sqrt(noise_power / 2) * (
        rng.randn(len(signal)) + 1j * rng.randn(len(signal))
    )
    return (signal + noise).astype(np.complex64)


# ---------------------------------------------------------------------------
# Individual modulation generators
# ---------------------------------------------------------------------------


def _generate_psk(
    n: int,
    order: int,
    rng: np.random.RandomState,
    sps: int = _SPS,
) -> np.ndarray:
    """PSK: exp(j*2*pi*k/M + offset) with RRC pulse shaping."""
    num_symbols = n // sps + 1
    symbol_indices = rng.randint(0, order, num_symbols)

    # Order-specific phase offset for distinguishable constellations
    if order == 2:
        phase_offset = 0.0
    elif order == 4:
        phase_offset = np.pi / 4
    elif order == 8:
        phase_offset = 0.0
    elif order == 16:
        phase_offset = np.pi / 16
    else:
        phase_offset = np.pi / order

    phases = 2 * np.pi * symbol_indices / order + phase_offset
    symbols = np.exp(1j * phases)

    # Realistic phase noise -- higher order is more sensitive
    phase_noise_std = 0.02 * np.log2(order)
    symbols *= np.exp(1j * rng.randn(num_symbols) * phase_noise_std)

    # Zero-insertion upsampling (correct for RRC pulse shaping)
    upsampled = np.zeros(len(symbols) * sps, dtype=complex)
    upsampled[::sps] = symbols
    signal = upsampled[:n]
    signal = _apply_filter(signal, rng, sps=sps, family="psk")
    return signal.astype(np.complex64)


def _generate_qam(
    n: int,
    order: int,
    rng: np.random.RandomState,
    sps: int = _SPS,
) -> np.ndarray:
    """QAM with correct cross-constellation for 32- and 128-QAM."""
    num_symbols = n // sps
    sqrt_order = int(np.sqrt(order))

    constellation: list[complex] = []

    if sqrt_order * sqrt_order == order:
        # Perfect square (16, 64, 256): standard rectangular grid
        for i in range(sqrt_order):
            for j in range(sqrt_order):
                real = 2 * i - sqrt_order + 1
                imag = 2 * j - sqrt_order + 1
                constellation.append(complex(real, imag))
    elif order == 32:
        # 32-QAM FIX: cross-constellation from 6x6 grid minus 4 corners = 32
        for i in range(6):
            for j in range(6):
                if (i, j) in [(0, 0), (0, 5), (5, 0), (5, 5)]:
                    continue
                real = 2 * i - 5
                imag = 2 * j - 5
                constellation.append(complex(real, imag))
    elif order == 128:
        # 128-QAM: cross from 12x12 grid minus 4 corner 2x2 blocks = 128
        for i in range(12):
            for j in range(12):
                if (i < 2 and j < 2) or (i < 2 and j >= 10):
                    continue
                if (i >= 10 and j < 2) or (i >= 10 and j >= 10):
                    continue
                real = 2 * i - 11
                imag = 2 * j - 11
                constellation.append(complex(real, imag))
    else:
        # Fallback rectangular approximation for unexpected orders
        cols = int(np.ceil(np.sqrt(order * 2)))
        rows = int(np.ceil(order / cols))
        for i in range(rows):
            for j in range(cols):
                if len(constellation) >= order:
                    break
                real = 2 * j - cols + 1
                imag = 2 * i - rows + 1
                constellation.append(complex(real, imag))

    points = np.array(constellation[:order])
    points = points / np.sqrt(np.mean(np.abs(points) ** 2))

    symbol_indices = rng.randint(0, len(points), num_symbols)
    symbols = points[symbol_indices]
    # Zero-insertion upsampling (correct for RRC pulse shaping)
    upsampled = np.zeros(len(symbols) * sps, dtype=complex)
    upsampled[::sps] = symbols
    signal = upsampled[:n]
    signal = _apply_filter(signal, rng, sps=sps, family="qam")
    return signal.astype(np.complex64)


def _generate_apsk(
    n: int,
    order: int,
    rng: np.random.RandomState,
    sps: int = _SPS,
) -> np.ndarray:
    """APSK with concentric rings (DVB-S2 style configurations)."""
    num_symbols = n // sps

    constellation: list[complex] = []
    if order == 16:
        # 4 inner + 12 outer
        r1 = 1.0
        r2 = rng.uniform(2.3, 2.8) * r1
        for k in range(4):
            constellation.append(r1 * np.exp(1j * 2 * np.pi * k / 4))
        for k in range(12):
            constellation.append(r2 * np.exp(1j * 2 * np.pi * k / 12))
    elif order == 32:
        # 4 + 12 + 16
        r1 = 1.0
        r2 = rng.uniform(2.0, 2.5)
        r3 = rng.uniform(3.2, 4.0)
        for k in range(4):
            constellation.append(r1 * np.exp(1j * 2 * np.pi * k / 4))
        for k in range(12):
            constellation.append(r2 * np.exp(1j * 2 * np.pi * k / 12))
        for k in range(16):
            constellation.append(r3 * np.exp(1j * 2 * np.pi * k / 16))
    elif order == 64:
        # 4 + 12 + 20 + 28
        r1 = 1.0
        r2 = rng.uniform(1.8, 2.2)
        r3 = rng.uniform(2.8, 3.5)
        r4 = rng.uniform(4.0, 5.0)
        for pts, r in [(4, r1), (12, r2), (20, r3), (28, r4)]:
            for k in range(pts):
                constellation.append(r * np.exp(1j * 2 * np.pi * k / pts))
    elif order == 128:
        # 4 + 12 + 20 + 28 + 32 + 32
        base_radii = [1.0, 1.8, 2.8, 3.8, 4.9, 6.0]
        radii = [r * rng.uniform(0.9, 1.1) for r in base_radii]
        pts_per_ring = [4, 12, 20, 28, 32, 32]
        for pts, r in zip(pts_per_ring, radii):
            for k in range(pts):
                constellation.append(r * np.exp(1j * 2 * np.pi * k / pts))
    else:
        # Fallback: distribute points across rings
        num_rings = max(int(np.log2(order)), 1)
        pts_so_far = 0
        for ring in range(num_rings):
            r = float(ring + 1)
            pts_in_ring = min(4 * (ring + 1), order - pts_so_far)
            for k in range(pts_in_ring):
                constellation.append(r * np.exp(1j * 2 * np.pi * k / pts_in_ring))
            pts_so_far += pts_in_ring

    points = np.array(constellation[:order])
    points = points / np.sqrt(np.mean(np.abs(points) ** 2))

    symbol_indices = rng.randint(0, len(points), num_symbols)
    symbols = points[symbol_indices]
    # Zero-insertion upsampling (correct for RRC pulse shaping)
    upsampled = np.zeros(len(symbols) * sps, dtype=complex)
    upsampled[::sps] = symbols
    signal = upsampled[:n]
    signal = _apply_filter(signal, rng, sps=sps, family="apsk")
    return signal.astype(np.complex64)


def _generate_ask(
    n: int,
    order: int,
    rng: np.random.RandomState,
    sps: int = _SPS,
) -> np.ndarray:
    """ASK: unipolar amplitude levels with RRC shaping."""
    num_symbols = n // sps
    levels = np.linspace(0.2, 1.0, order)
    symbol_indices = rng.randint(0, order, num_symbols)
    symbols = levels[symbol_indices]
    # Zero-insertion upsampling (correct for RRC pulse shaping)
    upsampled = np.zeros(len(symbols) * sps, dtype=complex)
    upsampled[::sps] = symbols
    signal = upsampled[:n]
    signal = _apply_filter(signal, rng, sps=sps, family="ask")
    return signal.astype(np.complex64)


def _generate_pam(
    n: int,
    order: int,
    rng: np.random.RandomState,
    sps: int = _SPS,
) -> np.ndarray:
    """PAM: bipolar real-valued symbols shifted to complex baseband."""
    num_symbols = n // sps
    # Bipolar levels: ..., -3, -1, +1, +3, ...
    levels = np.linspace(-(order - 1), order - 1, order)
    levels = levels / np.sqrt(np.mean(levels**2))
    symbol_indices = rng.randint(0, order, num_symbols)
    symbols = levels[symbol_indices]
    # Zero-insertion upsampling (correct for RRC pulse shaping)
    upsampled = np.zeros(len(symbols) * sps, dtype=complex)
    upsampled[::sps] = symbols
    signal = upsampled[:n]
    # RRC first while still at baseband
    signal = _apply_filter(signal, rng, sps=sps, family="pam")
    # Shift to complex baseband with small frequency offset
    freq_offset = rng.uniform(-0.05, 0.05)
    t = np.arange(len(signal))
    signal = signal * np.exp(1j * 2 * np.pi * freq_offset * t)
    return signal.astype(np.complex64)


def _generate_fsk(
    n: int,
    order: int,
    gaussian: bool,
    rng: np.random.RandomState,
    sps: int = _SPS,
) -> np.ndarray:
    """FSK / GFSK with constant frequency spacing between tones."""
    num_symbols = n // sps
    # Modulation index h in [0.3, 1.0] -- realistic FSK deviation.
    # Frequency deviation per symbol = h / (2 * sps) in normalised frequency.
    mod_index = rng.uniform(0.3, 1.0)
    freq_spacing = mod_index / sps
    symbol_indices = rng.randint(0, order, num_symbols)
    freqs = freq_spacing * (symbol_indices - (order - 1) / 2)
    freq_signal = np.repeat(freqs, sps)[:n]

    if gaussian:
        # Gaussian filter for GFSK (BT=0.5)
        bt = 0.5
        span = 2 * sps
        t = np.arange(-span, span + 1)
        h = np.exp(-2 * (np.pi * bt * t / sps) ** 2)
        h = h / h.sum()
        freq_signal = np.convolve(freq_signal, h, mode="same")

    phase = np.cumsum(2 * np.pi * freq_signal)
    signal = np.exp(1j * phase)
    return signal.astype(np.complex64)


def _generate_msk(
    n: int,
    order: int,
    gaussian: bool,
    rng: np.random.RandomState,
    sps: int = _SPS,
) -> np.ndarray:
    """MSK / GMSK: FSK with modulation index h=0.5."""
    num_symbols = n // sps
    h = 0.5 / max(np.log2(order), 1.0)

    symbol_indices = rng.randint(0, order, num_symbols)
    if order == 2:
        freq_devs = h * (2 * symbol_indices - 1).astype(np.float64)
    else:
        freq_devs = (
            h * (2 * symbol_indices - order + 1).astype(np.float64) / max(order - 1, 1)
        )

    freq_signal = np.repeat(freq_devs, sps)[:n]

    if gaussian:
        # GMSK: Gaussian filter (BT=0.3, GSM standard)
        bt = 0.3
        span = 4 * sps
        t = np.arange(-span, span + 1)
        h_gauss = np.exp(-2 * (np.pi * bt * t / sps) ** 2)
        h_gauss = h_gauss / h_gauss.sum()
        freq_signal = np.convolve(freq_signal, h_gauss, mode="same")

    phase = np.cumsum(2 * np.pi * freq_signal)
    signal = np.exp(1j * phase)
    return signal.astype(np.complex64)


def _generate_ofdm(
    n: int,
    num_subcarriers: int,
    rng: np.random.RandomState,
) -> np.ndarray:
    """OFDM via sigrift.lib.dsp.ofdm with random subcarrier modulation."""
    modulation = rng.choice(["bpsk", "qpsk", "16qam", "64qam"])
    gen_ofdm = _get_ofdm_generator()
    return gen_ofdm(
        n_samples=n,
        num_subcarriers=num_subcarriers,
        cp_fraction=0.25,
        modulation=modulation,
        guard_fraction=0.0625,
        rng=rng,
    )


def _generate_lora_css(
    n: int,
    rng: np.random.RandomState,
) -> np.ndarray:
    """LoRa chirp spread spectrum: SF=7..12, BW={125,250,500}kHz."""
    sf = rng.randint(7, 13)  # 7..12 inclusive

    # Bandwidth options normalised to ~2 MHz sample rate
    bw_options = [0.061, 0.122, 0.244]
    bw_normalized = bw_options[rng.randint(0, 3)]

    samples_per_symbol = 2**sf
    oversample = int(1.0 / bw_normalized)
    effective_sps = min(samples_per_symbol * oversample // 4, n // 2)
    effective_sps = max(effective_sps, 32)

    num_symbols = n // effective_sps + 1
    symbols = rng.randint(0, 2**sf, num_symbols)

    signal = np.zeros(n, dtype=np.complex64)
    idx = 0

    for symbol in symbols:
        if idx >= n:
            break

        chirp_len = min(effective_sps, n - idx)
        t = np.arange(chirp_len) / chirp_len

        # Base up-chirp with cyclic symbol-dependent frequency offset
        freq_offset = (symbol / (2**sf)) * bw_normalized
        inst_freq = t * bw_normalized - bw_normalized / 2 + freq_offset
        inst_freq = (
            (inst_freq + bw_normalized / 2) % bw_normalized
        ) - bw_normalized / 2

        phase = 2 * np.pi * np.cumsum(inst_freq) + rng.uniform(0, 2 * np.pi)
        signal[idx : idx + chirp_len] = np.exp(1j * phase)
        idx += chirp_len

    # Occasionally insert down-chirps (preamble/sync)
    if rng.random() < 0.3:
        down_start = rng.randint(0, max(1, n - effective_sps))
        down_len = min(effective_sps, n - down_start)
        t = np.arange(down_len) / down_len
        inst_freq = -t * bw_normalized + bw_normalized / 2
        phase = 2 * np.pi * np.cumsum(inst_freq)
        signal[down_start : down_start + down_len] = np.exp(1j * phase)

    return signal.astype(np.complex64)


def _generate_am_dsb(
    n: int,
    rng: np.random.RandomState,
) -> np.ndarray:
    """AM double sideband."""
    t = np.arange(n)
    mod_freq = rng.uniform(0.005, 0.02)
    modulating = np.sin(2 * np.pi * mod_freq * t)
    modulating += 0.3 * np.sin(2 * np.pi * 2 * mod_freq * t)
    modulating += 0.1 * np.sin(2 * np.pi * 3 * mod_freq * t)
    mod_depth = rng.uniform(0.3, 0.9)
    carrier_freq = rng.uniform(0.1, 0.2)
    carrier = np.exp(1j * 2 * np.pi * carrier_freq * t)
    signal = (
        1 + mod_depth * modulating / (np.max(np.abs(modulating)) + 1e-10)
    ) * carrier
    return signal.astype(np.complex64)


def _generate_am_ssb(
    n: int,
    rng: np.random.RandomState,
) -> np.ndarray:
    """AM single sideband via Hilbert transform."""
    t = np.arange(n)
    mod_freq = rng.uniform(0.005, 0.02)
    modulating = np.sin(2 * np.pi * mod_freq * t)
    modulating += 0.3 * np.sin(2 * np.pi * 2 * mod_freq * t)
    analytic = hilbert(modulating)
    carrier_freq = rng.uniform(0.1, 0.2)
    if rng.rand() > 0.5:
        signal = analytic * np.exp(1j * 2 * np.pi * carrier_freq * t)
    else:
        signal = np.conj(analytic) * np.exp(1j * 2 * np.pi * carrier_freq * t)
    return signal.astype(np.complex64)


def _generate_fm(
    n: int,
    rng: np.random.RandomState,
) -> np.ndarray:
    """FM: narrowband and wideband variants."""
    t = np.arange(n)
    is_wideband = rng.random() < 0.5

    if is_wideband:
        # Wideband FM (broadcast-style)
        num_tones = rng.randint(3, 8)
        modulating = np.zeros(n)
        for i in range(num_tones):
            freq = rng.uniform(0.001, 0.015)
            amp = rng.uniform(0.3, 1.0) / (i + 1)
            phase = rng.uniform(0, 2 * np.pi)
            modulating += amp * np.sin(2 * np.pi * freq * t + phase)

        # Filtered noise for speech/music texture
        noise_content = np.convolve(rng.randn(n), np.ones(50) / 50, mode="same")
        modulating += rng.uniform(0.1, 0.3) * noise_content

        # 19 kHz stereo pilot tone (70% chance)
        if rng.random() < 0.7:
            pilot_freq = 0.00928  # ~19 kHz at 2.048 MHz
            modulating += 0.1 * np.sin(2 * np.pi * pilot_freq * t)

        modulating = modulating / (np.max(np.abs(modulating)) + 1e-10)
        beta = rng.uniform(4.0, 12.0)
        carrier_freq = rng.uniform(0.02, 0.1)
        max_audio_freq = 0.015
    else:
        # Narrowband FM (amateur / NOAA / FRS)
        num_tones = rng.randint(1, 4)
        modulating = np.zeros(n)
        for i in range(num_tones):
            mf = rng.uniform(0.0005, 0.003)
            amp = 1.0 / (i + 1)
            modulating += amp * np.sin(2 * np.pi * mf * t + rng.uniform(0, 2 * np.pi))
        modulating = modulating / (np.max(np.abs(modulating)) + 1e-10)
        beta = rng.uniform(1.0, 4.0)
        carrier_freq = rng.uniform(0.05, 0.2)
        max_audio_freq = 0.003

    fd = beta * max_audio_freq
    inst_phase = 2 * np.pi * carrier_freq * t + 2 * np.pi * fd * np.cumsum(modulating)
    signal = np.exp(1j * inst_phase)
    return signal.astype(np.complex64)


def _generate_tone(
    n: int,
    rng: np.random.RandomState,
) -> np.ndarray:
    """Single carrier tone with optional small drift."""
    t = np.arange(n)
    freq = rng.uniform(0.05, 0.3)
    phase = rng.uniform(0, 2 * np.pi)
    drift = rng.uniform(-1e-6, 1e-6)
    signal = np.exp(1j * (2 * np.pi * freq * t + phase + drift * t * t))
    return signal.astype(np.complex64)


def _generate_noise(
    n: int,
    rng: np.random.RandomState,
) -> np.ndarray:
    """Pure Gaussian noise -- no signal component.

    Used as a dedicated noise-only class so the classifier can learn to
    distinguish 'no signal present' from low-SNR modulations.
    """
    signal = (rng.randn(n) + 1j * rng.randn(n)).astype(np.complex64)
    return signal


# ---------------------------------------------------------------------------
# Gaussian frequency filter helper (shared by GFSK/GMSK protocol generators)
# ---------------------------------------------------------------------------


def _gauss_filter(freq_signal: np.ndarray, bt: float, sps: int) -> np.ndarray:
    """Apply Gaussian frequency smoothing for GFSK/GMSK variants."""
    span = max(2 * sps, 4)
    t = np.arange(-span, span + 1)
    h = np.exp(-2 * (np.pi * bt * t / sps) ** 2)
    h = h / h.sum()
    return np.convolve(freq_signal, h, mode="same")


# ---------------------------------------------------------------------------
# Protocol-specific signal generators (v4.15.0)
# ---------------------------------------------------------------------------


def _generate_adsb(
    n: int,
    rng: np.random.RandomState,
) -> np.ndarray:
    """ADS-B 1090 MHz Mode-S: PPM pulse-position encoding."""
    signal = np.zeros(n, dtype=np.complex64)
    us = max(int(2.048e6 / 1e6), 1)
    for pulse_us in [0.0, 1.0, 3.5, 4.5]:
        start = int(pulse_us * us)
        end = min(start + us, n)
        if start < n:
            signal[start:end] = 1.0

    msg_bits = rng.randint(0, 2, rng.choice([56, 112]))
    data_start = int(8 * us)
    for i, bit in enumerate(msg_bits):
        chip_start = data_start + i * 2 * us
        if bit == 1:
            s, e = chip_start, min(chip_start + us, n)
        else:
            s, e = chip_start + us, min(chip_start + 2 * us, n)
        if s < n:
            signal[s : min(e, n)] = 1.0

    used = data_start + len(msg_bits) * 2 * us
    if used > 0 and used < n:
        reps = n // used + 1
        signal = np.tile(signal[:used], reps)[:n]

    return signal.astype(np.complex64)


def _generate_uat(
    n: int,
    rng: np.random.RandomState,
) -> np.ndarray:
    """UAT 978 MHz: PPM-like encoding at 1.041667 Mbps."""
    signal = np.zeros(n, dtype=np.complex64)
    bit_rate = 1.041667e6
    sps = max(int(2.048e6 / bit_rate), 2)
    half = sps // 2

    num_bits = n // sps + 1
    bits = rng.randint(0, 2, num_bits)

    for i, bit in enumerate(bits):
        base = i * sps
        if bit == 1:
            s, e = base, min(base + half, n)
        else:
            s, e = base + half, min(base + sps, n)
        if s < n:
            signal[s : min(e, n)] = 1.0

    return signal[:n].astype(np.complex64)


def _generate_tpms(
    n: int,
    rng: np.random.RandomState,
) -> np.ndarray:
    """TPMS ~315/433 MHz: OOK with Manchester encoding, ~20 kbps."""
    data_rate = 20e3
    sps = max(int(2.048e6 / data_rate), 4)
    half = sps // 2

    num_bits = n // sps + 1
    bits = rng.randint(0, 2, min(num_bits, 100))

    signal = np.zeros(n, dtype=np.complex64)
    idx = 0
    for bit in bits:
        if idx + sps > n:
            break
        if bit == 1:
            signal[idx : idx + half] = 0.0
            signal[idx + half : idx + sps] = 1.0
        else:
            signal[idx : idx + half] = 1.0
            signal[idx + half : idx + sps] = 0.0
        idx += sps

    if idx > 0 and idx < n:
        reps = n // idx + 1
        signal = np.tile(signal[:idx], reps)[:n]

    return signal.astype(np.complex64)


def _generate_dect(
    n: int,
    rng: np.random.RandomState,
    sps: int = _SPS,
) -> np.ndarray:
    """DECT: GFSK BT=0.5, 1.152 Msps symbol rate, TDD burst."""
    sym_rate = 1.152e6
    eff_sps = max(int(2.048e6 / sym_rate), 2)
    num_symbols = n // eff_sps + 1

    preamble = np.array([0, 1] * 12)
    data = rng.randint(0, 2, max(num_symbols - 24, 10))
    all_bits = np.concatenate([preamble, data])[:num_symbols]

    freq_dev = 0.5 / eff_sps
    freqs = freq_dev * (2 * all_bits - 1).astype(np.float64)
    freq_signal = np.repeat(freqs, eff_sps)[:n]
    freq_signal = _gauss_filter(freq_signal, bt=0.5, sps=eff_sps)

    phase = np.cumsum(2 * np.pi * freq_signal)
    return np.exp(1j * phase).astype(np.complex64)


def _generate_zwave(
    n: int,
    rng: np.random.RandomState,
    sps: int = _SPS,
) -> np.ndarray:
    """Z-Wave: FSK with preamble 0x55*10 + SOF 0xF0."""
    data_rate = rng.choice([9.6e3, 40e3, 100e3])
    eff_sps = max(int(2.048e6 / data_rate), 2)
    num_symbols = n // eff_sps + 1

    preamble = np.tile([0, 1], 40)
    sof = np.array([1, 1, 1, 1, 0, 0, 0, 0])
    data = rng.randint(0, 2, max(num_symbols - 88, 10))
    all_bits = np.concatenate([preamble, sof, data])[:num_symbols]

    mod_index = rng.uniform(0.5, 1.0)
    freq_dev = mod_index / (2 * eff_sps)
    freqs = freq_dev * (2 * all_bits - 1).astype(np.float64)
    freq_signal = np.repeat(freqs, eff_sps)[:n]

    phase = np.cumsum(2 * np.pi * freq_signal)
    return np.exp(1j * phase).astype(np.complex64)


def _generate_p25(
    n: int,
    rng: np.random.RandomState,
    sps: int = _SPS,
) -> np.ndarray:
    """P25 Phase I: C4FM (4-level FSK), 4800 baud."""
    baud = 4800
    eff_sps = max(int(2.048e6 / baud), 2)
    num_symbols = n // eff_sps + 1

    levels = np.array([-3, -1, 1, 3], dtype=np.float64)
    symbol_indices = rng.randint(0, 4, num_symbols)
    symbols = levels[symbol_indices]

    dev_norm = 1.8e3 / 2.048e6
    freqs = dev_norm * symbols / 3.0
    freq_signal = np.repeat(freqs, eff_sps)[:n]
    freq_signal = _gauss_filter(freq_signal, bt=0.2, sps=eff_sps)

    phase = np.cumsum(2 * np.pi * freq_signal)
    return np.exp(1j * phase).astype(np.complex64)


def _generate_wisun(
    n: int,
    rng: np.random.RandomState,
    sps: int = _SPS,
) -> np.ndarray:
    """Wi-SUN: 2-FSK or 4-FSK, 50-300 kbps."""
    data_rate = rng.choice([50e3, 100e3, 150e3, 200e3, 300e3])
    order = rng.choice([2, 4])
    eff_sps = max(int(2.048e6 / data_rate), 2)
    num_symbols = n // eff_sps + 1

    mod_index = rng.uniform(0.5, 1.0)
    freq_dev = mod_index / (2 * eff_sps)
    symbol_indices = rng.randint(0, order, num_symbols)
    freqs = (
        freq_dev
        * (2 * symbol_indices - (order - 1)).astype(np.float64)
        / max(order - 1, 1)
    )
    freq_signal = np.repeat(freqs, eff_sps)[:n]

    phase = np.cumsum(2 * np.pi * freq_signal)
    return np.exp(1j * phase).astype(np.complex64)


def _generate_scada_fsk(
    n: int,
    rng: np.random.RandomState,
) -> np.ndarray:
    """SCADA Bell 202: 1200 baud, mark=1200 Hz, space=2200 Hz."""
    baud = 1200
    eff_sps = max(int(2.048e6 / baud), 2)
    num_symbols = n // eff_sps + 1

    bits = rng.randint(0, 2, num_symbols)
    f_mark = 1200.0 / 2.048e6
    f_space = 2200.0 / 2.048e6
    freqs = np.where(bits == 1, f_mark, f_space)
    freq_signal = np.repeat(freqs, eff_sps)[:n]

    phase = np.cumsum(2 * np.pi * freq_signal)
    return np.exp(1j * phase).astype(np.complex64)


def _generate_dmr(
    n: int,
    rng: np.random.RandomState,
    sps: int = _SPS,
) -> np.ndarray:
    """DMR: 4FSK TDMA, 4800 baud, 12.5 kHz channel."""
    baud = 4800
    eff_sps = max(int(2.048e6 / baud), 2)
    num_symbols = n // eff_sps + 1

    levels = np.array([-3, -1, 1, 3], dtype=np.float64)
    symbol_indices = rng.randint(0, 4, num_symbols)
    symbols = levels[symbol_indices]

    dev_norm = 1.944e3 / 2.048e6
    freqs = dev_norm * symbols / 3.0
    freq_signal = np.repeat(freqs, eff_sps)[:n]
    freq_signal = _gauss_filter(freq_signal, bt=0.2, sps=eff_sps)

    phase = np.cumsum(2 * np.pi * freq_signal)
    return np.exp(1j * phase).astype(np.complex64)


def _generate_tetra(
    n: int,
    rng: np.random.RandomState,
    sps: int = _SPS,
) -> np.ndarray:
    """TETRA: pi/4-DQPSK, 18 kbaud, 25 kHz channel."""
    baud = 18000
    eff_sps = max(int(2.048e6 / baud), 2)
    num_symbols = n // eff_sps + 1

    dphases = np.array([np.pi / 4, 3 * np.pi / 4, -3 * np.pi / 4, -np.pi / 4])
    phase_indices = rng.randint(0, 4, num_symbols)
    cumulative_phase = np.cumsum(dphases[phase_indices])

    symbols = np.exp(1j * cumulative_phase)
    upsampled = np.zeros(len(symbols) * eff_sps, dtype=complex)
    upsampled[::eff_sps] = symbols
    signal = upsampled[:n]
    signal = _apply_rrc(signal, sps=eff_sps, alpha=0.35)
    return signal.astype(np.complex64)


def _generate_pocsag(
    n: int,
    rng: np.random.RandomState,
    sps: int = _SPS,
) -> np.ndarray:
    """POCSAG paging: 2-FSK, +/-4.5 kHz dev, 512/1200/2400 baud."""
    baud = rng.choice([512, 1200, 2400])
    eff_sps = max(int(2.048e6 / baud), 2)
    num_symbols = n // eff_sps + 1

    sync_bits = np.array([int(b) for b in format(0x7CD215D8, "032b")])
    data = rng.randint(0, 2, max(num_symbols - 32, 10))
    all_bits = np.concatenate([sync_bits, data])[:num_symbols]

    dev_norm = 4.5e3 / 2.048e6
    freqs = dev_norm * (2 * all_bits - 1).astype(np.float64)
    freq_signal = np.repeat(freqs, eff_sps)[:n]

    phase = np.cumsum(2 * np.pi * freq_signal)
    return np.exp(1j * phase).astype(np.complex64)


def _generate_ais(
    n: int,
    rng: np.random.RandomState,
    sps: int = _SPS,
) -> np.ndarray:
    """AIS: GMSK BT=0.4, 9600 bps, HDLC framing."""
    baud = 9600
    eff_sps = max(int(2.048e6 / baud), 2)
    num_symbols = n // eff_sps + 1

    flag = np.array([0, 1, 1, 1, 1, 1, 1, 0])
    data = rng.randint(0, 2, max(num_symbols - 16, 10))
    all_bits = np.concatenate([flag, data, flag])[:num_symbols]

    h = 0.5 / eff_sps
    freqs = h * (2 * all_bits - 1).astype(np.float64)
    freq_signal = np.repeat(freqs, eff_sps)[:n]
    freq_signal = _gauss_filter(freq_signal, bt=0.4, sps=eff_sps)

    phase = np.cumsum(2 * np.pi * freq_signal)
    return np.exp(1j * phase).astype(np.complex64)


def _generate_dstar(
    n: int,
    rng: np.random.RandomState,
    sps: int = _SPS,
) -> np.ndarray:
    """D-STAR: GMSK BT=0.5, 4800 bps with frame sync."""
    baud = 4800
    eff_sps = max(int(2.048e6 / baud), 2)
    num_symbols = n // eff_sps + 1

    sync = np.array([int(b) for b in format(0x55556EA5, "032b")])
    data = rng.randint(0, 2, max(num_symbols - 32, 10))
    all_bits = np.concatenate([sync, data])[:num_symbols]

    h = 0.5 / eff_sps
    freqs = h * (2 * all_bits - 1).astype(np.float64)
    freq_signal = np.repeat(freqs, eff_sps)[:n]
    freq_signal = _gauss_filter(freq_signal, bt=0.5, sps=eff_sps)

    phase = np.cumsum(2 * np.pi * freq_signal)
    return np.exp(1j * phase).astype(np.complex64)


def _generate_gsm(
    n: int,
    rng: np.random.RandomState,
    sps: int = _SPS,
) -> np.ndarray:
    """GSM: GMSK BT=0.3, 270.833 kbaud, 577us timeslot."""
    baud = 270833
    eff_sps = max(int(2.048e6 / baud), 2)
    num_symbols = n // eff_sps + 1

    if rng.random() < 0.3:
        freq_norm = 67.7e3 / 2.048e6
        t = np.arange(n)
        return np.exp(1j * 2 * np.pi * freq_norm * t).astype(np.complex64)

    data1 = rng.randint(0, 2, 58)
    midamble = np.array(
        [0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1]
    )
    data2 = rng.randint(0, 2, 58)
    tail = np.zeros(3, dtype=int)
    burst = np.concatenate([tail, data1, midamble, data2, tail])[:num_symbols]
    if len(burst) < num_symbols:
        burst = np.concatenate([burst, rng.randint(0, 2, num_symbols - len(burst))])

    h = 0.5 / eff_sps
    freqs = h * (2 * burst - 1).astype(np.float64)
    freq_signal = np.repeat(freqs, eff_sps)[:n]
    freq_signal = _gauss_filter(freq_signal, bt=0.3, sps=eff_sps)

    phase = np.cumsum(2 * np.pi * freq_signal)
    return np.exp(1j * phase).astype(np.complex64)


def _generate_nrf24(
    n: int,
    rng: np.random.RandomState,
    sps: int = _SPS,
) -> np.ndarray:
    """nRF24L01+: GFSK BT=0.5, 1 or 2 Mbps, 1 MHz channels."""
    data_rate = rng.choice([1e6, 2e6])
    eff_sps = max(int(2.048e6 / data_rate), 2)
    num_symbols = n // eff_sps + 1

    preamble_byte = rng.choice([0xAA, 0x55])
    preamble = np.array([int(b) for b in format(preamble_byte, "08b")])
    data = rng.randint(0, 2, max(num_symbols - 8, 10))
    all_bits = np.concatenate([preamble, data])[:num_symbols]

    mod_index = rng.uniform(0.4, 0.6)
    freq_dev = mod_index / (2 * eff_sps)
    freqs = freq_dev * (2 * all_bits - 1).astype(np.float64)
    freq_signal = np.repeat(freqs, eff_sps)[:n]
    freq_signal = _gauss_filter(freq_signal, bt=0.5, sps=eff_sps)

    phase = np.cumsum(2 * np.pi * freq_signal)
    return np.exp(1j * phase).astype(np.complex64)


def _generate_fpv_analog(
    n: int,
    rng: np.random.RandomState,
) -> np.ndarray:
    """FPV analog video: wideband FM with video sync pulses."""
    t = np.arange(n)
    h_sync_freq = 15.734e3 / 2.048e6
    video = np.zeros(n, dtype=np.float64)

    video += 0.3 * np.sign(np.sin(2 * np.pi * h_sync_freq * t))

    content = np.convolve(rng.randn(n), np.ones(20) / 20, mode="same")
    video += 0.5 * content / (np.max(np.abs(content)) + 1e-10)
    video = video / (np.max(np.abs(video)) + 1e-10)

    beta = rng.uniform(8.0, 15.0)
    carrier_freq = rng.uniform(0.05, 0.15)
    max_video_freq = 0.02
    fd = beta * max_video_freq
    inst_phase = 2 * np.pi * carrier_freq * t + 2 * np.pi * fd * np.cumsum(video)
    return np.exp(1j * inst_phase).astype(np.complex64)


def _generate_pmr446(
    n: int,
    rng: np.random.RandomState,
) -> np.ndarray:
    """PMR446: narrowband FM +/-2.5 kHz deviation with CTCSS sub-tone."""
    t = np.arange(n)
    ctcss_freq = rng.uniform(67.0, 254.0) / 2.048e6
    ctcss = 0.15 * np.sin(2 * np.pi * ctcss_freq * t)

    num_tones = rng.randint(1, 4)
    audio = np.zeros(n)
    for i in range(num_tones):
        af = rng.uniform(300, 3000) / 2.048e6
        audio += (1.0 / (i + 1)) * np.sin(
            2 * np.pi * af * t + rng.uniform(0, 2 * np.pi)
        )

    modulating = ctcss + audio
    modulating = modulating / (np.max(np.abs(modulating)) + 1e-10)

    dev = 2.5e3 / 2.048e6
    carrier_freq = rng.uniform(0.05, 0.2)
    inst_phase = 2 * np.pi * carrier_freq * t + 2 * np.pi * dev * np.cumsum(modulating)
    return np.exp(1j * inst_phase).astype(np.complex64)


def _generate_wireless_mic(
    n: int,
    rng: np.random.RandomState,
) -> np.ndarray:
    """Wireless microphone: NFM +/-5 kHz deviation, low power."""
    t = np.arange(n)
    num_tones = rng.randint(2, 6)
    audio = np.zeros(n)
    for i in range(num_tones):
        af = rng.uniform(300, 3000) / 2.048e6
        audio += (1.0 / (i + 1)) * np.sin(
            2 * np.pi * af * t + rng.uniform(0, 2 * np.pi)
        )
    audio = audio / (np.max(np.abs(audio)) + 1e-10)

    dev = 5.0e3 / 2.048e6
    carrier_freq = rng.uniform(0.05, 0.2)
    inst_phase = 2 * np.pi * carrier_freq * t + 2 * np.pi * dev * np.cumsum(audio)
    signal = np.exp(1j * inst_phase)

    extra_noise = 0.3 * (rng.randn(n) + 1j * rng.randn(n))
    return (signal + extra_noise).astype(np.complex64)


def _generate_sigfox(
    n: int,
    rng: np.random.RandomState,
) -> np.ndarray:
    """Sigfox: ultra-narrowband DBPSK, ~100 Hz BW, ~100 bps."""
    baud = 100
    eff_sps = max(int(2.048e6 / baud), 2)
    num_symbols = n // eff_sps + 1

    bits = rng.randint(0, 2, num_symbols)
    dphases = np.pi * bits
    phases = np.cumsum(dphases)
    symbols = np.exp(1j * phases)

    upsampled = np.zeros(len(symbols) * eff_sps, dtype=complex)
    upsampled[::eff_sps] = symbols
    signal = upsampled[:n]
    signal = _apply_rrc(signal, sps=eff_sps, alpha=0.3)
    return signal.astype(np.complex64)


def _generate_nbiot(
    n: int,
    rng: np.random.RandomState,
) -> np.ndarray:
    """NB-IoT: narrow OFDM, 12 subcarriers x 15 kHz = 180 kHz."""
    nfft = 128
    active = 12
    cp_len = nfft // 4
    symbol_len = nfft + cp_len

    signal = np.zeros(n, dtype=np.complex64)
    idx = 0
    while idx + symbol_len <= n:
        freq = np.zeros(nfft, dtype=np.complex128)
        start_sc = (nfft - active) // 2
        for k in range(active):
            phase = rng.choice([np.pi / 4, 3 * np.pi / 4, -np.pi / 4, -3 * np.pi / 4])
            freq[start_sc + k] = np.exp(1j * phase)

        sym = np.fft.ifft(freq)
        with_cp = np.concatenate([sym[-cp_len:], sym])
        end = min(idx + symbol_len, n)
        signal[idx:end] = with_cp[: end - idx]
        idx += symbol_len

    return signal.astype(np.complex64)


def _generate_halow(
    n: int,
    rng: np.random.RandomState,
) -> np.ndarray:
    """802.11ah HaLow: sub-GHz OFDM, 1-16 MHz BW."""
    nfft = rng.choice([32, 64, 128, 256, 512])
    return _generate_ofdm(n, nfft, rng)


def _generate_oqpsk_dsss(
    n: int,
    rng: np.random.RandomState,
) -> np.ndarray:
    """802.15.4 O-QPSK with DSSS: 2 Mchips/s, 250 kbps data rate."""
    chip_rate = 2e6
    chips_per_symbol = 32
    eff_sps = max(int(2.048e6 / chip_rate), 1)

    num_chips = n // eff_sps + 1
    num_data_symbols = num_chips // chips_per_symbol + 1

    signal_i = np.zeros(n, dtype=np.float64)
    signal_q = np.zeros(n, dtype=np.float64)
    idx = 0

    for _ in range(num_data_symbols):
        if idx >= n:
            break
        pn = rng.choice([-1.0, 1.0], chips_per_symbol)
        i_data = rng.choice([-1.0, 1.0])
        q_data = rng.choice([-1.0, 1.0])

        for chip in pn:
            if idx >= n:
                break
            end = min(idx + eff_sps, n)
            signal_i[idx:end] = i_data * chip
            signal_q[idx:end] = q_data * chip
            idx += eff_sps

    half_chip = max(eff_sps // 2, 1)
    signal_q = np.roll(signal_q, half_chip)

    signal = (signal_i + 1j * signal_q).astype(np.complex64)
    return signal[:n]


def _generate_uhf_rfid(
    n: int,
    rng: np.random.RandomState,
) -> np.ndarray:
    """UHF RFID (EPC Gen2): ASK with PIE encoding + Miller backscatter."""
    sps = max(int(2.048e6 / 40e3), 2)
    num_bits = n // sps + 1
    bits = rng.randint(0, 2, num_bits)

    signal = np.zeros(n, dtype=np.complex64)
    idx = 0

    if rng.random() < 0.5:
        for bit in bits:
            if idx >= n:
                break
            if bit == 0:
                pw = sps // 2
                signal[idx : min(idx + pw, n)] = 0.2
                signal[min(idx + pw, n) : min(idx + sps, n)] = 1.0
            else:
                pw = sps * 3 // 4
                signal[idx : min(idx + pw, n)] = 0.2
                signal[min(idx + pw, n) : min(idx + sps, n)] = 1.0
            idx += sps
    else:
        subcarrier_freq = 0.01 + rng.uniform(0, 0.02)
        t = np.arange(n)
        carrier = np.cos(2 * np.pi * subcarrier_freq * t)
        data_signal = np.repeat(2 * bits[: n // sps + 1] - 1, sps)[:n].astype(
            np.float64
        )
        signal = (data_signal * carrier * 0.3).astype(np.complex64)

    return signal[:n].astype(np.complex64)


def _generate_gps_jammer(
    n: int,
    rng: np.random.RandomState,
) -> np.ndarray:
    """GPS jammer: broadband noise burst OR swept CW chirp ~20 MHz."""
    if rng.random() < 0.5:
        signal = (rng.randn(n) + 1j * rng.randn(n)).astype(np.complex64)
        bw = rng.uniform(0.3, 0.45)
        t = np.arange(n)
        bp = np.exp(1j * 2 * np.pi * rng.uniform(-bw / 2, bw / 2) * t)
        signal = signal * bp
    else:
        t = np.arange(n) / n
        sweep_bw = rng.uniform(0.3, 0.45)
        inst_freq = sweep_bw * (t - 0.5)
        phase = 2 * np.pi * np.cumsum(inst_freq)
        signal = np.exp(1j * phase)

    return signal.astype(np.complex64)


def _generate_iridium(
    n: int,
    rng: np.random.RandomState,
) -> np.ndarray:
    """Iridium: DQPSK, 50 kHz channel, 25 ksps, 8.28ms burst slots."""
    baud = 25000
    eff_sps = max(int(2.048e6 / baud), 2)
    num_symbols = n // eff_sps + 1

    dphases = np.array([0, np.pi / 2, np.pi, -np.pi / 2])
    phase_indices = rng.randint(0, 4, num_symbols)
    cumulative_phase = np.cumsum(dphases[phase_indices])

    symbols = np.exp(1j * cumulative_phase)

    burst_len = min(int(8.28e-3 * 2.048e6), n)
    guard_len = min(int(0.25e-3 * 2.048e6), burst_len // 4)

    upsampled = np.zeros(len(symbols) * eff_sps, dtype=complex)
    upsampled[::eff_sps] = symbols
    signal = upsampled[:n]
    signal = _apply_rrc(signal, sps=eff_sps, alpha=0.4)

    if burst_len > 0:
        for pos in range(0, n, burst_len):
            end = min(pos + guard_len, n)
            signal[pos:end] = 0.0

    return signal.astype(np.complex64)


def _generate_dji_ofdm(
    n: int,
    rng: np.random.RandomState,
) -> np.ndarray:
    """DJI OcuSync: OFDM nfft=1024, CP=1/8, clustered pilots."""
    return _generate_ofdm(n, 1024, rng)


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

_GENERATORS: dict[str, Callable[..., np.ndarray]] = {}


def _register_generators() -> None:
    """Build class_name -> generator mapping for all 76 classes.

    Every generator callable has the signature ``(n, rng, sps)`` where
    *sps* is the samples-per-symbol value for the current call.  Generators
    that do not use *sps* (analog, OFDM, LoRa, noise, protocol) accept and
    ignore it.
    """
    global _GENERATORS

    # ASK
    _GENERATORS["ook"] = lambda n, rng, sps: _generate_ask(n, 2, rng, sps=sps)
    for m in [4, 8, 16]:
        _GENERATORS[f"{m}ask"] = lambda n, rng, sps, _m=m: _generate_ask(
            n, _m, rng, sps=sps
        )

    # PAM
    for m in [4, 8, 16]:
        _GENERATORS[f"{m}pam"] = lambda n, rng, sps, _m=m: _generate_pam(
            n, _m, rng, sps=sps
        )

    # PSK
    _GENERATORS["bpsk"] = lambda n, rng, sps: _generate_psk(n, 2, rng, sps=sps)
    _GENERATORS["qpsk"] = lambda n, rng, sps: _generate_psk(n, 4, rng, sps=sps)
    for m in [8, 16, 32]:
        _GENERATORS[f"{m}psk"] = lambda n, rng, sps, _m=m: _generate_psk(
            n, _m, rng, sps=sps
        )

    # QAM
    for m in [16, 32, 64, 128, 256]:
        _GENERATORS[f"{m}qam"] = lambda n, rng, sps, _m=m: _generate_qam(
            n, _m, rng, sps=sps
        )

    # APSK
    for m in [16, 32, 64, 128]:
        _GENERATORS[f"{m}apsk"] = lambda n, rng, sps, _m=m: _generate_apsk(
            n, _m, rng, sps=sps
        )

    # FSK / GFSK
    for m in [2, 4]:
        _GENERATORS[f"{m}fsk"] = lambda n, rng, sps, _m=m: _generate_fsk(
            n, _m, False, rng, sps=sps
        )
        _GENERATORS[f"{m}gfsk"] = lambda n, rng, sps, _m=m: _generate_fsk(
            n, _m, True, rng, sps=sps
        )

    # MSK / GMSK
    for m in [2, 4]:
        _GENERATORS[f"{m}msk"] = lambda n, rng, sps, _m=m: _generate_msk(
            n, _m, False, rng, sps=sps
        )
        _GENERATORS[f"{m}gmsk"] = lambda n, rng, sps, _m=m: _generate_msk(
            n, _m, True, rng, sps=sps
        )

    # OFDM (does not use sps)
    for sc in [64, 128, 256, 512, 1024, 2048]:
        _GENERATORS[f"ofdm-{sc}"] = lambda n, rng, sps, _sc=sc: _generate_ofdm(
            n, _sc, rng
        )

    # LoRa CSS (does not use sps)
    _GENERATORS["lora-css"] = lambda n, rng, sps: _generate_lora_css(n, rng)

    # Analog (do not use sps)
    _GENERATORS["am-dsb"] = lambda n, rng, sps: _generate_am_dsb(n, rng)
    _GENERATORS["am-ssb"] = lambda n, rng, sps: _generate_am_ssb(n, rng)
    _GENERATORS["fm"] = lambda n, rng, sps: _generate_fm(n, rng)
    _GENERATORS["tone"] = lambda n, rng, sps: _generate_tone(n, rng)

    # Noise (does not use sps)
    _GENERATORS["noise"] = lambda n, rng, sps: _generate_noise(n, rng)

    # -------------------------------------------------------------------
    # v4.15.0 protocol generators
    # -------------------------------------------------------------------

    # Pulsed family
    _GENERATORS["adsb"] = lambda n, rng, sps: _generate_adsb(n, rng)
    _GENERATORS["uat"] = lambda n, rng, sps: _generate_uat(n, rng)
    _GENERATORS["tpms"] = lambda n, rng, sps: _generate_tpms(n, rng)

    # FSK protocol variants
    _GENERATORS["dect"] = lambda n, rng, sps: _generate_dect(n, rng, sps)
    _GENERATORS["zwave"] = lambda n, rng, sps: _generate_zwave(n, rng, sps)
    _GENERATORS["wisun"] = lambda n, rng, sps: _generate_wisun(n, rng, sps)
    _GENERATORS["scada-fsk"] = lambda n, rng, sps: _generate_scada_fsk(n, rng)
    _GENERATORS["pocsag"] = lambda n, rng, sps: _generate_pocsag(n, rng, sps)
    _GENERATORS["nrf24"] = lambda n, rng, sps: _generate_nrf24(n, rng, sps)
    _GENERATORS["ais"] = lambda n, rng, sps: _generate_ais(n, rng, sps)
    _GENERATORS["dstar"] = lambda n, rng, sps: _generate_dstar(n, rng, sps)
    _GENERATORS["gsm"] = lambda n, rng, sps: _generate_gsm(n, rng, sps)

    # Trunked family
    _GENERATORS["p25"] = lambda n, rng, sps: _generate_p25(n, rng, sps)
    _GENERATORS["dmr"] = lambda n, rng, sps: _generate_dmr(n, rng, sps)
    _GENERATORS["tetra"] = lambda n, rng, sps: _generate_tetra(n, rng, sps)

    # OFDM protocol variants
    _GENERATORS["dji-ofdm"] = lambda n, rng, sps: _generate_dji_ofdm(n, rng)
    _GENERATORS["nbiot"] = lambda n, rng, sps: _generate_nbiot(n, rng)
    _GENERATORS["halow"] = lambda n, rng, sps: _generate_halow(n, rng)

    # 802.15.4 family
    _GENERATORS["oqpsk-dsss"] = lambda n, rng, sps: _generate_oqpsk_dsss(n, rng)
    _GENERATORS["wireless-hart"] = lambda n, rng, sps: _generate_oqpsk_dsss(n, rng)
    _GENERATORS["isa100"] = lambda n, rng, sps: _generate_oqpsk_dsss(n, rng)

    # Analog / narrowband FM variants
    _GENERATORS["fpv-analog"] = lambda n, rng, sps: _generate_fpv_analog(n, rng)
    _GENERATORS["analog-video-24"] = lambda n, rng, sps: _generate_fpv_analog(n, rng)
    _GENERATORS["pmr446"] = lambda n, rng, sps: _generate_pmr446(n, rng)
    _GENERATORS["wireless-mic"] = lambda n, rng, sps: _generate_wireless_mic(n, rng)

    # Satellite family
    _GENERATORS["iridium"] = lambda n, rng, sps: _generate_iridium(n, rng)

    # Interference family
    _GENERATORS["gps-jammer"] = lambda n, rng, sps: _generate_gps_jammer(n, rng)

    # ASK additions
    _GENERATORS["ism433"] = lambda n, rng, sps: _generate_ask(n, 2, rng, sps=sps)
    _GENERATORS["uhf-rfid"] = lambda n, rng, sps: _generate_uhf_rfid(n, rng)

    # Spread spectrum additions
    _GENERATORS["sigfox"] = lambda n, rng, sps: _generate_sigfox(n, rng)
    _GENERATORS["elrs"] = lambda n, rng, sps: _generate_lora_css(n, rng)
    _GENERATORS["sidewalk"] = lambda n, rng, sps: (
        _generate_lora_css(n, rng)
        if rng.random() < 0.5
        else _generate_nrf24(n, rng, sps)
    )

    # LoRa protocol refinements (all use LoRa CSS PHY)
    _GENERATORS["lora-meshtastic"] = lambda n, rng, sps: _generate_lora_css(n, rng)
    _GENERATORS["lora-meshcore"] = lambda n, rng, sps: _generate_lora_css(n, rng)
    _GENERATORS["lora-lorawan"] = lambda n, rng, sps: _generate_lora_css(n, rng)


_register_generators()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_signal(
    class_name: str,
    n_samples: int = 4096,
    sample_rate: float = 2_048_000.0,
    snr_db: float = 15.0,
    rng: np.random.RandomState | None = None,
    channel_config: object | None = None,
) -> np.ndarray:
    """Generate a synthetic IQ signal for any of the 76 modulation classes.

    This is the SINGLE authoritative signal generator for the entire SigRift
    codebase.  No other module should contain signal generation logic.

    Parameters
    ----------
    class_name : str
        One of the 76 class names from ``sigrift.lib.taxonomy.CLASSES``.
    n_samples : int
        Number of complex IQ samples to produce.
    sample_rate : float
        Nominal sample rate (Hz).  Currently used for documentation;
        all generators work in normalised frequency.
    snr_db : float
        Target signal-to-noise ratio in dB.
    rng : np.random.RandomState or None
        Random state for reproducibility.  If ``None``, a new unseeded
        state is created.
    channel_config : ChannelConfig or None
        Optional channel impairment configuration.  When provided, channel
        effects (multipath, CFO, phase noise, etc.) are applied AFTER signal
        generation but BEFORE AWGN noise addition.  Default ``None`` means
        no channel model (backward compatible).

    Returns
    -------
    np.ndarray
        Complex64 array of length ``n_samples``.

    Raises
    ------
    ValueError
        If ``class_name`` is not a recognised modulation class.
    """
    if rng is None:
        rng = np.random.RandomState()

    # Randomise samples-per-symbol each call so the model learns to handle
    # varying symbol rates (real-world receivers see SPS in roughly 4..32).
    sps = int(rng.randint(4, 33))  # uniform in [4, 32]

    gen_fn = _GENERATORS.get(class_name)
    if gen_fn is None:
        raise ValueError(
            f"Unknown modulation class: {class_name!r}. "
            f"Valid classes: {sorted(_GENERATORS.keys())}"
        )

    signal = gen_fn(n_samples, rng, sps)

    # Validate -- replace NaN/Inf with noise
    if not np.isfinite(signal).all():
        logger.warning(
            "Non-finite values in generated %s signal; replacing with noise", class_name
        )
        signal = (rng.randn(n_samples) + 1j * rng.randn(n_samples)).astype(np.complex64)

    # Ensure correct length
    if len(signal) < n_samples:
        signal = np.pad(signal, (0, n_samples - len(signal)), mode="wrap")
    signal = signal[:n_samples]

    # Normalize to unit power
    signal = _normalize_power(signal)

    # Apply channel impairments (after generation, before AWGN)
    # Lazy import to avoid circular dependency via sigrift.lib.dsp.__init__
    if channel_config is not None:
        from sigrift.lib.dsp.channel_models import apply_channel

        signal = apply_channel(signal, channel_config, rng)

    # Add AWGN
    signal = _add_awgn(signal, snr_db, rng)

    return signal.astype(np.complex64)


def list_classes() -> list[str]:
    """Return all supported modulation class names."""
    return sorted(_GENERATORS.keys())
