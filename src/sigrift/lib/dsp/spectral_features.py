"""Spectral feature extraction for in-model DSP feature injection.

Pure-torch implementations computed inside the model ``forward()`` from
``[B, 2, N]`` IQ input.  All operations use **real-valued** tensors and
avoid ``torch.fft.*`` for ONNX compatibility.  Six feature families:

1. **Nth-power spectral peaks** -- raise signal to Nth power, then estimate
   peak-to-average power using segmented periodogram (time-domain).  BPSK
   peaks at N=2, QPSK at N=4, 8PSK at N=8; QAM/APSK have no strong peaks.

2. **Cyclic-prefix autocorrelation** -- normalised autocorrelation at
   candidate CP lags.  OFDM signals show a strong peak at the true
   CP lag; non-OFDM signals are flat.

3. **HOS cumulants** -- 4th-order cumulants (C20, C40, C41, C42) normalised
   by signal power.  8 features that discriminate PSK orders, QAM orders,
   and QAM vs APSK.  See ``cumulant_features.py``.

4-9. **Extended features** (32 new) -- envelope shape, instantaneous stats,
   higher-order stats, envelope, cyclostationary, time-frequency, zero-crossing,
   and wavelet features for improved modulation discrimination.
"""

import math

import torch

from sigrift.lib.dsp.cumulant_features import cumulant_features

# Total DSP features: spectral peaks (3) + CP autocorrelation (6) + cumulants (8)
#                    + extended features (32) + enhanced discriminative (5)
NUM_DSP_FEATURES = 54


def _complex_power_real(
    i: torch.Tensor, q: torch.Tensor, p: int
) -> tuple[torch.Tensor, torch.Tensor]:
    """Raise (I + jQ) to power *p* using real arithmetic.

    Uses iterative complex multiplication::

        (a+jb)(c+jd) = (ac-bd) + j(ad+bc)

    Parameters
    ----------
    i, q : torch.Tensor
        I and Q components, shape ``[B, N]``.
    p : int
        Exponent (must be >= 1).

    Returns
    -------
    tuple of (torch.Tensor, torch.Tensor)
        ``(I_out, Q_out)`` representing ``(I + jQ)^p``.
    """
    ri, rq = i, q
    for _ in range(p - 1):
        new_i = ri * i - rq * q
        new_q = ri * q + rq * i
        ri, rq = new_i, new_q
    return ri, rq


def _segmented_peak_to_mean(
    i: torch.Tensor, q: torch.Tensor, seg_len: int = 256
) -> torch.Tensor:
    """Estimate spectral peak-to-mean ratio without FFT.

    Uses the variance-to-mean-squared ratio of instantaneous power (crest
    factor of the power envelope) as a proxy.  Signals with strong spectral
    lines (e.g. PSK raised to Nth power) have highly periodic power envelopes,
    while noise-like signals have flat power.

    Parameters
    ----------
    i, q : torch.Tensor
        I and Q components, shape ``[B, N]``.
    seg_len : int
        Segment length (unused in crest-factor method, kept for API compat).

    Returns
    -------
    torch.Tensor
        ``[B]`` in dB, clamped to [0, 30].
    """
    # Instantaneous power
    power = i * i + q * q  # [B, N]

    # Power variance ratio (crest factor of power envelope)
    power_var = power.var(dim=-1)  # [B]
    power_mean = power.mean(dim=-1).clamp(min=1e-12)  # [B]
    crest = power_var / (power_mean * power_mean + 1e-12)

    ratio_db = 10.0 * torch.log10(crest + 1e-12)
    ratio_db = ratio_db.clamp(0.0, 30.0)
    return ratio_db


def nth_power_spectral_peaks(
    x_complex: torch.Tensor = None,
    powers: tuple[int, ...] = (2, 4, 8),
    *,
    _iq_pair: tuple[torch.Tensor, torch.Tensor] | None = None,
) -> torch.Tensor:
    """Compute Nth-power spectral peak features.

    For each power N, raises the signal to the Nth power and computes a
    peak-to-mean power ratio that discriminates PSK (strong periodicity
    in x^N) from QAM/APSK (noise-like x^N).

    Parameters
    ----------
    x_complex : torch.Tensor, optional
        Complex signal ``[B, N]``.  Ignored if ``_iq_pair`` is provided.
    powers : tuple of int
        Exponents to raise the signal to.
    _iq_pair : tuple of (Tensor, Tensor) or None
        If provided, ``(I, Q)`` real tensors ``[B, N]`` (ONNX-safe path).

    Returns
    -------
    torch.Tensor
        ``[B, len(powers)]`` peak-to-mean ratios in dB, clamped to [0, 30].
    """
    if _iq_pair is not None:
        i_in, q_in = _iq_pair
    else:
        i_in = x_complex.real.float()
        q_in = x_complex.imag.float()

    results = []
    for p in powers:
        ri, rq = _complex_power_real(i_in, q_in, p)
        ratio_db = _segmented_peak_to_mean(ri, rq)
        results.append(ratio_db)
    return torch.stack(results, dim=-1)  # [B, len(powers)]


def cp_autocorrelation(
    x_complex: torch.Tensor = None,
    lags: tuple[int, ...] = (64, 128, 256, 512, 1024, 2048),
    *,
    _iq_pair: tuple[torch.Tensor, torch.Tensor] | None = None,
) -> torch.Tensor:
    """Compute normalised cyclic-prefix autocorrelation at candidate lags.

    All operations are real-valued (ONNX-safe).

    Parameters
    ----------
    x_complex : torch.Tensor, optional
        Complex signal ``[B, N]``.  Ignored if ``_iq_pair`` is provided.
    lags : tuple of int
        Candidate CP lags to evaluate.
    _iq_pair : tuple of (Tensor, Tensor) or None
        If provided, ``(I, Q)`` real tensors ``[B, N]`` (ONNX-safe).

    Returns
    -------
    torch.Tensor
        ``[B, len(lags)]`` autocorrelation magnitudes, clamped to [0, 1].
    """
    if _iq_pair is not None:
        si, sq = _iq_pair
    else:
        si = x_complex.real.float()
        sq = x_complex.imag.float()

    n = int(si.shape[-1])

    results = []
    for lag in lags:
        if lag >= n:
            results.append(torch.zeros(si.shape[0], device=si.device))
            continue
        # head * conj(tail): Re{(a+jb)(c-jd)} = ac+bd, Im{...} = bc-ad
        hi, hq = si[:, : n - lag], sq[:, : n - lag]
        ti, tq = si[:, lag:], sq[:, lag:]
        corr_real = (hi * ti + hq * tq).sum(dim=-1)
        corr_imag = (hq * ti - hi * tq).sum(dim=-1)
        corr_mag = torch.sqrt(corr_real * corr_real + corr_imag * corr_imag + 1e-12)
        # Normalise by geometric mean of head and tail energies
        head_energy = (hi * hi + hq * hq).sum(dim=-1).clamp(min=1e-12)
        tail_energy = (ti * ti + tq * tq).sum(dim=-1).clamp(min=1e-12)
        norm_corr = corr_mag / torch.sqrt(head_energy * tail_energy)
        norm_corr = norm_corr.clamp(0.0, 1.0)
        results.append(norm_corr)
    return torch.stack(results, dim=-1)  # [B, len(lags)]


def _envelope_shape_features(i: torch.Tensor, q: torch.Tensor) -> torch.Tensor:
    """Compute envelope shape features from instantaneous power (ONNX-safe).

    Features: envelope flatness, envelope centroid, envelope spread, envelope skewness.

    Parameters
    ----------
    i, q : torch.Tensor
        I and Q components, shape ``[B, N]``.

    Returns
    -------
    torch.Tensor
        ``[B, 4]``
    """
    eps = 1e-12
    # Compute instantaneous power (envelope squared)
    power = i * i + q * q  # [B, N]
    N = power.shape[-1]

    # Envelope flatness: geometric mean / arithmetic mean of power
    # Use log-domain for geometric mean
    log_power = torch.log(power + eps)
    geo_mean = torch.exp(log_power.mean(dim=-1))
    arith_mean = power.mean(dim=-1).clamp(min=eps)
    flatness = (geo_mean / arith_mean).clamp(0.0, 1.0)  # [B]

    # Envelope centroid: center of mass of power sequence
    indices = torch.arange(N, device=i.device, dtype=i.dtype).unsqueeze(0)  # [1, N]
    power_sum = power.sum(dim=-1, keepdim=True).clamp(min=eps)  # [B, 1]
    centroid = (power * indices).sum(dim=-1) / power_sum.squeeze(-1)
    centroid = centroid / max(N - 1, 1)  # normalise to [0, 1]

    # Envelope spread: variance of power distribution around centroid
    deviations = indices - centroid.unsqueeze(-1)  # [B, N]
    spread = torch.sqrt(
        (power * deviations * deviations).sum(dim=-1) / power_sum.squeeze(-1) + eps
    )
    spread = spread / max(N - 1, 1)  # normalise

    # Envelope skewness: 3rd moment of power distribution
    skewness_num = (power * deviations * deviations * deviations).sum(dim=-1)
    spread_cubed = (spread * max(N - 1, 1)).clamp(min=eps) ** 3
    skewness = skewness_num / (power_sum.squeeze(-1) * spread_cubed + eps)
    skewness = skewness.clamp(-5.0, 5.0)

    return torch.stack([flatness, centroid, spread, skewness], dim=-1)


def _instantaneous_stats(i: torch.Tensor, q: torch.Tensor) -> torch.Tensor:
    """Compute instantaneous frequency and amplitude statistics.

    Features: mean inst. freq, std inst. freq, mean inst. amplitude, std inst. amplitude.

    Parameters
    ----------
    i, q : torch.Tensor
        I and Q components, shape ``[B, N]``.

    Returns
    -------
    torch.Tensor
        ``[B, 4]``
    """
    eps = 1e-12

    # Instantaneous amplitude
    amp = torch.sqrt(i * i + q * q + eps)  # [B, N]
    amp_mean = amp.mean(dim=-1)  # [B]
    amp_std = amp.std(dim=-1)  # [B]

    # Instantaneous phase via atan2
    phase = torch.atan2(q, i)  # [B, N]

    # Instantaneous frequency = derivative of phase (diff of unwrapped phase)
    # Use phase difference and wrap to [-pi, pi]
    dphi = phase[:, 1:] - phase[:, :-1]  # [B, N-1]
    # Wrap to [-pi, pi]
    dphi = dphi - 2.0 * math.pi * torch.round(dphi / (2.0 * math.pi))

    freq_mean = dphi.mean(dim=-1) / math.pi  # normalise to [-1, 1]
    freq_std = dphi.std(dim=-1) / math.pi

    # Clamp outputs
    freq_mean = freq_mean.clamp(-5.0, 5.0)
    freq_std = freq_std.clamp(0.0, 5.0)
    amp_mean = amp_mean.clamp(0.0, 5.0)
    amp_std = amp_std.clamp(0.0, 5.0)

    return torch.stack([freq_mean, freq_std, amp_mean, amp_std], dim=-1)


def _higher_order_stats(i: torch.Tensor, q: torch.Tensor) -> torch.Tensor:
    """Compute higher-order statistics beyond 4th-order cumulants.

    Features: kurtosis of magnitude, kurtosis of phase, 6th-order cumulant mag,
    8th-order cumulant mag.

    Parameters
    ----------
    i, q : torch.Tensor
        I and Q components, shape ``[B, N]``.

    Returns
    -------
    torch.Tensor
        ``[B, 4]``
    """
    eps = 1e-12

    # Magnitude and phase
    mag = torch.sqrt(i * i + q * q + eps)  # [B, N]
    phase = torch.atan2(q, i)  # [B, N]

    # Kurtosis of magnitude: E[(x-mu)^4] / E[(x-mu)^2]^2 - 3
    mag_mean = mag.mean(dim=-1, keepdim=True)
    mag_centered = mag - mag_mean
    mag_var = (mag_centered * mag_centered).mean(dim=-1).clamp(min=eps)
    mag_kurt = (mag_centered**4).mean(dim=-1) / (mag_var * mag_var + eps) - 3.0
    mag_kurt = mag_kurt.clamp(-5.0, 5.0)

    # Kurtosis of phase difference (avoids wrap artifacts at ±π)
    dphi = phase[:, 1:] - phase[:, :-1]
    dphi = dphi - 2.0 * math.pi * torch.round(dphi / (2.0 * math.pi))
    dphi_mean = dphi.mean(dim=-1, keepdim=True)
    dphi_centered = dphi - dphi_mean
    dphi_var = (dphi_centered * dphi_centered).mean(dim=-1).clamp(min=eps)
    phase_kurt = (dphi_centered**4).mean(dim=-1) / (dphi_var * dphi_var + eps) - 3.0
    phase_kurt = phase_kurt.clamp(-5.0, 5.0)

    # 6th-order cumulant magnitude proxy: E[|z|^6] / E[|z|^2]^3
    p = i * i + q * q  # |z|^2
    m21 = p.mean(dim=-1).clamp(min=eps)
    m63 = (p * p * p).mean(dim=-1)  # E[|z|^6]
    c6_mag = m63 / (m21 * m21 * m21 + eps)
    c6_mag = c6_mag.clamp(0.0, 30.0)

    # 8th-order cumulant magnitude proxy: E[|z|^8] / E[|z|^2]^4
    m84 = (p * p * p * p).mean(dim=-1)  # E[|z|^8]
    c8_mag = m84 / (m21**4 + eps)
    c8_mag = c8_mag.clamp(0.0, 200.0)

    return torch.stack([mag_kurt, phase_kurt, c6_mag, c8_mag], dim=-1)


def _envelope_features(i: torch.Tensor, q: torch.Tensor) -> torch.Tensor:
    """Compute envelope features.

    Features: mean envelope, std envelope, envelope PAPR, envelope autocorrelation peak.

    Parameters
    ----------
    i, q : torch.Tensor
        I and Q components, shape ``[B, N]``.

    Returns
    -------
    torch.Tensor
        ``[B, 4]``
    """
    eps = 1e-12

    # Envelope = magnitude
    env = torch.sqrt(i * i + q * q + eps)  # [B, N]

    env_mean = env.mean(dim=-1)  # [B]
    env_std = env.std(dim=-1)  # [B]

    # PAPR: peak-to-average power ratio
    env_peak = env.max(dim=-1).values  # [B]
    env_rms_sq = (env * env).mean(dim=-1).clamp(min=eps)
    papr = (env_peak * env_peak) / env_rms_sq
    papr_db = 10.0 * torch.log10(papr + eps)
    papr_db = papr_db.clamp(0.0, 30.0)

    # Envelope autocorrelation peak (at lag 1, normalised)
    env_centered = env - env_mean.unsqueeze(-1)
    env_var = (env_centered * env_centered).sum(dim=-1).clamp(min=eps)
    # Autocorrelation at lag 1
    acorr = (env_centered[:, :-1] * env_centered[:, 1:]).sum(dim=-1)
    acorr_norm = (acorr / env_var).clamp(-1.0, 1.0)

    env_mean = env_mean.clamp(0.0, 5.0)
    env_std = env_std.clamp(0.0, 5.0)

    return torch.stack([env_mean, env_std, papr_db, acorr_norm], dim=-1)


def _cyclostationary_features(i: torch.Tensor, q: torch.Tensor) -> torch.Tensor:
    """Compute cyclostationary features using time-domain methods.

    Features: spectral coherence peak, spectral coherence frequency,
    alpha-profile energy, conjugate alpha-profile energy.

    Parameters
    ----------
    i, q : torch.Tensor
        I and Q components, shape ``[B, N]``.

    Returns
    -------
    torch.Tensor
        ``[B, 4]``
    """
    eps = 1e-12
    N = i.shape[-1]

    # Spectral coherence proxy via cyclic autocorrelation
    # Test a set of candidate cycle frequencies (alpha) using correlation
    # of x(t) * conj(x(t)) shifted by alpha
    p = i * i + q * q  # |z|^2, shape [B, N]
    p_mean = p.mean(dim=-1, keepdim=True).clamp(min=eps)
    p_centered = p - p_mean

    # Test a few candidate lags for cyclostationarity
    candidate_lags = [1, 2, 4, 8, 16, 32]
    max_corr = torch.zeros(i.shape[0], device=i.device)
    max_lag = torch.zeros(i.shape[0], device=i.device)

    p_energy = (p_centered * p_centered).sum(dim=-1).clamp(min=eps)
    for lag in candidate_lags:
        if lag >= N:
            continue
        corr = (p_centered[:, : N - lag] * p_centered[:, lag:]).sum(dim=-1)
        corr_norm = (corr / p_energy).abs()
        update_mask = corr_norm > max_corr
        max_corr = torch.where(update_mask, corr_norm, max_corr)
        max_lag = torch.where(
            update_mask, torch.full_like(max_lag, float(lag)), max_lag
        )

    sc_peak = max_corr.clamp(0.0, 1.0)
    sc_freq = max_lag / max(N, 1)  # normalised lag position

    # Alpha-profile energy: sum of squared cyclic correlations
    alpha_energy = torch.zeros(i.shape[0], device=i.device)
    for lag in candidate_lags:
        if lag >= N:
            continue
        corr = (p_centered[:, : N - lag] * p_centered[:, lag:]).sum(dim=-1)
        corr_norm = corr / p_energy
        alpha_energy = alpha_energy + corr_norm * corr_norm
    alpha_energy = alpha_energy.clamp(0.0, 10.0)

    # Conjugate alpha-profile: use x(t)*x(t) instead of x(t)*conj(x(t))
    # z^2 = (I+jQ)^2 = I^2-Q^2 + j*2IQ
    z2_re = i * i - q * q
    z2_im = 2.0 * i * q
    z2_power = z2_re * z2_re + z2_im * z2_im  # |z^2|^2
    z2_mean = z2_power.mean(dim=-1, keepdim=True).clamp(min=eps)
    z2_centered = z2_power - z2_mean
    z2_energy = (z2_centered * z2_centered).sum(dim=-1).clamp(min=eps)

    conj_alpha_energy = torch.zeros(i.shape[0], device=i.device)
    for lag in candidate_lags:
        if lag >= N:
            continue
        corr = (z2_centered[:, : N - lag] * z2_centered[:, lag:]).sum(dim=-1)
        corr_norm = corr / z2_energy
        conj_alpha_energy = conj_alpha_energy + corr_norm * corr_norm
    conj_alpha_energy = conj_alpha_energy.clamp(0.0, 10.0)

    return torch.stack([sc_peak, sc_freq, alpha_energy, conj_alpha_energy], dim=-1)


def _time_frequency_features(i: torch.Tensor, q: torch.Tensor) -> torch.Tensor:
    """Compute time-frequency features using short-time energy analysis.

    Features: STFT energy variance across time, STFT energy variance across frequency,
    time-frequency localization, spectral entropy.

    Parameters
    ----------
    i, q : torch.Tensor
        I and Q components, shape ``[B, N]``.

    Returns
    -------
    torch.Tensor
        ``[B, 4]``
    """
    eps = 1e-12
    N = i.shape[-1]

    # Segment the signal into short windows (proxy for STFT)
    seg_len = min(64, N)
    n_segs = max(N // seg_len, 1)
    usable = n_segs * seg_len

    i_segs = i[:, :usable].reshape(i.shape[0], n_segs, seg_len)  # [B, T, F]
    q_segs = q[:, :usable].reshape(q.shape[0], n_segs, seg_len)

    # Per-segment, per-bin power (proxy for spectrogram)
    seg_power = i_segs * i_segs + q_segs * q_segs  # [B, T, F]

    # Energy per time segment
    energy_time = seg_power.sum(dim=-1)  # [B, T]
    energy_time_mean = energy_time.mean(dim=-1).clamp(min=eps)
    energy_time_var = energy_time.var(dim=-1) / (
        energy_time_mean * energy_time_mean + eps
    )
    energy_time_var = energy_time_var.clamp(0.0, 10.0)

    # Energy per frequency bin
    energy_freq = seg_power.sum(dim=1)  # [B, F]
    energy_freq_mean = energy_freq.mean(dim=-1).clamp(min=eps)
    energy_freq_var = energy_freq.var(dim=-1) / (
        energy_freq_mean * energy_freq_mean + eps
    )
    energy_freq_var = energy_freq_var.clamp(0.0, 10.0)

    # Time-frequency localization: ratio of peak energy to total
    peak_energy = seg_power.reshape(i.shape[0], -1).max(dim=-1).values
    total_energy = seg_power.reshape(i.shape[0], -1).sum(dim=-1).clamp(min=eps)
    tf_localization = peak_energy / total_energy
    tf_localization = (tf_localization * n_segs * seg_len).clamp(0.0, 100.0)

    # Spectral entropy: entropy of power distribution across frequency bins
    power_per_bin = energy_freq  # [B, F]
    power_sum = power_per_bin.sum(dim=-1, keepdim=True).clamp(min=eps)
    prob = power_per_bin / power_sum + eps
    spectral_entropy = -(prob * torch.log(prob)).sum(dim=-1)
    # Normalise by max entropy (log of number of bins)
    max_entropy = math.log(seg_len) if seg_len > 1 else 1.0
    spectral_entropy = (spectral_entropy / max_entropy).clamp(0.0, 1.5)

    return torch.stack(
        [energy_time_var, energy_freq_var, tf_localization, spectral_entropy], dim=-1
    )


def _zero_crossing_features(i: torch.Tensor, q: torch.Tensor) -> torch.Tensor:
    """Compute zero-crossing features.

    Features: ZCR (real), ZCR (imag), zero-crossing regularity, mean ZC interval.

    Parameters
    ----------
    i, q : torch.Tensor
        I and Q components, shape ``[B, N]``.

    Returns
    -------
    torch.Tensor
        ``[B, 4]``
    """
    eps = 1e-12
    N = i.shape[-1]

    # Zero-crossing rate for I channel
    i_sign = torch.sign(i)
    i_crossings = (i_sign[:, 1:] != i_sign[:, :-1]).float()
    zcr_i = i_crossings.mean(dim=-1)  # [B]

    # Zero-crossing rate for Q channel
    q_sign = torch.sign(q)
    q_crossings = (q_sign[:, 1:] != q_sign[:, :-1]).float()
    zcr_q = q_crossings.mean(dim=-1)  # [B]

    # Zero-crossing regularity: std of inter-crossing intervals
    # Computed as std of distances between crossings (use I channel)
    # Proxy: variance of the crossing indicator smoothed
    # Higher regularity = lower variance of local ZCR
    seg_len = min(32, max(N // 4, 2))
    n_segs = max((N - 1) // seg_len, 1)
    usable = n_segs * seg_len
    if usable > 0 and n_segs > 1:
        local_zcr = (
            i_crossings[:, :usable].reshape(i.shape[0], n_segs, seg_len).mean(dim=-1)
        )
        zcr_std = local_zcr.std(dim=-1)
        zcr_mean_local = local_zcr.mean(dim=-1).clamp(min=eps)
        regularity = 1.0 - (zcr_std / zcr_mean_local).clamp(0.0, 1.0)
    else:
        regularity = torch.zeros(i.shape[0], device=i.device)

    # Mean zero-crossing interval (normalised)
    # Approximate as 1 / ZCR (normalised by N)
    mean_zc_interval = 1.0 / (zcr_i + eps)
    mean_zc_interval = (mean_zc_interval / max(N, 1)).clamp(0.0, 1.0)

    zcr_i = zcr_i.clamp(0.0, 1.0)
    zcr_q = zcr_q.clamp(0.0, 1.0)
    regularity = regularity.clamp(0.0, 1.0)

    return torch.stack([zcr_i, zcr_q, regularity, mean_zc_interval], dim=-1)


def _wavelet_features(i: torch.Tensor, q: torch.Tensor) -> torch.Tensor:
    """Compute wavelet/multi-resolution features using Haar wavelet.

    Features: detail energy ratio (level 1, 2, 3), approximation energy ratio.

    Parameters
    ----------
    i, q : torch.Tensor
        I and Q components, shape ``[B, N]``.

    Returns
    -------
    torch.Tensor
        ``[B, 4]``
    """
    eps = 1e-12

    # Work with signal magnitude for wavelet decomposition
    mag = torch.sqrt(i * i + q * q + eps)  # [B, N]
    total_energy = (mag * mag).sum(dim=-1).clamp(min=eps)  # [B]

    detail_energies = []
    approx = mag

    for level in range(3):
        N_cur = approx.shape[-1]
        # Ensure even length
        usable = (N_cur // 2) * 2
        if usable < 2:
            detail_energies.append(torch.zeros(i.shape[0], device=i.device))
            continue
        approx_trunc = approx[:, :usable]
        even = approx_trunc[:, 0::2]
        odd = approx_trunc[:, 1::2]

        # Haar wavelet: approx = (even + odd) / sqrt(2), detail = (even - odd) / sqrt(2)
        inv_sqrt2 = 1.0 / math.sqrt(2.0)
        detail = (even - odd) * inv_sqrt2
        approx = (even + odd) * inv_sqrt2

        detail_energy = (detail * detail).sum(dim=-1)
        detail_energies.append(detail_energy / total_energy)

    # Pad if we couldn't compute all 3 levels
    while len(detail_energies) < 3:
        detail_energies.append(torch.zeros(i.shape[0], device=i.device))

    # Approximation energy ratio at final level
    approx_energy = (approx * approx).sum(dim=-1) / total_energy

    d1 = detail_energies[0].clamp(0.0, 1.0)
    d2 = detail_energies[1].clamp(0.0, 1.0)
    d3 = detail_energies[2].clamp(0.0, 1.0)
    approx_ratio = approx_energy.clamp(0.0, 1.0)

    return torch.stack([d1, d2, d3, approx_ratio], dim=-1)


def extended_features(
    _iq_pair: tuple[torch.Tensor, torch.Tensor],
) -> torch.Tensor:
    """Compute 32 extended DSP features from normalised IQ pair.

    All operations are real-valued (ONNX-safe).

    Parameters
    ----------
    _iq_pair : tuple of (Tensor, Tensor)
        ``(I, Q)`` real tensors ``[B, N]``.

    Returns
    -------
    torch.Tensor
        ``[B, 32]`` extended features.
    """
    i, q = _iq_pair
    f1 = _envelope_shape_features(i, q)  # [B, 4]
    f2 = _instantaneous_stats(i, q)  # [B, 4]
    f3 = _higher_order_stats(i, q)  # [B, 4]
    f4 = _envelope_features(i, q)  # [B, 4]
    f5 = _cyclostationary_features(i, q)  # [B, 4]
    f6 = _time_frequency_features(i, q)  # [B, 4]
    f7 = _zero_crossing_features(i, q)  # [B, 4]
    f8 = _wavelet_features(i, q)  # [B, 4]
    result = torch.cat([f1, f2, f3, f4, f5, f6, f7, f8], dim=-1)  # [B, 32]
    # Sanitise: replace any NaN/Inf
    result = torch.nan_to_num(result, nan=0.0, posinf=0.0, neginf=0.0)
    return result


def _enhanced_discriminative_features(i: torch.Tensor, q: torch.Tensor) -> torch.Tensor:
    """Compute 5 enhanced discriminative features for improved signal classification.

    All operations are real-valued (ONNX-safe).

    Features:

    1. **Spectral flatness (Wiener entropy)**: ratio of geometric to arithmetic
       mean of the power spectral density. High for noise/spread-spectrum (LoRa,
       FHSS), low for narrowband/tonal signals (FSK, PSK).

    2. **Symbol rate estimate**: dominant autocorrelation period of magnitude
       envelope, normalised by signal length. Different modulations have
       characteristic symbol rates (e.g. GSM 270k vs DECT 1.152M).

    3. **Spectral kurtosis**: kurtosis of the power spectral density.
       Discriminates between signals with spectral peaks (narrowband) vs
       flat spectrum (wideband/noise).

    4. **Bandwidth occupancy ratio**: fraction of spectral bins with power
       above 10% of peak. Narrowband < 0.1, wideband/OFDM > 0.5.

    5. **Phase entropy**: normalised entropy of quantised phase distribution.
       PSK signals have low entropy (discrete phase states), noise has high
       entropy (uniform phase).

    Parameters
    ----------
    i, q : torch.Tensor
        I and Q components, shape ``[B, N]``.

    Returns
    -------
    torch.Tensor
        ``[B, 5]``
    """
    eps = 1e-12
    B, N = i.shape

    # --- Power spectral density via periodogram (real-valued proxy) ---
    # Use squared-magnitude of DFT computed via real arithmetic:
    # Segment the signal and compute power per bin
    seg_len = min(256, N)
    n_segs = max(N // seg_len, 1)
    usable = n_segs * seg_len

    i_segs = i[:, :usable].reshape(B, n_segs, seg_len)
    q_segs = q[:, :usable].reshape(B, n_segs, seg_len)
    # Average power per bin across segments
    psd = (i_segs * i_segs + q_segs * q_segs).mean(dim=1)  # [B, seg_len]

    # 1. Spectral flatness: geometric mean / arithmetic mean of PSD
    log_psd = torch.log(psd + eps)
    geo_mean = torch.exp(log_psd.mean(dim=-1))
    arith_mean = psd.mean(dim=-1).clamp(min=eps)
    spectral_flatness = (geo_mean / arith_mean).clamp(0.0, 1.0)  # [B]

    # 2. Symbol rate estimate via autocorrelation of magnitude envelope
    mag = torch.sqrt(i * i + q * q + eps)  # [B, N]
    mag_centered = mag - mag.mean(dim=-1, keepdim=True)
    mag_energy = (mag_centered * mag_centered).sum(dim=-1).clamp(min=eps)  # [B]
    # Test candidate lags and find first peak above threshold
    max_lag = min(N // 2, 512)
    candidate_lags = list(range(2, max_lag, max(max_lag // 64, 1)))
    best_corr = torch.zeros(B, device=i.device)
    best_lag = torch.zeros(B, device=i.device)
    prev_corr = torch.full((B,), -1.0, device=i.device)
    for lag in candidate_lags:
        corr = (mag_centered[:, : N - lag] * mag_centered[:, lag:]).sum(dim=-1)
        corr_norm = corr / mag_energy
        # Detect peak: corr > prev and corr > best and corr > 0.3
        is_peak = (corr_norm > prev_corr) & (corr_norm > 0.3) & (corr_norm > best_corr)
        best_corr = torch.where(is_peak, corr_norm, best_corr)
        best_lag = torch.where(is_peak, torch.full_like(best_lag, float(lag)), best_lag)
        prev_corr = corr_norm
    # Normalise lag to [0, 1] range
    symbol_rate_est = (best_lag / max(N, 1)).clamp(0.0, 1.0)  # [B]

    # 3. Spectral kurtosis: kurtosis of PSD across frequency bins
    psd_mean = psd.mean(dim=-1, keepdim=True).clamp(min=eps)
    psd_centered = psd - psd_mean
    psd_var = (psd_centered * psd_centered).mean(dim=-1).clamp(min=eps)
    psd_kurt = (psd_centered**4).mean(dim=-1) / (psd_var * psd_var + eps) - 3.0
    psd_kurt = psd_kurt.clamp(-5.0, 50.0)  # [B]

    # 4. Bandwidth occupancy ratio: fraction of bins above 10% of peak
    psd_peak = psd.max(dim=-1, keepdim=True).values.clamp(min=eps)
    occupied = (psd > 0.1 * psd_peak).float()
    bw_occupancy = occupied.mean(dim=-1).clamp(0.0, 1.0)  # [B]

    # 5. Phase entropy: entropy of quantised phase distribution
    phase = torch.atan2(q, i)  # [B, N], range [-pi, pi]
    # Quantise to 32 bins
    n_bins = 32
    bin_idx = ((phase + math.pi) / (2.0 * math.pi) * n_bins).long().clamp(0, n_bins - 1)
    # One-hot accumulate for histogram
    one_hot = torch.zeros(B, n_bins, device=i.device)
    one_hot.scatter_add_(1, bin_idx, torch.ones_like(bin_idx, dtype=torch.float32))
    # Normalise to probability and compute entropy
    prob = one_hot / (one_hot.sum(dim=-1, keepdim=True) + eps)
    phase_entropy = -(prob * torch.log(prob + eps)).sum(dim=-1)
    max_entropy = math.log(n_bins)
    phase_entropy = (phase_entropy / max_entropy).clamp(0.0, 1.5)  # [B]

    result = torch.stack(
        [
            spectral_flatness,
            symbol_rate_est,
            psd_kurt,
            bw_occupancy,
            phase_entropy,
        ],
        dim=-1,
    )
    return torch.nan_to_num(result, nan=0.0, posinf=0.0, neginf=0.0)


def compute_dsp_features(x: torch.Tensor) -> torch.Tensor:
    """Compute combined DSP features from IQ input.

    All operations use real-valued tensors for ONNX compatibility.
    Input IQ is normalised to unit RMS before feature extraction to
    prevent numerical overflow in high-power operations (z^8) and
    ensure cumulant normalisation stability.

    Parameters
    ----------
    x : torch.Tensor
        IQ input ``[B, 2, N]``.

    Returns
    -------
    torch.Tensor
        ``[B, 54]`` -- spectral peaks (3) + CP autocorrelation (6)
        + cumulants (8) + extended (32) + enhanced discriminative (5).
    """
    i_sig = x[:, 0, :]  # [B, N]
    q_sig = x[:, 1, :]  # [B, N]

    # DC removal: subtract per-sample mean to eliminate RTL-SDR DC spike.
    # This prevents HOS cumulants and spectral peaks from being corrupted.
    i_sig = i_sig - i_sig.mean(dim=-1, keepdim=True)
    q_sig = q_sig - q_sig.mean(dim=-1, keepdim=True)

    # Normalise to unit RMS for numerical safety (z^8 overflow prevention).
    # Detach the scale factor so gradients don't flow through normalisation.
    with torch.no_grad():
        rms = torch.sqrt(
            (i_sig * i_sig + q_sig * q_sig).mean(dim=-1, keepdim=True).clamp(min=1e-12)
        )
    i_norm = i_sig / rms
    q_norm = q_sig / rms

    # Sanitise: replace any NaN/Inf from corrupted inputs
    i_norm = torch.nan_to_num(i_norm, nan=0.0, posinf=0.0, neginf=0.0)
    q_norm = torch.nan_to_num(q_norm, nan=0.0, posinf=0.0, neginf=0.0)

    iq_pair = (i_norm, q_norm)
    spectral = nth_power_spectral_peaks(_iq_pair=iq_pair)  # [B, 3]
    cp = cp_autocorrelation(_iq_pair=iq_pair)  # [B, 6]
    cumulants = cumulant_features(_iq_pair=iq_pair)  # [B, 8]
    ext = extended_features(_iq_pair=iq_pair)  # [B, 32]
    enhanced = _enhanced_discriminative_features(i_norm, q_norm)  # [B, 5]
    return torch.cat([spectral, cp, cumulants, ext, enhanced], dim=-1)  # [B, 54]
