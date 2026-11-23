"""Higher-Order Statistics (HOS) cumulant features for modulation classification.

Pure-torch implementations computed inside the model ``forward()`` from
``[B, 2, N]`` IQ input.  All operations use **real-valued** tensors and
avoid ``torch.fft.*`` / complex dtypes for ONNX compatibility.

Implements 4th-order cumulants (C20, C40, C41, C42) normalised by signal
power (C21).  8 real-valued features are extracted:

1. ``|C20_hat|``      -- ASK/PAM (~1.0) vs PSK/QAM (~0.0)
2. ``angle(C20)/pi``  -- PSK order (BPSK=0, QPSK=pi/2)
3. ``|C40_hat|``      -- BPSK=2.0, QPSK=1.0, 8PSK=0.0
4. ``angle(C40)/pi``  -- constellation rotation
5. ``|C41_hat|``      -- QAM (~0.68) vs APSK (~0.45)
6. ``C42_hat``        -- QAM order (16QAM=-0.68, 64QAM=-0.619)
7. ``Re{C40_hat}``    -- BPSK(+2.0) vs QPSK(-1.0) sign
8. ``Re{C41_hat}``    -- additional QAM/APSK separation

Reference: Swami & Sadler, "Hierarchical digital modulation classification
using cumulants," IEEE Trans. Comm., vol. 48, no. 3, 2000.
"""

import torch

# Number of cumulant features produced by this module
NUM_CUMULANT_FEATURES = 8


def _compute_moments(i: torch.Tensor, q: torch.Tensor) -> tuple[torch.Tensor, ...]:
    """Compute raw moments M20, M21, M40, M41, M42 from I/Q using real arithmetic.

    All moments are returned as (real, imag) pairs except M21 and M42 which
    are purely real.

    Parameters
    ----------
    i, q : torch.Tensor
        I and Q components, shape ``[B, N]``.

    Returns
    -------
    tuple of torch.Tensor
        ``(M20_re, M20_im, M21, M40_re, M40_im, M41_re, M41_im, M42)``
        all with shape ``[B]``.
    """
    # Per-sample products [B, N]
    i2 = i * i
    q2 = q * q
    iq = i * q
    p = i2 + q2  # |z|^2

    # M20 = E[z^2] = E[(I+jQ)^2] = E[I^2 - Q^2] + j*E[2IQ]
    m20_re = (i2 - q2).mean(dim=-1)
    m20_im = (2.0 * iq).mean(dim=-1)

    # M21 = E[|z|^2] = E[I^2 + Q^2]  (purely real)
    m21 = p.mean(dim=-1)

    # M40 = E[z^4]
    # Re{z^4} = I^4 - 6*I^2*Q^2 + Q^4
    # Im{z^4} = 4*I^3*Q - 4*I*Q^3 = 4*IQ*(I^2 - Q^2)
    i4 = i2 * i2
    q4 = q2 * q2
    i2q2 = i2 * q2
    m40_re = (i4 - 6.0 * i2q2 + q4).mean(dim=-1)
    m40_im = (4.0 * iq * (i2 - q2)).mean(dim=-1)

    # M41 = E[z^3 * z*] = E[z^2 * |z|^2]
    # Re{z^2 * |z|^2} = (I^2-Q^2) * (I^2+Q^2) = I^4 - Q^4
    # Im{z^2 * |z|^2} = 2*IQ * (I^2+Q^2)
    m41_re = (i4 - q4).mean(dim=-1)
    m41_im = (2.0 * iq * p).mean(dim=-1)

    # M42 = E[|z|^4] = E[(I^2+Q^2)^2]  (purely real)
    m42 = (p * p).mean(dim=-1)

    return m20_re, m20_im, m21, m40_re, m40_im, m41_re, m41_im, m42


def _cumulants_from_moments(
    m20_re: torch.Tensor,
    m20_im: torch.Tensor,
    m21: torch.Tensor,
    m40_re: torch.Tensor,
    m40_im: torch.Tensor,
    m41_re: torch.Tensor,
    m41_im: torch.Tensor,
    m42: torch.Tensor,
) -> tuple[torch.Tensor, ...]:
    """Compute cumulants C20, C40, C41, C42 from raw moments.

    Relations (for zero-mean signals)::

        C20 = M20
        C40 = M40 - 3 * M20^2
        C41 = M41 - 3 * M20 * M21
        C42 = M42 - |M20|^2 - 2 * M21^2

    Parameters
    ----------
    m20_re, m20_im, m21, m40_re, m40_im, m41_re, m41_im, m42 : torch.Tensor
        Raw moments, all shape ``[B]``.

    Returns
    -------
    tuple of torch.Tensor
        ``(C20_re, C20_im, C40_re, C40_im, C41_re, C41_im, C42)``
        all shape ``[B]``.
    """
    # C20 = M20 (for zero-mean signals)
    c20_re = m20_re
    c20_im = m20_im

    # C40 = M40 - 3 * M20^2
    # M20^2 = (m20_re + j*m20_im)^2
    m20_sq_re = m20_re * m20_re - m20_im * m20_im
    m20_sq_im = 2.0 * m20_re * m20_im
    c40_re = m40_re - 3.0 * m20_sq_re
    c40_im = m40_im - 3.0 * m20_sq_im

    # C41 = M41 - 3 * M20 * M21  (M21 is real)
    c41_re = m41_re - 3.0 * m20_re * m21
    c41_im = m41_im - 3.0 * m20_im * m21

    # C42 = M42 - |M20|^2 - 2 * M21^2
    m20_mag_sq = m20_re * m20_re + m20_im * m20_im
    c42 = m42 - m20_mag_sq - 2.0 * m21 * m21

    return c20_re, c20_im, c40_re, c40_im, c41_re, c41_im, c42


def cumulant_features(
    x_complex: torch.Tensor = None,
    *,
    _iq_pair: tuple[torch.Tensor, torch.Tensor] | None = None,
) -> torch.Tensor:
    """Compute 8 normalised HOS cumulant features.

    All operations are real-valued (ONNX-safe).

    Parameters
    ----------
    x_complex : torch.Tensor, optional
        Complex signal ``[B, N]``.  Ignored if ``_iq_pair`` is provided.
    _iq_pair : tuple of (Tensor, Tensor) or None
        If provided, ``(I, Q)`` real tensors ``[B, N]`` (ONNX-safe path).

    Returns
    -------
    torch.Tensor
        ``[B, 8]`` normalised cumulant features, clamped to [-5, 5].
    """
    if _iq_pair is not None:
        i_in, q_in = _iq_pair
    else:
        i_in = x_complex.real.float()
        q_in = x_complex.imag.float()

    # Compute raw moments
    m20_re, m20_im, m21, m40_re, m40_im, m41_re, m41_im, m42 = _compute_moments(
        i_in, q_in
    )

    # Compute cumulants
    c20_re, c20_im, c40_re, c40_im, c41_re, c41_im, c42 = _cumulants_from_moments(
        m20_re, m20_im, m21, m40_re, m40_im, m41_re, m41_im, m42
    )

    # Normalise by C21 = M21 (signal power) with eps clamping for stability
    eps = 1e-10
    c21 = m21.clamp(min=eps)
    c21_sq = c21 * c21

    # Normalised cumulants (hat = divided by appropriate power of C21)
    c20_hat_re = c20_re / c21
    c20_hat_im = c20_im / c21

    c40_hat_re = c40_re / c21_sq
    c40_hat_im = c40_im / c21_sq

    c41_hat_re = c41_re / c21_sq
    c41_hat_im = c41_im / c21_sq

    c42_hat = c42 / c21_sq

    # Complex magnitudes
    c20_mag = torch.sqrt(c20_hat_re * c20_hat_re + c20_hat_im * c20_hat_im + eps)
    c40_mag = torch.sqrt(c40_hat_re * c40_hat_re + c40_hat_im * c40_hat_im + eps)
    c41_mag = torch.sqrt(c41_hat_re * c41_hat_re + c41_hat_im * c41_hat_im + eps)

    # Angles scaled to [-1, 1] by dividing by pi
    pi = 3.141592653589793
    mag_thresh = 1e-6

    c20_angle = torch.where(
        c20_mag > mag_thresh,
        torch.atan2(c20_hat_im, c20_hat_re) / pi,
        torch.zeros_like(c20_mag),
    )
    c40_angle = torch.where(
        c40_mag > mag_thresh,
        torch.atan2(c40_hat_im, c40_hat_re) / pi,
        torch.zeros_like(c40_mag),
    )

    # Build feature vector [B, 8]
    features = torch.stack(
        [
            c20_mag,  # 1. |C20_hat| -- ASK/PAM vs PSK/QAM
            c20_angle,  # 2. angle(C20)/pi -- PSK order
            c40_mag,  # 3. |C40_hat| -- PSK discriminator
            c40_angle,  # 4. angle(C40)/pi -- constellation rotation
            c41_mag,  # 5. |C41_hat| -- QAM vs APSK
            c42_hat,  # 6. C42_hat -- QAM order
            c40_hat_re,  # 7. Re{C40_hat} -- BPSK vs QPSK sign
            c41_hat_re,  # 8. Re{C41_hat} -- QAM/APSK separation
        ],
        dim=-1,
    )

    return features.clamp(-5.0, 5.0)
