"""Regression tests for IQ imbalance estimation + correction (review D11).

The imbalance model is the one the Gram-Schmidt estimator assumes::

    I = I0
    Q = A * (Q0 * cos(phi) + I0 * sin(phi))

After ``correct_iq_imbalance(estimate_iq_imbalance(x))`` the I and Q rails
must be uncorrelated and of equal power for every (A, phi) on the grid.
"""

import numpy as np
import pytest

from sigrift.lib.dsp.iq_correction import (
    apply_iq_imbalance,
    correct_iq_imbalance,
    estimate_iq_imbalance,
)

_N = 50_000


def _clean(seed: int) -> np.ndarray:
    rng = np.random.default_rng(seed)
    # Constant-envelope signal with random phase: I and Q are uncorrelated
    # and of equal power, and the SNR gate in the estimator passes.
    phases = rng.uniform(0.0, 2.0 * np.pi, _N)
    return np.exp(1j * phases)


def _impair(x: np.ndarray, amp: float, phi: float) -> np.ndarray:
    i0 = x.real
    q0 = x.imag
    q = amp * (q0 * np.cos(phi) + i0 * np.sin(phi))
    return i0 + 1j * q


def _corr_and_balance(y: np.ndarray) -> tuple[float, float]:
    i = y.real
    q = y.imag
    corr = float(np.mean(i * q) / np.sqrt(np.mean(i * i) * np.mean(q * q)))
    balance = float(np.mean(q * q) / np.mean(i * i))
    return corr, balance


def _sample_orthogonal(x: np.ndarray) -> np.ndarray:
    """Remove the finite-sample I/Q correlation of the clean reference."""
    i = x.real
    q = x.imag
    q = q - (np.mean(i * q) / np.mean(i * i)) * i
    q = q * np.sqrt(np.mean(i * i) / np.mean(q * q))
    return i + 1j * q


@pytest.mark.parametrize("amp", [0.5, 0.8, 1.0, 1.2, 1.5, 2.0])
@pytest.mark.parametrize("phi", [-0.4, -0.1, 0.0, 0.1, 0.3, 0.5])
def test_estimate_then_correct_orthogonalises(amp, phi):
    x = _impair(_sample_orthogonal(_clean(1234)), amp, phi)
    a_est, p_est = estimate_iq_imbalance(x)
    assert a_est == pytest.approx(amp, rel=1e-6)
    assert p_est == pytest.approx(phi, abs=1e-6)

    corr, balance = _corr_and_balance(correct_iq_imbalance(x, a_est, p_est))
    assert abs(corr) < 1e-6
    assert balance == pytest.approx(1.0, abs=1e-6)


def test_review_case_amp_1_5_phi_0_3():
    """The review's counter-example: the old formula left corr ~= 0.10."""
    clean = _sample_orthogonal(_clean(7))
    y = correct_iq_imbalance(_impair(clean, 1.5, 0.3), 1.5, 0.3)
    corr, balance = _corr_and_balance(y)
    assert abs(corr) < 1e-6
    assert balance == pytest.approx(1.0, abs=1e-6)
    # The model is invertible, so the clean signal comes back exactly.
    np.testing.assert_allclose(y, clean, atol=1e-9)


@pytest.mark.parametrize("amp_imb", [0.02, 0.1, 0.3])
@pytest.mark.parametrize("phase_imb", [0.02, 0.1, 0.3])
def test_correction_balances_augmentation_model(amp_imb, phase_imb):
    """Estimate+correct also orthogonalises the augmentation model's output."""
    x = apply_iq_imbalance(_clean(99), amp_imb, phase_imb)
    a_est, p_est = estimate_iq_imbalance(x)
    corr, balance = _corr_and_balance(correct_iq_imbalance(x, a_est, p_est))
    assert abs(corr) < 1e-6
    assert balance == pytest.approx(1.0, abs=1e-6)
