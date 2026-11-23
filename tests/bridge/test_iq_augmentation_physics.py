"""Receiver-model regressions for IQ augmentation (PRE20).

ADI Design Note 1027, "Theory of Operation of IQ Demodulation", describes
quadrature phase error as I-to-Q crosstalk, not a common carrier rotation:
https://www.analog.com/en/resources/design-notes/2023/11/21/07/11/optimizing-performance-wideband-direct-conversion-receivers.html

The oracles below use RF mixing/low-pass filtering, image power, and measured
rail correlation rather than repeating the implementation's baseband matrix.
"""

import numpy as np
import pytest

from sigrift.lib.dsp.iq_correction import (
    apply_iq_imbalance,
    correct_iq_imbalance,
    estimate_iq_imbalance,
)


def _tone(bin_index=37, size=4096):
    return np.exp(2j * np.pi * bin_index * np.arange(size) / size)


@pytest.mark.parametrize("amplitude_imb", [-0.3, 0.0, 0.3])
@pytest.mark.parametrize("phase_imb", [-0.2, 0.0, 0.2])
def test_matches_independent_rf_mixer_receiver(amplitude_imb, phase_imb):
    size, carrier_bin = 4096, 512
    angle = 2 * np.pi * np.arange(size) / size
    clean = _tone(size=size)
    rf = np.real(clean * np.exp(1j * carrier_bin * angle))

    def lowpass(samples):
        spectrum = np.fft.fft(samples)
        spectrum[np.abs(np.fft.fftfreq(size) * size) >= carrier_bin / 2] = 0
        return np.fft.ifft(spectrum).real

    # LO separation is pi/2 - phase_imb. The factor two restores the
    # downconverter's half-amplitude mixing loss; the low-pass rejects 2*LO.
    i_mixed = 2 * rf * np.cos(carrier_bin * angle + phase_imb / 2)
    q_mixed = -2 * rf * np.sin(carrier_bin * angle - phase_imb / 2)
    expected = (1 + amplitude_imb / 2) * lowpass(i_mixed) + 1j * (
        1 - amplitude_imb / 2
    ) * lowpass(q_mixed)

    actual = apply_iq_imbalance(clean, amplitude_imb, phase_imb)
    np.testing.assert_allclose(actual, expected, rtol=0, atol=3e-13)


@pytest.mark.parametrize("bin_index", [-37, 37])
@pytest.mark.parametrize("phase_imb", [-0.2, 0.2])
def test_phase_only_image_power_matches_quadrature_error(bin_index, phase_imb):
    clean = _tone(bin_index)
    augmented = apply_iq_imbalance(clean, 0.0, phase_imb)
    spectrum = np.fft.fft(augmented)
    image_to_signal = abs(spectrum[-bin_index] / spectrum[bin_index]) ** 2
    # Equal-gain quadrature paths have IRR=cot(phi/2)^2. A pure rotation
    # would instead leave the image at numerical noise for every phi.
    assert image_to_signal == pytest.approx(np.tan(phase_imb / 2) ** 2, rel=1e-10)


@pytest.mark.parametrize("amplitude_imb", [-0.3, 0.3])
def test_gain_only_image_power_keeps_fractional_gain_contract(amplitude_imb):
    spectrum = np.fft.fft(apply_iq_imbalance(_tone(), amplitude_imb, 0.0))
    image_to_signal = abs(spectrum[-37] / spectrum[37]) ** 2
    assert image_to_signal == pytest.approx((amplitude_imb / 2) ** 2, rel=1e-10)


@pytest.mark.parametrize(
    "amplitude_imb,phase_imb", [(-0.3, -0.2), (0.0, 0.2), (0.3, 0.2)]
)
def test_phase_convention_and_estimator_correction_compatibility(
    amplitude_imb, phase_imb
):
    augmented = apply_iq_imbalance(_tone(), amplitude_imb, phase_imb)
    i, q = augmented.real, augmented.imag
    correlation = np.mean(i * q) / np.sqrt(np.mean(i * i) * np.mean(q * q))
    assert correlation == pytest.approx(np.sin(phase_imb), abs=1e-12)

    amplitude, phase = estimate_iq_imbalance(augmented)
    assert amplitude == pytest.approx((1 - amplitude_imb / 2) / (1 + amplitude_imb / 2))
    assert phase == pytest.approx(phase_imb, abs=1e-12)
    corrected = np.fft.fft(correct_iq_imbalance(augmented, amplitude, phase))
    assert abs(corrected[-37] / corrected[37]) ** 2 < 1e-24


@pytest.mark.parametrize("dtype", [np.complex64, np.complex128])
def test_preserves_input_dtype_shape_and_zero_impairment(dtype):
    clean = _tone().astype(dtype)
    before = clean.copy()
    np.testing.assert_array_equal(apply_iq_imbalance(clean, 0.0, 0.0), clean)
    augmented = apply_iq_imbalance(clean, 0.1, 0.2)
    assert augmented.dtype == clean.dtype
    assert augmented.shape == clean.shape
    np.testing.assert_array_equal(clean, before)

    empty = np.array([], dtype=dtype)
    result = apply_iq_imbalance(empty, 0.1, 0.2)
    assert result.dtype == empty.dtype
    assert result.shape == empty.shape
    assert result is not empty
