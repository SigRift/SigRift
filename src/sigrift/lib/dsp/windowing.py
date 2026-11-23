"""Windowed FFT, PSD, and spectrogram utilities.

All spectral analysis should use windowing to reduce spectral leakage.
Hann window is the default for bandwidth estimation and SNR measurement.
"""

import numpy as np
from scipy.signal import get_window as _scipy_get_window


def get_window(name: str, size: int) -> np.ndarray:
    """Get a window function by name.

    Thin wrapper around ``scipy.signal.get_window`` with float64 output.

    Parameters
    ----------
    name : str
        Window name (e.g. ``'hann'``, ``'hamming'``, ``'blackman'``,
        ``'kaiser'``).
    size : int
        Window length in samples.

    Returns
    -------
    np.ndarray
        Window array of shape ``(size,)`` with dtype float64.
    """
    if size <= 0:
        return np.array([], dtype=np.float64)
    return _scipy_get_window(name, size).astype(np.float64)


def windowed_fft(
    iq_data: np.ndarray,
    window: str = "hann",
    nfft: int | None = None,
) -> np.ndarray:
    """Apply a window then compute the FFT.

    Parameters
    ----------
    iq_data : np.ndarray
        Complex IQ array.
    window : str
        Window name (default ``'hann'``).
    nfft : int or None
        FFT size. ``None`` uses ``len(iq_data)``.

    Returns
    -------
    np.ndarray
        Complex FFT output (not shifted).
    """
    n = len(iq_data)
    if n == 0:
        return np.array([], dtype=np.complex128)
    if nfft is None:
        nfft = n

    w = get_window(window, n)
    windowed = iq_data[:n] * w
    return np.fft.fft(windowed, n=nfft)


def windowed_psd(
    iq_data: np.ndarray,
    window: str = "hann",
    nfft: int | None = None,
) -> np.ndarray:
    """Compute energy-normalized power spectral density with windowing.

    The PSD is normalized by the window's energy so that Parseval's theorem
    holds (total PSD power matches time-domain power).

    Parameters
    ----------
    iq_data : np.ndarray
        Complex IQ array.
    window : str
        Window name (default ``'hann'``).
    nfft : int or None
        FFT size. ``None`` uses ``len(iq_data)``.

    Returns
    -------
    np.ndarray
        Real PSD array (linear scale), length ``nfft``.
    """
    n = len(iq_data)
    if nfft is None:
        nfft = n

    w = get_window(window, n)
    windowed = iq_data[:n] * w

    spectrum = np.fft.fft(windowed, n=nfft)
    psd = np.abs(spectrum) ** 2

    # Normalize by window energy
    window_energy = np.sum(w**2)
    if window_energy > 0:
        psd = psd / window_energy

    return psd


def windowed_spectrogram(
    iq_data: np.ndarray,
    fft_size: int = 256,
    overlap: float = 0.5,
    window: str = "hann",
) -> np.ndarray:
    """Compute dB spectrogram with windowing.

    Parameters
    ----------
    iq_data : np.ndarray
        Complex IQ array.
    fft_size : int
        FFT size per frame.
    overlap : float
        Fractional overlap between frames, in [0, 1).
    window : str
        Window name.

    Returns
    -------
    np.ndarray
        2D array of shape ``(num_frames, fft_size)`` in dB (float32).

    Raises
    ------
    ValueError
        If overlap is not in [0, 1).
    """
    if not 0.0 <= overlap < 1.0:
        raise ValueError(f"overlap must be in [0, 1), got {overlap}")
    hop_size = int(fft_size * (1 - overlap))
    if hop_size < 1:
        hop_size = 1
    num_frames = max(1, (len(iq_data) - fft_size) // hop_size + 1)

    w = get_window(window, fft_size)

    spectrogram = np.zeros((num_frames, fft_size), dtype=np.float32)

    for i in range(num_frames):
        start = i * hop_size
        frame = iq_data[start : start + fft_size] * w
        spectrum = np.fft.fftshift(np.fft.fft(frame))
        spectrogram[i] = 20.0 * np.log10(np.abs(spectrum) + 1e-10)

    return spectrogram
