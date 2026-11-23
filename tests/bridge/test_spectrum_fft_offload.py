"""Tests for spectrum FFT thread offloading.

Covers Sprint 5 Item 21:
  - _compute_fft produces correct output shape and dtype
  - _compute_fft runs successfully via asyncio.to_thread
  - Window copy is not mutated by the FFT pipeline
"""

from __future__ import annotations

import asyncio

import numpy as np
import pytest

from sigrift.lib.shiny.spectrum_streamer import SpectrumStreamer


class TestComputeFFT:
    """Unit tests for SpectrumStreamer._compute_fft static method."""

    def _make_iq_bytes(self, fft_size: int = 1024) -> bytes:
        """Generate synthetic IQ bytes (uint8 pairs) for one FFT frame."""
        rng = np.random.default_rng(42)
        return rng.integers(0, 256, size=fft_size * 2, dtype=np.uint8).tobytes()

    def test_output_shape(self) -> None:
        """Output has display_bins elements."""
        fft_size = 1024
        display_bins = 512
        raw = self._make_iq_bytes(fft_size)
        window = np.hanning(fft_size).astype(np.float32)

        result = SpectrumStreamer._compute_fft(raw, window, fft_size, display_bins)

        assert result.shape == (display_bins,)

    def test_output_dtype(self) -> None:
        """Output is float (dB values)."""
        fft_size = 1024
        display_bins = 512
        raw = self._make_iq_bytes(fft_size)
        window = np.hanning(fft_size).astype(np.float32)

        result = SpectrumStreamer._compute_fft(raw, window, fft_size, display_bins)

        assert result.dtype in (np.float32, np.float64)

    def test_output_finite(self) -> None:
        """All output values are finite (no NaN or inf)."""
        fft_size = 1024
        display_bins = 512
        raw = self._make_iq_bytes(fft_size)
        window = np.hanning(fft_size).astype(np.float32)

        result = SpectrumStreamer._compute_fft(raw, window, fft_size, display_bins)

        assert np.all(np.isfinite(result))

    def test_different_bin_sizes(self) -> None:
        """Works with different fft_size / display_bins ratios."""
        for fft_size, display_bins in [(512, 256), (1024, 512), (2048, 512)]:
            raw = self._make_iq_bytes(fft_size)
            window = np.hanning(fft_size).astype(np.float32)

            result = SpectrumStreamer._compute_fft(
                raw, window, fft_size, display_bins,
            )

            assert result.shape == (display_bins,), (
                f"Failed for fft_size={fft_size}, display_bins={display_bins}"
            )

    def test_window_not_mutated(self) -> None:
        """The window array is not modified by _compute_fft."""
        fft_size = 1024
        display_bins = 512
        raw = self._make_iq_bytes(fft_size)
        window = np.hanning(fft_size).astype(np.float32)
        window_before = window.copy()

        SpectrumStreamer._compute_fft(raw, window, fft_size, display_bins)

        np.testing.assert_array_equal(window, window_before)

    def test_deterministic_output(self) -> None:
        """Same input produces same output."""
        fft_size = 1024
        display_bins = 512
        raw = self._make_iq_bytes(fft_size)
        window = np.hanning(fft_size).astype(np.float32)

        r1 = SpectrumStreamer._compute_fft(raw, window, fft_size, display_bins)
        r2 = SpectrumStreamer._compute_fft(raw, window, fft_size, display_bins)

        np.testing.assert_array_equal(r1, r2)


class TestComputeFFTAsync:
    """Verify _compute_fft works correctly via asyncio.to_thread."""

    @pytest.mark.asyncio
    async def test_to_thread_produces_same_result(self) -> None:
        """asyncio.to_thread gives the same result as direct call."""
        fft_size = 1024
        display_bins = 512
        rng = np.random.default_rng(99)
        raw = rng.integers(0, 256, size=fft_size * 2, dtype=np.uint8).tobytes()
        window = np.hanning(fft_size).astype(np.float32)

        sync_result = SpectrumStreamer._compute_fft(
            raw, window, fft_size, display_bins,
        )
        async_result = await asyncio.to_thread(
            SpectrumStreamer._compute_fft, raw, window, fft_size, display_bins,
        )

        np.testing.assert_array_equal(sync_result, async_result)

    @pytest.mark.asyncio
    async def test_concurrent_fft_calls(self) -> None:
        """Multiple concurrent to_thread FFT calls produce correct results."""
        fft_size = 1024
        display_bins = 512
        window = np.hanning(fft_size).astype(np.float32)

        rng = np.random.default_rng(0)
        frames = [
            rng.integers(0, 256, size=fft_size * 2, dtype=np.uint8).tobytes()
            for _ in range(8)
        ]

        # Compute expected results synchronously
        expected = [
            SpectrumStreamer._compute_fft(f, window, fft_size, display_bins)
            for f in frames
        ]

        # Compute via concurrent to_thread calls
        tasks = [
            asyncio.to_thread(
                SpectrumStreamer._compute_fft, f, window, fft_size, display_bins,
            )
            for f in frames
        ]
        results = await asyncio.gather(*tasks)

        for i, (exp, got) in enumerate(zip(expected, results)):
            np.testing.assert_array_equal(exp, got, err_msg=f"Frame {i} mismatch")
