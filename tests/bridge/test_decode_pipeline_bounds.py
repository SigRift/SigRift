"""Protocol decoding is bounded whatever sample rate a capture claims.

The sample rate comes from the ``X-Sample-Rate`` header a SENSOR key sets
on the IQ upload, and every upload for a DMR / P25 / LoRa detection queues
a ``protocol_decode`` job.  The pipeline resampled by that rate without
bounds: below 48 kHz a DMR capture was interpolated by 48000 / rate
(rate 1000: x48, 2 Mi samples -> ~8 GB and minutes of pure-Python
demodulation), and at absurd rates ``Fraction.limit_denominator`` left the
factor 0, replaced by ``1 / round(rate / target)`` (rate 1e12: an
anti-alias FIR of ~4e8 taps, 3 GiB).  Now the factor's terms, the
interpolation and the output length are bounded, rates outside
1 kHz .. 250 MHz are not decoded, and the upload refuses them.
"""

from __future__ import annotations

import logging
import time
import tracemalloc

import numpy as np
import pytest

from sigrift.bridge import decode_pipeline as dp
from sigrift.bridge.iq_store import analysis_max_samples

#: Most either term of a resampling factor may be (a few over the nominal
#: limit for the rounding of ratio x denominator).
_TERM_BOUND = dp._MAX_RESAMPLE_TERM + dp._MAX_UPSAMPLE


@pytest.fixture
def resampling(monkeypatch: pytest.MonkeyPatch) -> dict[str, list]:
    """Record every ``resample_poly`` call; refuse (and record) unbounded ones.

    An unbounded call raises instead of running, so the regression shows
    as a recorded violation rather than gigabytes of allocation.
    """
    import scipy.signal

    seen: dict[str, list] = {"calls": [], "violations": []}
    real = scipy.signal.resample_poly

    def checked(x, up, down, *args, **kwargs):
        call = (len(x), int(up), int(down))
        seen["calls"].append(call)
        out_len = -(-len(x) * int(up) // int(down))
        if max(up, down) > _TERM_BOUND or out_len > analysis_max_samples():
            seen["violations"].append(call)
            raise MemoryError(f"unbounded resampling {call}")
        return real(x, up, down, *args, **kwargs)

    monkeypatch.setattr(scipy.signal, "resample_poly", checked)
    return seen


def _warm_imports() -> None:
    # Module imports (scipy, the demodulators, the decoders) allocate too;
    # keep them out of the measured peak.
    import scipy.signal  # noqa: F401

    import sigrift.lib.dsp.demod  # noqa: F401
    import sigrift.lib.protocol.dmr  # noqa: F401
    import sigrift.lib.protocol.lora_phy  # noqa: F401
    import sigrift.lib.protocol.meshtastic  # noqa: F401
    import sigrift.lib.protocol.p25  # noqa: F401


def _decode(iq: np.ndarray, signal_class: str, rate: float) -> tuple[list, float, int]:
    _warm_imports()
    pipe = dp.ProtocolDecodePipeline(None, crypto_key_store=None)
    tracemalloc.start()
    t0 = time.monotonic()
    try:
        out = pipe.decode_iq(iq, signal_class, 446e6, rate)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    return out, time.monotonic() - t0, peak


class TestClaimedRate:
    @pytest.mark.parametrize(
        ("signal_class", "rate"),
        [
            ("dmr", 1_000.0),  # was: x48 interpolation
            ("p25", 5_000.0),  # below 2 samples per 4800-baud symbol
            ("dmr", 1.7),
            ("dmr", 1e12),  # was: a 1 / 20833333 factor (4e8-tap FIR)
            ("p25", 1e12),
            ("lora-css", 1e12),
            ("meshtastic", 1e12),
            ("dmr", float(np.nextafter(250e6, 1e12))),
        ],
    )
    def test_absurd_rate_on_a_full_window_costs_nothing(
        self, signal_class: str, rate: float, resampling, caplog
    ) -> None:
        # A whole analysis window of zeros (a ~16 KB gzip upload).
        iq = np.zeros(analysis_max_samples(), dtype=np.complex64)
        with caplog.at_level(logging.WARNING):
            out, elapsed, peak = _decode(iq, signal_class, rate)
        assert out == []
        assert resampling["violations"] == []
        assert peak < 8 * 2**20, f"{peak / 2**20:.0f} MiB"
        assert elapsed < 5.0
        assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []

    @pytest.mark.parametrize(
        ("signal_class", "rate"),
        [
            ("dmr", 9_600.0),  # x5 interpolation: output capped to the window
            ("p25", 12_345.0),
            ("dmr", 196e6),  # x4083 decimation
            ("lora-css", 250e6),  # x2000 decimation
            ("meshtastic", 3e6),
        ],
    )
    def test_plausible_rate_resamples_within_bounds(
        self,
        signal_class: str,
        rate: float,
        resampling,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Exercise real resampling and demodulation with a scaled window.
        # Coverage plus tracemalloc amplifies the per-sample Python loop;
        # 256 Ki samples exceeded the 30 s per-test timeout on busy CI workers.
        # The resampling spy still checks the exact configured output bound,
        # and the malicious-rate cases above retain the full analysis window.
        monkeypatch.setenv("BRIDGE_IQ_ANALYSIS_MAX_SAMPLES", str(64 * 1024))
        rng = np.random.default_rng(0)
        n = analysis_max_samples()
        iq = (rng.standard_normal(n) + 1j * rng.standard_normal(n)).astype(np.complex64)
        out, elapsed, peak = _decode(iq, signal_class, rate)
        assert out == []  # noise
        assert resampling["violations"] == []
        [(n_in, up, down)] = resampling["calls"]
        assert max(up, down) <= _TERM_BOUND
        assert -(-n_in * up // down) <= n
        assert peak < 128 * 2**20, f"{peak / 2**20:.0f} MiB"
        assert elapsed < 60.0

    def test_longer_input_than_the_window_is_truncated(
        self, resampling, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # decode_iq bounds its own input, not only the job handler's load.
        monkeypatch.setenv("BRIDGE_IQ_ANALYSIS_MAX_SAMPLES", str(64 * 1024))
        iq = np.zeros(4 * 1024 * 1024, dtype=np.complex64)
        assert (
            dp.ProtocolDecodePipeline(None, None).decode_iq(
                iq, "dmr", 446e6, 2_048_000.0
            )
            == []
        )
        [(n_in, _up, _down)] = resampling["calls"]
        assert n_in == 64 * 1024


class TestResample:
    @pytest.mark.parametrize(
        "rate",
        [9_600.0, 12_345.678, 47_999.0, 48_001.0, 250e3, 1e6, 2.048e6, 2.4e6,
         10e6, 20e6, 61.44e6, 123_456_789.0, 196e6],
    )  # fmt: skip
    def test_factor_terms_and_output_are_bounded(self, rate: float) -> None:
        iq = np.ones(100_000, dtype=np.complex64)
        target = dp._FSK_DEMOD_RATE
        result = dp._resample(iq, rate, target, max_out=50_000)
        assert result is not None
        out, out_rate = result
        assert len(out) <= 50_000
        up_down = out_rate / rate
        assert up_down == pytest.approx(target / rate, rel=1e-3)
        from fractions import Fraction

        factor = Fraction(up_down).limit_denominator(10 * _TERM_BOUND)
        assert max(factor.numerator, factor.denominator) <= _TERM_BOUND

    @pytest.mark.parametrize("rate", [1.0, 5_000.0, 200e6, 1e12, 0.0, -1.0])
    def test_out_of_range_factor_is_refused(self, rate: float) -> None:
        iq = np.ones(1000, dtype=np.complex64)
        assert dp._resample(iq, rate, dp._FSK_DEMOD_RATE, max_out=10**6) is None

    def test_same_rate_is_only_truncated(self) -> None:
        iq = np.arange(10, dtype=np.complex64)
        out, rate = dp._resample(iq, 48_000.0, 48_000.0, max_out=4)
        assert rate == 48_000.0 and out.tolist() == [0, 1, 2, 3]
