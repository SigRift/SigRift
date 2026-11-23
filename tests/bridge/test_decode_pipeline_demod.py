"""The protocol decode pipeline drives the REAL demodulators (review Q6).

``decode_iq`` called ``demod.demodulate(iq, sample_rate=...)``, but the
real demodulators are ``FSKDemodulator(sample_rate).demodulate(iq,
preset=None)`` and ``LoRaCSSDemodulator(sample_rate).demodulate(iq,
sf=None, bw=None)`` (and the FSK ones were even built with the preset as
their sample rate).  Every call raised ``TypeError``, was logged as an
ERROR traceback and returned ``[]``; the earlier tests replaced the
demodulator with a stub that had the made-up signature.

These tests synthesise captures (4FSK DMR / P25 C4FM bursts built here
from ETSI TS 102 361-1 and TIA-102.BAAA, LoRa chirps) and run them
through the real demodulator classes.
"""

from __future__ import annotations

import logging

import numpy as np
import pytest

import sigrift.lib.dsp.demod as demod_mod
from sigrift.bridge.decode_pipeline import ProtocolDecodePipeline
from sigrift.lib.protocol.base import DecodedPacket

# -- Synthetic 4FSK captures ---------------------------------------------------

#: ETSI TS 102 361-1 / TIA-102.BAAA dibit -> 4FSK symbol.
_SYMBOL = {(0, 1): 3, (0, 0): 1, (1, 0): -1, (1, 1): -3}
_DMR_BS_VOICE_SYNC = 0x755FD7DF75F7
_P25_FRAME_SYNC = 0x5575F5FF77FF
_P25_BCH_GEN = 0o6331141367235453  # BCH(63,16) generator, degree 47


def _bits(value: int, width: int) -> list[int]:
    return [(value >> (width - 1 - i)) & 1 for i in range(width)]


def _random_bits(rng: np.random.Generator, n: int) -> list[int]:
    return rng.integers(0, 2, n).tolist()


def _dmr_voice_bursts(n_bursts: int, rng: np.random.Generator) -> list[list[int]]:
    """264-bit BS voice bursts: 108 bits, voice sync, 108 bits."""
    return [
        _random_bits(rng, 108) + _bits(_DMR_BS_VOICE_SYNC, 48) + _random_bits(rng, 108)
        for _ in range(n_bursts)
    ]


def _dmr_stream(bursts: list[list[int]], rng: np.random.Generator) -> list[int]:
    stream = _random_bits(rng, 200)
    for burst in bursts:
        stream += burst + _random_bits(rng, 24)  # + CACH
    return stream + _random_bits(rng, 200)


def _p25_nid(nac: int, duid: int) -> list[int]:
    info = (nac << 4) | duid
    rem = info << 47
    for bit in range(62, 46, -1):
        if rem & (1 << bit):
            rem ^= _P25_BCH_GEN << (bit - 47)
    codeword = _bits((info << 47) | rem, 63)
    return codeword + [sum(codeword) % 2]


def _p25_stream(nac: int, duids: list[int], rng: np.random.Generator) -> list[int]:
    stream = _random_bits(rng, 150)
    for duid in duids:
        frame = (
            _bits(_P25_FRAME_SYNC, 48) + _p25_nid(nac, duid) + _random_bits(rng, 1500)
        )
        for i, bit in enumerate(frame):  # status dibit after every 70 bits
            stream.append(bit)
            if i % 70 == 69:
                stream += [1, 0]
    return stream + _random_bits(rng, 150)


def _fsk_capture(
    bits: list[int],
    sample_rate: float,
    hz_per_level: float,
    noise: float = 0.0,
    seed: int = 7,
) -> np.ndarray:
    """4FSK-modulate *bits* (4800 baud, levels +-1 / +-3) at *sample_rate*."""
    rng = np.random.default_rng(seed)
    symbols = np.array(
        [_SYMBOL[(bits[i], bits[i + 1])] for i in range(0, len(bits) - 1, 2)]
    )
    sps = sample_rate / 4800.0
    n = int(len(symbols) * sps)
    freq = symbols[(np.arange(n) / sps).astype(np.int64)] * hz_per_level
    smooth = max(1, int(sps / 2))  # band-limit the frequency steps
    freq = np.convolve(freq, np.ones(smooth) / smooth, mode="same")
    iq = np.exp(1j * 2 * np.pi * np.cumsum(freq) / sample_rate)
    if noise:
        iq = iq + noise * (rng.standard_normal(n) + 1j * rng.standard_normal(n))
    return iq.astype(np.complex64)


def _pipeline() -> ProtocolDecodePipeline:
    return ProtocolDecodePipeline(None, crypto_key_store=None)


@pytest.fixture
def demod_calls(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, float, dict]]:
    """Record every call of the real demodulators' ``demodulate``."""
    calls: list[tuple[str, float, dict]] = []
    for cls in (demod_mod.FSKDemodulator, demod_mod.LoRaCSSDemodulator):
        real = cls.demodulate

        def recording(self, iq, *args, _real=real, _name=cls.__name__, **kwargs):
            calls.append((_name, float(self.sample_rate), dict(kwargs)))
            return _real(self, iq, *args, **kwargs)

        monkeypatch.setattr(cls, "demodulate", recording)
    return calls


# -- DMR -----------------------------------------------------------------------


class TestDmr:
    # Same noise density in the channel at every rate (0.3 at 2.048 MHz).
    @pytest.mark.parametrize(
        ("sample_rate", "noise"),
        [(2_048_000.0, 0.3), (2_400_000.0, 0.3), (250_000.0, 0.1)],
    )
    def test_every_burst_of_a_capture_is_decoded(
        self, sample_rate: float, noise: float, demod_calls, caplog
    ) -> None:
        rng = np.random.default_rng(1)
        bursts = _dmr_voice_bursts(12, rng)
        iq = _fsk_capture(_dmr_stream(bursts, rng), sample_rate, 648.0, noise=noise)
        with caplog.at_level(logging.WARNING):
            out = _pipeline().decode_iq(
                iq, "dmr", 446e6, sample_rate, "n1", detection_id="det-dmr"
            )
        assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []
        [(name, rate, kwargs)] = demod_calls
        assert name == "FSKDemodulator"
        assert rate == pytest.approx(48_000.0)
        assert kwargs["preset"].name == "dmr"
        assert len(out) == len(bursts)
        assert {r["protocol"] for r in out} == {"dmr"}
        assert {r["message_type"] for r in out} == {"voice"}
        assert all(r["detection_id"] == "det-dmr" for r in out)
        # The voice payload is the burst minus its sync, bit for bit.
        expected = [
            np.packbits(np.array(b[:108] + b[156:], dtype=np.uint8)).tobytes().hex()
            for b in bursts
        ]
        assert [r["payload_hex"] for r in out] == expected

    def test_demodulated_bits_reach_the_decoder(self, monkeypatch) -> None:
        # Decoder stubbed: the real demodulator alone must deliver the
        # transmitted burst, bit for bit, in some decode_packet window.
        rng = np.random.default_rng(2)
        [burst] = _dmr_voice_bursts(1, rng)
        iq = _fsk_capture(_dmr_stream([burst], rng), 2_048_000.0, 648.0)
        windows: list[str] = []

        class Recording:
            def decode_packet(self, raw: bytes, **kwargs) -> DecodedPacket:
                windows.append(
                    "".join(str(b) for b in np.unpackbits(np.frombuffer(raw, np.uint8)))
                )
                return DecodedPacket(protocol="dmr", raw_bytes=raw, payload=b"")

            def extract_messages(self, packet):
                return []

        pipe = _pipeline()
        monkeypatch.setattr(pipe, "_select_decoder", lambda protocol: Recording())
        assert pipe.decode_iq(iq, "dmr", 446e6, 2_048_000.0) == []
        target = "".join(map(str, burst))
        assert any(target in w for w in windows)

    def test_noise_decodes_to_nothing_quietly(self, demod_calls, caplog) -> None:
        rng = np.random.default_rng(3)
        iq = (rng.standard_normal(400_000) + 1j * rng.standard_normal(400_000)).astype(
            np.complex64
        )
        with caplog.at_level(logging.DEBUG, logger="sigrift.bridge.decode_pipeline"):
            out = _pipeline().decode_iq(iq, "dmr", 446e6, 2_048_000.0)
        assert out == []
        assert len(demod_calls) == 1
        assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []

    def test_short_capture_is_skipped(self, demod_calls) -> None:
        iq = np.ones(1000, dtype=np.complex64)
        assert _pipeline().decode_iq(iq, "dmr", 446e6, 2_048_000.0) == []
        assert demod_calls == []  # under 64 symbols: nothing to demodulate


def _whole_bursts_only_decoder():
    """A DMRDecoder that reports only syncs whose whole burst it was given.

    (A cut-off burst at either end of its input is never reported, not
    even as truncated.)  The pipeline must not depend on being told about
    cut-off frames.
    """
    from sigrift.lib.protocol.base import FrameSyncError
    from sigrift.lib.protocol.dmr import DMRDecoder

    class WholeBurstsOnly(DMRDecoder):
        def decode_packet(self, raw: bytes, **kwargs) -> DecodedPacket:
            bits = np.unpackbits(np.frombuffer(raw, np.uint8)).tolist()
            try:
                _kind, offset = self.detect_sync(bits[108 : len(bits) - 108])
            except FrameSyncError:
                return DecodedPacket(protocol="dmr", raw_bytes=raw, payload=b"")
            sync = 108 + offset
            burst = np.packbits(np.array(bits[sync - 108 : sync + 156], np.uint8))
            packet = super().decode_packet(burst.tobytes())
            packet.metadata["sync_offset"] = sync
            return packet

    return WholeBurstsOnly()


class TestDmrSyncBitErrors:
    """A burst whose sync has (tolerated) bit errors is decoded too.

    ``DMRDecoder.detect_sync`` returns the first error-free sync of what it
    is given, else the best one: an earlier burst whose sync has bit errors
    was skipped whenever an error-free one followed in the same window.
    """

    @pytest.fixture(params=["reports-cut-off-syncs", "whole-bursts-only"])
    def decoder(self, request):
        from sigrift.lib.protocol.dmr import DMRDecoder

        if request.param == "whole-bursts-only":
            return _whole_bursts_only_decoder()
        return DMRDecoder()

    @staticmethod
    def _with_sync_errors(burst: list[int]) -> list[int]:
        burst = list(burst)
        for i in (5, 20):  # DMRDecoder tolerates up to 4 sync bit errors
            burst[108 + i] ^= 1
        return burst

    @staticmethod
    def _voice_payloads(bursts: list[list[int]]) -> list[bytes]:
        return [
            np.packbits(np.array(b[:108] + b[156:], dtype=np.uint8)).tobytes()
            for b in bursts
        ]

    # lead_in 842 puts the first sync where the window cuts its burst off,
    # so it is decoded by the retry from 108 bits before its sync.
    @pytest.mark.parametrize("lead_in", [0, 200, 333, 842, 905])
    @pytest.mark.parametrize("noisy", [(0,), (0, 2), (1, 3), (0, 1, 2, 3, 4, 5)])
    def test_every_burst_is_decoded(self, decoder, lead_in: int, noisy: tuple) -> None:
        from sigrift.bridge.decode_pipeline import _FRAMINGS

        rng = np.random.default_rng(11)
        bursts = _dmr_voice_bursts(6, rng)
        for i in noisy:
            bursts[i] = self._with_sync_errors(bursts[i])
        stream = _random_bits(rng, lead_in)
        for burst in bursts:
            stream += burst + _random_bits(rng, 24)
        stream += _random_bits(rng, 200)
        packets = _pipeline()._decode_frames(
            decoder, np.array(stream, dtype=np.uint8), _FRAMINGS["dmr"]
        )
        decoded = [p for p in packets if p.payload]
        assert [p.payload for p in decoded] == self._voice_payloads(bursts)
        assert [p.metadata["sync_errors"] for p in decoded] == [
            2 if i in noisy else 0 for i in range(len(bursts))
        ]

    def test_through_the_real_demodulator(self, demod_calls) -> None:
        rng = np.random.default_rng(12)
        bursts = _dmr_voice_bursts(4, rng)
        bursts[0] = self._with_sync_errors(bursts[0])
        bursts[2] = self._with_sync_errors(bursts[2])
        iq = _fsk_capture(_dmr_stream(bursts, rng), 2_048_000.0, 648.0, noise=0.1)
        out = _pipeline().decode_iq(iq, "dmr", 446e6, 2_048_000.0)
        assert len(demod_calls) == 1
        assert [bytes.fromhex(r["payload_hex"]) for r in out] == (
            self._voice_payloads(bursts)
        )


# -- P25 -----------------------------------------------------------------------


class TestP25:
    def test_every_frame_nid_is_decoded(self, demod_calls, caplog) -> None:
        rng = np.random.default_rng(4)
        duids = [0x5, 0xA, 0x5, 0xA, 0x3]
        bits = _p25_stream(0x293, duids, rng)
        iq = _fsk_capture(bits, 2_048_000.0, 600.0, noise=0.3)
        with caplog.at_level(logging.WARNING):
            out = _pipeline().decode_iq(iq, "p25", 851e6, 2_048_000.0, "n2")
        assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []
        [(name, rate, kwargs)] = demod_calls
        assert name == "FSKDemodulator" and kwargs["preset"].name == "p25_c4fm"
        assert rate == pytest.approx(48_000.0)
        assert [r["message_type"] for r in out] == [
            "ldu1_voice",
            "ldu2_encryption_sync",
            "ldu1_voice",
            "ldu2_encryption_sync",
            "tdu_termination",
        ]
        assert all(r["metadata"]["nac"] == 0x293 for r in out)

    def test_capture_without_frame_sync_is_not_an_error(self, caplog) -> None:
        # P25Decoder raises FrameSyncError when there is no sync; that used
        # to surface as an ERROR traceback.
        iq = _fsk_capture(
            _random_bits(np.random.default_rng(5), 4000), 2_048_000.0, 600.0
        )
        with caplog.at_level(logging.WARNING):
            assert _pipeline().decode_iq(iq, "p25", 851e6, 2_048_000.0) == []
        assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []


# -- LoRa / Meshtastic -----------------------------------------------------------


def _lora_capture(sf: int, bw: float, oversample: int, values: list[int]) -> np.ndarray:
    """Up-chirps: 10 preamble symbols (value 0), then *values*, oversampled."""
    n = 2**sf
    base = demod_mod.LoRaCSSDemodulator(sample_rate=bw).generate_base_chirp(sf, bw)
    symbols = [0] * 10 + values
    chips = np.concatenate([np.roll(base, -v) for v in symbols] + [np.zeros(4 * n)])
    from scipy.signal import resample_poly

    return resample_poly(chips, oversample, 1).astype(np.complex64)


class TestLora:
    @pytest.mark.parametrize("signal_class", ["lora-css", "meshtastic"])
    def test_real_css_demodulator_runs_at_the_chip_rate(
        self, signal_class: str, demod_calls, caplog
    ) -> None:
        iq = _lora_capture(7, 125_000.0, 8, [5, 9, 40, 77, 100, 3, 64, 12])
        with caplog.at_level(logging.WARNING):
            out = _pipeline().decode_iq(iq, signal_class, 868e6, 1_000_000.0)
        assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []
        # The demodulator assumes one sample per chip: it runs on the
        # capture resampled to the detected bandwidth, which it is given.
        [(name, rate, kwargs)] = demod_calls
        assert name == "LoRaCSSDemodulator"
        assert rate == pytest.approx(125_000.0)
        assert kwargs == {"bw": pytest.approx(125_000.0)}
        # Arbitrary chirps are not a valid LoRa frame: nothing is stored.
        assert out == []

    def test_symbols_reach_the_phy_decoder_packed_by_sf(self, monkeypatch) -> None:
        values = [5, 9, 40, 77, 100, 3, 64, 12, 1, 2]
        iq = _lora_capture(7, 125_000.0, 8, values)
        seen: list[tuple[bytes, dict]] = []

        class Phy:
            verified = True

            def decode_packet(self, raw: bytes, **kwargs) -> DecodedPacket:
                seen.append((raw, kwargs))
                return DecodedPacket(
                    protocol="lora",
                    raw_bytes=raw,
                    payload=b"\x01\x02" if self.verified else b"",
                    metadata={"header": {"header_ok": self.verified}, "crc_ok": True},
                )

            def extract_messages(self, packet):
                from sigrift.lib.protocol.lora_phy import LoRaPhyDecoder

                return LoRaPhyDecoder().extract_messages(packet)

        phy = Phy()
        pipe = _pipeline()
        monkeypatch.setattr(pipe, "_select_decoder", lambda protocol: phy)
        out = pipe.decode_iq(iq, "lora-css", 868e6, 1_000_000.0)
        [(raw, kwargs)] = seen
        assert kwargs == {"sf": 7}
        bits = np.unpackbits(np.frombuffer(raw, np.uint8))
        symbols = [
            int("".join(map(str, bits[i : i + 7])), 2)
            for i in range(0, len(bits) - 6, 7)
        ]
        assert len(symbols) >= 3
        assert [r["payload_hex"] for r in out] == ["0102"]

        # A frame that fails the PHY checks is dropped.
        phy.verified = False
        seen.clear()
        assert pipe.decode_iq(iq, "lora-css", 868e6, 1_000_000.0) == []
        assert len(seen) == 1

    def test_rate_below_lora_bandwidth_is_skipped(self, demod_calls) -> None:
        iq = np.ones(50_000, dtype=np.complex64)
        assert _pipeline().decode_iq(iq, "lora-css", 868e6, 100_000.0) == []
        assert demod_calls == []


def test_dect_is_not_demodulated(demod_calls) -> None:
    # DECT has a demodulator preset but no decoder: demodulating it was
    # wasted work.
    iq = np.ones(100_000, dtype=np.complex64)
    assert _pipeline().decode_iq(iq, "dect", 1.9e9, 2_048_000.0) == []
    assert demod_calls == []


def test_job_handler_decodes_a_stored_capture(tmp_path) -> None:
    import gzip

    from sigrift.bridge.decode_pipeline import protocol_decode_job_handler
    from sigrift.bridge.iq_store import IQStore

    rng = np.random.default_rng(6)
    bursts = _dmr_voice_bursts(4, rng)
    iq = _fsk_capture(_dmr_stream(bursts, rng), 1_000_000.0, 648.0, noise=0.2)
    store = IQStore(base_dir=tmp_path)
    store.store("det-job", gzip.compress(iq.tobytes()))
    handler = protocol_decode_job_handler(_pipeline(), store)
    result = handler(
        "job", {"detection_id": "det-job", "signal_class": "dmr", "sample_rate": 1e6}
    )
    assert result["status"] == "decoded", result
    assert result["messages"] == 4
    assert result["stored"] == 0  # no store configured
