"""Golden-vector tests for the UAT ADS-B decoder (review D6).

Frames are built here from DO-282B, independently of the decoder:

* payload fields are packed at their DO-282B bit positions (1-based, MSB
  of byte 0 is bit 1);
* parity is a systematic RS encode over GF(256), field polynomial
  x^8 + x^7 + x^2 + x + 1, generator roots alpha^120 .. alpha^(120+P-1),
  using shift-and-add field arithmetic (no lookup tables);
* the IQ test modulates sync + frame as binary CPFSK (h = 0.6), which has
  a constant envelope.
"""

import numpy as np
import pytest

from sigrift.lib.dsp.uat_decoder import (
    UATMessage,
    _bits_to_bytes,
    _uat_fec_check,
    decode_uat_message,
    demodulate_uat,
)

BIT_RATE = 1_041_667
SYNC_ADSB = 0xEACDDA4E2


# -- independent GF(256) / RS encoder -------------------------------------


def _gmul(a: int, b: int) -> int:
    r = 0
    while b:
        if b & 1:
            r ^= a
        b >>= 1
        a <<= 1
        if a & 0x100:
            a ^= 0x187
    return r


def _alpha_pow(e: int) -> int:
    r = 1
    for _ in range(e % 255):
        r = _gmul(r, 2)
    return r


def _generator(nroots: int) -> list[int]:
    g = [1]  # highest power first
    for i in range(nroots):
        root = _alpha_pow(120 + i)
        nxt = g + [0]
        for j, c in enumerate(g):
            nxt[j + 1] ^= _gmul(c, root)
        g = nxt
    return g


def _rs_encode(data: bytes, nroots: int) -> bytes:
    g = _generator(nroots)
    rem = list(data) + [0] * nroots
    for i in range(len(data)):
        coef = rem[i]
        if coef:
            for j in range(1, len(g)):
                rem[i + j] ^= _gmul(g[j], coef)
    return bytes(data) + bytes(rem[len(data) :])


# -- DO-282B field packing --------------------------------------------------


def _put(buf: bytearray, first_bit: int, width: int, value: int) -> None:
    """Write *value* MSB-first at 1-based bit positions first_bit.."""
    for k in range(width):
        bit = (value >> (width - 1 - k)) & 1
        pos = first_bit - 1 + k
        if bit:
            buf[pos // 8] |= 0x80 >> (pos % 8)


def _payload(
    n_bytes: int,
    payload_type: int,
    aq: int,
    address: int,
    lat: float,
    lon: float,
    alt_ft: int,
    nic: int,
) -> bytearray:
    buf = bytearray(n_bytes)
    _put(buf, 1, 5, payload_type)
    _put(buf, 6, 3, aq)
    _put(buf, 9, 24, address)
    raw_lat = round((lat if lat >= 0 else lat + 180.0) * (1 << 24) / 360.0)
    raw_lon = round((lon if lon >= 0 else lon + 360.0) * (1 << 24) / 360.0)
    _put(buf, 33, 23, raw_lat)
    _put(buf, 56, 24, raw_lon)
    _put(buf, 80, 1, 0)  # barometric altitude
    _put(buf, 81, 12, (alt_ft + 1000) // 25 + 1)
    _put(buf, 93, 4, nic)
    return buf


_B40 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ  .."


def _mode_status(buf: bytearray, emitter: int, callsign: str, nac_p: int) -> None:
    cs = [_B40.index(c) for c in callsign.ljust(8)]
    _put(buf, 137, 16, emitter * 1600 + cs[0] * 40 + cs[1])
    _put(buf, 153, 16, cs[2] * 1600 + cs[3] * 40 + cs[4])
    _put(buf, 169, 16, cs[5] * 1600 + cs[6] * 40 + cs[7])
    _put(buf, 201, 4, nac_p)


def _basic_frame() -> bytes:
    data = _payload(18, 0, 0, 0xA1B2C3, 37.5, -122.25, 35000, 8)
    return _rs_encode(bytes(data), 12)


def _long_frame() -> bytes:
    data = _payload(34, 1, 0, 0x3C4D5E, -33.75, 151.125, 4500, 9)
    _mode_status(data, 3, "QFA12", 10)
    return _rs_encode(bytes(data), 14)


def _to_bits(frame: bytes) -> np.ndarray:
    return np.array(
        [(b >> (7 - i)) & 1 for b in frame for i in range(8)], dtype=np.int32
    )


# -- tests ------------------------------------------------------------------


def test_basic_frame_fields():
    msg = decode_uat_message(_to_bits(_basic_frame()))
    assert isinstance(msg, UATMessage)
    assert msg.icao_address == "A1B2C3"
    assert msg.msg_type == "basic"
    assert msg.payload_type == 0
    assert msg.address_qualifier == 0
    assert msg.lat == pytest.approx(37.5, abs=1e-4)
    assert msg.lon == pytest.approx(-122.25, abs=1e-4)
    assert msg.altitude_ft == 35000.0
    assert msg.nic == 8
    assert msg.rs_errors == 0
    assert len(msg.raw_bytes) == 18


def test_long_frame_mode_status():
    msg = decode_uat_message(_to_bits(_long_frame()))
    assert msg is not None
    assert msg.msg_type == "long"
    assert msg.payload_type == 1
    assert msg.icao_address == "3C4D5E"
    assert msg.lat == pytest.approx(-33.75, abs=1e-4)
    assert msg.lon == pytest.approx(151.125, abs=1e-4)
    assert msg.altitude_ft == 4500.0
    assert msg.nic == 9
    assert msg.emitter_category == 3
    assert msg.callsign == "QFA12"
    assert msg.nac == 10
    assert len(msg.raw_bytes) == 34


def test_tisb_address_qualifier():
    data = _payload(18, 0, 2, 0x123456, 10.0, 20.0, 1000, 5)
    msg = decode_uat_message(_to_bits(_rs_encode(bytes(data), 12)))
    assert msg is not None and msg.msg_type == "tisb"


def test_reserved_payload_type_has_no_state_vector():
    # Payload type 11 is a reserved (header-only) type in DO-282B: no state
    # vector is defined, so even an RS-valid frame whose SV bytes happen to be
    # non-zero must NOT yield position/altitude/NIC (cf. dump978, which
    # decodes the SV only for mdb_type 0-10).  Non-zero payload types are Long
    # frames (48 bytes), so build it at Long length.
    data = _payload(34, 11, 0, 0x445566, 37.5, -122.25, 35000, 8)
    msg = decode_uat_message(_to_bits(_rs_encode(bytes(data), 14)))
    assert msg is not None
    assert msg.payload_type == 11
    assert msg.icao_address == "445566"
    assert msg.lat is None and msg.lon is None
    assert msg.altitude_ft is None
    assert msg.nic is None


@pytest.mark.parametrize(
    ("builder", "max_errors", "n_bytes"),
    [(_basic_frame, 6, 30), (_long_frame, 7, 48)],
)
def test_rs_corrects_up_to_capacity(builder, max_errors, n_bytes):
    good = builder()
    rng = np.random.default_rng(5)
    for n_err in range(1, max_errors + 1):
        bad = bytearray(good)
        for pos in rng.choice(n_bytes, size=n_err, replace=False):
            bad[pos] ^= int(rng.integers(1, 256))
        msg = decode_uat_message(_to_bits(bytes(bad)))
        assert msg is not None, n_err
        assert msg.rs_errors == n_err
        assert msg.raw_bytes == good[: len(msg.raw_bytes)]


def test_uncorrectable_frame_dropped():
    bad = bytearray(_basic_frame())
    for pos in range(0, 14, 2):  # 7 byte errors > t = 6
        bad[pos] ^= 0x5A
    assert decode_uat_message(_to_bits(bytes(bad))) is None


def test_random_bits_dropped():
    rng = np.random.default_rng(11)
    for _ in range(20):
        bits = rng.integers(0, 2, 384).astype(np.int32)
        assert decode_uat_message(bits) is None


def test_fec_check_is_rs():
    assert _uat_fec_check(_basic_frame(), 30) is True
    assert _uat_fec_check(_long_frame(), 48) is True
    assert _uat_fec_check(bytes(30), 29) is False
    bad = bytearray(_basic_frame())
    for pos in range(7):
        bad[pos * 3] ^= 0xFF
    assert _uat_fec_check(bytes(bad), 30) is False


def test_short_bits_return_none():
    assert decode_uat_message(np.zeros(100, dtype=np.int32)) is None


def test_bits_to_bytes():
    bits = np.array([1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1])
    assert _bits_to_bytes(bits) == bytes([0xAA, 0x0F])


# -- IQ level: CPFSK modulation, FM discriminator demod ---------------------


def _cpfsk(bits: list[int], fs: float, rng) -> np.ndarray:
    sps = fs / BIT_RATE
    n = int(np.ceil(len(bits) * sps))
    t_bits = np.floor(np.arange(n) / sps).astype(int)
    sym = np.where(np.array(bits)[np.minimum(t_bits, len(bits) - 1)] == 1, 1.0, -1.0)
    dev = 0.3 * BIT_RATE  # h = 0.6
    phase = np.cumsum(2 * np.pi * dev * sym / fs) + rng.uniform(0, 2 * np.pi)
    return np.exp(1j * phase)


@pytest.mark.parametrize("fs", [2 * BIT_RATE, 4 * BIT_RATE, 6.25e6])
@pytest.mark.parametrize("builder", [_basic_frame, _long_frame])
def test_iq_round_trip(fs, builder):
    rng = np.random.default_rng(int(fs) % 1000)
    sync = [(SYNC_ADSB >> (35 - i)) & 1 for i in range(36)]
    frame_bits = _to_bits(builder()).tolist()
    tail = rng.integers(0, 2, 200).tolist()
    burst = _cpfsk(sync + frame_bits + tail, fs, rng)
    noise_lead = 0.05 * (rng.standard_normal(137) + 1j * rng.standard_normal(137))
    iq = np.concatenate([noise_lead, burst])
    iq = iq + 0.05 * (rng.standard_normal(len(iq)) + 1j * rng.standard_normal(len(iq)))

    bits = demodulate_uat(iq, sample_rate=fs)
    assert bits.dtype == np.int32 and bits.ndim == 1
    msg = decode_uat_message(bits)
    assert msg is not None
    expected = decode_uat_message(_to_bits(builder()))
    assert msg.raw_bytes == expected.raw_bytes


def test_demod_no_sync_returns_empty():
    rng = np.random.default_rng(3)
    iq = rng.standard_normal(5000) + 1j * rng.standard_normal(5000)
    bits = demodulate_uat(iq, sample_rate=2.5e6)
    assert bits.ndim == 1 and bits.dtype == np.int32
    assert decode_uat_message(bits) is None
    assert len(demodulate_uat(np.array([], dtype=complex), 2.5e6)) == 0
