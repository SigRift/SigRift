"""Golden-vector tests for the P25 NID decoder (review D4c).

Frames are assembled here from TIA-102.BAAA, independently of the decoder:
48-bit frame sync, NID = BCH(63,16) systematic codeword (generator octal
6331 1413 6723 5453, encoded by long division) + even parity bit, and a
status dibit inserted after every 70 bits counted from the frame sync.
"""

import numpy as np
import pytest

from sigrift.lib.protocol.base import FrameSyncError
from sigrift.lib.protocol.p25 import P25Decoder, bch_63_16_decode

FRAME_SYNC = 0x5575F5FF77FF
GEN = 0o6331141367235453  # degree 47


def _bits(value: int, width: int) -> list[int]:
    return [(value >> (width - 1 - i)) & 1 for i in range(width)]


def _bch_encode(info16: int) -> list[int]:
    rem = info16 << 47
    for bit in range(62, 46, -1):
        if rem & (1 << bit):
            rem ^= GEN << (bit - 47)
    return _bits((info16 << 47) | rem, 63)


def _nid(nac: int, duid: int) -> list[int]:
    cw = _bch_encode((nac << 4) | duid)
    return cw + [sum(cw) % 2]


def _with_status(info_bits: list[int]) -> list[int]:
    out: list[int] = []
    for i, b in enumerate(info_bits):
        out.append(b)
        if i % 70 == 69:
            out.extend([1, 0])  # status dibit
    return out


def _pack(bits: list[int]) -> bytes:
    bits = bits + [0] * ((-len(bits)) % 8)
    return bytes(
        sum(bits[i + k] << (7 - k) for k in range(8)) for i in range(0, len(bits), 8)
    )


def _frame(nac: int, duid: int, nid_errors: list[int] = (), lead: int = 21) -> bytes:
    nid = _nid(nac, duid)
    for pos in nid_errors:
        nid[pos] ^= 1
    rng = np.random.default_rng(nac)
    body = rng.integers(0, 2, 400).tolist()
    stream = _with_status(_bits(FRAME_SYNC, 48) + nid + body)
    return _pack([0] * lead + stream)


@pytest.fixture
def decoder():
    return P25Decoder()


@pytest.mark.parametrize(
    ("duid", "msg_type"),
    [
        (0x0, "hdu_call_setup"),
        (0x3, "tdu_termination"),
        (0x5, "ldu1_voice"),
        (0x7, "tsbk_trunking"),
        (0xA, "ldu2_encryption_sync"),
        (0xC, "pdu_data"),
        (0xF, "tdulc_termination"),
    ],
)
def test_clean_nid(decoder, duid, msg_type):
    pkt = decoder.decode_packet(_frame(0x293, duid))
    nid = pkt.metadata["nid"]
    assert nid["bch_ok"] is True
    assert nid["nac"] == 0x293
    assert nid["duid"] == duid
    assert nid["bch_errors"] == 0
    assert nid["parity_ok"] is True
    assert pkt.confidence == pytest.approx(0.95)
    msgs = decoder.extract_messages(pkt)
    assert len(msgs) == 1
    assert msgs[0].message_type == msg_type
    assert msgs[0].metadata["nac"] == 0x293
    # Body fields are FEC-protected and not decoded: nothing is invented.
    assert msgs[0].source_id == "" and msgs[0].dest_id == ""
    assert msgs[0].metadata["body_fields_decoded"] is False


@pytest.mark.parametrize("n_err", [1, 3, 6, 11])
def test_nid_errors_corrected(decoder, n_err):
    rng = np.random.default_rng(n_err)
    positions = rng.choice(63, size=n_err, replace=False).tolist()
    pkt = decoder.decode_packet(_frame(0xABC, 0x7, positions))
    nid = pkt.metadata["nid"]
    assert nid["bch_ok"] is True
    assert (nid["nac"], nid["duid"]) == (0xABC, 0x7)
    assert nid["bch_errors"] == n_err
    assert 0.5 <= pkt.confidence < 0.95


def test_errors_in_nac_bits_corrected(decoder):
    """Errors inside the NAC/DUID bits must not leak into the result."""
    pkt = decoder.decode_packet(_frame(0x123, 0x5, [0, 3, 7, 12, 15]))
    assert pkt.metadata["nid"]["nac"] == 0x123
    assert pkt.metadata["nid"]["duid"] == 0x5


def test_uncorrectable_nid_dropped(decoder):
    positions = list(range(0, 63, 5))  # 13 errors > t = 11
    pkt = decoder.decode_packet(_frame(0x293, 0x5, positions))
    assert pkt.metadata["nid"]["bch_ok"] is False
    assert pkt.metadata["nid"]["nac"] is None
    assert pkt.confidence == 0.0
    assert pkt.errors
    assert decoder.extract_messages(pkt) == []


def test_status_symbol_inside_nid_is_removed(decoder):
    """The first status dibit falls inside the NID (frame bits 70-71)."""
    for lead in (0, 5, 13):
        pkt = decoder.decode_packet(_frame(0xF0F, 0xA, lead=lead))
        assert pkt.metadata["nid"]["bch_errors"] == 0
        assert pkt.metadata["nid"]["nac"] == 0xF0F


def test_bch_decoder_against_independent_encoder():
    rng = np.random.default_rng(0)
    for _ in range(50):
        info = int(rng.integers(0, 1 << 16))
        cw = _bch_encode(info)
        for pos in rng.choice(63, size=int(rng.integers(0, 12)), replace=False):
            cw[pos] ^= 1
        res = bch_63_16_decode(cw)
        assert res is not None
        assert sum(b << (15 - i) for i, b in enumerate(res[0])) == info


def test_no_sync_raises(decoder):
    with pytest.raises(FrameSyncError):
        decoder.decode_packet(bytes(40))
