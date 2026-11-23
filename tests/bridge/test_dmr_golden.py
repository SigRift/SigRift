"""Golden-vector tests for the DMR decoder (review D4).

Bursts are encoded here from ETSI TS 102 361-1, independently of the
decoder (polynomial division and shift-and-add field arithmetic, no tables):

* slot type: Golay(20,8) = shortened extended Golay(24,12), generator
  x^11+x^10+x^6+x^5+x^4+x^2+1, 11-bit remainder then overall parity;
* BPTC(196,96): R(3) + 13x15 matrix, rows 0-8 Hamming(15,11,3), columns
  Hamming(13,9,3) (cyclic Hamming, g = x^4 + x + 1), interleave
  position (a * 181) mod 196;
* CSBK: CRC-CCITT (init 0, inverted) XOR 0xA5A5;
* voice LC header: RS(12,9) over GF(256) (x^8+x^4+x^3+x^2+1), roots
  alpha^1..alpha^3, parity XOR 0x96.
"""

import pytest

from sigrift.lib.protocol.dmr import DMRDecoder

SYNC_BS_DATA = 0xDFF57D75DF5D
SYNC_BS_VOICE = 0x755FD7DF75F7


def _bits(value: int, width: int) -> list[int]:
    return [(value >> (width - 1 - i)) & 1 for i in range(width)]


def _poly_rem(value: int, gen: int, gen_deg: int) -> int:
    for bit in range(value.bit_length() - 1, gen_deg - 1, -1):
        if value & (1 << bit):
            value ^= gen << (bit - gen_deg)
    return value


def _golay2087(info8: int) -> list[int]:
    p11 = _poly_rem(info8 << 11, 0xC75, 11)
    overall = (bin(info8).count("1") + bin(p11).count("1")) % 2
    return _bits(info8, 8) + _bits(p11, 11) + [overall]


def _hamming(data: list[int]) -> list[int]:
    val = int("".join(map(str, data)), 2)
    return data + _bits(_poly_rem(val << 4, 0b10011, 4), 4)


def _bptc_encode(data96: list[int]) -> list[int]:
    rows = [[0, 0, 0] + data96[0:8]]
    rows += [data96[8 + 11 * r : 19 + 11 * r] for r in range(8)]
    m = [_hamming(row) for row in rows]  # 9 rows x 15
    cols = [_hamming([m[r][c] for r in range(9)]) for c in range(15)]
    matrix = [[cols[c][r] for c in range(15)] for r in range(13)]
    deint = [0] + [b for row in matrix for b in row]
    raw = [0] * 196
    for a in range(196):
        raw[(a * 181) % 196] = deint[a]
    return raw


def _crc_ccitt(data: bytes) -> int:
    crc = 0
    for byte in data:
        for k in range(7, -1, -1):
            top = ((crc >> 15) & 1) ^ ((byte >> k) & 1)
            crc = (crc << 1) & 0xFFFF
            if top:
                crc ^= 0x1021
    return crc ^ 0xFFFF


def _gmul(a: int, b: int) -> int:
    r = 0
    while b:
        if b & 1:
            r ^= a
        b >>= 1
        a <<= 1
        if a & 0x100:
            a ^= 0x11D
    return r


def _rs129_parity(data9: bytes) -> bytes:
    gen = [1]
    root = 1
    for _ in range(3):
        root = _gmul(root, 2)
        nxt = gen + [0]
        for j, c in enumerate(gen):
            nxt[j + 1] ^= _gmul(c, root)
        gen = nxt
    rem = list(data9) + [0, 0, 0]
    for i in range(9):
        coef = rem[i]
        if coef:
            for j in range(1, 4):
                rem[i + j] ^= _gmul(gen[j], coef)
    return bytes(rem[9:])


def _to_bits(data: bytes) -> list[int]:
    return [b for byte in data for b in _bits(byte, 8)]


def _burst(colour: int, data_type: int, data12: bytes, lead: int = 13) -> list[int]:
    raw = _bptc_encode(_to_bits(data12))
    st = _golay2087((colour << 4) | data_type)
    burst = raw[:98] + st[:10] + _bits(SYNC_BS_DATA, 48) + st[10:] + raw[98:]
    assert len(burst) == 264
    return [0] * lead + burst + [0] * 7


def _pack(bits: list[int]) -> bytes:
    bits = bits + [0] * ((-len(bits)) % 8)
    return bytes(
        int("".join(map(str, bits[i : i + 8])), 2) for i in range(0, len(bits), 8)
    )


def _csbk(mask: int = 0xA5A5) -> bytes:
    # LB=1, PF=0, CSBKO=0x04 (UU_V_Req); FID 0; target 1111; source 3120101.
    body = bytes([0x80 | 0x04, 0x00, 0x00, 0x00]) + (1111).to_bytes(3, "big")
    body += (3120101).to_bytes(3, "big")
    crc = _crc_ccitt(body) ^ mask
    return body + crc.to_bytes(2, "big")


def _voice_lc(mask: int = 0x96) -> bytes:
    # FLCO 0 (group voice), FID 0, options 0, TG 9, source 3120101.
    lc = bytes([0x00, 0x00, 0x00]) + (9).to_bytes(3, "big")
    lc += (3120101).to_bytes(3, "big")
    return lc + bytes(p ^ mask for p in _rs129_parity(lc))


@pytest.fixture
def decoder():
    return DMRDecoder()


def test_csbk_golden(decoder):
    pkt = decoder.decode_packet(_pack(_burst(1, 3, _csbk())))
    assert pkt.errors == []
    assert pkt.metadata["slot_type"]["colour_code"] == 1
    assert pkt.metadata["slot_type"]["data_type_name"] == "CSBK"
    assert pkt.metadata["crc_ok"] is True
    csbk = pkt.metadata["csbk"]
    assert csbk["opcode"] == 0x04 and csbk["opcode_name"] == "UU_V_REQ"
    assert csbk["last"] is True
    assert csbk["target"] == 1111 and csbk["source"] == 3120101
    assert pkt.confidence == pytest.approx(0.95)
    (msg,) = decoder.extract_messages(pkt)
    assert msg.message_type == "csbk_uu_v_req"
    assert (msg.source_id, msg.dest_id) == ("3120101", "1111")


def test_voice_lc_header_golden(decoder):
    pkt = decoder.decode_packet(_pack(_burst(7, 1, _voice_lc())))
    assert pkt.errors == []
    assert pkt.metadata["rs_ok"] is True
    lc = pkt.metadata["lc"]
    assert lc["flco_name"] == "GROUP_VOICE" and lc["group"] is True
    assert lc["dest_id"] == 9 and lc["source_id"] == 3120101
    (msg,) = decoder.extract_messages(pkt)
    assert msg.message_type == "voice_lc_header"
    assert (msg.source_id, msg.dest_id) == ("3120101", "9")


def test_errors_corrected(decoder):
    bits = _burst(1, 3, _csbk())
    lead = 13
    for k in (0, 4, 9):  # 3 slot-type errors (Golay corrects 3)
        pos = lead + (98 + k if k < 10 else 156 + k - 10)
        bits[pos] ^= 1
    for raw_pos in (5, 60, 150):  # 3 scattered BPTC bit errors
        pos = lead + (raw_pos if raw_pos < 98 else raw_pos + 68)
        bits[pos] ^= 1
    pkt = decoder.decode_packet(_pack(bits))
    assert pkt.metadata["slot_type"]["golay_errors"] == 3
    assert pkt.metadata["bptc_errors"] >= 3
    assert pkt.metadata["csbk"]["source"] == 3120101
    assert 0.3 <= pkt.confidence < 0.95


def test_crc_mismatch_dropped(decoder):
    # Wrong data-type mask: valid FEC, but the CSBK CRC check must fail.
    pkt = decoder.decode_packet(_pack(_burst(1, 3, _csbk(mask=0xCCCC))))
    assert pkt.confidence == 0.0
    assert pkt.payload == b""
    assert "csbk" not in pkt.metadata
    assert any("CRC" in e for e in pkt.errors)
    assert decoder.extract_messages(pkt) == []


def test_rs_failure_dropped(decoder):
    pkt = decoder.decode_packet(_pack(_burst(1, 1, _voice_lc(mask=0x99))))
    assert pkt.confidence == 0.0
    assert "lc" not in pkt.metadata
    assert decoder.extract_messages(pkt) == []


def test_uncorrectable_slot_type_dropped(decoder):
    bits = _burst(1, 3, _csbk())
    for k in range(5):  # 5 errors > 3
        bits[13 + 98 + k] ^= 1
    pkt = decoder.decode_packet(_pack(bits))
    assert pkt.confidence == 0.0
    assert decoder.extract_messages(pkt) == []


def test_truncated_burst_not_padded(decoder):
    bits = _burst(1, 3, _csbk(), lead=0)[60:]  # sync now at bit 48
    pkt = decoder.decode_packet(_pack(bits))
    assert pkt.confidence == 0.0
    assert any("truncated" in e for e in pkt.errors)


def test_truncated_leading_burst_then_complete_burst_is_decoded(decoder):
    # Capture starts mid-burst: the first sync is cut off, but a complete
    # CSBK burst follows.  The decoder must advance past the truncated sync
    # and decode the later burst instead of returning zero messages (P9).
    truncated = _burst(1, 3, _csbk(), lead=0)[60:]  # leading sync at bit 48
    complete = _burst(1, 3, _csbk())
    pkt = decoder.decode_packet(_pack(truncated + complete))
    assert pkt.errors == []
    assert pkt.metadata["crc_ok"] is True
    assert pkt.metadata["csbk"]["source"] == 3120101
    (msg,) = decoder.extract_messages(pkt)
    assert msg.message_type == "csbk_uu_v_req"


@pytest.mark.parametrize("leading", [False, True])
def test_noisy_complete_burst_wins_over_cut_off_exact_sync(decoder, leading):
    # A complete CSBK burst whose sync has one bit error, followed by a burst
    # cut off after its (exact) sync.  An exact sync anywhere used to win the
    # search, so the cut-off trailing sync was chosen and the decodable burst
    # skipped ("truncated burst").  Only syncs whose whole 264-bit burst fits
    # may be chosen (P9).
    complete = _burst(1, 3, _csbk())
    complete[13 + 108 + 5] ^= 1  # 1-bit sync error
    trailing = _burst(1, 3, _csbk())[: 13 + 108 + 48 + 20]
    bits = complete + trailing
    if leading:  # and a capture that also starts mid-burst
        bits = _burst(1, 3, _csbk(), lead=0)[60:] + bits
    pkt = decoder.decode_packet(_pack(bits))
    assert pkt.errors == []
    assert pkt.metadata["sync_errors"] == 1
    assert pkt.metadata["crc_ok"] is True
    assert pkt.metadata["csbk"]["source"] == 3120101


def test_only_cut_off_bursts_reported_as_truncated(decoder):
    # Cut off at both ends: no sync with a whole burst, so "truncated", not
    # "no sync", and nothing decoded.
    bits = _burst(1, 3, _csbk())[: 13 + 108 + 48 + 20]
    pkt = decoder.decode_packet(_pack(bits))
    assert pkt.confidence == 0.0
    assert any("truncated" in e for e in pkt.errors)


def test_bptc_deinterleave_permutation():
    data = _to_bits(_csbk())
    assert DMRDecoder.bptc_deinterleave(_bptc_encode(data)) == data


def test_voice_burst(decoder):
    voice = [1, 0] * 54
    bits = voice + _bits(SYNC_BS_VOICE, 48) + voice
    pkt = decoder.decode_packet(_pack(bits))
    assert pkt.metadata["sync_type"] == "bs_voice"
    assert len(pkt.payload) == 27  # 216 voice bits
    (msg,) = decoder.extract_messages(pkt)
    assert msg.message_type == "voice"
    assert msg.source_id == "" and msg.dest_id == ""


def _csbk_opcode(opcode: int, oct46: int, oct79: int, mask: int = 0xA5A5) -> bytes:
    # octet 0: LB=1, PF=0, CSBKO=opcode; octet 1: FID 0; octets 2-3 reserved;
    # octets 4-6 and 7-9 carry per-opcode address/timing fields.
    body = bytes([0x80 | (opcode & 0x3F), 0x00, 0x00, 0x00])
    body += oct46.to_bytes(3, "big") + oct79.to_bytes(3, "big")
    crc = _crc_ccitt(body) ^ mask
    return body + crc.to_bytes(2, "big")


def test_csbk_nack_rsp_source_before_target(decoder):
    # NACK_Rsp (0x26): PDU order is Source(4-6) then Target(7-9) — the reverse
    # of UU_V_Req — so a single target/source rule would swap the ids.
    pkt = decoder.decode_packet(_pack(_burst(1, 3, _csbk_opcode(0x26, 2001, 3002))))
    csbk = pkt.metadata["csbk"]
    assert csbk["opcode_name"] == "NACK_RSP"
    assert csbk["source"] == 2001 and csbk["target"] == 3002
    (msg,) = decoder.extract_messages(pkt)
    assert msg.message_type == "csbk_nack_rsp"
    assert (msg.source_id, msg.dest_id) == ("2001", "3002")


def test_csbk_ct_csbk_has_no_unit_addresses(decoder):
    # CT_CSBK (0x07): octets 4-9 carry channel-timing fields, not unit ids —
    # they must not be reported as source/dest addresses.
    pkt = decoder.decode_packet(
        _pack(_burst(1, 3, _csbk_opcode(0x07, 0xBCDEF0, 0x567ABC)))
    )
    csbk = pkt.metadata["csbk"]
    assert csbk["opcode_name"] == "CT_CSBK"
    assert csbk["source"] is None and csbk["target"] is None
    (msg,) = decoder.extract_messages(pkt)
    assert msg.message_type == "csbk_ct_csbk"
    assert msg.source_id == "" and msg.dest_id == ""
