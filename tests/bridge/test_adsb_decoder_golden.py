"""Golden-vector tests for the ADS-B decoder (sigrift.lib.dsp.adsb_decoder).

Vectors are the worked examples from "The 1090 MHz Riddle" (Junzi Sun,
https://mode-s.org/decode) and agree with pyModeS:

* 8D40621D58C382D690C8AC2863A7 -- airborne position, even CPR frame,
  altitude 38000 ft (Q-bit = 1).
* 8D40621D58C386435CC412692AD6 -- airborne position, odd CPR frame.
  With the even frame being the most recent (t_even=1457996402,
  t_odd=1457996400) the global decode is lat 52.25720, lon 3.91937.
* 8D485020994409940838175B284F -- airborne velocity, subtype 1
  (ground speed): 159.20 kt, track 182.88 deg.
"""

from __future__ import annotations

import math

import numpy as np
import pytest

from sigrift.lib.dsp.adsb_decoder import (
    _crc24,
    _decode_altitude,
    _decode_velocity,
    _nl,
    decode_adsb,
    decode_cpr,
)

EVEN_POS = "8D40621D58C382D690C8AC2863A7"
ODD_POS = "8D40621D58C386435CC412692AD6"
VELOCITY = "8D485020994409940838175B284F"


def hex_to_bits(msg_hex: str) -> np.ndarray:
    """Convert a hex Mode S frame to the MSB-first 0/1 int array decode_adsb takes."""
    n_bits = len(msg_hex) * 4
    value = int(msg_hex, 16)
    return np.array([(value >> (n_bits - 1 - i)) & 1 for i in range(n_bits)], dtype=np.int32)


def _int_to_bits(value: int, width: int) -> np.ndarray:
    return np.array([(value >> (width - 1 - i)) & 1 for i in range(width)], dtype=np.int32)


class TestGoldenFrames:
    @pytest.mark.parametrize("msg", [EVEN_POS, ODD_POS, VELOCITY])
    def test_golden_frames_have_valid_crc(self, msg: str) -> None:
        assert _crc24(hex_to_bits(msg)) == 0

    def test_altitude_38000ft(self) -> None:
        msg = decode_adsb(hex_to_bits(EVEN_POS))
        assert msg is not None
        assert msg.icao_address == "40621D"
        assert msg.altitude_ft == pytest.approx(38000.0)

    def test_odd_frame_altitude(self) -> None:
        msg = decode_adsb(hex_to_bits(ODD_POS))
        assert msg is not None
        assert msg.altitude_ft == pytest.approx(38000.0)

    def test_cpr_flags_and_raw_fields(self) -> None:
        even = decode_adsb(hex_to_bits(EVEN_POS))
        odd = decode_adsb(hex_to_bits(ODD_POS))
        assert even is not None and odd is not None
        assert even.cpr_odd is False
        assert odd.cpr_odd is True
        # Raw 17-bit CPR values from the reference worked example.
        assert even.cpr_lat * 131072 == pytest.approx(93000)
        assert even.cpr_lon * 131072 == pytest.approx(51372)
        assert odd.cpr_lat * 131072 == pytest.approx(74158)
        assert odd.cpr_lon * 131072 == pytest.approx(50194)

    def test_cpr_global_decode_even_newer(self) -> None:
        even = decode_adsb(hex_to_bits(EVEN_POS))
        odd = decode_adsb(hex_to_bits(ODD_POS))
        assert even is not None and odd is not None
        result = decode_cpr(
            even.cpr_lat, even.cpr_lon, odd.cpr_lat, odd.cpr_lon, even_newer=True
        )
        assert result is not None
        lat, lon = result
        assert lat == pytest.approx(52.25720, abs=1e-4)
        assert lon == pytest.approx(3.91937, abs=1e-4)

    def test_cpr_global_decode_odd_newer(self) -> None:
        even = decode_adsb(hex_to_bits(EVEN_POS))
        odd = decode_adsb(hex_to_bits(ODD_POS))
        assert even is not None and odd is not None
        result = decode_cpr(
            even.cpr_lat, even.cpr_lon, odd.cpr_lat, odd.cpr_lon, even_newer=False
        )
        assert result is not None
        lat, lon = result
        # pyModeS: position(even, odd, t_even=1457996400, t_odd=1457996402)
        assert lat == pytest.approx(52.26578, abs=1e-4)
        assert lon == pytest.approx(3.93891, abs=1e-4)

    def test_velocity_ground_speed(self) -> None:
        msg = decode_adsb(hex_to_bits(VELOCITY))
        assert msg is not None
        assert msg.icao_address == "485020"
        assert msg.velocity_kts == pytest.approx(159.20, abs=0.01)
        assert msg.heading_deg == pytest.approx(182.88, abs=0.01)


class TestVelocityFields:
    def _subtype1(self, dew: int, vew: int, dns: int, vns: int, st: int = 1) -> np.ndarray:
        # ST(3) IC(1) IFR(1) NUCv(3) Dew(1) Vew(10) Dns(1) Vns(10) + padding
        bits = np.concatenate(
            [
                _int_to_bits(st, 3),
                [1, 1],  # intent change + IFR: must not shift the fields
                _int_to_bits(0b101, 3),
                [dew],
                _int_to_bits(vew, 10),
                [dns],
                _int_to_bits(vns, 10),
                np.zeros(21, dtype=np.int32),
            ]
        )
        return bits.astype(np.int32)

    def test_east_component_only(self) -> None:
        # Vew raw = 101 -> 100 kt east; Vns raw = 1 -> 0 kt
        speed, heading = _decode_velocity(self._subtype1(0, 101, 0, 1))
        assert speed == pytest.approx(100.0)
        assert heading == pytest.approx(90.0)

    def test_south_west(self) -> None:
        speed, heading = _decode_velocity(self._subtype1(1, 31, 1, 41))
        assert speed == pytest.approx(math.hypot(30, 40))
        assert heading == pytest.approx(math.degrees(math.atan2(-30, -40)) % 360)

    def test_supersonic_subtype_scales_by_four(self) -> None:
        speed, heading = _decode_velocity(self._subtype1(0, 101, 0, 1, st=2))
        assert speed == pytest.approx(400.0)
        assert heading == pytest.approx(90.0)

    def test_zero_raw_value_means_unavailable(self) -> None:
        assert _decode_velocity(self._subtype1(0, 0, 0, 10)) == (None, None)
        assert _decode_velocity(self._subtype1(0, 10, 0, 0)) == (None, None)


class TestAltitudeField:
    def test_q_bit_is_message_bit_48(self) -> None:
        # 38000 ft: N = 1560 = 0b11000011000, Q (index 7) inserted.
        field = _int_to_bits(0xC38, 12)  # 1100 0011 1000 -> Q at index 7 = 1
        assert int(field[7]) == 1
        assert _decode_altitude(field) == pytest.approx(38000.0)

    def test_q1_n0_is_minus_1000ft(self) -> None:
        field = np.zeros(12, dtype=np.int32)
        field[7] = 1
        assert _decode_altitude(field) == pytest.approx(-1000.0)

    @pytest.mark.parametrize(
        ("code", "expected"),
        [
            # 12-bit AC field values with Q=0 (Gillham / Mode C), cross-checked
            # against pyModeS.common.altitude.
            (0x200, -1000.0),
            (0x80, -1200.0),
            (0x20A, 0.0),
            (0xA0A, 100.0),
            (0x820, 2300.0),
            (0x921, 50300.0),
            (0x81, 62700.0),
            (0x84, 126700.0),
        ],
    )
    def test_gillham_100ft(self, code: int, expected: float) -> None:
        assert _decode_altitude(_int_to_bits(code, 12)) == pytest.approx(expected)

    def test_gillham_illegal_c_bits_return_none(self) -> None:
        # Q=0 with all C bits (C1, C2, C4 at indices 0, 2, 4) clear is illegal.
        field = _int_to_bits(0b010000000000, 12)  # only A1 set
        assert _decode_altitude(field) is None


class TestNLClosedForm:
    @pytest.mark.parametrize(
        ("lat", "expected"),
        [
            (0.0, 59),
            (10.0, 59),
            (10.47, 59),
            (10.48, 58),
            (40.0, 45),
            (45.0, 42),
            (52.2572, 36),
            (60.0, 29),
            (86.53, 3),
            (86.54, 2),
            (87.0, 2),
            (87.01, 1),
            (90.0, 1),
        ],
    )
    def test_reference_values(self, lat: float, expected: int) -> None:
        assert _nl(lat) == expected
        assert _nl(-lat) == expected

    def test_monotonic_non_increasing(self) -> None:
        values = [_nl(lat / 100.0) for lat in range(0, 9000)]
        assert all(a >= b for a, b in zip(values, values[1:]))
        assert values[0] == 59 and values[-1] == 1
        # every zone count 59..1 appears
        assert set(values) == set(range(1, 60))
