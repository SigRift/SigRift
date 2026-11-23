"""Shared RF frequency band definitions.

Provides canonical band ranges and a lookup function used by calibrator,
quantile tracker, and other anomaly-scoring modules.
"""

from __future__ import annotations

BAND_RANGES: list[tuple[str, float, float]] = [
    ("sub_1ghz", 0.0, 1_000_000_000),
    ("l_band", 1_000_000_000, 2_000_000_000),
    ("s_band", 2_000_000_000, 2_400_000_000),
    ("ism_2_4ghz", 2_400_000_000, 2_500_000_000),
    ("s_band_upper", 2_500_000_000, 4_000_000_000),
    ("c_band", 4_000_000_000, 5_000_000_000),
    ("ism_5ghz", 5_000_000_000, 5_900_000_000),
]


def get_band(freq_hz: float) -> str:
    """Map a frequency in Hz to its band name.

    Returns "other" for frequencies not covered by any defined range.
    """
    for name, lo, hi in BAND_RANGES:
        if lo <= freq_hz < hi:
            return name
    return "other"
