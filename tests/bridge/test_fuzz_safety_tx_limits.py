"""TX safety limits of ``sigrift.bridge.fuzz_safety`` (SAFETY-CRITICAL).

``test_security_review_20260324.py`` checks NaN/Inf inputs and a few
forbidden centre frequencies. These pin the rest of the contract: every
forbidden band is refused at both edges, the signal's bandwidth counts
(also when given as a negative number), the advisory ISM check only warns,
the operator's gain and duration settings are honoured but can never lift
the hard caps, a malformed setting falls back to the default, and a full
TX request is refused for each limit it breaks.
"""

from __future__ import annotations

import logging

import pytest

from sigrift.bridge import fuzz_safety
from sigrift.bridge.fuzz_safety import (
    DEFAULT_ALLOWED_BANDS,
    MAX_TX_DURATION_HARD,
    MAX_TX_GAIN_HARD,
    BandViolationError,
    FuzzSafetyError,
    PowerViolationError,
    get_max_tx_duration,
    get_max_tx_gain,
    is_allowed_band,
    validate_tx_frequency,
    validate_tx_gain,
    validate_tx_request,
)

ISM_433 = 433.92e6
OUTSIDE_ISM_WARNING = "outside all default allowed ISM bands"
# The protected bands, written out here rather than read from
# FORBIDDEN_BANDS: narrowing or deleting an entry of the product's table
# must fail these tests, not quietly shrink them.
REQUIRED_FORBIDDEN_BANDS = [
    (118e6, 137e6, "Aviation VHF"),
    (225e6, 400e6, "Military UHF"),
    (960e6, 1215e6, "Aviation L-band / ADS-B / DME"),
    (1164e6, 1240e6, "GPS L5 / Galileo"),
    (1559e6, 1610e6, "GPS L1 / GLONASS / Galileo"),
    (121.475e6, 121.525e6, "Aviation emergency"),
    (156.7625e6, 156.8375e6, "Marine Ch. 16 distress"),
    (406.0e6, 406.1e6, "COSPAS-SARSAT emergency"),
    (1544e6, 1545e6, "INMARSAT distress"),
]


@pytest.fixture(autouse=True)
def _no_operator_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start every test from the built-in defaults, whatever the host sets."""
    monkeypatch.delenv("BRIDGE_FUZZ_MAX_TX_GAIN", raising=False)
    monkeypatch.delenv("BRIDGE_FUZZ_MAX_DURATION", raising=False)


def _warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == fuzz_safety.__name__ and r.levelno == logging.WARNING
    ]


# ---------------------------------------------------------------------------
# Forbidden bands
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "freq_hz",
    [
        pytest.param(freq, id=f"{desc}@{freq / 1e6:.4f}MHz")
        for low, high, desc in REQUIRED_FORBIDDEN_BANDS
        for freq in (low, (low + high) / 2, high)
    ],
)
def test_every_forbidden_band_is_refused_at_its_edges_and_centre(
    freq_hz: float,
) -> None:
    # A band nested in a wider one (121.5 MHz inside Aviation VHF) may be
    # reported under the wider band; what matters is that it is refused.
    with pytest.raises(BandViolationError, match="overlaps forbidden band"):
        validate_tx_frequency(freq_hz)


def test_a_carrier_just_outside_a_forbidden_band_is_not_refused() -> None:
    validate_tx_frequency(137e6 + 1)
    validate_tx_frequency(225e6 - 1)


def test_the_signal_bandwidth_is_part_of_the_footprint() -> None:
    # 117.9 MHz is clear of Aviation VHF (118-137 MHz) as a carrier, but a
    # 300 kHz wide signal reaches 118.05 MHz.
    with pytest.raises(BandViolationError, match="Aviation VHF"):
        validate_tx_frequency(117.9e6, bandwidth_hz=300e3)
    validate_tx_frequency(117.9e6, bandwidth_hz=100e3)


def test_a_negative_bandwidth_cannot_shrink_the_footprint() -> None:
    with pytest.raises(BandViolationError, match="Aviation VHF"):
        validate_tx_frequency(117.9e6, bandwidth_hz=-300e3)


def test_a_frequency_outside_ism_but_not_forbidden_only_warns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger=fuzz_safety.__name__):
        validate_tx_frequency(50e6, bandwidth_hz=25e3)
    assert _warnings(caplog) == [
        f"TX at 50.0000 MHz (BW 25.0 kHz) is {OUTSIDE_ISM_WARNING}"
    ]


def test_an_ism_frequency_passes_without_a_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger=fuzz_safety.__name__):
        validate_tx_frequency(ISM_433, bandwidth_hz=125e3)
    assert _warnings(caplog) == []


# ---------------------------------------------------------------------------
# Advisory ISM bands
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("freq_hz", "bandwidth_hz", "allowed"),
    [
        pytest.param((low + high) / 2, 0.0, True, id=desc)
        for low, high, desc in DEFAULT_ALLOWED_BANDS
    ]
    + [
        pytest.param(434.79e6, 10e3, False, id="straddles-ISM-433-top-edge"),
        pytest.param(902e6, -10e3, False, id="negative-bw-straddles-ISM-915"),
        pytest.param(915e6, 26e6, True, id="exactly-fills-ISM-915"),
        pytest.param(50e6, 0.0, False, id="outside-every-band"),
    ],
)
def test_is_allowed_band_needs_the_whole_footprint_inside_one_band(
    freq_hz: float, bandwidth_hz: float, allowed: bool
) -> None:
    assert is_allowed_band(freq_hz, bandwidth_hz) is allowed


# ---------------------------------------------------------------------------
# Gain
# ---------------------------------------------------------------------------


def test_gain_above_the_configured_max_but_under_the_hard_cap_is_refused() -> None:
    assert get_max_tx_gain() == 20
    validate_tx_gain(20)
    with pytest.raises(PowerViolationError, match="exceeds configured max of 20 dB"):
        validate_tx_gain(25)


@pytest.mark.parametrize(
    ("setting", "effective"),
    [
        ("30", 30),
        ("5", 5),
        (str(MAX_TX_GAIN_HARD + 60), MAX_TX_GAIN_HARD),
    ],
)
def test_the_operator_gain_setting_is_honoured_but_clamped_to_the_hard_cap(
    monkeypatch: pytest.MonkeyPatch, setting: str, effective: int
) -> None:
    monkeypatch.setenv("BRIDGE_FUZZ_MAX_TX_GAIN", setting)
    assert get_max_tx_gain() == effective
    validate_tx_gain(effective)
    with pytest.raises(PowerViolationError, match="exceeds"):
        validate_tx_gain(effective + 1)


def test_a_raised_gain_setting_never_lifts_the_hard_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BRIDGE_FUZZ_MAX_TX_GAIN", "1000")
    with pytest.raises(PowerViolationError, match="exceeds hard cap of 40 dB"):
        validate_tx_gain(MAX_TX_GAIN_HARD + 1)


@pytest.mark.parametrize("setting", ["high", "25.5", "nan", "inf", "-inf", ""])
def test_a_malformed_gain_setting_falls_back_to_the_default(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, setting: str
) -> None:
    monkeypatch.setenv("BRIDGE_FUZZ_MAX_TX_GAIN", setting)
    with caplog.at_level(logging.WARNING, logger=fuzz_safety.__name__):
        assert get_max_tx_gain() == 20
    assert _warnings(caplog) == [
        f"Invalid BRIDGE_FUZZ_MAX_TX_GAIN={setting!r}, using default 20"
    ]


# ---------------------------------------------------------------------------
# Duration
# ---------------------------------------------------------------------------


def test_the_default_duration_limit() -> None:
    assert get_max_tx_duration() == 60.0


@pytest.mark.parametrize(
    ("setting", "effective"),
    [
        ("120", 120.0),
        ("0.5", 0.5),
        ("1000", MAX_TX_DURATION_HARD),
        ("1e9", MAX_TX_DURATION_HARD),
    ],
)
def test_the_operator_duration_setting_is_honoured_but_clamped_to_the_hard_cap(
    monkeypatch: pytest.MonkeyPatch, setting: str, effective: float
) -> None:
    monkeypatch.setenv("BRIDGE_FUZZ_MAX_DURATION", setting)
    assert get_max_tx_duration() == effective


# float() parses these, but none is a duration: NaN compares false with
# everything, so min() kept it and "duration > nan" let every request
# through, hard cap included.
NON_FINITE_SETTINGS = ["nan", "-nan", "inf", "-inf", "Infinity"]


@pytest.mark.parametrize("setting", ["one minute", "60s", "", *NON_FINITE_SETTINGS])
def test_a_malformed_duration_setting_falls_back_to_the_default(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, setting: str
) -> None:
    monkeypatch.setenv("BRIDGE_FUZZ_MAX_DURATION", setting)
    with caplog.at_level(logging.WARNING, logger=fuzz_safety.__name__):
        assert get_max_tx_duration() == 60.0
    assert _warnings(caplog) == [
        f"Invalid BRIDGE_FUZZ_MAX_DURATION={setting!r}, using default 60.0"
    ]


# ---------------------------------------------------------------------------
# Whole TX request
# ---------------------------------------------------------------------------


def test_the_violation_errors_are_all_fuzz_safety_errors() -> None:
    assert issubclass(BandViolationError, FuzzSafetyError)
    assert issubclass(PowerViolationError, FuzzSafetyError)


def test_a_request_inside_every_limit_is_validated_and_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger=fuzz_safety.__name__):
        validate_tx_request(ISM_433, 125e3, 10, 30.0)
    assert [
        r.getMessage() for r in caplog.records if r.name == fuzz_safety.__name__
    ] == ["TX request validated: 433.9200 MHz, BW 125.0 kHz, gain 10 dB, 30.0s"]


@pytest.mark.parametrize(
    ("freq_hz", "bandwidth_hz", "gain", "duration_s", "error", "message"),
    [
        pytest.param(
            1090e6, 1e6, 10, 10.0, BandViolationError, "ADS-B", id="forbidden-band"
        ),
        pytest.param(
            ISM_433,
            125e3,
            30,
            10.0,
            PowerViolationError,
            "configured max",
            id="gain-over-configured-max",
        ),
        pytest.param(
            ISM_433,
            125e3,
            10,
            60.5,
            FuzzSafetyError,
            "exceeds max of 60.0s",
            id="duration-over-default-max",
        ),
        pytest.param(
            ISM_433,
            125e3,
            10,
            0,
            FuzzSafetyError,
            "must be positive",
            id="zero-duration",
        ),
        pytest.param(
            ISM_433,
            125e3,
            10,
            -5.0,
            FuzzSafetyError,
            "must be positive",
            id="negative-duration",
        ),
        pytest.param(
            ISM_433,
            125e3,
            10,
            "30",
            FuzzSafetyError,
            "Invalid duration value",
            id="duration-not-a-number",
        ),
    ],
)
def test_a_request_breaking_any_limit_is_refused_and_not_logged_as_valid(
    caplog: pytest.LogCaptureFixture,
    freq_hz: float,
    bandwidth_hz: float,
    gain: float,
    duration_s: float,
    error: type[Exception],
    message: str,
) -> None:
    with caplog.at_level(logging.INFO, logger=fuzz_safety.__name__):
        with pytest.raises(error, match=message):
            validate_tx_request(freq_hz, bandwidth_hz, gain, duration_s)
    assert not any("validated" in r.getMessage() for r in caplog.records)


def test_a_raised_duration_setting_never_lifts_the_hard_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BRIDGE_FUZZ_MAX_DURATION", "100000")
    validate_tx_request(ISM_433, 125e3, 10, MAX_TX_DURATION_HARD)
    with pytest.raises(FuzzSafetyError, match="exceeds max of 300.0s"):
        validate_tx_request(ISM_433, 125e3, 10, MAX_TX_DURATION_HARD + 1)


@pytest.mark.parametrize("setting", NON_FINITE_SETTINGS)
def test_a_non_finite_duration_setting_enforces_the_default_limit(
    monkeypatch: pytest.MonkeyPatch, setting: str
) -> None:
    monkeypatch.setenv("BRIDGE_FUZZ_MAX_DURATION", setting)
    validate_tx_request(ISM_433, 125e3, 10, 60.0)
    for duration_s in (60.5, MAX_TX_DURATION_HARD + 1, 10 * 24 * 3600.0):
        with pytest.raises(FuzzSafetyError, match="exceeds max of 60.0s"):
            validate_tx_request(ISM_433, 125e3, 10, duration_s)
