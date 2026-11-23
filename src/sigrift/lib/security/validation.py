"""Input validation for RF parameters and network addresses.

All validation functions raise ValueError on invalid input and return
the validated (possibly cleaned) value on success.
"""

from __future__ import annotations

import re
from pathlib import Path


def validate_frequency(
    freq_hz: float,
    min_hz: float = 1e6,
    max_hz: float = 6e9,
) -> float:
    """Validate a frequency value in Hz.

    Parameters
    ----------
    freq_hz : float
        Frequency in Hz.
    min_hz : float
        Minimum allowed frequency (default 1 MHz).
    max_hz : float
        Maximum allowed frequency (default 6 GHz).

    Returns
    -------
    float
        Validated frequency.

    Raises
    ------
    ValueError
        If frequency is out of range or not a finite number.
    """
    freq_hz = float(freq_hz)
    if not (min_hz <= freq_hz <= max_hz):
        raise ValueError(
            f"Frequency {freq_hz:.0f} Hz is outside valid range "
            f"[{min_hz:.0f}, {max_hz:.0f}] Hz"
        )
    return freq_hz


def validate_gain(
    gain_db: float,
    min_db: float = 0,
    max_db: float = 73,
) -> float:
    """Validate a gain value in dB.

    Parameters
    ----------
    gain_db : float
        Gain in dB.
    min_db : float
        Minimum allowed gain (default 0 dB).
    max_db : float
        Maximum allowed gain (default 73 dB).

    Returns
    -------
    float
        Validated gain.

    Raises
    ------
    ValueError
        If gain is out of range.
    """
    gain_db = float(gain_db)
    if not (min_db <= gain_db <= max_db):
        raise ValueError(
            f"Gain {gain_db:.1f} dB is outside valid range "
            f"[{min_db:.1f}, {max_db:.1f}] dB"
        )
    return gain_db


def validate_sample_rate(
    rate: float,
    min_rate: float = 225001,
    max_rate: float = 3.2e6,
) -> float:
    """Validate a sample rate in Hz.

    Parameters
    ----------
    rate : float
        Sample rate in Hz.
    min_rate : float
        Minimum allowed rate (default 225001 Hz for RTL-SDR).
    max_rate : float
        Maximum allowed rate (default 3.2 MHz for RTL-SDR).

    Returns
    -------
    float
        Validated sample rate.

    Raises
    ------
    ValueError
        If sample rate is out of range.
    """
    rate = float(rate)
    if not (min_rate <= rate <= max_rate):
        raise ValueError(
            f"Sample rate {rate:.0f} Hz is outside valid range "
            f"[{min_rate:.0f}, {max_rate:.0f}] Hz"
        )
    return rate


def validate_host(host: str) -> str:
    """Validate a hostname or IP address.

    Accepts:
    - IPv4 addresses (e.g. ``"127.0.0.1"``, ``"0.0.0.0"``)
    - Hostnames matching ``[a-zA-Z0-9.-]+`` (e.g. ``"localhost"``, ``"node-1.local"``)

    Rejects:
    - Empty strings
    - Strings with whitespace or special characters
    - Strings longer than 253 characters (DNS limit)

    Parameters
    ----------
    host : str
        Hostname or IP address string.

    Returns
    -------
    str
        Validated and stripped host string.

    Raises
    ------
    ValueError
        If the host is invalid.
    """
    host = str(host).strip()
    if not host:
        raise ValueError("Host cannot be empty")

    if len(host) > 253:
        raise ValueError(f"Host too long ({len(host)} chars, max 253)")

    # Allow IPv4 addresses and hostnames (fullmatch: '$' would also match
    # before a trailing newline)
    if not re.fullmatch(r"[a-zA-Z0-9]([a-zA-Z0-9.\-]*[a-zA-Z0-9])?", host):
        raise ValueError(
            f"Invalid host format: {host!r}. "
            "Expected IPv4 address or hostname (alphanumeric, dots, hyphens)."
        )

    return host


def validate_port(port: int) -> int:
    """Validate a TCP/UDP port number.

    Parameters
    ----------
    port : int
        Port number.

    Returns
    -------
    int
        Validated port number.

    Raises
    ------
    ValueError
        If port is not in range 1-65535.
    """
    port = int(port)
    if not (1 <= port <= 65535):
        raise ValueError(f"Port {port} is outside valid range [1, 65535]")
    return port


def validate_path(path: str, base_dir: str) -> str:
    """Validate a file path to prevent path traversal attacks.

    Resolves the path and verifies it falls within ``base_dir``.
    Rejects paths containing ``..`` components that escape the base directory.

    Parameters
    ----------
    path : str
        File path to validate.
    base_dir : str
        Allowed base directory.

    Returns
    -------
    str
        Resolved absolute path as string.

    Raises
    ------
    ValueError
        If the path is empty, or resolves outside base_dir.
    """
    if not path:
        raise ValueError("Path cannot be empty")

    resolved = Path(path).resolve()
    base = Path(base_dir).resolve()

    # Check that the resolved path is within the base directory
    try:
        resolved.relative_to(base)
    except ValueError:
        raise ValueError(
            f"Path traversal detected: {path!r} resolves to {resolved} "
            f"which is outside base directory {base}"
        )

    return str(resolved)
