"""Preamble and sync word detection using matched filtering.

Scans IQ data for known preamble/sync word patterns using normalized
cross-correlation.  Ships with a built-in database of common RF protocol
preambles (WiFi, Bluetooth, Zigbee, LoRa, ADS-B, DMR, P25, Barker codes).
Users can add custom patterns at runtime.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class SyncPattern:
    """A known preamble / sync word bit pattern."""

    name: str
    bits: list[int]
    protocol: str
    modulation: str
    description: str = ""
    chip_rate: float | None = None


@dataclass
class PreambleMatch:
    """A single matched preamble occurrence in IQ data."""

    pattern_name: str
    protocol: str
    sample_offset: int
    correlation_peak: float
    confidence: float
    bit_sequence: list[int]
    estimated_symbol_rate: float


# ---------------------------------------------------------------------------
# Built-in Barker code generators
# ---------------------------------------------------------------------------

_BARKER_CODES: dict[int, list[int]] = {
    2: [1, 0],
    3: [1, 1, 0],
    4: [1, 1, 0, 1],
    5: [1, 1, 1, 0, 1],
    7: [1, 1, 1, 0, 0, 1, 0],
    11: [1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0],
    13: [1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1],
}


def _generate_barker(length: int) -> list[int]:
    """Return a standard Barker code of the given length.

    Parameters
    ----------
    length : int
        One of 2, 3, 4, 5, 7, 11, 13.

    Returns
    -------
    list[int]
        Barker code bit sequence.

    Raises
    ------
    ValueError
        If the requested length is not a valid Barker code length.
    """
    if length not in _BARKER_CODES:
        raise ValueError(
            f"No Barker code of length {length}. Valid lengths: {sorted(_BARKER_CODES)}"
        )
    return list(_BARKER_CODES[length])


# ---------------------------------------------------------------------------
# Symbol mapping
# ---------------------------------------------------------------------------


def _bits_to_symbols(bits: list[int], modulation: str) -> np.ndarray:
    """Map a bit pattern to complex baseband symbols.

    Parameters
    ----------
    bits : list[int]
        Binary sequence (0/1 values).
    modulation : str
        ``"bpsk"`` or ``"qpsk"``.  Defaults to BPSK for unknown values.

    Returns
    -------
    np.ndarray
        Complex-valued symbol array.
    """
    bits_arr = np.asarray(bits, dtype=np.float64)

    if modulation.lower() == "qpsk":
        # Pair bits: each pair -> one QPSK symbol
        n = len(bits_arr)
        if n % 2 != 0:
            bits_arr = np.append(bits_arr, 0.0)
            n += 1
        i_bits = bits_arr[0::2]
        q_bits = bits_arr[1::2]
        symbols = (2.0 * i_bits - 1.0) + 1j * (2.0 * q_bits - 1.0)
        symbols /= np.sqrt(2.0)
        return symbols

    # Default: BPSK  (0 -> -1, 1 -> +1)
    return (2.0 * bits_arr - 1.0) + 0j


# ---------------------------------------------------------------------------
# Normalized cross-correlation
# ---------------------------------------------------------------------------


def _normalized_xcorr(signal: np.ndarray, template: np.ndarray) -> np.ndarray:
    """Compute normalized cross-correlation between *signal* and *template*.

    Uses sliding-window correlation normalized by local energy so that
    output values are in the range [-1, 1].

    Parameters
    ----------
    signal : np.ndarray
        Complex or real 1-D array.
    template : np.ndarray
        Complex or real 1-D template (shorter than *signal*).

    Returns
    -------
    np.ndarray
        Real-valued correlation array of length ``len(signal) - len(template) + 1``.
        Values are in [-1, 1].
    """
    sig = np.asarray(signal, dtype=np.complex128).ravel()
    tmpl = np.asarray(template, dtype=np.complex128).ravel()

    m = len(tmpl)
    n = len(sig)
    if m > n:
        return np.array([], dtype=np.float64)

    out_len = n - m + 1
    tmpl_energy = np.real(np.vdot(tmpl, tmpl))
    if tmpl_energy < 1e-30:
        return np.zeros(out_len, dtype=np.float64)

    result = np.empty(out_len, dtype=np.float64)
    for k in range(out_len):
        seg = sig[k : k + m]
        seg_energy = np.real(np.vdot(seg, seg))
        denom = np.sqrt(seg_energy * tmpl_energy)
        if denom < 1e-30:
            result[k] = 0.0
        else:
            result[k] = np.abs(np.vdot(seg, tmpl)) / denom
    return result


# ---------------------------------------------------------------------------
# Built-in pattern database
# ---------------------------------------------------------------------------


def _builtin_patterns() -> list[SyncPattern]:
    """Return the built-in preamble/sync-word pattern database."""

    patterns: list[SyncPattern] = []

    # -- IEEE 802.11b Barker-11 preamble ------------------------------------
    patterns.append(
        SyncPattern(
            name="IEEE 802.11b Barker preamble",
            bits=[1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0],
            protocol="wifi",
            modulation="bpsk",
            description="11-chip Barker code used in 802.11b PLCP preamble",
            chip_rate=11e6,
        )
    )

    # -- Bluetooth advertising access code (0x8E89BED6) ---------------------
    bt_sync = 0x8E89BED6
    bt_bits = [(bt_sync >> (31 - i)) & 1 for i in range(32)]
    patterns.append(
        SyncPattern(
            name="Bluetooth advertising access code",
            bits=bt_bits,
            protocol="bluetooth",
            modulation="bpsk",
            description="BLE advertising channel access address 0x8E89BED6",
            chip_rate=1e6,
        )
    )

    # -- Zigbee SHR preamble (32 zero bits) ---------------------------------
    patterns.append(
        SyncPattern(
            name="Zigbee SHR preamble",
            bits=[0] * 32,
            protocol="zigbee",
            modulation="bpsk",
            description="IEEE 802.15.4 SHR: 32 zero symbols (4 octets of 0x00)",
            chip_rate=2e6,
        )
    )

    # -- LoRa sync word (0x34 default) --------------------------------------
    lora_default = 0x34
    lora_bits = [(lora_default >> (7 - i)) & 1 for i in range(8)]
    patterns.append(
        SyncPattern(
            name="LoRa sync word (default 0x34)",
            bits=lora_bits,
            protocol="lora",
            modulation="bpsk",
            description="Default LoRa sync word 0x34",
        )
    )

    # -- LoRaWAN sync word (0x12) -------------------------------------------
    lorawan = 0x12
    lorawan_bits = [(lorawan >> (7 - i)) & 1 for i in range(8)]
    patterns.append(
        SyncPattern(
            name="LoRaWAN sync word (0x12)",
            bits=lorawan_bits,
            protocol="lora",
            modulation="bpsk",
            description="LoRaWAN public network sync word 0x12",
        )
    )

    # -- ADS-B preamble -----------------------------------------------------
    adsb_bits = [1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0]
    patterns.append(
        SyncPattern(
            name="ADS-B preamble",
            bits=adsb_bits,
            protocol="adsb",
            modulation="bpsk",
            description="Mode-S / ADS-B 16-bit preamble",
            chip_rate=2e6,
        )
    )

    # -- DMR BS voice sync --------------------------------------------------
    dmr_bs_voice = 0x755FD7DF75F7
    dmr_bits_bs = [(dmr_bs_voice >> (47 - i)) & 1 for i in range(48)]
    patterns.append(
        SyncPattern(
            name="DMR BS voice sync",
            bits=dmr_bits_bs,
            protocol="dmr",
            modulation="qpsk",
            description="DMR Base Station voice sync pattern",
        )
    )

    # -- DMR MS voice sync --------------------------------------------------
    dmr_ms_voice = 0xD5D7F77FD757
    dmr_bits_ms = [(dmr_ms_voice >> (47 - i)) & 1 for i in range(48)]
    patterns.append(
        SyncPattern(
            name="DMR MS voice sync",
            bits=dmr_bits_ms,
            protocol="dmr",
            modulation="qpsk",
            description="DMR Mobile Station voice sync pattern",
        )
    )

    # -- DMR data sync ------------------------------------------------------
    dmr_data = 0xDFF57D75DF5D
    dmr_data_bits = [(dmr_data >> (47 - i)) & 1 for i in range(48)]
    patterns.append(
        SyncPattern(
            name="DMR data sync",
            bits=dmr_data_bits,
            protocol="dmr",
            modulation="qpsk",
            description="DMR data sync pattern",
        )
    )

    # -- P25 frame sync (48 bits) -------------------------------------------
    p25_fs = 0x5575F5FF77FF
    p25_bits = [(p25_fs >> (47 - i)) & 1 for i in range(48)]
    patterns.append(
        SyncPattern(
            name="P25 frame sync",
            bits=p25_bits,
            protocol="p25",
            modulation="qpsk",
            description="APCO P25 frame sync word",
        )
    )

    # -- Generic Barker codes -----------------------------------------------
    for length in (7, 11, 13):
        patterns.append(
            SyncPattern(
                name=f"Barker-{length}",
                bits=_generate_barker(length),
                protocol="generic",
                modulation="bpsk",
                description=f"Standard Barker code of length {length}",
            )
        )

    return patterns


# ---------------------------------------------------------------------------
# PreambleDetector
# ---------------------------------------------------------------------------


class PreambleDetector:
    """Detect preambles / sync words in IQ data via matched filtering.

    Parameters
    ----------
    patterns : list[SyncPattern] or None
        Known sync patterns.  ``None`` loads the built-in database.
    """

    def __init__(self, patterns: list[SyncPattern] | None = None) -> None:
        if patterns is None:
            self._patterns = _builtin_patterns()
        else:
            self._patterns = list(patterns)

    @property
    def patterns(self) -> list[SyncPattern]:
        """Return the current pattern list (read-only copy)."""
        return list(self._patterns)

    def add_pattern(self, pattern: SyncPattern) -> None:
        """Add a pattern to the detector."""
        self._patterns.append(pattern)

    # -- Detection ----------------------------------------------------------

    def detect(
        self,
        iq: np.ndarray,
        sample_rate: float = 1.0,
        threshold: float = 0.7,
    ) -> list[PreambleMatch]:
        """Scan *iq* for all known preamble/sync patterns.

        Parameters
        ----------
        iq : np.ndarray
            Complex IQ samples (1-D).
        sample_rate : float
            Sample rate in Hz (used for symbol rate estimation).
        threshold : float
            Minimum normalized correlation to count as a match (0-1).

        Returns
        -------
        list[PreambleMatch]
            Matches sorted by correlation_peak descending.
        """
        matches: list[PreambleMatch] = []
        for pat in self._patterns:
            matches.extend(
                self.detect_pattern(
                    iq, pat, sample_rate=sample_rate, threshold=threshold
                )
            )
        matches.sort(key=lambda m: m.correlation_peak, reverse=True)
        return matches

    def detect_pattern(
        self,
        iq: np.ndarray,
        pattern: SyncPattern,
        sample_rate: float = 1.0,
        threshold: float = 0.7,
    ) -> list[PreambleMatch]:
        """Scan *iq* for a specific *pattern*.

        Parameters
        ----------
        iq : np.ndarray
            Complex IQ samples (1-D).
        pattern : SyncPattern
            The pattern to search for.
        sample_rate : float
            Sample rate in Hz.
        threshold : float
            Minimum normalized correlation (0-1).

        Returns
        -------
        list[PreambleMatch]
            All matches above the threshold.
        """
        iq = np.asarray(iq, dtype=np.complex128).ravel()
        template = _bits_to_symbols(pattern.bits, pattern.modulation)

        if len(template) > len(iq):
            return []

        corr = _normalized_xcorr(iq, template)
        if len(corr) == 0:
            return []

        # Find peaks above threshold
        matches: list[PreambleMatch] = []
        for idx in range(len(corr)):
            val = float(corr[idx])
            if val < threshold:
                continue
            # Simple local-maximum check (allow edges)
            is_peak = True
            if idx > 0 and corr[idx - 1] > val:
                is_peak = False
            if idx < len(corr) - 1 and corr[idx + 1] > val:
                is_peak = False
            if not is_peak:
                continue

            # Estimate symbol rate from pattern length and sample rate
            n_symbols = len(template)
            est_symbol_rate = sample_rate / max(n_symbols, 1)

            matches.append(
                PreambleMatch(
                    pattern_name=pattern.name,
                    protocol=pattern.protocol,
                    sample_offset=int(idx),
                    correlation_peak=round(val, 6),
                    confidence=round(val, 6),
                    bit_sequence=list(pattern.bits),
                    estimated_symbol_rate=round(est_symbol_rate, 2),
                )
            )

        return matches
