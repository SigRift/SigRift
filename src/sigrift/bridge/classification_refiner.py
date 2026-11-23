"""Post-classification refinement for protocol and band-specific labels.

Enhances generic signal class labels with protocol-specific and
band-specific information based on the observed center frequency.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def refine_classification(signal_class: str, freq_hz: float) -> str:
    """Return a refined label incorporating band information, or the original.

    Parameters
    ----------
    signal_class : str
        Canonical signal class from the classifier (e.g. "ofdm", "dqpsk").
    freq_hz : float
        Center frequency in Hz.

    Returns
    -------
    str
        Refined label (e.g. "WiFi 5GHz", "DMR UHF") or ``signal_class``
        unchanged when no refinement rule matches.
    """
    if freq_hz is None or freq_hz <= 0:
        return signal_class

    sc = signal_class.lower()
    freq_mhz = freq_hz / 1e6

    # WiFi: OFDM-based signals in ISM/UNII bands
    if "wifi" in sc or "ofdm" in sc:
        if 2400 <= freq_mhz <= 2500:
            return "WiFi 2.4GHz"
        if 5150 <= freq_mhz <= 5850:
            return "WiFi 5GHz"
        if 5925 <= freq_mhz <= 7125:
            return "WiFi 6E"

    # DMR: DQPSK-based signals in public safety / land mobile bands
    if "dmr" in sc or "dqpsk" in sc:
        if 136 <= freq_mhz <= 174:
            return "DMR VHF"
        if 400 <= freq_mhz <= 527:
            return "DMR UHF"
        if 700 <= freq_mhz <= 900:
            return "DMR 800MHz"

    # FHSS: frequency-hopping signals in ISM bands
    if "fhss" in sc:
        if 2400 <= freq_mhz <= 2500:
            return "Bluetooth/FHSS 2.4GHz"
        if 902 <= freq_mhz <= 928:
            return "ISM 900MHz FHSS"

    # LoRa in ISM bands
    if "lora" in sc or "css" in sc:
        if 862 <= freq_mhz <= 870 or 902 <= freq_mhz <= 928:
            return "LoRa ISM"

    # 802.15.4 in 2.4 GHz
    if "oqpsk" in sc or "802154" in sc:
        if 2400 <= freq_mhz <= 2484:
            return "802.15.4 ISM"

    # P25 bands
    if "p25" in sc or "c4fm" in sc:
        if 136 <= freq_mhz <= 174:
            return "P25 VHF"
        if 400 <= freq_mhz <= 527:
            return "P25 UHF"
        if 764 <= freq_mhz <= 870:
            return "P25 800MHz"

    # SCADA in VHF/UHF
    if "scada" in sc:
        if 150 <= freq_mhz <= 174:
            return "SCADA VHF"
        if 400 <= freq_mhz <= 470:
            return "SCADA UHF"

    # DECT
    if "dect" in sc:
        if 1880 <= freq_mhz <= 1900:
            return "DECT 1.9GHz"

    # TETRA
    if "tetra" in sc:
        if 380 <= freq_mhz <= 400:
            return "TETRA"

    # Wireless mic
    if "wireless-mic" in sc:
        if 470 <= freq_mhz <= 698:
            return "Wireless Mic UHF"

    # ADS-B
    if "adsb" in sc:
        if 1085 <= freq_mhz <= 1095:
            return "ADS-B 1090MHz"

    # GPS jammer
    if "gps-jammer" in sc or "gps" in sc:
        if 1570 <= freq_mhz <= 1580:
            return "GPS L1 Interference"

    return signal_class
