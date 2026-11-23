"""RF signal utility functions for The Bridge.

Provides bandwidth estimation based on signal class and frequency,
and other RF-related helper functions.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Bandwidth lookup table: canonical signal class -> typical bandwidth in Hz
# ---------------------------------------------------------------------------
# Values represent typical occupied bandwidths for each modulation type.
# These are approximate and used as fallback when edge nodes do not
# provide measured bandwidth.

BANDWIDTH_BY_CLASS: dict[str, float] = {
    # ASK family — typically narrow-band ISM
    "ook": 25_000,  # 25 kHz (e.g., 433 MHz remotes)
    "4ask": 50_000,  # 50 kHz
    "8ask": 100_000,  # 100 kHz
    "16ask": 200_000,  # 200 kHz
    # PAM family — baseband / wired-like
    "4pam": 50_000,  # 50 kHz
    "8pam": 100_000,  # 100 kHz
    "16pam": 200_000,  # 200 kHz
    # PSK family — various narrowband digital
    "bpsk": 25_000,  # 25 kHz
    "qpsk": 50_000,  # 50 kHz
    "8psk": 100_000,  # 100 kHz
    "16psk": 200_000,  # 200 kHz
    "32psk": 200_000,  # 200 kHz
    # QAM family — moderate to wideband digital
    "16qam": 200_000,  # 200 kHz
    "32qam": 500_000,  # 500 kHz
    "64qam": 1_000_000,  # 1 MHz
    "high-order-qam": 5_000_000,  # 5 MHz (e.g., cable/WiFi subcarrier)
    # APSK family — satellite digital
    "16apsk": 1_000_000,  # 1 MHz
    "32apsk": 2_000_000,  # 2 MHz
    "high-order-apsk": 5_000_000,  # 5 MHz
    # FSK family — narrowband digital
    "2fsk": 25_000,  # 25 kHz
    "4fsk": 50_000,  # 50 kHz
    "gfsk": 50_000,  # 50 kHz (e.g., Bluetooth = 1 MHz, but typical ISM)
    # MSK family — narrowband constant-envelope
    "2msk": 25_000,  # 25 kHz
    "4msk": 50_000,  # 50 kHz
    "gmsk": 200_000,  # 200 kHz (e.g., GSM channel)
    # OFDM — wideband multi-carrier
    "ofdm": 20_000_000,  # 20 MHz (e.g., WiFi 802.11a/g/n)
    # Spread spectrum
    "lora-css": 125_000,  # 125 kHz (LoRa default BW)
    # Analog
    "am": 10_000,  # 10 kHz (AM broadcast channel)
    "fm": 200_000,  # 200 kHz (FM broadcast channel)
    "tone": 3_000,  # 3 kHz (single CW tone)
}


def estimate_bandwidth(signal_class: str, freq_hz: float = 0.0) -> float | None:
    """Estimate occupied bandwidth for a signal class.

    Parameters
    ----------
    signal_class : str
        Canonical signal class name (e.g., "bpsk", "ofdm", "fm").
    freq_hz : float
        Center frequency in Hz.  Used for frequency-dependent
        bandwidth adjustments (e.g., WiFi channel widths vary by band).

    Returns
    -------
    float or None
        Estimated bandwidth in Hz, or None if the class is unknown.
    """
    bw = BANDWIDTH_BY_CLASS.get(signal_class)
    if bw is None:
        return None

    # Frequency-dependent adjustments
    if signal_class == "ofdm" and freq_hz > 0:
        # WiFi 5 GHz often uses 40/80/160 MHz channels
        if freq_hz >= 5_150_000_000:
            bw = 40_000_000  # 40 MHz typical for 5 GHz WiFi
        # Sub-GHz OFDM (e.g., 802.11ah) uses narrower channels
        elif freq_hz < 1_000_000_000:
            bw = 1_000_000  # 1 MHz for sub-GHz OFDM

    if signal_class == "gfsk" and freq_hz > 0:
        # Bluetooth at 2.4 GHz uses 1 MHz channels
        if 2_400_000_000 <= freq_hz <= 2_500_000_000:
            bw = 1_000_000

    if signal_class == "gmsk" and freq_hz > 0:
        # GSM channel at 900/1800 MHz
        if 880_000_000 <= freq_hz <= 960_000_000:
            bw = 200_000
        elif 1_710_000_000 <= freq_hz <= 1_880_000_000:
            bw = 200_000

    return bw
