"""Signal class normalization — reduce 76-class taxonomy to 60 canonical classes.

Merges near-indistinguishable classes at realistic SNR levels:

  - OFDM-{64,128,256,512,1024,2048} -> "ofdm"       (6 -> 1, saves 5)
  - 128qam, 256qam -> "high-order-qam"               (2 -> 1, saves 1)
  - 64apsk, 128apsk -> "high-order-apsk"              (2 -> 1, saves 1)
  - 2gmsk, 4gmsk -> "gmsk"                            (2 -> 1, saves 1)
  - 2gfsk, 4gfsk -> "gfsk"                            (2 -> 1, saves 1)
  - am-dsb, am-ssb -> "am"                            (2 -> 1, saves 1)
  - dji-ofdm -> "ofdm"                                (saves 1)
  - elrs -> "lora-css"                                 (saves 1)
  - ism433 -> "ook"                                    (saves 1)
  - analog-video-24 -> "fpv-analog"                    (saves 1)
  - wireless-hart -> "oqpsk-dsss"                      (saves 1)
  - isa100 -> "oqpsk-dsss"                             (saves 1)
  - lora-meshtastic -> "lora-css"                      (saves 1)
  - lora-meshcore -> "lora-css"                        (saves 1)
  - lora-lorawan -> "lora-css"                         (saves 1)

Result: 76 - 19 = 57 canonical classes (includes noise).

The ``SIGNAL_CLASS_MAP`` dict maps old names to canonical names.
Classes not present in the map are already canonical (identity mapping).
"""

from __future__ import annotations

# -- Merge map: old class name -> canonical class name ----------------------
# Only classes that change are listed; unlisted classes are already canonical.

SIGNAL_CLASS_MAP: dict[str, str] = {
    # OFDM subcarrier counts are indistinguishable from classification alone
    "ofdm-64": "ofdm",
    "ofdm-128": "ofdm",
    "ofdm-256": "ofdm",
    "ofdm-512": "ofdm",
    "ofdm-1024": "ofdm",
    "ofdm-2048": "ofdm",
    # High-order QAM: 128/256 are nearly impossible to separate at <20 dB SNR
    "128qam": "high-order-qam",
    "256qam": "high-order-qam",
    # High-order APSK: 64/128 rings merge visually at realistic SNR
    "64apsk": "high-order-apsk",
    "128apsk": "high-order-apsk",
    # Gaussian MSK variants — shaping difference is sub-symbol
    "2gmsk": "gmsk",
    "4gmsk": "gmsk",
    # Gaussian FSK variants — same rationale
    "2gfsk": "gfsk",
    "4gfsk": "gfsk",
    # AM sideband distinction requires carrier reference
    "am-dsb": "am",
    "am-ssb": "am",
    # New merges (v4.15.0)
    "dji-ofdm": "ofdm",
    "elrs": "lora-css",
    "ism433": "ook",
    "analog-video-24": "fpv-analog",
    "wireless-hart": "oqpsk-dsss",
    "isa100": "oqpsk-dsss",
    # LoRa protocol refinements — all map to lora-css
    "lora-meshtastic": "lora-css",
    "lora-meshcore": "lora-css",
    "lora-lorawan": "lora-css",
}

# -- Canonical class list (60 classes, sorted by family) --------------------

CANONICAL_CLASSES: list[str] = [
    # ASK (4)
    "ook",
    "4ask",
    "8ask",
    "16ask",
    # PAM (3)
    "4pam",
    "8pam",
    "16pam",
    # PSK (5)
    "bpsk",
    "qpsk",
    "8psk",
    "16psk",
    "32psk",
    # QAM (3+1 merged)
    "16qam",
    "32qam",
    "64qam",
    "high-order-qam",
    # APSK (2+1 merged)
    "16apsk",
    "32apsk",
    "high-order-apsk",
    # FSK (2 plain + 1 merged + MSK 2 plain + 1 merged + protocol variants)
    "2fsk",
    "4fsk",
    "gfsk",
    "2msk",
    "4msk",
    "gmsk",
    "dect",
    "zwave",
    "wisun",
    "scada-fsk",
    "pocsag",
    "nrf24",
    "ais",
    "dstar",
    "gsm",
    # OFDM (1 merged + new)
    "ofdm",
    "nbiot",
    "halow",
    # Spread spectrum (1 + new)
    "lora-css",
    "sigfox",
    "sidewalk",
    # 802154 (new)
    "oqpsk-dsss",
    # Analog (2+1 merged + new)
    "am",
    "fm",
    "tone",
    "fpv-analog",
    # Narrowband FM (new)
    "pmr446",
    "wireless-mic",
    # Noise (1)
    "noise",
    # PULSED (new)
    "adsb",
    "uat",
    "tpms",
    # TRUNKED (new)
    "p25",
    "dmr",
    "tetra",
    # SATELLITE (new)
    "iridium",
    # INTERFERENCE (new)
    "gps-jammer",
    # ASK new
    "uhf-rfid",
]

# -- Family mapping for canonical classes -----------------------------------

CANONICAL_CLASS_TO_FAMILY: dict[str, str] = {
    "ook": "ASK",
    "4ask": "ASK",
    "8ask": "ASK",
    "16ask": "ASK",
    "uhf-rfid": "ASK",
    "4pam": "PAM",
    "8pam": "PAM",
    "16pam": "PAM",
    "bpsk": "PSK",
    "qpsk": "PSK",
    "8psk": "PSK",
    "16psk": "PSK",
    "32psk": "PSK",
    "16qam": "QAM",
    "32qam": "QAM",
    "64qam": "QAM",
    "high-order-qam": "QAM",
    "16apsk": "APSK",
    "32apsk": "APSK",
    "high-order-apsk": "APSK",
    "2fsk": "FSK",
    "4fsk": "FSK",
    "gfsk": "FSK",
    "2msk": "FSK",
    "4msk": "FSK",
    "gmsk": "FSK",
    "dect": "FSK",
    "zwave": "FSK",
    "wisun": "FSK",
    "scada-fsk": "FSK",
    "pocsag": "FSK",
    "nrf24": "FSK",
    "ais": "FSK",
    "dstar": "FSK",
    "gsm": "FSK",
    "ofdm": "OFDM",
    "nbiot": "OFDM",
    "halow": "OFDM",
    "lora-css": "SPREAD_SPECTRUM",
    "sigfox": "SPREAD_SPECTRUM",
    "sidewalk": "SPREAD_SPECTRUM",
    "oqpsk-dsss": "802154",
    "am": "ANALOG",
    "fm": "ANALOG",
    "tone": "ANALOG",
    "fpv-analog": "ANALOG",
    "pmr446": "NARROWBAND_FM",
    "wireless-mic": "NARROWBAND_FM",
    "noise": "NOISE",
    "adsb": "PULSED",
    "uat": "PULSED",
    "tpms": "PULSED",
    "p25": "TRUNKED",
    "dmr": "TRUNKED",
    "tetra": "TRUNKED",
    "iridium": "SATELLITE",
    "gps-jammer": "INTERFERENCE",
}

NUM_CANONICAL_CLASSES: int = len(CANONICAL_CLASSES)

# -- Families for the open-default model's collapsed classes ----------------
# The shipped 16-class "open-default" model (sigrift.lib.taxonomy_open)
# emits these family-level names, which are not canonical classes here.
# Its other 10 names already are. Without this table they fell through to
# "UNKNOWN", which the "Novel Signal Detected" alert rule keys on. They are
# kept out of CANONICAL_CLASSES / CANONICAL_CLASS_TO_FAMILY so the class
# list and the Rust gateway parity (class_map.rs) are unchanged.

OPEN_DEFAULT_CLASS_TO_FAMILY: dict[str, str] = {
    "ask": "ASK",
    "psk": "PSK",
    "qam": "QAM",
    "fsk": "FSK",
    "msk": "FSK",
    "dsss": "SPREAD_SPECTRUM",
}


def normalize_class(signal_class: str) -> str:
    """Map a raw signal class name to its canonical (merged) name.

    If the class is already canonical or unknown, it is returned as-is.
    """
    return SIGNAL_CLASS_MAP.get(signal_class, signal_class)


def normalize_family(signal_class: str) -> str:
    """Return the family for a (possibly un-normalized) signal class.

    Normalizes the class first, then looks up the family.
    Falls back to ``"UNKNOWN"`` for unrecognized classes.
    """
    canonical = normalize_class(signal_class)
    family = CANONICAL_CLASS_TO_FAMILY.get(canonical)
    if family is None:
        family = OPEN_DEFAULT_CLASS_TO_FAMILY.get(canonical, "UNKNOWN")
    return family
