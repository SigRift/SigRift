"""Single source of truth for class / family / super-family / modulation-type mappings.

Hierarchy (4 levels):
    super-family (9) -> family (16) -> modulation-type (13) -> class (76)

v4.15.0: Added 35 protocol classes for TSCM, IoT, SCADA, satellite, and ICS.
"""

import torch

# -- Production class list (76 classes) ----------------------------------------
CLASSES: list[str] = [
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
    # QAM (5)
    "16qam",
    "32qam",
    "64qam",
    "128qam",
    "256qam",
    # APSK (4)
    "16apsk",
    "32apsk",
    "64apsk",
    "128apsk",
    # FSK (4 + 9 new = 13)
    "2fsk",
    "4fsk",
    "2gfsk",
    "4gfsk",
    "dect",
    "zwave",
    "wisun",
    "scada-fsk",
    "pocsag",
    "nrf24",
    "ais",
    "dstar",
    "gsm",
    # MSK (4)
    "2msk",
    "4msk",
    "2gmsk",
    "4gmsk",
    # OFDM (6 + 3 new = 9)
    "ofdm-64",
    "ofdm-128",
    "ofdm-256",
    "ofdm-512",
    "ofdm-1024",
    "ofdm-2048",
    "dji-ofdm",
    "nbiot",
    "halow",
    # Spread spectrum (1)
    "lora-css",
    # 802154 (3) — new family
    "oqpsk-dsss",
    "wireless-hart",
    "isa100",
    # Analog (4 + 2 new = 6)
    "am-dsb",
    "am-ssb",
    "fm",
    "tone",
    "fpv-analog",
    "analog-video-24",
    # Narrowband FM (2) — new family
    "pmr446",
    "wireless-mic",
    # Noise (1)
    "noise",
    # PULSED (3) — new family + super
    "adsb",
    "uat",
    "tpms",
    # TRUNKED (3) — new family
    "p25",
    "dmr",
    "tetra",
    # SATELLITE (1) — new family
    "iridium",
    # INTERFERENCE (1) — new family + super
    "gps-jammer",
    # ASK additions (2)
    "ism433",
    "uhf-rfid",
    # Spread spectrum additions (3)
    "elrs",
    "sigfox",
    "sidewalk",
    # LoRa protocol refinements (3) — map to lora-css in class_map
    "lora-meshtastic",
    "lora-meshcore",
    "lora-lorawan",
]

NUM_CLASSES: int = len(CLASSES)
CLASS_TO_IDX: dict[str, int] = {c: i for i, c in enumerate(CLASSES)}

# -- Families (16) ------------------------------------------------------------
FAMILIES: list[str] = [
    "ASK",
    "PAM",
    "PSK",
    "QAM",
    "APSK",
    "FSK",
    "OFDM",
    "ANALOG",
    "SPREAD_SPECTRUM",
    "NOISE",
    # New families (v4.15.0)
    "PULSED",
    "802154",
    "SATELLITE",
    "INTERFERENCE",
    "TRUNKED",
    "NARROWBAND_FM",
]

NUM_FAMILIES: int = len(FAMILIES)
FAMILY_TO_IDX: dict[str, int] = {f: i for i, f in enumerate(FAMILIES)}

FAMILY_TO_CLASSES: dict[str, list[str]] = {
    "ASK": ["ook", "4ask", "8ask", "16ask", "ism433", "uhf-rfid"],
    "PAM": ["4pam", "8pam", "16pam"],
    "PSK": ["bpsk", "qpsk", "8psk", "16psk", "32psk"],
    "QAM": ["16qam", "32qam", "64qam", "128qam", "256qam"],
    "APSK": ["16apsk", "32apsk", "64apsk", "128apsk"],
    "FSK": [
        "2fsk",
        "4fsk",
        "2gfsk",
        "4gfsk",
        "2msk",
        "4msk",
        "2gmsk",
        "4gmsk",
        "dect",
        "zwave",
        "wisun",
        "scada-fsk",
        "pocsag",
        "nrf24",
        "ais",
        "dstar",
        "gsm",
    ],
    "OFDM": [
        "ofdm-64",
        "ofdm-128",
        "ofdm-256",
        "ofdm-512",
        "ofdm-1024",
        "ofdm-2048",
        "dji-ofdm",
        "nbiot",
        "halow",
    ],
    "ANALOG": ["am-dsb", "am-ssb", "fm", "tone", "fpv-analog", "analog-video-24"],
    "SPREAD_SPECTRUM": [
        "lora-css",
        "elrs",
        "sigfox",
        "sidewalk",
        "lora-meshtastic",
        "lora-meshcore",
        "lora-lorawan",
    ],
    "NOISE": ["noise"],
    "PULSED": ["adsb", "uat", "tpms"],
    "802154": ["oqpsk-dsss", "wireless-hart", "isa100"],
    "SATELLITE": ["iridium"],
    "INTERFERENCE": ["gps-jammer"],
    "TRUNKED": ["p25", "dmr", "tetra"],
    "NARROWBAND_FM": ["pmr446", "wireless-mic"],
}

# -- Super-families (9) -------------------------------------------------------
SUPER_FAMILIES: list[str] = [
    "CONSTANT_ENVELOPE",
    "LINEAR_DIGITAL",
    "MULTI_CARRIER",
    "AMPLITUDE_ONLY",
    "ANALOG",
    "SPREAD_SPECTRUM",
    "NOISE",
    # New super-families (v4.15.0)
    "PULSED",
    "INTERFERENCE",
]

NUM_SUPER_FAMILIES: int = len(SUPER_FAMILIES)
SF_TO_IDX: dict[str, int] = {sf: i for i, sf in enumerate(SUPER_FAMILIES)}

SUPER_FAMILY_TO_FAMILIES: dict[str, list[str]] = {
    "CONSTANT_ENVELOPE": ["FSK", "TRUNKED", "SATELLITE"],
    "LINEAR_DIGITAL": ["PSK", "QAM", "APSK"],
    "MULTI_CARRIER": ["OFDM"],
    "AMPLITUDE_ONLY": ["ASK", "PAM"],
    "ANALOG": ["ANALOG", "NARROWBAND_FM"],
    "SPREAD_SPECTRUM": ["SPREAD_SPECTRUM", "802154"],
    "NOISE": ["NOISE"],
    "PULSED": ["PULSED"],
    "INTERFERENCE": ["INTERFERENCE"],
}

# -- Modulation Types (13) -- intermediate level between family and class ------
MODULATION_TYPES: list[str] = [
    "PHASE_MODULATED",  # PSK
    "AMPL_PHASE_RECTANGULAR",  # QAM
    "AMPL_PHASE_RING",  # APSK
    "AMPLITUDE_ONLY_DIGITAL",  # ASK + PAM
    "FREQUENCY_MODULATED",  # FSK + MSK + protocol FSK variants
    "MULTICARRIER",  # OFDM
    "SPREAD_SPECTRUM_MOD",  # LoRa, Sigfox, Sidewalk
    "ANALOG_MOD",  # AM, FM, tone, analog video
    "NOISE_MOD",  # Noise (no modulation)
    # New modulation types (v4.15.0)
    "PULSE_MODULATED",  # ADS-B, UAT, TPMS
    "TRUNKED_DIGITAL",  # P25, DMR, TETRA
    "SATELLITE_BURST",  # Iridium
    "INTERFERENCE_MOD",  # GPS jammer
]

NUM_MODULATION_TYPES: int = len(MODULATION_TYPES)
MT_TO_IDX: dict[str, int] = {mt: i for i, mt in enumerate(MODULATION_TYPES)}

MT_TO_CLASSES: dict[str, list[str]] = {
    "PHASE_MODULATED": ["bpsk", "qpsk", "8psk", "16psk", "32psk"],
    "AMPL_PHASE_RECTANGULAR": ["16qam", "32qam", "64qam", "128qam", "256qam"],
    "AMPL_PHASE_RING": ["16apsk", "32apsk", "64apsk", "128apsk"],
    "AMPLITUDE_ONLY_DIGITAL": [
        "ook",
        "4ask",
        "8ask",
        "16ask",
        "4pam",
        "8pam",
        "16pam",
        "ism433",
        "uhf-rfid",
    ],
    "FREQUENCY_MODULATED": [
        "2fsk",
        "4fsk",
        "2gfsk",
        "4gfsk",
        "2msk",
        "4msk",
        "2gmsk",
        "4gmsk",
        "dect",
        "zwave",
        "wisun",
        "scada-fsk",
        "pocsag",
        "nrf24",
        "ais",
        "dstar",
        "gsm",
    ],
    "MULTICARRIER": [
        "ofdm-64",
        "ofdm-128",
        "ofdm-256",
        "ofdm-512",
        "ofdm-1024",
        "ofdm-2048",
        "dji-ofdm",
        "nbiot",
        "halow",
    ],
    "SPREAD_SPECTRUM_MOD": [
        "lora-css",
        "oqpsk-dsss",
        "wireless-hart",
        "isa100",
        "elrs",
        "sigfox",
        "sidewalk",
        "lora-meshtastic",
        "lora-meshcore",
        "lora-lorawan",
    ],
    "ANALOG_MOD": [
        "am-dsb",
        "am-ssb",
        "fm",
        "tone",
        "fpv-analog",
        "analog-video-24",
        "pmr446",
        "wireless-mic",
    ],
    "NOISE_MOD": ["noise"],
    "PULSE_MODULATED": ["adsb", "uat", "tpms"],
    "TRUNKED_DIGITAL": ["p25", "dmr", "tetra"],
    "SATELLITE_BURST": ["iridium"],
    "INTERFERENCE_MOD": ["gps-jammer"],
}

FAMILY_TO_MT: dict[str, list[str]] = {
    "ASK": ["AMPLITUDE_ONLY_DIGITAL"],
    "PAM": ["AMPLITUDE_ONLY_DIGITAL"],
    "PSK": ["PHASE_MODULATED"],
    "QAM": ["AMPL_PHASE_RECTANGULAR"],
    "APSK": ["AMPL_PHASE_RING"],
    "FSK": ["FREQUENCY_MODULATED"],
    "OFDM": ["MULTICARRIER"],
    "ANALOG": ["ANALOG_MOD"],
    "SPREAD_SPECTRUM": ["SPREAD_SPECTRUM_MOD"],
    "NOISE": ["NOISE_MOD"],
    "PULSED": ["PULSE_MODULATED"],
    "802154": ["SPREAD_SPECTRUM_MOD"],
    "SATELLITE": ["SATELLITE_BURST"],
    "INTERFERENCE": ["INTERFERENCE_MOD"],
    "TRUNKED": ["TRUNKED_DIGITAL"],
    "NARROWBAND_FM": ["ANALOG_MOD"],
}

# -- Auto-generated reverse mappings -------------------------------------------
CLASS_TO_FAMILY: dict[str, str] = {}
for _fam, _cls_list in FAMILY_TO_CLASSES.items():
    for _cls in _cls_list:
        CLASS_TO_FAMILY[_cls] = _fam

CLASS_TO_FAMILY_IDX: dict[str, int] = {
    c: FAMILY_TO_IDX[CLASS_TO_FAMILY[c]] for c in CLASSES
}

FAMILY_TO_SF: dict[str, str] = {}
for _sf, _fam_list in SUPER_FAMILY_TO_FAMILIES.items():
    for _fam in _fam_list:
        FAMILY_TO_SF[_fam] = _sf

FAMILY_TO_SF_IDX: dict[str, int] = {f: SF_TO_IDX[FAMILY_TO_SF[f]] for f in FAMILIES}

CLASS_TO_SF: dict[str, str] = {c: FAMILY_TO_SF[CLASS_TO_FAMILY[c]] for c in CLASSES}
CLASS_TO_SF_IDX: dict[str, int] = {c: SF_TO_IDX[CLASS_TO_SF[c]] for c in CLASSES}

CLASS_TO_MT: dict[str, str] = {}
for _mt, _cls_list in MT_TO_CLASSES.items():
    for _cls in _cls_list:
        CLASS_TO_MT[_cls] = _mt

CLASS_TO_MT_IDX: dict[str, int] = {c: MT_TO_IDX[CLASS_TO_MT[c]] for c in CLASSES}


# -- Tensor builders ----------------------------------------------------------


def build_class_family_tensor(classes: list[str] | None = None) -> torch.Tensor:
    """Return int tensor [num_classes] mapping class index -> family index."""
    classes = classes or CLASSES
    return torch.tensor([CLASS_TO_FAMILY_IDX[c] for c in classes], dtype=torch.long)


def build_class_sf_tensor(classes: list[str] | None = None) -> torch.Tensor:
    """Return int tensor [num_classes] mapping class index -> super-family index."""
    classes = classes or CLASSES
    return torch.tensor([CLASS_TO_SF_IDX[c] for c in classes], dtype=torch.long)


def build_class_mt_tensor(classes: list[str] | None = None) -> torch.Tensor:
    """Return int tensor [num_classes] mapping class index -> modulation-type index."""
    classes = classes or CLASSES
    return torch.tensor([CLASS_TO_MT_IDX[c] for c in classes], dtype=torch.long)


def build_family_class_mask(classes: list[str] | None = None) -> torch.Tensor:
    """Return binary float mask [NUM_FAMILIES, num_classes]."""
    classes = classes or CLASSES
    mask = torch.zeros(NUM_FAMILIES, len(classes))
    for i, c in enumerate(classes):
        mask[CLASS_TO_FAMILY_IDX[c], i] = 1.0
    return mask


def build_mt_class_mask(classes: list[str] | None = None) -> torch.Tensor:
    """Return binary float mask [NUM_MODULATION_TYPES, num_classes]."""
    classes = classes or CLASSES
    mask = torch.zeros(NUM_MODULATION_TYPES, len(classes))
    for i, c in enumerate(classes):
        mask[CLASS_TO_MT_IDX[c], i] = 1.0
    return mask


def build_sf_family_mask() -> torch.Tensor:
    """Return binary float mask [NUM_SUPER_FAMILIES, NUM_FAMILIES]."""
    mask = torch.zeros(NUM_SUPER_FAMILIES, NUM_FAMILIES)
    for sf, fam_list in SUPER_FAMILY_TO_FAMILIES.items():
        sf_idx = SF_TO_IDX[sf]
        for fam in fam_list:
            mask[sf_idx, FAMILY_TO_IDX[fam]] = 1.0
    return mask


def build_family_mt_mask() -> torch.Tensor:
    """Return binary float mask [NUM_FAMILIES, NUM_MODULATION_TYPES]."""
    mask = torch.zeros(NUM_FAMILIES, NUM_MODULATION_TYPES)
    for fam, mt_list in FAMILY_TO_MT.items():
        fam_idx = FAMILY_TO_IDX[fam]
        for mt in mt_list:
            mask[fam_idx, MT_TO_IDX[mt]] = 1.0
    return mask
