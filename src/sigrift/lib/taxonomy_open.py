"""Open-source default class taxonomy for the community edge classifier.

A focused 16-class TSCM-oriented subset of the full 76-class production
taxonomy. Designed for:

- An open-source default model that can ship signed in releases.
- Classes that are reproducibly trainable via synthetic IQ + optional
  HackRF→RTL-SDR captures, with no proprietary signatures or
  regulated cellular bands.
- Family-level collapsing where order-specific distinctions
  (16/64/256 QAM, OFDM subcarrier counts, FSK 2-level vs 4-level
  Gaussian variants) don't carry TSCM-relevant signal.

Used by ``training/train_open_default.py``. The collapse map lets
``OnTheFlySignalDataset`` keep its full 76-class signal-generation
catalogue while emitting collapsed labels — the model learns to
generalise within a family (e.g. all QAM orders → ``qam``).
"""

from __future__ import annotations

# 16-class open default — train the EdgeRFClassifier against this set.
# Order matters: index in this list becomes the model's output class id.
OPEN_DEFAULT_CLASSES: list[str] = [
    "noise",
    "tone",
    "am",
    "fm",
    "ask",
    "psk",
    "qam",
    "fsk",
    "gfsk",
    "msk",
    "ofdm",
    "lora-css",
    "dsss",
    "adsb",
    "fpv-analog",
    "pocsag",
]

# Map from a source class in the 76-class taxonomy to the open-default
# bucket. Anything not in this map is excluded from training in
# open-default mode (e.g. ``gsm``, ``dect`` — regulated / proprietary).
SOURCE_TO_OPEN_DEFAULT: dict[str, str] = {
    # ASK family — collapse orders
    "ook": "ask",
    "4ask": "ask",
    "8ask": "ask",
    "16ask": "ask",
    # PAM is amplitude-modulation-adjacent; lump into ASK for TSCM
    # triage. The geometric distinction (PAM ≠ ASK in carrier phase)
    # does not buy anything operational at the dashboard level.
    "4pam": "ask",
    "8pam": "ask",
    "16pam": "ask",
    # PSK orders
    "bpsk": "psk",
    "qpsk": "psk",
    "8psk": "psk",
    "16psk": "psk",
    "32psk": "psk",
    # QAM orders
    "16qam": "qam",
    "32qam": "qam",
    "64qam": "qam",
    "128qam": "qam",
    "256qam": "qam",
    # APSK orders — fold into QAM. Constellations are siblings in TSCM
    # context; satellite-uplink-specific shaping doesn't help triage.
    "16apsk": "qam",
    "32apsk": "qam",
    "64apsk": "qam",
    "128apsk": "qam",
    # FSK family
    "2fsk": "fsk",
    "4fsk": "fsk",
    # GFSK orders
    "2gfsk": "gfsk",
    "4gfsk": "gfsk",
    # MSK / GMSK orders
    "2msk": "msk",
    "4msk": "msk",
    "2gmsk": "msk",
    "4gmsk": "msk",
    # OFDM subcarrier variants — same family, training-signal-wise
    "ofdm-64": "ofdm",
    "ofdm-128": "ofdm",
    "ofdm-256": "ofdm",
    "ofdm-512": "ofdm",
    "ofdm-1024": "ofdm",
    "ofdm-2048": "ofdm",
    # Spread-spectrum: LoRa CSS gets its own class; OQPSK-DSSS
    # (Zigbee 802.15.4) and similar land in `dsss`
    "lora-css": "lora-css",
    "oqpsk-dsss": "dsss",
    # Analog
    "am-dsb": "am",
    "am-ssb": "am",
    "fm": "fm",
    "tone": "tone",
    "noise": "noise",
    # Named protocols kept as-is in the open set
    "adsb": "adsb",
    "fpv-analog": "fpv-analog",
    "pocsag": "pocsag",
}

# Inverse mapping: open-default class → list of source classes that
# render into that bucket. Useful for the dataset's stratified sampler
# (so e.g. ``qam`` draws roughly equally from 16/32/64/128/256 QAM).
OPEN_DEFAULT_TO_SOURCES: dict[str, list[str]] = {}
for _src, _dst in SOURCE_TO_OPEN_DEFAULT.items():
    OPEN_DEFAULT_TO_SOURCES.setdefault(_dst, []).append(_src)

# Sanity check: every open-default class has at least one source class.
_missing = [c for c in OPEN_DEFAULT_CLASSES if c not in OPEN_DEFAULT_TO_SOURCES]
assert not _missing, f"OPEN_DEFAULT_CLASSES missing source coverage: {_missing}"

# Index map for label tensor construction.
OPEN_DEFAULT_TO_IDX: dict[str, int] = {c: i for i, c in enumerate(OPEN_DEFAULT_CLASSES)}

# Open-default class → existing taxonomy family name. Used by
# ``register_open_default_classes()`` below to patch the full
# class→family lookup so that ``sigrift.lib.training.trainer.Trainer``
# can build its (always-constructed) HierarchicalFocalLoss without
# choking on our collapsed class names. The hierarchical loss is
# discarded at train time when ``hierarchical=False``; the family
# assignment here only needs to be non-crashing, not semantically
# meaningful at the family-loss level.
OPEN_DEFAULT_TO_FAMILY: dict[str, str] = {
    "noise": "NOISE",
    "tone": "INTERFERENCE",
    "am": "ANALOG",
    "fm": "ANALOG",
    "ask": "ASK",
    "psk": "PSK",
    "qam": "QAM",
    "fsk": "FSK",
    "gfsk": "FSK",
    "msk": "FSK",
    "ofdm": "OFDM",
    "lora-css": "SPREAD_SPECTRUM",
    "dsss": "SPREAD_SPECTRUM",
    "adsb": "PULSED",
    "fpv-analog": "ANALOG",
    "pocsag": "FSK",
}


def register_open_default_classes() -> None:
    """Register the open-default class names with the global taxonomy.

    Inserts entries into ``sigrift.lib.taxonomy.CLASS_TO_FAMILY_IDX`` and
    its sibling ``CLASS_TO_SF_IDX`` / ``CLASS_TO_MT_IDX`` dicts so the
    Trainer can construct its hierarchical-loss helper without raising
    ``KeyError`` on our collapsed class names. Idempotent.

    Call this once at the top of any process that constructs a
    Trainer with ``classes=OPEN_DEFAULT_CLASSES``.
    """
    from sigrift.lib import taxonomy as _tx

    for cls, fam in OPEN_DEFAULT_TO_FAMILY.items():
        if cls in _tx.CLASS_TO_FAMILY_IDX:
            continue
        _tx.CLASS_TO_FAMILY_IDX[cls] = _tx.FAMILY_TO_IDX[fam]
        _tx.CLASS_TO_FAMILY[cls] = fam
        sf = _tx.FAMILY_TO_SF[fam]
        _tx.CLASS_TO_SF[cls] = sf
        _tx.CLASS_TO_SF_IDX[cls] = _tx.SF_TO_IDX[sf]
        # MT (modulation-type) is the finest grouping above class;
        # not all families have an MT, so guard for absence.
        mt = _tx.CLASS_TO_MT.get(cls)
        if mt is None:
            # Fall back: register against the family's own name if it
            # exists as an MT; otherwise leave unset (HierarchicalFocalLoss
            # tolerates this).
            _tx.CLASS_TO_MT[cls] = fam
            _tx.CLASS_TO_MT_IDX[cls] = _tx.MT_TO_IDX.get(fam, 0)
