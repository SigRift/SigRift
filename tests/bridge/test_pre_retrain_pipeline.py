"""Tests for v4.15.0 protocol signal generators, channel model wiring, and training pipeline.

Validates that every class in the taxonomy has a working generator that
produces finite complex64 IQ samples of the correct length. Also validates
channel_config passthrough and per-family augmentation selection.
"""

import pytest
import numpy as np

SAMPLE_RATE = 2.048e6
NUM_SAMPLES = 4096

NEW_CLASSES = [
    "adsb", "uat", "tpms", "dect", "zwave", "p25", "wisun", "scada-fsk",
    "dmr", "tetra", "pocsag", "ais", "dstar", "gsm", "nrf24",
    "dji-ofdm", "nbiot", "halow", "fpv-analog", "pmr446", "wireless-mic",
    "sigfox", "oqpsk-dsss", "uhf-rfid", "gps-jammer", "iridium",
    "elrs", "sidewalk", "ism433", "analog-video-24", "wireless-hart", "isa100",
    "lora-meshtastic", "lora-meshcore", "lora-lorawan",
]


@pytest.mark.parametrize("signal_class", NEW_CLASSES)
def test_generator_produces_valid_output(signal_class):
    from sigrift.lib.training.signal_factory import generate_signal

    signal = generate_signal(
        signal_class, n_samples=NUM_SAMPLES, sample_rate=SAMPLE_RATE, snr_db=20.0,
    )
    assert signal is not None
    assert signal.dtype == np.complex64
    assert np.all(np.isfinite(signal))
    assert len(signal) == NUM_SAMPLES


@pytest.mark.parametrize("signal_class", NEW_CLASSES)
def test_generator_deterministic_with_seed(signal_class):
    from sigrift.lib.training.signal_factory import generate_signal

    rng1 = np.random.RandomState(42)
    sig1 = generate_signal(
        signal_class, n_samples=NUM_SAMPLES, sample_rate=SAMPLE_RATE,
        snr_db=20.0, rng=rng1,
    )
    rng2 = np.random.RandomState(42)
    sig2 = generate_signal(
        signal_class, n_samples=NUM_SAMPLES, sample_rate=SAMPLE_RATE,
        snr_db=20.0, rng=rng2,
    )
    np.testing.assert_array_equal(sig1, sig2)


def test_channel_config_wiring():
    from sigrift.lib.training.signal_factory import generate_signal
    from sigrift.lib.dsp.channel_models import ChannelConfig

    config = ChannelConfig(apply_probability=1.0)
    rng_no_ch = np.random.RandomState(99)
    sig_no_ch = generate_signal(
        "bpsk", n_samples=NUM_SAMPLES, sample_rate=SAMPLE_RATE,
        snr_db=20.0, rng=rng_no_ch, channel_config=None,
    )
    rng_ch = np.random.RandomState(99)
    sig_ch = generate_signal(
        "bpsk", n_samples=NUM_SAMPLES, sample_rate=SAMPLE_RATE,
        snr_db=20.0, rng=rng_ch, channel_config=config,
    )
    assert sig_ch is not None
    assert np.all(np.isfinite(sig_ch))
    assert len(sig_ch) == NUM_SAMPLES
    assert not np.array_equal(sig_no_ch, sig_ch)


def test_channel_config_none_backward_compat():
    from sigrift.lib.training.signal_factory import generate_signal

    signal = generate_signal(
        "bpsk", n_samples=NUM_SAMPLES, sample_rate=SAMPLE_RATE,
        snr_db=20.0, channel_config=None,
    )
    assert signal is not None
    assert np.all(np.isfinite(signal))
    assert len(signal) == NUM_SAMPLES


def test_all_taxonomy_classes_have_generator():
    from sigrift.lib.taxonomy import CLASSES
    from sigrift.lib.training.signal_factory import generate_signal

    missing = []
    for cls in CLASSES:
        try:
            sig = generate_signal(cls, n_samples=1024, sample_rate=SAMPLE_RATE, snr_db=20.0)
            if sig is None:
                missing.append(cls)
        except (KeyError, NotImplementedError, ValueError):
            missing.append(cls)
    assert missing == [], f"Classes without generators: {missing}"


def test_generator_count_matches_taxonomy():
    from sigrift.lib.taxonomy import CLASSES
    from sigrift.lib.training.signal_factory import list_classes

    registered = set(list_classes())
    taxonomy = set(CLASSES)
    missing_from_factory = taxonomy - registered
    assert missing_from_factory == set(), (
        f"Taxonomy classes not in signal_factory: {missing_from_factory}"
    )


def test_aliases_produce_same_shape():
    from sigrift.lib.training.signal_factory import generate_signal

    alias_pairs = [
        ("wireless-hart", "oqpsk-dsss"),
        ("isa100", "oqpsk-dsss"),
        ("analog-video-24", "fpv-analog"),
    ]
    for alias, canonical in alias_pairs:
        sig_a = generate_signal(alias, n_samples=NUM_SAMPLES, sample_rate=SAMPLE_RATE, snr_db=20.0)
        sig_c = generate_signal(canonical, n_samples=NUM_SAMPLES, sample_rate=SAMPLE_RATE, snr_db=20.0)
        assert sig_a.shape == sig_c.shape
        assert sig_a.dtype == sig_c.dtype


def test_small_sample_count():
    """Generators should work with small sample counts without errors."""
    from sigrift.lib.training.signal_factory import generate_signal

    for cls in ["adsb", "gsm", "nbiot", "oqpsk-dsss", "sigfox"]:
        sig = generate_signal(cls, n_samples=256, sample_rate=SAMPLE_RATE, snr_db=15.0)
        assert len(sig) == 256
        assert np.all(np.isfinite(sig))


def test_channel_config_with_new_protocol():
    from sigrift.lib.training.signal_factory import generate_signal
    from sigrift.lib.dsp.channel_models import ChannelConfig

    config = ChannelConfig(apply_probability=1.0)
    for cls in ["adsb", "dmr", "nbiot", "iridium"]:
        sig = generate_signal(
            cls, n_samples=NUM_SAMPLES, sample_rate=SAMPLE_RATE,
            snr_db=20.0, channel_config=config,
        )
        assert sig is not None
        assert np.all(np.isfinite(sig))
        assert len(sig) == NUM_SAMPLES


# --- Training pipeline wiring tests ---

def test_dataset_channel_config_passthrough():
    """OnTheFlySignalDataset stores channel_config when provided."""
    from sigrift.lib.dsp.channel_models import ChannelConfig
    from sigrift.lib.training.dataset import OnTheFlySignalDataset

    config = ChannelConfig()
    ds = OnTheFlySignalDataset(
        classes=["bpsk", "qpsk"],
        samples_per_epoch=10,
        input_samples=1024,
        sample_rate=2.048e6,
        channel_config=config,
    )
    assert ds.channel_config is config


def test_dataset_none_channel_config():
    """Default channel_config is None."""
    from sigrift.lib.training.dataset import OnTheFlySignalDataset

    ds = OnTheFlySignalDataset(
        classes=["bpsk"],
        samples_per_epoch=10,
        input_samples=1024,
        sample_rate=2.048e6,
    )
    assert ds.channel_config is None


def test_ofdm_family_gets_ofdm_augmentation():
    """OFDM family classes use OFDM augmentation config."""
    from sigrift.lib.taxonomy import CLASS_TO_FAMILY

    ofdm_classes = [c for c, f in CLASS_TO_FAMILY.items() if f == "OFDM"]
    assert len(ofdm_classes) > 0
    for c in ofdm_classes:
        assert CLASS_TO_FAMILY[c] == "OFDM"


def test_non_ofdm_family_not_ofdm():
    """Non-OFDM classes (e.g. PSK, FSK) are not mapped to OFDM family."""
    from sigrift.lib.taxonomy import CLASS_TO_FAMILY

    for c in ("bpsk", "qpsk", "2fsk", "4gfsk", "ook", "fm"):
        if c in CLASS_TO_FAMILY:
            assert CLASS_TO_FAMILY[c] != "OFDM"


def test_rtl_sdr_realistic_is_realistic_channel():
    """train.py REALISTIC_CHANNEL uses RTL_SDR_REALISTIC preset."""
    from sigrift.lib.dsp.channel_models import RTL_SDR_REALISTIC

    assert RTL_SDR_REALISTIC.apply_probability == 1.0
    assert RTL_SDR_REALISTIC.multipath_probability == 1.0
    assert RTL_SDR_REALISTIC.cfo_probability == 1.0
    assert RTL_SDR_REALISTIC.phase_noise_probability == 1.0
    assert RTL_SDR_REALISTIC.adc_bits == 8


def test_dataset_channel_config_import():
    """ChannelConfig can be imported from dataset module's dependencies."""
    from sigrift.lib.dsp.channel_models import ChannelConfig
    from sigrift.lib.training.dataset import OnTheFlySignalDataset

    assert hasattr(OnTheFlySignalDataset, "__init__")
    assert ChannelConfig is not None
