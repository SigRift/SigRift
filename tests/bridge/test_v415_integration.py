"""v4.15.0 integration tests — cross-module validation."""
import pytest
import sqlite3
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch


class TestTaxonomyIntegration:
    """Verify taxonomy consistency across all consumers."""

    def test_all_canonical_classes_have_family(self):
        """Every canonical class maps to a family."""
        from sigrift.bridge.class_map import CANONICAL_CLASSES, CANONICAL_CLASS_TO_FAMILY
        for cls in CANONICAL_CLASSES:
            assert cls in CANONICAL_CLASS_TO_FAMILY, f"{cls} missing family mapping"

    def test_signal_class_map_targets_are_canonical(self):
        """Every merge target in SIGNAL_CLASS_MAP is a canonical class."""
        from sigrift.bridge.class_map import SIGNAL_CLASS_MAP, CANONICAL_CLASSES
        for src, target in SIGNAL_CLASS_MAP.items():
            assert target in CANONICAL_CLASSES, f"{src}->{target}, but {target} not canonical"

    def test_taxonomy_classes_superset_of_canonical(self):
        """taxonomy.py CLASSES includes all canonical classes or their sources."""
        from sigrift.lib.taxonomy import CLASSES
        from sigrift.bridge.class_map import CANONICAL_CLASSES, SIGNAL_CLASS_MAP

        # Every canonical class should be reachable from a taxonomy class
        for canon in CANONICAL_CLASSES:
            # Either canon is directly in CLASSES, or some CLASSES entry maps to it
            direct = canon in CLASSES
            mapped = any(SIGNAL_CLASS_MAP.get(c) == canon for c in CLASSES)
            assert direct or mapped, f"Canonical {canon} unreachable from taxonomy"

    def test_new_families_in_taxonomy_and_classmap(self):
        """New families exist in both taxonomy and class_map."""
        from sigrift.lib.taxonomy import FAMILIES
        from sigrift.bridge.class_map import CANONICAL_CLASS_TO_FAMILY

        new_families = {"PULSED", "802154", "SATELLITE", "INTERFERENCE", "TRUNKED", "NARROWBAND_FM"}
        for fam in new_families:
            assert fam in FAMILIES, f"{fam} not in taxonomy FAMILIES"
            # At least one canonical class should map to this family
            fam_classes = [c for c, f in CANONICAL_CLASS_TO_FAMILY.items() if f == fam]
            assert len(fam_classes) > 0, f"No canonical classes map to family {fam}"

    def test_canonical_class_count(self):
        """Canonical class list has the expected count after merges."""
        from sigrift.bridge.class_map import CANONICAL_CLASSES, NUM_CANONICAL_CLASSES
        assert len(CANONICAL_CLASSES) == NUM_CANONICAL_CLASSES
        # v4.15.0: 57 canonical classes (76 taxonomy - 19 merges)
        assert NUM_CANONICAL_CLASSES == 57

    def test_taxonomy_76_classes(self):
        """Taxonomy has exactly 76 classes."""
        from sigrift.lib.taxonomy import CLASSES, NUM_CLASSES
        assert len(CLASSES) == 76
        assert NUM_CLASSES == 76

    def test_taxonomy_16_families(self):
        """Taxonomy has 16 families."""
        from sigrift.lib.taxonomy import FAMILIES, NUM_FAMILIES
        assert len(FAMILIES) == 16
        assert NUM_FAMILIES == 16

    def test_taxonomy_9_super_families(self):
        """Taxonomy has 9 super-families."""
        from sigrift.lib.taxonomy import SUPER_FAMILIES, NUM_SUPER_FAMILIES
        assert len(SUPER_FAMILIES) == 9
        assert NUM_SUPER_FAMILIES == 9

    def test_taxonomy_13_modulation_types(self):
        """Taxonomy has 13 modulation types."""
        from sigrift.lib.taxonomy import MODULATION_TYPES, NUM_MODULATION_TYPES
        assert len(MODULATION_TYPES) == 13
        assert NUM_MODULATION_TYPES == 13

    def test_every_class_has_family(self):
        """Every taxonomy class belongs to exactly one family."""
        from sigrift.lib.taxonomy import CLASSES, FAMILY_TO_CLASSES
        all_classified = set()
        for fam_classes in FAMILY_TO_CLASSES.values():
            all_classified.update(fam_classes)
        for cls in CLASSES:
            assert cls in all_classified, f"{cls} not assigned to any family"

    def test_every_family_under_super_family(self):
        """Every family belongs to a super-family."""
        from sigrift.lib.taxonomy import FAMILIES, SUPER_FAMILY_TO_FAMILIES
        all_under_sf = set()
        for sf_families in SUPER_FAMILY_TO_FAMILIES.values():
            all_under_sf.update(sf_families)
        for fam in FAMILIES:
            assert fam in all_under_sf, f"Family {fam} not under any super-family"


class TestScoringIntegration:
    """Verify scoring pipeline changes work end-to-end."""

    def test_correlation_weight_is_003(self):
        """CORRELATION dimension has weight 0.03."""
        from sigrift.bridge.anomaly.scorer import AnomalyDimension, _DEFAULT_WEIGHTS
        assert _DEFAULT_WEIGHTS[AnomalyDimension.CORRELATION] == 0.03

    def test_all_weights_sum_near_one(self):
        """Default dimension weights sum to ~1.18 (SIGNATURE_MATCH 0.15 added)."""
        from sigrift.bridge.anomaly.scorer import _DEFAULT_WEIGHTS
        total = sum(_DEFAULT_WEIGHTS.values())
        assert abs(total - 1.18) < 0.01, f"Weights sum to {total}, expected 1.18"

    def test_14_dimensions(self):
        """There are 14 anomaly dimensions."""
        from sigrift.bridge.anomaly.scorer import AnomalyDimension
        assert len(AnomalyDimension) == 14

    def test_mad_preference_in_scorer_source(self):
        """Scorer source contains MAD preference logic."""
        import sigrift.bridge.anomaly.scorer as mod
        source = open(mod.__file__).read()
        assert "power_mad_score" in source
        assert "snr_mad_score" in source

    def test_cusum_boost_in_scorer_source(self):
        """Scorer source contains CUSUM boost logic."""
        import sigrift.bridge.anomaly.scorer as mod
        source = open(mod.__file__).read()
        assert "has_recent_changepoint" in source

    def test_default_weights_string_version(self):
        """DEFAULT_RF_DIMENSION_WEIGHTS has string keys matching enum values."""
        from sigrift.bridge.anomaly.scorer import (
            AnomalyDimension, DEFAULT_RF_DIMENSION_WEIGHTS, _DEFAULT_WEIGHTS,
        )
        assert len(DEFAULT_RF_DIMENSION_WEIGHTS) == len(_DEFAULT_WEIGHTS)
        for dim, weight in _DEFAULT_WEIGHTS.items():
            assert dim.value in DEFAULT_RF_DIMENSION_WEIGHTS
            assert DEFAULT_RF_DIMENSION_WEIGHTS[dim.value] == weight


class TestCrossCorrelationIntegration:
    """Verify cross-correlation engine wiring."""

    def test_correlation_engine_importable(self):
        """CrossCorrelator can be imported."""
        from sigrift.bridge.correlation_engine import CrossCorrelator
        assert CrossCorrelator is not None

    def test_cross_correlation_dataclass(self):
        """CrossCorrelation has the expected fields."""
        from sigrift.bridge.correlation_engine import CrossCorrelation
        cc = CrossCorrelation(
            source_a="sdr", source_a_id="1",
            source_b="wifi", source_b_id="2",
            freq_hz=2.412e9, time_delta_ms=50.0,
            correlation_type="confirmed",
            node_id="node1", timestamp="2026-03-20T00:00:00Z",
        )
        assert cc.correlation_type == "confirmed"
        assert cc.freq_hz == 2.412e9

    def test_correlation_engine_with_empty_db(self):
        """CrossCorrelator works with empty database."""
        from sigrift.bridge.correlation_engine import CrossCorrelator

        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript("""
            CREATE TABLE detections (detection_id TEXT PRIMARY KEY, freq_hz REAL, timestamp TEXT, signal_class TEXT, node_id TEXT);
            CREATE TABLE wifi_metadata (id INTEGER PRIMARY KEY, channel INTEGER, timestamp TEXT, node_id TEXT);
            CREATE TABLE bt_devices (id INTEGER PRIMARY KEY, channel INTEGER, timestamp TEXT, node_id TEXT);
            CREATE TABLE zigbee_devices (id INTEGER PRIMARY KEY, channel INTEGER, timestamp TEXT, node_id TEXT);
            CREATE TABLE cross_correlations (id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_a TEXT, source_a_id TEXT, source_b TEXT, source_b_id TEXT,
                freq_hz REAL, time_delta_ms REAL, correlation_type TEXT,
                node_id TEXT, timestamp TEXT, tenant_id TEXT DEFAULT 'default');
        """)
        ctx = MagicMock()
        ctx.get_conn.return_value = conn

        correlator = CrossCorrelator(ctx)
        now = datetime.now(timezone.utc).isoformat()
        results = correlator.correlate("sdr", [{"freq_hz": 2412e6, "timestamp": now, "id": "1"}], "node1")
        assert len(results) >= 1
        assert results[0].correlation_type == "unmatched_sdr"

    def test_freq_tolerances_defined(self):
        """CrossCorrelator defines frequency tolerances for source pairs."""
        from sigrift.bridge.correlation_engine import CrossCorrelator
        assert ("bt", "sdr") in CrossCorrelator.FREQ_TOLERANCE
        assert ("aircraft", "sdr") in CrossCorrelator.FREQ_TOLERANCE

    def test_wifi_channel_freq_map(self):
        """WiFi channel frequency map includes 2.4 and 5 GHz channels."""
        from sigrift.bridge.correlation_engine import WIFI_CHANNEL_FREQ
        assert WIFI_CHANNEL_FREQ[1] == 2412  # 2.4 GHz channel 1
        assert WIFI_CHANNEL_FREQ[36] == 5180  # 5 GHz channel 36
        assert WIFI_CHANNEL_FREQ[165] == 5825


class TestMigrations:
    """Verify database migrations are correctly numbered."""

    def test_migration_48_cross_correlations(self):
        """Migration 48 creates cross_correlations table."""
        from sigrift.bridge.storage import base
        source = open(base.__file__).read()
        assert "cross_correlations" in source

    def test_migration_49_aircraft_tracks(self):
        """Migration 49 creates aircraft_tracks table."""
        from sigrift.bridge.storage import base
        source = open(base.__file__).read()
        assert "aircraft_tracks" in source

    def test_max_migration_is_56(self):
        """RF stream protection is the next unique migration after legacy55."""
        from sigrift.bridge.storage.base import _MIGRATIONS
        versions = [v for v, _d, _s in _MIGRATIONS]
        assert max(versions) == 56
        assert len(versions) == len(set(versions))
        assert _MIGRATIONS[-1][0] == 56


class TestNewStores:
    """Verify new storage modules work."""

    def test_aircraft_store_importable(self):
        from sigrift.bridge.storage.aircraft import AircraftStore
        assert AircraftStore is not None

    def test_aircraft_store_crud(self):
        """AircraftStore insert and query."""
        from sigrift.bridge.storage.aircraft import AircraftStore
        import threading

        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute("""CREATE TABLE aircraft_tracks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            icao_address TEXT NOT NULL, callsign TEXT, source TEXT NOT NULL,
            lat REAL, lon REAL, altitude_ft REAL, velocity_kts REAL,
            heading_deg REAL, squawk TEXT, rssi_dbm REAL,
            node_id TEXT NOT NULL, timestamp TEXT NOT NULL,
            tenant_id TEXT NOT NULL DEFAULT 'default')""")

        from contextlib import contextmanager

        from sigrift.bridge.storage.base import sqlite_transaction

        ctx = MagicMock()
        ctx.get_conn.return_value = conn
        ctx.write_lock = threading.Lock()
        ctx.tenant_id = "default"

        # Stores write through SharedContext.write_transaction(); give the
        # mock the real semantics (write lock + commit/rollback on conn).
        @contextmanager
        def _write_transaction():
            with ctx.write_lock, sqlite_transaction(conn):
                yield conn

        ctx.write_transaction = _write_transaction
        store = AircraftStore(ctx)

        row_id = store.insert_position({
            "icao_address": "ABC123",
            "source": "adsb",
            "lat": 40.0, "lon": -74.0,
            "altitude_ft": 35000,
            "node_id": "sdr1",
        })
        assert row_id > 0

        active = store.get_active_aircraft()
        assert len(active) >= 1
        assert active[0]["icao_address"] == "ABC123"


class TestDSPDecoders:
    """Verify DSP decoders are importable and functional."""

    def test_adsb_decoder_importable(self):
        from sigrift.lib.dsp.adsb_decoder import decode_adsb, demodulate_ppm
        assert decode_adsb is not None
        assert demodulate_ppm is not None

    def test_uat_decoder_importable(self):
        from sigrift.lib.dsp.uat_decoder import decode_uat_message, demodulate_uat
        assert decode_uat_message is not None
        assert demodulate_uat is not None

    def test_lora_demodulator_importable(self):
        from sigrift.lib.dsp.lora_demodulator import dechirp, classify_protocol
        assert dechirp is not None
        assert classify_protocol is not None

    def test_lora_classify_protocol_meshtastic(self):
        from sigrift.lib.dsp.lora_demodulator import classify_protocol
        assert classify_protocol(0x12) == "meshtastic"

    def test_lora_classify_protocol_lorawan(self):
        from sigrift.lib.dsp.lora_demodulator import classify_protocol
        assert classify_protocol(0x34) == "lorawan"

    def test_lora_classify_protocol_generic(self):
        from sigrift.lib.dsp.lora_demodulator import classify_protocol
        assert classify_protocol(0xFF) == "generic"


class TestClassificationRefiner:
    """Verify new refinement rules."""

    def test_lora_ism_refinement(self):
        from sigrift.bridge.classification_refiner import refine_classification
        result = refine_classification("lora-css", 868e6)
        assert result == "LoRa ISM"

    def test_p25_vhf_refinement(self):
        from sigrift.bridge.classification_refiner import refine_classification
        result = refine_classification("p25", 155e6)
        assert result == "P25 VHF"

    def test_p25_uhf_refinement(self):
        from sigrift.bridge.classification_refiner import refine_classification
        result = refine_classification("p25", 450e6)
        assert result == "P25 UHF"

    def test_p25_800mhz_refinement(self):
        from sigrift.bridge.classification_refiner import refine_classification
        result = refine_classification("p25", 850e6)
        assert result == "P25 800MHz"

    def test_adsb_refinement(self):
        from sigrift.bridge.classification_refiner import refine_classification
        result = refine_classification("adsb", 1090e6)
        assert result == "ADS-B 1090MHz"

    def test_gps_jammer_refinement(self):
        from sigrift.bridge.classification_refiner import refine_classification
        result = refine_classification("gps-jammer", 1575.42e6)
        assert result == "GPS L1 Interference"

    def test_dect_refinement(self):
        from sigrift.bridge.classification_refiner import refine_classification
        result = refine_classification("dect", 1890e6)
        assert result == "DECT 1.9GHz"

    def test_scada_vhf_refinement(self):
        from sigrift.bridge.classification_refiner import refine_classification
        result = refine_classification("scada-fsk", 160e6)
        assert result == "SCADA VHF"

    def test_wireless_mic_refinement(self):
        from sigrift.bridge.classification_refiner import refine_classification
        result = refine_classification("wireless-mic", 600e6)
        assert result == "Wireless Mic UHF"

    def test_no_refinement_passthrough(self):
        from sigrift.bridge.classification_refiner import refine_classification
        result = refine_classification("noise", 100e6)
        assert result == "noise"

    def test_none_freq_passthrough(self):
        from sigrift.bridge.classification_refiner import refine_classification
        result = refine_classification("p25", None)
        assert result == "p25"

    def test_zero_freq_passthrough(self):
        from sigrift.bridge.classification_refiner import refine_classification
        result = refine_classification("adsb", 0)
        assert result == "adsb"


class TestSignalGenerators:
    """Spot-check that new generators produce valid output."""

    @pytest.mark.parametrize("cls", [
        "adsb", "dect", "p25", "dmr", "nbiot", "sigfox", "iridium",
    ])
    def test_generator_valid_output(self, cls):
        import numpy as np
        from sigrift.lib.training.signal_factory import generate_signal
        sig = generate_signal(cls, n_samples=2048, sample_rate=2.048e6, snr_db=20.0)
        assert sig is not None
        assert np.all(np.isfinite(sig))
        assert len(sig) == 2048

    @pytest.mark.parametrize("cls", [
        "uat", "tetra", "pocsag", "ais", "zwave", "halow", "fpv-analog",
    ])
    def test_additional_generators(self, cls):
        import numpy as np
        from sigrift.lib.training.signal_factory import generate_signal
        sig = generate_signal(cls, n_samples=2048, sample_rate=2.048e6, snr_db=20.0)
        assert sig is not None
        assert np.all(np.isfinite(sig))
        assert len(sig) == 2048

    def test_generator_produces_complex_output(self):
        import numpy as np
        from sigrift.lib.training.signal_factory import generate_signal
        sig = generate_signal("adsb", n_samples=1024, snr_db=20.0)
        assert np.iscomplexobj(sig)


class TestClassMapNormalization:
    """Verify class normalization works correctly."""

    def test_normalize_ofdm_variants(self):
        from sigrift.bridge.class_map import normalize_class
        for variant in ["ofdm-64", "ofdm-128", "ofdm-256", "ofdm-512", "ofdm-1024", "ofdm-2048"]:
            assert normalize_class(variant) == "ofdm"

    def test_normalize_lora_protocols(self):
        from sigrift.bridge.class_map import normalize_class
        assert normalize_class("lora-meshtastic") == "lora-css"
        assert normalize_class("lora-meshcore") == "lora-css"
        assert normalize_class("lora-lorawan") == "lora-css"

    def test_normalize_identity_for_canonical(self):
        from sigrift.bridge.class_map import normalize_class
        assert normalize_class("adsb") == "adsb"
        assert normalize_class("p25") == "p25"
        assert normalize_class("noise") == "noise"

    def test_normalize_dji_ofdm(self):
        from sigrift.bridge.class_map import normalize_class
        assert normalize_class("dji-ofdm") == "ofdm"

    def test_normalize_family(self):
        from sigrift.bridge.class_map import normalize_family
        assert normalize_family("adsb") == "PULSED"
        assert normalize_family("p25") == "TRUNKED"
        assert normalize_family("iridium") == "SATELLITE"
        assert normalize_family("gps-jammer") == "INTERFERENCE"
        assert normalize_family("lora-meshtastic") == "SPREAD_SPECTRUM"

    def test_unknown_class_family(self):
        from sigrift.bridge.class_map import normalize_family
        assert normalize_family("totally-unknown") == "UNKNOWN"
