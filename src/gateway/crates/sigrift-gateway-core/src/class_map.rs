//! Signal class normalization — reduce 76-class taxonomy to 57 canonical classes.

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

static SIGNAL_CLASS_MAP: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    m.insert("ofdm-64", "ofdm");
    m.insert("ofdm-128", "ofdm");
    m.insert("ofdm-256", "ofdm");
    m.insert("ofdm-512", "ofdm");
    m.insert("ofdm-1024", "ofdm");
    m.insert("ofdm-2048", "ofdm");
    m.insert("128qam", "high-order-qam");
    m.insert("256qam", "high-order-qam");
    m.insert("64apsk", "high-order-apsk");
    m.insert("128apsk", "high-order-apsk");
    m.insert("2gmsk", "gmsk");
    m.insert("4gmsk", "gmsk");
    m.insert("2gfsk", "gfsk");
    m.insert("4gfsk", "gfsk");
    m.insert("am-dsb", "am");
    m.insert("am-ssb", "am");
    // New merges (v4.15.0)
    m.insert("dji-ofdm", "ofdm");
    m.insert("elrs", "lora-css");
    m.insert("ism433", "ook");
    m.insert("analog-video-24", "fpv-analog");
    m.insert("wireless-hart", "oqpsk-dsss");
    m.insert("isa100", "oqpsk-dsss");
    m.insert("lora-meshtastic", "lora-css");
    m.insert("lora-meshcore", "lora-css");
    m.insert("lora-lorawan", "lora-css");
    m
});

static CLASS_TO_FAMILY: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    m.insert("ook", "ASK");
    m.insert("4ask", "ASK");
    m.insert("8ask", "ASK");
    m.insert("16ask", "ASK");
    m.insert("uhf-rfid", "ASK");
    m.insert("4pam", "PAM");
    m.insert("8pam", "PAM");
    m.insert("16pam", "PAM");
    m.insert("bpsk", "PSK");
    m.insert("qpsk", "PSK");
    m.insert("8psk", "PSK");
    m.insert("16psk", "PSK");
    m.insert("32psk", "PSK");
    m.insert("16qam", "QAM");
    m.insert("32qam", "QAM");
    m.insert("64qam", "QAM");
    m.insert("high-order-qam", "QAM");
    m.insert("16apsk", "APSK");
    m.insert("32apsk", "APSK");
    m.insert("high-order-apsk", "APSK");
    m.insert("2fsk", "FSK");
    m.insert("4fsk", "FSK");
    m.insert("gfsk", "FSK");
    m.insert("2msk", "FSK");
    m.insert("4msk", "FSK");
    m.insert("gmsk", "FSK");
    m.insert("dect", "FSK");
    m.insert("zwave", "FSK");
    m.insert("wisun", "FSK");
    m.insert("scada-fsk", "FSK");
    m.insert("pocsag", "FSK");
    m.insert("nrf24", "FSK");
    m.insert("ais", "FSK");
    m.insert("dstar", "FSK");
    m.insert("gsm", "FSK");
    m.insert("ofdm", "OFDM");
    m.insert("nbiot", "OFDM");
    m.insert("halow", "OFDM");
    m.insert("lora-css", "SPREAD_SPECTRUM");
    m.insert("sigfox", "SPREAD_SPECTRUM");
    m.insert("sidewalk", "SPREAD_SPECTRUM");
    m.insert("oqpsk-dsss", "802154");
    m.insert("am", "ANALOG");
    m.insert("fm", "ANALOG");
    m.insert("tone", "ANALOG");
    m.insert("fpv-analog", "ANALOG");
    m.insert("pmr446", "NARROWBAND_FM");
    m.insert("wireless-mic", "NARROWBAND_FM");
    m.insert("noise", "NOISE");
    m.insert("adsb", "PULSED");
    m.insert("uat", "PULSED");
    m.insert("tpms", "PULSED");
    m.insert("p25", "TRUNKED");
    m.insert("dmr", "TRUNKED");
    m.insert("tetra", "TRUNKED");
    m.insert("iridium", "SATELLITE");
    m.insert("gps-jammer", "INTERFERENCE");
    m
});

/// Families for the open-default model's collapsed class names, which are
/// not canonical classes (its other ten names are). Without this table they
/// came out as "UNKNOWN", which raises the anomaly score and trips the
/// default "Novel Signal Detected" alert rule. Must match
/// `OPEN_DEFAULT_CLASS_TO_FAMILY` in the bridge's `class_map.py`.
static OPEN_DEFAULT_CLASS_TO_FAMILY: LazyLock<HashMap<&'static str, &'static str>> =
    LazyLock::new(|| {
        let mut m = HashMap::new();
        m.insert("ask", "ASK");
        m.insert("psk", "PSK");
        m.insert("qam", "QAM");
        m.insert("fsk", "FSK");
        m.insert("msk", "FSK");
        m.insert("dsss", "SPREAD_SPECTRUM");
        m
    });

pub fn normalize_class(signal_class: &str) -> &str {
    SIGNAL_CLASS_MAP
        .get(signal_class)
        .copied()
        .unwrap_or(signal_class)
}

/// The baseline key every class outside [`CANONICAL_CLASSES`] shares.
pub const UNKNOWN_BASELINE_CLASS: &str = "unknown";

static CANONICAL_SET: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| CANONICAL_CLASSES.iter().copied().collect());

/// The class name the anomaly baselines track `signal_class` under: its
/// canonical class, or [`UNKNOWN_BASELINE_CLASS`] for any class outside
/// the canonical taxonomy. Sensors choose `signal_class`, so keying the
/// baselines by it directly would let one sensor key make the gateway
/// track (and save) an unbounded set of arbitrary names; this keeps the
/// set of baseline keys fixed. The detection itself keeps its class.
pub fn baseline_class(signal_class: &str) -> &'static str {
    CANONICAL_SET
        .get(normalize_class(signal_class))
        .copied()
        .unwrap_or(UNKNOWN_BASELINE_CLASS)
}

pub fn normalize_family(signal_class: &str) -> &str {
    let canonical = normalize_class(signal_class);
    CLASS_TO_FAMILY
        .get(canonical)
        .or_else(|| OPEN_DEFAULT_CLASS_TO_FAMILY.get(canonical))
        .copied()
        .unwrap_or("UNKNOWN")
}

pub const CANONICAL_CLASSES: &[&str] = &[
    // ASK (4 + 1)
    "ook",
    "4ask",
    "8ask",
    "16ask",
    // PAM (3)
    "4pam",
    "8pam",
    "16pam",
    // PSK (5)
    "bpsk",
    "qpsk",
    "8psk",
    "16psk",
    "32psk",
    // QAM (3+1 merged)
    "16qam",
    "32qam",
    "64qam",
    "high-order-qam",
    // APSK (2+1 merged)
    "16apsk",
    "32apsk",
    "high-order-apsk",
    // FSK (2 plain + 1 merged + MSK 2 plain + 1 merged + protocol variants)
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
    // OFDM (1 merged + new)
    "ofdm",
    "nbiot",
    "halow",
    // Spread spectrum (1 + new)
    "lora-css",
    "sigfox",
    "sidewalk",
    // 802154 (new)
    "oqpsk-dsss",
    // Analog (2+1 merged + new)
    "am",
    "fm",
    "tone",
    "fpv-analog",
    // Narrowband FM (new)
    "pmr446",
    "wireless-mic",
    // Noise (1)
    "noise",
    // PULSED (new)
    "adsb",
    "uat",
    "tpms",
    // TRUNKED (new)
    "p25",
    "dmr",
    "tetra",
    // SATELLITE (new)
    "iridium",
    // INTERFERENCE (new)
    "gps-jammer",
    // ASK new
    "uhf-rfid",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_class_is_canonical_or_unknown() {
        assert_eq!(baseline_class("qpsk"), "qpsk");
        assert_eq!(baseline_class("ofdm-256"), "ofdm");
        assert_eq!(baseline_class("lora-meshtastic"), "lora-css");
        assert_eq!(baseline_class("unknown"), UNKNOWN_BASELINE_CLASS);
        assert_eq!(baseline_class(&"x".repeat(128)), UNKNOWN_BASELINE_CLASS);
        assert_eq!(baseline_class("QPSK"), UNKNOWN_BASELINE_CLASS);
        assert!(!CANONICAL_CLASSES.contains(&UNKNOWN_BASELINE_CLASS));
        for class in CANONICAL_CLASSES {
            assert_eq!(baseline_class(class), *class);
        }
    }

    #[test]
    fn open_default_model_classes_have_families() {
        // The shipped model's 16 output names, in output order.
        let expected = [
            ("noise", "NOISE"),
            ("tone", "ANALOG"),
            ("am", "ANALOG"),
            ("fm", "ANALOG"),
            ("ask", "ASK"),
            ("psk", "PSK"),
            ("qam", "QAM"),
            ("fsk", "FSK"),
            ("gfsk", "FSK"),
            ("msk", "FSK"),
            ("ofdm", "OFDM"),
            ("lora-css", "SPREAD_SPECTRUM"),
            ("dsss", "SPREAD_SPECTRUM"),
            ("adsb", "PULSED"),
            ("fpv-analog", "ANALOG"),
            ("pocsag", "FSK"),
        ];
        for (class, family) in expected {
            assert_eq!(normalize_family(class), family, "{class}");
        }
        // Matching stays exact, and other names are still unknown.
        assert_eq!(normalize_family("PSK"), "UNKNOWN");
        assert_eq!(normalize_family(" psk"), "UNKNOWN");
        assert_eq!(normalize_family("not-a-class"), "UNKNOWN");
        // The collapsed names get a family but are not canonical classes.
        assert_eq!(normalize_class("psk"), "psk");
        assert_eq!(baseline_class("psk"), UNKNOWN_BASELINE_CLASS);
        assert!(!CANONICAL_CLASSES.contains(&"psk"));
    }
}
