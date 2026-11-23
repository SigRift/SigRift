"""Anomaly detection package for The Bridge.

Exports the core components for multi-tier anomaly detection:
- Tier 1: BaselineManager + AnomalyScorer (statistical baselines)
- Tier 2: IsolationForestDetector (edge-side ML)
- Tier 3: AnomalyAutoencoder (central-server ML)
- CompositeScorer: combines all tiers
- SignalWhitelist: known-signal false-positive reduction
- WiFi: WifiBaselineManager + WifiAnomalyScorer
- Bluetooth: BtBaselineManager + BtAnomalyScorer
"""

from sigrift.bridge.anomaly.autoencoder import AnomalyAutoencoder, HAS_TORCH
from sigrift.bridge.anomaly.baseline import BaselineManager, FrequencyBaseline
from sigrift.bridge.anomaly.isolation_forest import HAS_SKLEARN, IsolationForestDetector
from sigrift.bridge.anomaly.scorer import (
    AnomalyDimension,
    AnomalyResult,
    AnomalyScorer,
    CompositeScorer,
    ScorerConfig,
)
from sigrift.bridge.anomaly.correlator import (
    CorrelationGroup,
    CorrelationResult,
    NodeCorrelator,
)
from sigrift.bridge.anomaly.emitter import Emitter, EmitterAssociator
from sigrift.bridge.anomaly.fhss import FHSSDetector, FHSSEvent
from sigrift.bridge.anomaly.whitelist import SignalWhitelist, WhitelistEntry
from sigrift.bridge.anomaly.bt_scorer import (
    BtAnomalyResult,
    BtAnomalyScorer,
    BtBaseline,
    BtBaselineManager,
)
from sigrift.bridge.anomaly.wifi_scorer import (
    WifiAnomalyResult,
    WifiAnomalyScorer,
    WifiBaseline,
    WifiBaselineManager,
)

__all__ = [
    "AnomalyAutoencoder",
    "BtAnomalyResult",
    "BtAnomalyScorer",
    "BtBaseline",
    "BtBaselineManager",
    "AnomalyDimension",
    "AnomalyResult",
    "AnomalyScorer",
    "BaselineManager",
    "CompositeScorer",
    "CorrelationGroup",
    "CorrelationResult",
    "Emitter",
    "EmitterAssociator",
    "FHSSDetector",
    "FHSSEvent",
    "FrequencyBaseline",
    "HAS_SKLEARN",
    "HAS_TORCH",
    "IsolationForestDetector",
    "NodeCorrelator",
    "ScorerConfig",
    "SignalWhitelist",
    "WhitelistEntry",
    "WifiAnomalyResult",
    "WifiAnomalyScorer",
    "WifiBaseline",
    "WifiBaselineManager",
]
