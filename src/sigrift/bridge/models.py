"""Pydantic request/response models for The Bridge.

Reuses node/heartbeat/command models from sigrift.lib.shiny.models where applicable.
Adds detection-specific models for the signal intelligence pipeline.

All models use Pydantic v2 patterns (``model_config`` instead of inner
``Config`` class).  Timestamps are always UTC-aware.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from sigrift.bridge import __version__
from sigrift.bridge.release_info import current_release
from sigrift.bridge.scanner_status import ScannerProtocol, ScannerReason, ScannerState

# ---------------------------------------------------------------------------
# Re-export shared models from shiny (node management, commands, alerts)
# ---------------------------------------------------------------------------

from sigrift.lib.shiny.models import (  # noqa: F401
    AlertCreate,  # noqa: F401
    AlertResponse,  # noqa: F401
    AlertSeverity,  # noqa: F401
    AlertThresholds,  # noqa: F401
    CommandRequest,  # noqa: F401
    CommandResponse,  # noqa: F401
    CommandStatus,  # noqa: F401
    ExportFormat,  # noqa: F401
    ExportReport,  # noqa: F401
    KeyCreate,  # noqa: F401
    KeyResponse,  # noqa: F401
    NodeMetrics,  # noqa: F401
    NodeResponse,  # noqa: F401
    NodeStatus,  # noqa: F401
    _utcnow,  # noqa: F401
    _validate_id,  # noqa: F401
)  # noqa: F401


class BridgeKeyResponse(KeyResponse):
    """One row of ``GET /api/keys/``: :class:`KeyResponse` plus ``expired``.

    ``expired`` is true when bridge auth rejects the key as expired: its
    ``expires_at`` has passed, or the stored value cannot be parsed (then
    ``expires_at`` is ``None``, which alone would read as "never expires").
    It is bridge auth's verdict only: the gateway parses a hand-edited
    ``expires_at`` its own way and can disagree (see
    ``dependencies.key_expiry``).  A key refused for another reason
    (disabled, revoked) is not ``expired``.
    """

    expired: bool = False


# ---------------------------------------------------------------------------
# Extended node response with floor plan position
# ---------------------------------------------------------------------------


class ScannerStatusRequest(BaseModel):
    """A scanner reports its own capture state, without client timestamps."""

    model_config = {"extra": "forbid"}

    protocol: ScannerProtocol
    state: ScannerState
    # Optional and only meaningful for "error"; older scanners omit it.
    reason: ScannerReason | None = None

    @model_validator(mode="after")
    def _reason_only_with_error(self) -> "ScannerStatusRequest":
        if self.reason is not None and self.state != "error":
            raise ValueError("reason is only valid with state 'error'")
        return self


class ScannerStatusResponse(ScannerStatusRequest):
    reported_at: datetime
    expires_in_seconds: float
    active: bool


class BridgeNodeResponse(NodeResponse):
    """NodeResponse extended with floor plan position and detection summary."""

    position_x: float | None = None
    position_y: float | None = None
    floor_label: str = ""
    detection_summary: dict[str, Any] | None = None
    scanner_status: dict[ScannerProtocol, ScannerStatusResponse] = Field(
        default_factory=dict
    )


# ---------------------------------------------------------------------------
# Detection models
# ---------------------------------------------------------------------------

# Matched with ``fullmatch`` (as ``_validate_id`` is): with ``match`` and a
# ``$`` anchor a trailing newline passed, which the gateway's
# ``validate_signal_class`` / ``validate_backend`` refuse.
_SIGNAL_CLASS_PATTERN = re.compile(r"[a-zA-Z0-9_/.-]{1,128}")
_BACKEND_PATTERN = re.compile(r"[a-zA-Z0-9_-]{1,32}")
# The gateway's ``validate_record_id``: detection and batch ids appear in
# URL paths (``/api/detections/{id}/iq``) and in log lines.
_RECORD_ID_PATTERN = re.compile(r"[a-zA-Z0-9_.:-]{1,128}")


def _validate_record_id(v: str, field: str) -> str:
    """Accept ``[a-zA-Z0-9_.:-]{1,128}`` without ``..``, as the gateway does.

    An empty id passes, as on the gateway, which replaces it.
    """
    if v and (not _RECORD_ID_PATTERN.fullmatch(v) or ".." in v):
        raise ValueError(f"{field} must match [a-zA-Z0-9_.:-]{{1,128}} without '..'")
    return v


class DetectionRecord(BaseModel):
    """A single RF signal detection from an edge node."""

    model_config = {"extra": "ignore", "populate_by_name": True}

    detection_id: str = Field(
        default_factory=lambda: uuid.uuid4().hex[:16],
        alias="id",
    )
    node_id: str
    timestamp: datetime | float = Field(default_factory=_utcnow)
    signal_class: str
    confidence: float = Field(ge=0.0, le=1.0)
    family: str = ""
    freq_hz: float = 0.0
    snr_db: float | None = None
    power_dbm: float | None = None
    inference_ms: float | None = None
    backend: str | None = "onnx"
    anomaly_score: float = Field(default=0.0, ge=0.0, le=1.0)
    baseline_status: str = "stable"
    has_iq_capture: bool = False
    gain_db: float | None = None
    lna_state: str | None = None
    bandwidth_hz: float | None = None
    refined_class: str = ""

    # IQ-derived features (optional, computed on edge when IQ capture available).
    # These enable spectral/modulation anomaly scoring without sending raw IQ.
    iq_spectral_flatness: float | None = None  # 0.0 = tonal, 1.0 = noise-like
    iq_bandwidth_measured: float | None = None  # Measured 3dB bandwidth (Hz)
    iq_dc_offset: float | None = None  # DC offset magnitude (0.0-1.0)
    iq_iq_imbalance: float | None = None  # IQ imbalance metric (0.0-1.0)
    iq_symbol_rate: float | None = None  # Estimated symbol rate (symbols/sec)
    iq_cfo_hz: float | None = None  # Carrier frequency offset (Hz)

    @field_validator("node_id")
    @classmethod
    def _check_node_id(cls, v: str) -> str:
        return _validate_id(v, "node_id")

    @field_validator("detection_id")
    @classmethod
    def _check_detection_id(cls, v: str) -> str:
        return _validate_record_id(v, "detection_id")

    @field_validator("signal_class")
    @classmethod
    def _check_signal_class(cls, v: str) -> str:
        if not _SIGNAL_CLASS_PATTERN.fullmatch(v):
            raise ValueError(
                f"signal_class must match [a-zA-Z0-9_/.-]{{1,128}}, got {v!r}"
            )
        return v

    @field_validator("backend")
    @classmethod
    def _check_backend(cls, v: str | None) -> str | None:
        if v is not None and not _BACKEND_PATTERN.fullmatch(v):
            raise ValueError(f"backend must match [a-zA-Z0-9_-]{{1,32}}, got {v!r}")
        return v

    @field_validator("baseline_status")
    @classmethod
    def _check_baseline_status(cls, v: str) -> str:
        allowed = {"learning", "stable", "unknown"}
        if v not in allowed:
            raise ValueError(f"baseline_status must be one of {allowed}, got {v!r}")
        return v


class DetectionSummary(BaseModel):
    """Aggregated summary of detections over a reporting period.

    Piggybacks on heartbeat requests to provide lightweight
    detection statistics without full batch data.
    """

    model_config = {"extra": "ignore"}

    period_seconds: float = Field(default=0.0, ge=0.0)
    total_frames: int = Field(default=0, ge=0)
    total_detections: int = Field(default=0, ge=0)
    class_counts: dict[str, int] = Field(default_factory=dict)
    avg_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    dominant_class: str = ""
    dominant_family: str = ""


class DetectionBatch(BaseModel):
    """Batch upload of detections from an edge node."""

    model_config = {"extra": "ignore"}

    node_id: str
    batch_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:16])
    period_start: datetime | float
    period_end: datetime | float
    detections: list[DetectionRecord] = Field(default_factory=list)
    summary: DetectionSummary | None = None

    @field_validator("node_id")
    @classmethod
    def _check_node_id(cls, v: str) -> str:
        return _validate_id(v, "node_id")

    @field_validator("batch_id")
    @classmethod
    def _check_batch_id(cls, v: str) -> str:
        return _validate_record_id(v, "batch_id")


class DetectionHourlySummary(BaseModel):
    """Single row in an edge-pre-aggregated hourly detection summary."""

    model_config = {"extra": "ignore"}

    hour: str
    signal_class: str
    family: str = ""
    freq_bin_hz: float = 0.0
    detection_count: int = 0
    avg_confidence: float = 0.0
    min_confidence: float = 0.0
    max_confidence: float = 0.0
    avg_snr_db: float | None = None
    avg_power_dbm: float | None = None
    avg_anomaly: float = 0.0
    max_anomaly: float = 0.0


class DetectionSummaryBatch(BaseModel):
    """Batch of hourly summaries from an edge node."""

    model_config = {"extra": "ignore"}

    node_id: str
    summaries: list[DetectionHourlySummary] = Field(default_factory=list)
    high_anomaly_detections: list[DetectionRecord] = Field(default_factory=list)

    @field_validator("node_id")
    @classmethod
    def _check_node_id(cls, v: str) -> str:
        return _validate_id(v, "node_id")


class DetectionQuery(BaseModel):
    """Query parameters for filtering stored detections."""

    model_config = {"extra": "forbid"}

    start: datetime | None = None
    end: datetime | None = None
    node_id: str | None = None
    signal_class: str | None = None
    family: str | None = None
    min_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    limit: int = Field(default=100, ge=1, le=10000)
    offset: int = Field(default=0, ge=0)


class DetectionStats(BaseModel):
    """Aggregated detection statistics over a time range."""

    total_detections: int = 0
    unique_classes: int = 0
    unique_nodes: int = 0
    avg_confidence: float = 0.0
    class_distribution: dict[str, int] = Field(default_factory=dict)
    family_distribution: dict[str, int] = Field(default_factory=dict)
    detections_per_second: float = 0.0
    active_frequencies: int = Field(
        default=0,
        ge=0,
        description="Distinct positive 100 kHz frequency bins in raw detections over the last hour, independent of the selected statistics window.",
    )


# ---------------------------------------------------------------------------
# Extended heartbeat (backwards compatible)
# ---------------------------------------------------------------------------


class BridgeHeartbeatRequest(BaseModel):
    """Heartbeat from a node, extended with optional detection summary.

    Backwards-compatible with the base HeartbeatRequest — the
    detection_summary field is optional and defaults to None.
    """

    model_config = {"extra": "forbid"}

    node_id: str
    metrics: NodeMetrics = Field(default_factory=NodeMetrics)
    detection_summary: DetectionSummary | None = None

    @field_validator("node_id")
    @classmethod
    def _check_node_id(cls, v: str) -> str:
        return _validate_id(v, "node_id")


class BridgeHeartbeatResponse(BaseModel):
    """Acknowledgement of a heartbeat."""

    accepted: bool
    node_id: str
    server_time: datetime = Field(default_factory=_utcnow)
    pending_commands: list[dict[str, Any]] = Field(default_factory=list)
    config_hash: str = ""


# ---------------------------------------------------------------------------
# System / Health (extended)
# ---------------------------------------------------------------------------


class TenantUsage(BaseModel):
    """Per-tenant row usage summary."""

    tables: dict[str, int] = Field(default_factory=dict)
    total_rows: int = 0
    row_limit: int = 0
    usage_pct: float = 0.0


class BridgeSystemStatus(BaseModel):
    """System-wide status summary including detection metrics."""

    node_count: int = 0
    active_nodes: int = 0
    stale_nodes: int = 0
    offline_nodes: int = 0
    alert_count: int = 0
    pending_jobs: int = 0
    running_jobs: int = 0
    spectrum_connected: bool = False
    training_running: bool = False
    uptime_seconds: float = 0.0
    total_detections_24h: int = 0
    detections_per_second: float = 0.0
    active_anomalies: int = 0
    unacked_alerts: int = 0
    active_frequencies: int = 0
    active_frequency_list: list = []
    tenant_usage: TenantUsage | None = None
    # PR-6: dashboard onboarding banner uses this to distinguish
    # "no scanners present" (show full installer one-liner) from
    # "in-stack scanner key registered but no heartbeat yet" (show
    # waiting message). True iff the bridge pre-registered a key
    # via BRIDGE_LOCAL_NODE_KEY at startup. Defaults to False so
    # older clients see no behavior change.
    local_scanner_key_registered: bool = False


class BridgeHealthResponse(BaseModel):
    """Response for the health-check endpoint."""

    status: str = "ok"
    version: str = __version__
    #: The image's release tag, ``main-<sha12>`` or ``dev`` (release_info).
    release: str = Field(default_factory=current_release)
    #: Whether imported protocol decryption keys are saved
    #: (storage/crypto_keys.Persistence); "unknown" without a vault.
    crypto_key_persistence: str = "unknown"
    timestamp: datetime = Field(default_factory=_utcnow)
    system: BridgeSystemStatus = Field(default_factory=BridgeSystemStatus)
    security_warnings: list[str] = Field(default_factory=list)
    disk_usage_pct: float | None = None
    raw_ingest_nodes: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# WiFi SIGINT models
# ---------------------------------------------------------------------------


class WifiMetadataRecord(BaseModel):
    """Single WiFi observation from an edge node."""

    model_config = {"extra": "ignore"}

    bssid: str = ""
    ssid: str = ""
    channel: int = Field(default=0, ge=0, le=233)
    channel_width: int = Field(default=20, ge=20, le=160)
    band: str = "2.4GHz"
    security: str = ""
    signal_dbm: float = 0.0
    noise_dbm: float = 0.0
    frame_type: str = ""
    client_mac: str = ""
    data_rate_mbps: float = 0.0
    retry_flag: int = Field(default=0, ge=0, le=1)
    vendor: str = ""
    client_vendor: str = ""

    @field_validator("band")
    @classmethod
    def _check_band(cls, v: str) -> str:
        allowed = {"2.4GHz", "5GHz", "6GHz", "unknown"}
        if v not in allowed:
            raise ValueError(f"band must be one of {allowed}, got {v!r}")
        return v


class WifiMetadataBatch(BaseModel):
    """Batch upload of WiFi metadata from an edge node."""

    model_config = {"extra": "ignore"}

    node_id: str
    records: list[WifiMetadataRecord] = Field(default_factory=list)

    @field_validator("node_id")
    @classmethod
    def _check_node_id(cls, v: str) -> str:
        return _validate_id(v, "node_id")


class WifiNetworkSummary(BaseModel):
    """Aggregated WiFi network info for API response."""

    bssid: str = ""
    ssid: str = ""
    channel: int = 0
    channel_width: int = 20
    band: str = "2.4GHz"
    security: str = ""
    avg_signal_dbm: float = 0.0
    client_count: int = 0
    frame_count: int = 0
    last_seen: str = ""
    node_ids: list[str] = Field(default_factory=list)
    vendor: str = ""


class WifiChannelStats(BaseModel):
    """Per-channel statistics for heatmap."""

    channel: int = 0
    band: str = "2.4GHz"
    frame_count: int = 0
    avg_signal_dbm: float = 0.0
    network_count: int = 0
    utilization_pct: float = 0.0


class WifiSummaryNetwork(BaseModel):
    """Single network entry in a WiFi summary from an edge node."""

    model_config = {"extra": "ignore"}

    bssid: str = ""
    ssid: str = ""
    channel: int | None = None
    channel_width: int | None = None
    band: str = ""
    security: str = ""
    signal_max_dbm: float = -100.0
    signal_avg_dbm: float = -100.0
    frame_count: int = 0
    client_count: int = 0
    first_seen: str = ""
    last_seen: str = ""


class WifiSummaryBatch(BaseModel):
    """Edge-aggregated WiFi summary replacing per-frame raw uploads."""

    model_config = {"extra": "ignore"}

    node_id: str
    scan_period_s: float = 30.0
    total_frames: int = 0
    networks: list[WifiSummaryNetwork] = Field(default_factory=list)
    channel_utilization: dict[str, float] = Field(default_factory=dict)
    deauth_count: int = 0
    probe_request_count: int = 0

    @field_validator("node_id")
    @classmethod
    def _check_node_id(cls, v: str) -> str:
        return _validate_id(v, "node_id")


class BtSummaryDevice(BaseModel):
    """Single device entry in a BT summary from an edge node.

    Mirrors WifiSummaryNetwork — one aggregate row per unique
    device_addr per scan window, replacing N raw observation rows.
    """

    model_config = {"extra": "ignore"}

    device_addr: str = ""
    device_name: str = ""
    device_type: str = "unknown"  # classic, ble, dual, unknown
    manufacturer_id: int | None = None
    manufacturer: str = ""
    rssi_max_dbm: float = -100.0
    rssi_avg_dbm: float = -100.0
    observation_count: int = 0
    channel: int = 0
    service_uuids: list[str] = Field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""


class BtSummaryBatch(BaseModel):
    """Edge-aggregated BT summary replacing per-observation raw uploads."""

    model_config = {"extra": "ignore"}

    node_id: str
    scan_period_s: float = 30.0
    total_observations: int = 0
    devices: list[BtSummaryDevice] = Field(default_factory=list)

    @field_validator("node_id")
    @classmethod
    def _check_node_id(cls, v: str) -> str:
        return _validate_id(v, "node_id")


# ---------------------------------------------------------------------------
# Geolocation models
# ---------------------------------------------------------------------------


class NodeLocation(BaseModel):
    """Geographic location of an edge node."""

    latitude: float = Field(ge=-90.0, le=90.0)
    longitude: float = Field(ge=-180.0, le=180.0)
    altitude_m: float | None = None
    location_name: str = Field(default="", max_length=256)


class IQCaptureRequest(BaseModel):
    """Request body for triggering a manual IQ capture on an edge node."""

    model_config = {"extra": "forbid"}

    freq_hz: float = Field(gt=0, description="Center frequency in Hz")
    duration_ms: int = Field(
        default=1000, ge=10, le=30000, description="Capture duration in milliseconds"
    )
    sample_rate: float = Field(
        default=2.4e6, gt=0, le=20e6, description="Sample rate in Hz"
    )
    # Default None means "use the node's configured scan gain": sending a
    # fixed 40 dB drove HackRF captures to LNA 40 / VGA 0, ~48 dB below the
    # scan gain (MLRF_HACKRF 40/48). The ceiling is HackRF's LNA+VGA reach
    # (102 dB); each device clamps a request to its own range.
    gain_db: float | None = Field(
        default=None,
        ge=0,
        le=102,
        description="Receiver gain in dB (default: node scan gain)",
    )
    # What the capture is of.  The node uploads a manual capture under a
    # new id, so its stub detection would otherwise be of class
    # "iq_capture", which is never protocol-decoded: with a decodable class
    # (DMR, P25, LoRa / Meshtastic) the capture is queued for decoding.
    signal_class: str | None = Field(
        default=None,
        pattern=r"^[a-zA-Z0-9_/.-]{1,128}$",
        description="Signal class of the captured channel (e.g. dmr, p25, lora-css)",
    )
    detection_id: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z0-9_-]{1,128}$",
        description="Detection this capture is of (its signal class is used)",
    )


class NodeLocationUpdate(BaseModel):
    """Request body for updating a node's geographic location."""

    model_config = {"extra": "forbid"}

    latitude: float = Field(ge=-90.0, le=90.0)
    longitude: float = Field(ge=-180.0, le=180.0)
    altitude_m: float | None = None
    location_name: str = Field(default="", max_length=256)


class GeoNodeSummary(BaseModel):
    """Node with location and recent detection summary for map display."""

    node_id: str
    latitude: float
    longitude: float
    altitude_m: float | None = None
    location_name: str = ""
    status: str = "unknown"
    detection_count_1h: int = 0
    top_signals: list[str] = Field(default_factory=list)
    last_heartbeat: str | None = None
    anomaly_count_1h: int = 0


class GeoHeatmapPoint(BaseModel):
    """Single point in a detection density heatmap."""

    latitude: float
    longitude: float
    weight: int = 0


class GeoCoverageArea(BaseModel):
    """Estimated coverage area for a node."""

    node_id: str
    latitude: float
    longitude: float
    radius_km: float = 1.0
    detection_classes: list[str] = Field(default_factory=list)
    avg_snr_db: float = 0.0


class GeoActivityItem(BaseModel):
    """A detection enriched with node location data."""

    detection_id: str = ""
    node_id: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    location_name: str = ""
    signal_class: str = ""
    confidence: float = 0.0
    freq_hz: float = 0.0
    snr_db: float | None = None
    power_dbm: float | None = None
    anomaly_score: float = 0.0
    timestamp: str = ""


# ---------------------------------------------------------------------------
# Alert rule condition models
# ---------------------------------------------------------------------------


class AlertCondition(BaseModel):
    """A single condition for an alert rule.

    Conditions are evaluated against detection fields using the specified
    operator.  Multiple conditions on a rule use AND logic.
    """

    model_config = {"extra": "forbid"}

    field: str  # "signal_class", "freq_hz", "snr_db", etc.
    operator: str  # "eq", "ne", "gt", "gte", "lt", "lte", "in", "not_in", "between"
    value: Any  # single value, list for "in"/"not_in", [lo, hi] for "between"

    @field_validator("field")
    @classmethod
    def _check_field(cls, v: str) -> str:
        allowed = {
            "signal_class",
            "freq_hz",
            "snr_db",
            "power_dbm",
            "anomaly_score",
            "node_id",
            "family",
            "bandwidth_hz",
            "confidence",
        }
        if v not in allowed:
            raise ValueError(f"field must be one of {sorted(allowed)}, got {v!r}")
        return v

    @field_validator("operator")
    @classmethod
    def _check_operator(cls, v: str) -> str:
        allowed = {"eq", "ne", "gt", "gte", "lt", "lte", "in", "not_in", "between"}
        if v not in allowed:
            raise ValueError(f"operator must be one of {sorted(allowed)}, got {v!r}")
        return v


class AlertRuleCreate(BaseModel):
    """Request body for creating an alert rule with conditions."""

    model_config = {"extra": "forbid"}

    name: str
    severity: str = "warning"
    conditions: list[AlertCondition] = Field(default_factory=list)
    logic: str = "AND"
    enabled: bool = True
    cooldown_seconds: int = Field(default=300, ge=0, le=86400)
    notify_webhook: bool = True

    @field_validator("name")
    @classmethod
    def _check_name(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 128:
            raise ValueError("Alert rule name must be 1-128 characters")
        return v

    @field_validator("severity")
    @classmethod
    def _check_severity(cls, v: str) -> str:
        allowed = {"info", "warning", "critical"}
        if v not in allowed:
            raise ValueError(f"severity must be one of {sorted(allowed)}, got {v!r}")
        return v

    @field_validator("logic")
    @classmethod
    def _check_logic(cls, v: str) -> str:
        v = v.upper()
        if v not in {"AND", "OR"}:
            raise ValueError(f"logic must be 'AND' or 'OR', got {v!r}")
        return v


class AlertRuleUpdate(BaseModel):
    """Request body for updating an alert rule."""

    model_config = {"extra": "forbid"}

    name: str | None = None
    severity: str | None = None
    conditions: list[AlertCondition] | None = None
    logic: str | None = None
    enabled: bool | None = None
    cooldown_seconds: int | None = Field(default=None, ge=0, le=86400)
    notify_webhook: bool | None = None

    @field_validator("severity")
    @classmethod
    def _check_severity(cls, v: str | None) -> str | None:
        if v is not None:
            allowed = {"info", "warning", "critical"}
            if v not in allowed:
                raise ValueError(
                    f"severity must be one of {sorted(allowed)}, got {v!r}"
                )
        return v

    @field_validator("logic")
    @classmethod
    def _check_logic(cls, v: str | None) -> str | None:
        if v is not None:
            v = v.upper()
            if v not in {"AND", "OR"}:
                raise ValueError(f"logic must be 'AND' or 'OR', got {v!r}")
        return v


class AlertRuleResponse(BaseModel):
    """Public representation of a condition-based alert rule."""

    rule_id: str
    name: str = ""
    severity: str = "warning"
    conditions: list[AlertCondition] = Field(default_factory=list)
    logic: str = "AND"
    enabled: bool = True
    cooldown_seconds: int = 300
    notify_webhook: bool = True
    created_at: str = ""
    last_triggered_at: str | None = None
    trigger_count: int = 0


class AlertRuleTestRequest(BaseModel):
    """Request body for dry-run testing a rule against recent detections."""

    model_config = {"extra": "forbid"}

    minutes: int = Field(default=60, ge=1, le=10080)
    limit: int = Field(default=1000, ge=1, le=10000)


# ---------------------------------------------------------------------------
# Watch band models
# ---------------------------------------------------------------------------


class WatchBandCreate(BaseModel):
    """Request body for creating a spectrum watch band."""

    model_config = {"extra": "forbid"}

    name: str = Field(..., min_length=1, max_length=128)
    freq_min_hz: float = Field(..., ge=0)
    freq_max_hz: float = Field(..., ge=0)
    trigger: str = Field(default="new_activity")
    power_threshold_dbm: float | None = Field(default=None)
    count_threshold: int | None = Field(default=None, ge=1)
    time_window_seconds: int = Field(default=300, ge=10, le=86400)
    severity: str = Field(default="warning")
    cooldown_seconds: int = Field(default=300, ge=0, le=86400)
    enabled: bool = True

    @field_validator("trigger")
    @classmethod
    def _check_trigger(cls, v: str) -> str:
        allowed = {"new_activity", "power_threshold", "count_threshold"}
        if v not in allowed:
            raise ValueError(f"trigger must be one of {sorted(allowed)}, got {v!r}")
        return v

    @field_validator("severity")
    @classmethod
    def _check_severity(cls, v: str) -> str:
        allowed = {"info", "warning", "critical"}
        if v not in allowed:
            raise ValueError(f"severity must be one of {sorted(allowed)}, got {v!r}")
        return v

    @field_validator("freq_max_hz")
    @classmethod
    def _check_freq_range(cls, v: float, info: Any) -> float:
        freq_min = info.data.get("freq_min_hz")
        if freq_min is not None and v <= freq_min:
            raise ValueError("freq_max_hz must be greater than freq_min_hz")
        return v


class WatchBandResponse(BaseModel):
    """Public representation of a spectrum watch band."""

    watch_id: str
    name: str = ""
    freq_min_hz: float = 0.0
    freq_max_hz: float = 0.0
    trigger: str = "new_activity"
    power_threshold_dbm: float | None = None
    count_threshold: int | None = None
    time_window_seconds: int = 300
    severity: str = "warning"
    cooldown_seconds: int = 300
    enabled: bool = True
    created_at: str = ""
    last_triggered_at: str | None = None
    trigger_count: int = 0


# ---------------------------------------------------------------------------
# FHSS detection models
# ---------------------------------------------------------------------------


class FHSSEventResponse(BaseModel):
    """Public representation of a detected FHSS signal event."""

    fhss_id: str
    node_id: str = ""
    timestamp: str = ""
    hop_rate_hz: float = 0.0
    hop_set: list[float] = Field(default_factory=list)
    bandwidth_hz: float = 0.0
    dwell_time_ms: float = 0.0
    duration_sec: float = 0.0
    signal_class: str = ""
    detection_count: int = 0
    confidence: float = 0.0
