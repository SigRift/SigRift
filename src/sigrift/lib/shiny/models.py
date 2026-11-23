"""Pydantic request/response models for the Shiny dashboard.

All models use Pydantic v2 patterns (``model_config`` instead of inner
``Config`` class).  Timestamps are always UTC-aware.  Node and key IDs
are validated against a strict regex to prevent injection.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

# Matched with ``fullmatch``: with ``match`` and a ``$`` anchor a trailing
# newline passed ("edge-01\n" was accepted next to "edge-01"), which the
# gateway's ``validate_node_id`` refuses.
_ID_PATTERN = re.compile(r"[a-zA-Z0-9_-]{1,64}")
_JOB_NAME_PATTERN = re.compile(r"[a-zA-Z0-9_-]{1,128}")


def _utcnow() -> datetime:
    """Return the current UTC-aware datetime."""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class NodeStatus(str, Enum):
    """Possible node states."""

    active = "active"
    stale = "stale"
    offline = "offline"
    unknown = "unknown"


class CommandStatus(str, Enum):
    """Status of a queued command."""

    queued = "queued"
    sent = "sent"
    completed = "completed"
    failed = "failed"


class JobState(str, Enum):
    """Job lifecycle states."""

    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class AlertSeverity(str, Enum):
    """Alert severity levels."""

    info = "info"
    warning = "warning"
    critical = "critical"


class ScheduleInterval(str, Enum):
    """Allowed schedule intervals."""

    hourly = "hourly"
    daily = "daily"
    weekly = "weekly"


class ExportFormat(str, Enum):
    """Report export formats."""

    json = "json"
    csv = "csv"
    html = "html"


# ---------------------------------------------------------------------------
# Validators (reusable)
# ---------------------------------------------------------------------------


def _validate_id(v: str, label: str = "ID") -> str:
    if not _ID_PATTERN.fullmatch(v):
        raise ValueError(f"{label} must match [a-zA-Z0-9_-]{{1,64}}, got {v!r}")
    return v


# ---------------------------------------------------------------------------
# Node models
# ---------------------------------------------------------------------------


class NodeRegistration(BaseModel):
    """Request to register a new node."""

    model_config = {"extra": "forbid"}

    node_id: str
    host: str = ""
    port: int = 0
    capabilities: dict[str, Any] = Field(default_factory=dict)

    @field_validator("node_id")
    @classmethod
    def _check_node_id(cls, v: str) -> str:
        return _validate_id(v, "node_id")


class NodeMetrics(BaseModel):
    """Metrics payload reported by a node heartbeat.

    Extra fields are accepted so older agents keep working, but a heartbeat
    stores only the metrics listed in ``sigrift.lib.shiny.node_metrics``,
    each only with a valid value; every other name is ignored.
    """

    model_config = {"extra": "allow"}

    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    classifications_per_sec: float = 0.0
    current_frequency_hz: float = 0.0
    status: NodeStatus = NodeStatus.active


class NodeResponse(BaseModel):
    """Public representation of a registered node."""

    node_id: str
    host: str = ""
    port: int = 0
    status: NodeStatus = NodeStatus.unknown
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    classifications_per_sec: float = 0.0
    current_frequency_hz: float = 0.0
    capabilities: dict[str, Any] = Field(default_factory=dict)
    last_seen: datetime | None = None
    registered_at: datetime | None = None


# ---------------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------------


class HeartbeatRequest(BaseModel):
    """Heartbeat from a node."""

    model_config = {"extra": "forbid"}

    node_id: str
    metrics: NodeMetrics = Field(default_factory=NodeMetrics)

    @field_validator("node_id")
    @classmethod
    def _check_node_id(cls, v: str) -> str:
        return _validate_id(v, "node_id")


class HeartbeatResponse(BaseModel):
    """Acknowledgement of a heartbeat."""

    accepted: bool
    node_id: str
    server_time: datetime = Field(default_factory=_utcnow)
    pending_commands: list[dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

# Commands that may be issued to nodes.  Every name here must have a handler
# in the edge agent (``sigrift.edge.node_agent._dispatch_command``): the agent
# drops any other name with only an INFO log, while the bridge has already
# reported it queued and then dispatched.  ``capture_start`` and
# ``capture_stop`` were listed without ever having a handler.  ``iq_capture``
# has one but is left out on purpose: it is queued through
# ``POST /api/nodes/{id}/capture``, which range-checks its parameters.
ALLOWED_COMMANDS = frozenset(
    {
        "restart",
        "update",
        "update_config",
        "status",
        "ping",
    }
)


class CommandRequest(BaseModel):
    """Request to issue a command to a node."""

    model_config = {"extra": "forbid"}

    command: str
    params: dict[str, Any] = Field(default_factory=dict)

    @field_validator("command")
    @classmethod
    def _check_command(cls, v: str) -> str:
        if v not in ALLOWED_COMMANDS:
            raise ValueError(
                f"Command {v!r} not in allowlist: {sorted(ALLOWED_COMMANDS)}"
            )
        return v


class CommandResponse(BaseModel):
    """Response after queuing a command."""

    command_id: str
    node_id: str
    command: str
    status: CommandStatus = CommandStatus.queued
    queued_at: datetime = Field(default_factory=_utcnow)


# ---------------------------------------------------------------------------
# Spectrum
# ---------------------------------------------------------------------------


class SpectrumConnectRequest(BaseModel):
    """Request to connect to an rtl_tcp source."""

    model_config = {"extra": "forbid"}

    host: str = "127.0.0.1"
    port: int = 1234
    center_freq_hz: float = 433_920_000.0
    sample_rate_hz: float = 2_048_000.0
    gain_db: float = 40.0


class SpectrumParams(BaseModel):
    """Current spectrum capture parameters."""

    center_freq_hz: float
    sample_rate_hz: float
    gain_db: float
    fft_size: int = 1024


class SpectrumStatus(BaseModel):
    """Status of the spectrum streamer."""

    connected: bool = False
    host: str = ""
    port: int = 0
    params: SpectrumParams | None = None
    connected_since: datetime | None = None
    frames_sent: int = 0


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------


class EpochData(BaseModel):
    """Metrics for a single training epoch."""

    epoch: int
    learning_rate: float = 0.0
    # Hierarchical losses
    loss_total: float = 0.0
    loss_cls: float = 0.0
    loss_mt: float = 0.0
    loss_fam: float = 0.0
    loss_sf: float = 0.0
    loss_cons: float = 0.0
    # Per-level accuracy
    acc_cls: float = 0.0
    acc_mt: float = 0.0
    acc_fam: float = 0.0
    acc_sf: float = 0.0
    # Validation
    val_loss: float | None = None
    val_acc_cls: float | None = None
    val_acc_mt: float | None = None
    val_acc_fam: float | None = None
    val_acc_sf: float | None = None
    # KD metrics (optional)
    kd_alpha: float | None = None
    kd_temperature: float | None = None
    kl_cls: float | None = None
    kl_mt: float | None = None
    kl_fam: float | None = None
    kl_sf: float | None = None


class TrainingStatus(BaseModel):
    """Current training run status."""

    run_id: str = ""
    running: bool = False
    current_epoch: int = 0
    total_epochs: int = 0
    best_epoch: int = 0
    best_val_acc: float = 0.0
    started_at: datetime | None = None
    latest_epoch: EpochData | None = None
    # Edge model info
    edge_param_count: int | None = None
    edge_compression_ratio: float | None = None


class TrainingHistory(BaseModel):
    """Summary of a completed training run."""

    run_id: str
    started_at: datetime
    finished_at: datetime | None = None
    total_epochs: int = 0
    best_epoch: int = 0
    best_val_acc: float = 0.0
    final_acc_cls: float = 0.0
    final_acc_mt: float = 0.0
    final_acc_fam: float = 0.0
    final_acc_sf: float = 0.0
    config_snapshot: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Signals
# ---------------------------------------------------------------------------


class SignalClass(BaseModel):
    """Description of a signal class in the taxonomy."""

    name: str
    mod_type: str = ""
    family: str = ""
    super_family: str = ""


class SignalSample(BaseModel):
    """Generated signal sample metadata."""

    signal_class: str
    snr_db: float
    num_samples: int
    sample_rate_hz: float = 2_048_000.0


class WaveformData(BaseModel):
    """Waveform data returned by the signal generator."""

    signal_class: str
    snr_db: float
    iq_real: list[float] = Field(default_factory=list)
    iq_imag: list[float] = Field(default_factory=list)
    constellation_x: list[float] = Field(default_factory=list)
    constellation_y: list[float] = Field(default_factory=list)
    psd_db: list[float] = Field(default_factory=list)
    psd_freq_hz: list[float] = Field(default_factory=list)
    dsp_features: list[float] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


class AlertThresholds(BaseModel):
    """Configurable thresholds that trigger alerts."""

    model_config = {"extra": "forbid"}

    cpu_percent: float = Field(default=90.0, ge=0.0, le=100.0)
    memory_mb: float = Field(default=4096.0, ge=0.0)
    disk_percent: float = Field(default=90.0, ge=0.0, le=100.0)
    gpu_percent: float = Field(default=95.0, ge=0.0, le=100.0)
    classification_rate_min: float = Field(default=0.0, ge=0.0)
    stale_timeout_s: float = Field(default=120.0, ge=0.0)


class AlertCreate(BaseModel):
    """Request to create an alert rule."""

    model_config = {"extra": "forbid"}

    name: str
    severity: AlertSeverity = AlertSeverity.warning
    thresholds: AlertThresholds = Field(default_factory=AlertThresholds)
    node_id: str | None = None

    @field_validator("name")
    @classmethod
    def _check_name(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 128:
            raise ValueError("Alert name must be 1-128 characters")
        return v


class AlertResponse(BaseModel):
    """Public representation of an alert event."""

    alert_id: str
    name: str = ""
    severity: AlertSeverity = AlertSeverity.warning
    message: str = ""
    node_id: str | None = None
    triggered_at: datetime = Field(default_factory=_utcnow)
    acknowledged: bool = False
    acknowledged_at: datetime | None = None
    acknowledged_by: str | None = None
    ack_note: str | None = None
    escalated: bool = False


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------


class HyperparameterPreset(BaseModel):
    """Named hyperparameter preset for training jobs."""

    name: str
    epochs: int = 200
    batch_size: int = 256
    learning_rate: float = 1e-3
    weight_decay: float = 1e-4
    gamma: float = 1.5
    label_smoothing: float = 0.1
    early_stopping_patience: int = 30


class JobCreate(BaseModel):
    """Request to create a training job."""

    model_config = {"extra": "forbid"}

    name: str
    preset: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)
    priority: int = Field(default=0, ge=0, le=100)

    @field_validator("name")
    @classmethod
    def _check_name(cls, v: str) -> str:
        if not _JOB_NAME_PATTERN.fullmatch(v):
            raise ValueError(f"Job name must match [a-zA-Z0-9_-]{{1,128}}, got {v!r}")
        return v


class JobStatus(BaseModel):
    """Status of a queued/running job."""

    job_id: str
    name: str
    state: JobState = JobState.queued
    priority: int = 0
    params: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=_utcnow)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    result: dict[str, Any] | None = None
    error: str | None = None


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------


# Largest ``expires_in_hours`` a create request may ask for: 10 million
# hours, about 1141 years.  An absolute ceiling that keeps
# ``now + timedelta(hours=...)`` far from datetime's year-9999 limit (the
# overflow used to be a 500), not a lifetime policy: the Shiny dashboard
# has none, and the bridge clamps every lifetime to
# BRIDGE_MAX_KEY_LIFETIME_DAYS (default 365) after this check.  It sits far
# above that cap so raising the env var never needs a model change.
MAX_KEY_EXPIRES_IN_HOURS = 10_000_000


class KeyCreate(BaseModel):
    """Request to create a new API key.

    ``expires_in_hours`` must be a finite number no larger than
    :data:`MAX_KEY_EXPIRES_IN_HOURS` (422 otherwise); omitted, zero or
    negative means the service's default lifetime.
    """

    model_config = {"extra": "forbid"}

    key_id: str
    description: str = ""
    expires_in_hours: float | None = Field(
        default=None,
        le=MAX_KEY_EXPIRES_IN_HOURS,
        allow_inf_nan=False,
        description=(
            f"Lifetime in hours: a finite number, at most "
            f"{MAX_KEY_EXPIRES_IN_HOURS}. Omitted, zero or negative means the "
            "service default (Shiny: never expires; bridge: "
            "BRIDGE_MAX_KEY_LIFETIME_DAYS, which also caps longer requests)."
        ),
    )
    node_id: str | None = None

    @field_validator("key_id")
    @classmethod
    def _check_key_id(cls, v: str) -> str:
        return _validate_id(v, "key_id")


class KeyResponse(BaseModel):
    """Public representation of a managed API key (never contains raw key)."""

    key_id: str
    description: str = ""
    created_at: datetime = Field(default_factory=_utcnow)
    expires_at: datetime | None = None
    last_used: datetime | None = None
    node_id: str | None = None
    revoked: bool = False


# The Shiny dashboard's own key models. KeyCreate/KeyResponse above are also
# the bridge's, so the role lives in these subclasses instead.


class ManagedKeyCreate(KeyCreate):
    """Shiny dashboard key creation: :class:`KeyCreate` plus role and purpose.

    ``viewer`` (default) reads the dashboard; ``analyst`` can also create
    alert rules, acknowledge alerts, create, rerun and reprioritise jobs,
    create and change schedules, queue model evaluations, and connect,
    disconnect and retune the spectrum source; ``admin`` can also register
    nodes and queue node commands.

    ``purpose`` says whether the key belongs to an edge node.  A ``node``
    key heartbeats for its node: created with ``node_id`` it is bound to
    that node, created without one it is bound to the node it first
    heartbeats for (unless another key already holds that node).  A
    ``dashboard`` key never heartbeats as a node.  The default is ``node``
    when ``node_id`` is given and ``dashboard`` otherwise.
    """

    role: Literal["viewer", "analyst", "admin"] = "viewer"
    purpose: Literal["node", "dashboard"] | None = None

    @field_validator("node_id")
    @classmethod
    def _check_node_id(cls, v: str | None) -> str | None:
        return None if v is None else _validate_id(v, "node_id")

    @model_validator(mode="after")
    def _check_purpose(self) -> ManagedKeyCreate:
        if self.purpose is None:
            self.purpose = "node" if self.node_id else "dashboard"
        elif self.purpose == "dashboard" and self.node_id:
            raise ValueError("a dashboard key cannot be bound to a node_id")
        return self


class ManagedKeyUpdate(BaseModel):
    """Change an existing key's purpose and node binding (master key only).

    Only the fields sent are changed:

    * ``node_id: "<node>"`` binds the key to that node (and makes it a
      ``node`` key unless ``purpose`` is also sent).  Several keys may be
      bound to one node this way; trust on first use never does that.
    * ``node_id: null`` unbinds it, e.g. to undo a wrong first-use claim.
    * ``purpose`` classifies a key created before key purposes existed:
      ``"dashboard"`` (never heartbeats as a node) or ``"node"`` (bound to
      the first node it heartbeats for that no other key holds).

    A ``dashboard`` key cannot be bound to a node.
    """

    model_config = {"extra": "forbid"}

    purpose: Literal["node", "dashboard"] | None = None
    node_id: str | None = None

    @field_validator("node_id")
    @classmethod
    def _check_node_id(cls, v: str | None) -> str | None:
        return None if v is None else _validate_id(v, "node_id")

    @model_validator(mode="after")
    def _check_fields(self) -> ManagedKeyUpdate:
        sent = self.model_fields_set
        if not sent:
            raise ValueError("send purpose and/or node_id")
        if "purpose" in sent and self.purpose is None:
            raise ValueError("purpose must be 'node' or 'dashboard'")
        if self.purpose == "dashboard" and self.node_id:
            raise ValueError("a dashboard key cannot be bound to a node_id")
        return self


class ManagedKeyResponse(KeyResponse):
    """:class:`KeyResponse` plus the key's role, purpose and expiry state.

    ``purpose`` is ``None`` for a key created before key purposes existed.
    ``expired`` is true when the auth layer rejects the key as expired: its
    ``expires_at`` has passed, or the stored value cannot be parsed (then
    ``expires_at`` is ``None``, which alone would read as "never expires").
    """

    role: str = "viewer"
    purpose: str | None = None
    expired: bool = False


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


class ExportReport(BaseModel):
    """Metadata for an exported report."""

    format: ExportFormat = ExportFormat.json
    record_count: int = 0
    generated_at: datetime = Field(default_factory=_utcnow)
    filters: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# System / Health
# ---------------------------------------------------------------------------


class SystemStatus(BaseModel):
    """System-wide status summary."""

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


class HealthResponse(BaseModel):
    """Response for the health-check endpoint."""

    status: str = "ok"
    version: str = "4.0.0"
    timestamp: datetime = Field(default_factory=_utcnow)
    system: SystemStatus = Field(default_factory=SystemStatus)
