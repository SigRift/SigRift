"""Abstract provider interfaces for SigRift plugin system.

All enterprise/pluggable features implement one of these ABCs and register
via Python entry points. Core code uses ``sigrift.engine.registry`` to
discover providers at runtime — no direct imports from enterprise packages.

Provider types:
    GeoProvider          Geolocation from signal observations (RSS, TDOA, etc.)
    AlertProvider        Push alerts to external systems (webhook, SIEM, email)
    ReportProvider       Generate formatted reports (PDF, HTML, STIX bundle)
    IngestProvider       Custom signal ingest pipelines (protocol decoders, etc.)
    FingerprintProvider  Device / PHY fingerprint extraction and match (enterprise)
    FuzzProvider         Protocol-aware frame fuzzing for decoder testing (enterprise)
    OidcProvider         OIDC / SSO authentication flows (enterprise)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Data models shared across providers
# ---------------------------------------------------------------------------


@dataclass
class SignalObservation:
    """A single signal observation from one receiver at one point in time."""

    frequency_hz: float
    timestamp_ns: int
    power_dbm: float
    node_id: str = ""
    signal_class: str = ""
    confidence: float = 0.0
    iq_samples: bytes | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class GeoEstimate:
    """Estimated geographic location of a signal source."""

    latitude: float | None = None
    longitude: float | None = None
    altitude_m: float | None = None
    confidence: float = 0.0
    error_radius_m: float | None = None
    method: str = ""  # "tdoa", "rss", "aoa", "manual", "hybrid"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class FingerprintVector:
    """A fingerprint embedding for a single device or PHY waveform.

    Produced by a :class:`FingerprintProvider`. Embedding length and
    semantics depend on the provider; callers treat the vector as opaque
    and only use it for similarity comparison via the same provider.
    """

    fingerprint_id: str
    embedding: list[float]
    signal_class: str = ""
    node_id: str = ""
    frequency_hz: float = 0.0
    timestamp_ns: int = 0
    model_version: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class FingerprintMatch:
    """A similarity-search hit between a query vector and a stored one."""

    fingerprint_id: str
    similarity: float
    signal_class: str = ""
    frequency_hz: float = 0.0
    node_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class FuzzCampaignPlan:
    """Declarative plan for a protocol-fuzzing campaign.

    Callers describe the target protocol, mutation strategies, and stop
    conditions; the :class:`FuzzProvider` turns this into a stream of
    mutated frames and tracks results in a storage backend.
    """

    campaign_id: str
    protocol: str  # "dmr", "p25", "lora", "meshtastic", …
    mutation_strategy: str = "bit_flip"  # provider-defined vocabulary
    iterations: int = 1000
    seed_frame: bytes | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class FuzzResult:
    """Outcome of a single fuzz iteration."""

    iteration: int
    mutated_frame: bytes
    accepted: bool = False  # decoder accepted the mutated frame
    error: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AlertPayload:
    """Structured alert for external delivery."""

    severity: str  # "critical", "high", "medium", "low", "info"
    title: str
    message: str
    source: str = "sigrift"
    node_id: str = ""
    signal_class: str = ""
    frequency_hz: float = 0.0
    anomaly_score: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Abstract provider interfaces
# ---------------------------------------------------------------------------


class GeoProvider(ABC):
    """Geolocation provider — estimates signal source position.

    Implementations:
        - RSS (signal strength triangulation) — community
        - TDOA (time difference of arrival) — enterprise
        - AOA (angle of arrival) — enterprise
        - Hybrid (multi-method fusion) — enterprise
    """

    @abstractmethod
    def estimate(self, observations: list[SignalObservation]) -> GeoEstimate:
        """Estimate position from a set of signal observations.

        Parameters
        ----------
        observations : list[SignalObservation]
            Observations from multiple receivers for the same signal.
            Must have at least ``min_receivers`` entries.

        Returns
        -------
        GeoEstimate
            Position estimate with confidence and method tag.
        """

    @property
    @abstractmethod
    def min_receivers(self) -> int:
        """Minimum number of receivers required for this method."""

    def configure(self, config: dict[str, Any]) -> None:
        """Optional: configure the provider with runtime settings.

        Default is a no-op. Implementations may use this for settings
        like ``coordinate_mode``, ``path_loss_exponent``, etc.
        Called by the registry when ``get_geo_provider(name, config=...)``
        is used.
        """

    @property
    def name(self) -> str:
        """Human-readable provider name."""
        return self.__class__.__name__


class AlertProvider(ABC):
    """Alert delivery provider — pushes notifications to external systems.

    Implementations:
        - Webhook (HTTP POST) — community
        - Syslog (RFC 5424) — community
        - SIEM (Splunk/Elastic/QRadar) — enterprise
        - Email (SMTP) — enterprise
        - SMS (Twilio/SNS) — enterprise
    """

    @abstractmethod
    def send(self, alert: AlertPayload) -> bool:
        """Deliver an alert to the external system.

        Returns True if delivery succeeded, False otherwise.
        Must not raise — log errors internally.
        """

    @property
    @abstractmethod
    def provider_type(self) -> str:
        """Provider type identifier (e.g. 'webhook', 'siem', 'email')."""

    @property
    def name(self) -> str:
        return self.__class__.__name__


class ReportProvider(ABC):
    """Report generation provider — produces formatted output.

    Implementations:
        - HTML sweep report — community
        - PDF audit report — enterprise
        - STIX 2.1 bundle — enterprise
        - CSV/JSON export — community
    """

    @abstractmethod
    def generate(self, session: dict[str, Any], output_path: str) -> str:
        """Generate a report for a sweep session.

        Parameters
        ----------
        session : dict
            Sweep session data (zones, detections, incidents).
        output_path : str
            Directory to write output file(s).

        Returns
        -------
        str
            Path to the generated report file.
        """

    @property
    @abstractmethod
    def format_name(self) -> str:
        """Output format identifier (e.g. 'pdf', 'html', 'stix')."""

    @property
    def name(self) -> str:
        return self.__class__.__name__


class FingerprintProvider(ABC):
    """Device / PHY fingerprint provider.

    Extracts an embedding from raw IQ samples for a detection, and searches
    a stored fingerprint library for similar prior observations. Community
    builds inject a :class:`~sigrift.providers.null.NullFingerprintProvider`
    that returns empty results; enterprise builds install
    ``sigrift-sentinel`` which registers a real implementation via the
    ``sigrift.fingerprint_providers`` entry point.

    Providers are expected to be *available*-or-*degrade* — ``extract`` may
    return ``None`` when IQ samples are missing; ``search`` may return an
    empty list. They must not raise for missing data.
    """

    @abstractmethod
    def extract(
        self,
        iq_samples: bytes | None,
        detection: dict[str, Any],
    ) -> FingerprintVector | None:
        """Extract a fingerprint vector from raw IQ samples.

        Parameters
        ----------
        iq_samples : bytes or None
            Complex IQ buffer for the detection, provider-specific format.
            Return ``None`` if the provider cannot handle this data.
        detection : dict
            Detection metadata (signal_class, frequency_hz, node_id, …).

        Returns
        -------
        FingerprintVector or None
            The extracted embedding, or ``None`` if extraction is not
            possible.
        """

    @abstractmethod
    def search(
        self,
        query: FingerprintVector,
        top_k: int = 5,
    ) -> list[FingerprintMatch]:
        """Find fingerprints in the library most similar to *query*.

        Returns at most ``top_k`` matches ordered by descending similarity.
        Providers that do not maintain a library return ``[]``.
        """

    @property
    def available(self) -> bool:
        """Whether this provider can actually perform extraction/search.

        Community (null) providers return ``False``; real implementations
        return ``True``. Callers use this to short-circuit expensive paths
        (e.g. declining to schedule a fingerprint job when ``available``
        is ``False``).
        """
        return True

    def configure(self, config: dict[str, Any]) -> None:
        """Optional runtime configuration hook. Default is a no-op."""

    @property
    def name(self) -> str:
        return self.__class__.__name__


class FuzzProvider(ABC):
    """Protocol-aware frame fuzzing provider.

    Runs mutation campaigns against protocol decoders to surface
    crashes, decoder state corruption, and key-recovery opportunities.
    Community builds inject
    :class:`~sigrift.providers.null.NullFuzzProvider` which refuses to
    run any campaign; enterprise builds install ``sigrift-sentinel``
    which registers a real implementation.
    """

    @abstractmethod
    def run_campaign(
        self,
        plan: FuzzCampaignPlan,
    ) -> list[FuzzResult]:
        """Execute *plan* and return per-iteration results.

        Providers that do not support the requested protocol return
        ``[]``. Providers must not raise on unknown protocols; prefer
        returning an empty list and logging the gap.
        """

    @property
    def available(self) -> bool:
        """Whether this provider can actually run campaigns.

        Community (null) providers return ``False``; real
        implementations return ``True``. Callers typically short-circuit
        route handlers to 402 / 404 when ``available`` is ``False``.
        """
        return True

    def configure(self, config: dict[str, Any]) -> None:
        """Optional runtime configuration hook. Default is a no-op."""

    @property
    def name(self) -> str:
        return self.__class__.__name__


class OidcProvider(ABC):
    """OIDC / SSO authentication flow provider.

    Community builds inject :class:`~sigrift.providers.null.NullOidcProvider`
    which refuses every authentication request; enterprise builds install
    ``sigrift-sentinel`` which registers a real implementation backed by
    the OIDC library of its choice. Provider is mostly a probe point —
    the actual auth flow runs through FastAPI routes mounted by the
    sentinel router package.
    """

    @abstractmethod
    def start_flow(self, request: Any) -> Any:
        """Initiate an OIDC login flow. Return a response (typically a
        redirect to the identity provider's authorise endpoint)."""

    @abstractmethod
    def callback(self, request: Any) -> Any:
        """Complete the OIDC flow after the IdP redirects back. Return a
        session or a redirect to the post-login landing page."""

    @property
    def available(self) -> bool:
        """Whether SSO can be performed. Community returns False."""
        return True

    def configure(self, config: dict[str, Any]) -> None:
        """Optional runtime configuration (issuer, client_id, etc.)."""

    @property
    def name(self) -> str:
        return self.__class__.__name__


class IngestProvider(ABC):
    """Custom ingest pipeline provider — protocol-specific decoders.

    Implementations:
        - Meshtastic LoRa decoder — community
        - DMR/P25 decoder — community
        - Custom proprietary protocol — enterprise
    """

    @abstractmethod
    def decode(
        self, raw_bytes: bytes, metadata: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Decode raw bytes into a structured detection.

        Returns None if the data doesn't match this protocol.
        """

    @property
    @abstractmethod
    def protocol_name(self) -> str:
        """Protocol identifier (e.g. 'meshtastic', 'dmr', 'p25')."""

    @property
    def name(self) -> str:
        return self.__class__.__name__
