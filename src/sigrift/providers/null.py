"""Null providers — fallbacks when no enterprise provider is installed.

These are used by the registry when no provider is registered for a given
type. They log warnings and return safe defaults rather than crashing.
"""

from __future__ import annotations

import logging
from typing import Any

from sigrift.providers.base import (
    AlertPayload,
    AlertProvider,
    FingerprintMatch,
    FingerprintProvider,
    FingerprintVector,
    FuzzCampaignPlan,
    FuzzProvider,
    FuzzResult,
    GeoEstimate,
    GeoProvider,
    IngestProvider,
    OidcProvider,
    ReportProvider,
    SignalObservation,
)

logger = logging.getLogger(__name__)


class NullGeoProvider(GeoProvider):
    """No-op geolocation — returns empty estimate with zero confidence."""

    def estimate(self, observations: list[SignalObservation]) -> GeoEstimate:
        logger.debug(
            "NullGeoProvider: no geolocation provider installed (%d observations discarded)",
            len(observations),
        )
        return GeoEstimate(confidence=0.0, method="none")

    @property
    def min_receivers(self) -> int:
        return 0


class NullAlertProvider(AlertProvider):
    """No-op alert delivery — logs and discards."""

    def send(self, alert: AlertPayload) -> bool:
        logger.debug(
            "NullAlertProvider: alert discarded (no provider): %s", alert.title
        )
        return False

    @property
    def provider_type(self) -> str:
        return "null"


class NullReportProvider(ReportProvider):
    """No-op report generation — returns empty path."""

    def generate(self, session: dict[str, Any], output_path: str) -> str:
        logger.debug("NullReportProvider: no report provider installed")
        return ""

    @property
    def format_name(self) -> str:
        return "null"


class NullIngestProvider(IngestProvider):
    """No-op ingest — always returns None."""

    def decode(
        self, raw_bytes: bytes, metadata: dict[str, Any]
    ) -> dict[str, Any] | None:
        return None

    @property
    def protocol_name(self) -> str:
        return "null"


class NullOidcProvider(OidcProvider):
    """No-op OIDC — refuses every flow with a 402-style response.

    Used by community builds. Routes should check ``provider.available``
    and return a 402 / 404 before calling ``start_flow`` or ``callback``.
    """

    def start_flow(self, request: Any) -> Any:
        logger.debug("NullOidcProvider: no OIDC provider installed — flow refused")
        return None

    def callback(self, request: Any) -> Any:
        logger.debug("NullOidcProvider: no OIDC provider installed — callback refused")
        return None

    @property
    def available(self) -> bool:
        return False


class NullFuzzProvider(FuzzProvider):
    """No-op fuzz — refuses to run any campaign.

    Used by community builds that have no fuzz backend installed.
    Routes that depend on fuzzing should check ``provider.available``
    and return a 402 / 503 rather than calling ``run_campaign`` — this
    provider accepts the call and returns an empty result list.
    """

    def run_campaign(self, plan: FuzzCampaignPlan) -> list[FuzzResult]:
        logger.debug(
            "NullFuzzProvider: no fuzz provider installed (campaign %s dropped)",
            plan.campaign_id,
        )
        return []

    @property
    def available(self) -> bool:
        return False


class NullFingerprintProvider(FingerprintProvider):
    """No-op fingerprint — extraction returns None, search returns empty.

    Used by community builds that have no fingerprint backend installed.
    Routes that depend on fingerprinting should check
    ``provider.available`` and return a 402 / 503 rather than invoking
    ``extract`` — this provider will accept the call and return empty
    results, but callers usually want to short-circuit earlier.
    """

    def extract(
        self,
        iq_samples: bytes | None,
        detection: dict[str, Any],
    ) -> FingerprintVector | None:
        logger.debug("NullFingerprintProvider: no fingerprint provider installed")
        return None

    def search(
        self,
        query: FingerprintVector,
        top_k: int = 5,
    ) -> list[FingerprintMatch]:
        return []

    @property
    def available(self) -> bool:
        return False
