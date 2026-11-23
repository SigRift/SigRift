"""Provider registry — discovers and loads plugins via entry points.

Enterprise packages register providers in their ``pyproject.toml``:

    [project.entry-points."sigrift.geo_providers"]
    tdoa = "sigrift_sentinel.providers.geolocation.tdoa:TdoaProvider"

Core discovers them at runtime without compile-time imports:

    from sigrift.providers.registry import get_geo_provider
    provider = get_geo_provider()  # returns TDOA if installed, NullGeo otherwise
"""

from __future__ import annotations

import logging
from typing import Any

from sigrift.providers.base import (
    AlertProvider,
    FingerprintProvider,
    FuzzProvider,
    GeoProvider,
    IngestProvider,
    OidcProvider,
    ReportProvider,
)

logger = logging.getLogger(__name__)

# Cache loaded providers to avoid repeated entry_point scans
_cache: dict[str, dict[str, Any]] = {}


def _load_entry_points(group: str) -> dict[str, Any]:
    """Load all entry points for a given group, cached."""
    if group in _cache:
        return _cache[group]

    try:
        from importlib.metadata import entry_points

        eps = entry_points(group=group)
        providers = {}
        for ep in eps:
            try:
                providers[ep.name] = ep.load()
                logger.info("Loaded provider: %s.%s", group, ep.name)
            except Exception as exc:
                logger.warning("Failed to load provider %s.%s: %s", group, ep.name, exc)
        _cache[group] = providers
        return providers
    except Exception as exc:
        logger.warning("Entry point discovery failed for %s: %s", group, exc)
        _cache[group] = {}
        return {}


def get_geo_providers() -> dict[str, type[GeoProvider]]:
    """Return all registered geolocation providers."""
    return _load_entry_points("sigrift.geo_providers")


def get_geo_provider(
    name: str | None = None,
    config: dict[str, Any] | None = None,
) -> GeoProvider:
    """Get a geolocation provider instance.

    Parameters
    ----------
    name : str or None
        Specific provider name. If None, returns the first registered
        provider, or NullGeoProvider if none are installed.
    config : dict or None
        Optional configuration passed to ``provider.configure(config)``
        before returning. Useful for setting coordinate_mode, path loss
        parameters, etc.
    """
    providers = get_geo_providers()
    if not providers:
        from sigrift.providers.null import NullGeoProvider

        return NullGeoProvider()
    if name and name in providers:
        provider = providers[name]()
    else:
        first_key = next(iter(providers))
        provider = providers[first_key]()
    if config:
        provider.configure(config)
    return provider


def get_alert_providers() -> dict[str, type[AlertProvider]]:
    """Return all registered alert providers."""
    return _load_entry_points("sigrift.alert_providers")


def get_alert_provider(name: str | None = None) -> AlertProvider:
    """Get an alert provider instance."""
    providers = get_alert_providers()
    if not providers:
        from sigrift.providers.null import NullAlertProvider

        return NullAlertProvider()
    if name and name in providers:
        return providers[name]()
    first_key = next(iter(providers))
    return providers[first_key]()


def get_report_providers() -> dict[str, type[ReportProvider]]:
    """Return all registered report providers."""
    return _load_entry_points("sigrift.report_providers")


def get_report_provider(name: str | None = None) -> ReportProvider:
    """Get a report provider instance."""
    providers = get_report_providers()
    if not providers:
        from sigrift.providers.null import NullReportProvider

        return NullReportProvider()
    if name and name in providers:
        return providers[name]()
    first_key = next(iter(providers))
    return providers[first_key]()


def get_ingest_providers() -> dict[str, type[IngestProvider]]:
    """Return all registered ingest providers."""
    return _load_entry_points("sigrift.ingest_providers")


def get_fingerprint_providers() -> dict[str, type[FingerprintProvider]]:
    """Return all registered fingerprint providers."""
    return _load_entry_points("sigrift.fingerprint_providers")


def get_fingerprint_provider(
    name: str | None = None,
    config: dict[str, Any] | None = None,
) -> FingerprintProvider:
    """Get a fingerprint provider instance.

    Falls back to ``NullFingerprintProvider`` when the enterprise
    ``sigrift-sentinel`` package is not installed.
    """
    providers = get_fingerprint_providers()
    if not providers:
        from sigrift.providers.null import NullFingerprintProvider

        return NullFingerprintProvider()
    if name and name in providers:
        provider = providers[name]()
    else:
        first_key = next(iter(providers))
        provider = providers[first_key]()
    if config:
        provider.configure(config)
    return provider


def get_fuzz_providers() -> dict[str, type[FuzzProvider]]:
    """Return all registered fuzz providers."""
    return _load_entry_points("sigrift.fuzz_providers")


def get_fuzz_provider(
    name: str | None = None,
    config: dict[str, Any] | None = None,
) -> FuzzProvider:
    """Get a fuzz provider instance.

    Falls back to ``NullFuzzProvider`` when the enterprise
    ``sigrift-sentinel`` package is not installed.
    """
    providers = get_fuzz_providers()
    if not providers:
        from sigrift.providers.null import NullFuzzProvider

        return NullFuzzProvider()
    if name and name in providers:
        provider = providers[name]()
    else:
        first_key = next(iter(providers))
        provider = providers[first_key]()
    if config:
        provider.configure(config)
    return provider


def get_oidc_providers() -> dict[str, type[OidcProvider]]:
    """Return all registered OIDC / SSO providers."""
    return _load_entry_points("sigrift.oidc_providers")


def get_oidc_provider(
    name: str | None = None,
    config: dict[str, Any] | None = None,
) -> OidcProvider:
    """Get an OIDC provider instance, with a NullOidcProvider fallback."""
    providers = get_oidc_providers()
    if not providers:
        from sigrift.providers.null import NullOidcProvider

        return NullOidcProvider()
    if name and name in providers:
        provider = providers[name]()
    else:
        first_key = next(iter(providers))
        provider = providers[first_key]()
    if config:
        provider.configure(config)
    return provider


def list_all_providers() -> dict[str, list[str]]:
    """List all registered providers by type."""
    return {
        "geo": list(get_geo_providers().keys()),
        "alert": list(get_alert_providers().keys()),
        "report": list(get_report_providers().keys()),
        "ingest": list(get_ingest_providers().keys()),
        "fingerprint": list(get_fingerprint_providers().keys()),
        "fuzz": list(get_fuzz_providers().keys()),
        "oidc": list(get_oidc_providers().keys()),
    }
