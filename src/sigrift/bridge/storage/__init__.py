"""Decomposed storage package for The Bridge.

Splits the monolithic DetectionStore into domain-specific sub-stores
for maintainability, testability, and scalability.

Sub-modules:
    base            – Schema, migrations, connection management
    detection_crud  – Detection insert/query/CRUD operations
    detection_analytics – Stats, timeline, heatmap, distribution, anomalies
    feedback        – Operator feedback & labelling
    audit           – Audit log, dismissals
    wifi_metadata   – WiFi metadata storage & queries
    wifi_anomalies  – WiFi anomaly management
    rf_anomalies    – RF anomaly management
"""

from sigrift.bridge.storage.base import (
    ACTIVE_FILTER,
    SharedContext,
    _DEFAULT_DB_PATH,
    _MIGRATIONS,
    _SCHEMA,
)

__all__ = [
    "SharedContext",
    "ACTIVE_FILTER",
    "_DEFAULT_DB_PATH",
    "_MIGRATIONS",
    "_SCHEMA",
]
