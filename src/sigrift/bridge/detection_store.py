"""SQLite storage backend for RF signal detections — facade.

This module now delegates to domain-specific sub-stores under
``sigrift.bridge.storage.*`` while preserving the original public API so
that existing consumers (routers, tests, app.py) require zero changes.

Sub-stores
----------
- ``DetectionCrudStore``        – insert/query/get/set CRUD
- ``DetectionAnalyticsStore``   – stats, timeline, heatmap, distribution
- ``FeedbackStore``             – operator feedback & labelling
- ``AuditStore``                – audit log, dismissals
- ``WiFiMetadataStore``         – WiFi metadata storage & queries
- ``WiFiAnomalyStore``          – WiFi anomaly management
- ``BtMetadataStore``           – Bluetooth device metadata storage & queries
- ``BtAnomalyStore``            – Bluetooth anomaly management
- ``RFAnomalyStore``            – RF anomaly management

All sub-stores share a :class:`SharedContext` that provides thread-safe
database access, write locking, and caching.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from pathlib import Path
from typing import Any

from sigrift.bridge.models import DetectionQuery, DetectionRecord, DetectionStats
from sigrift.bridge.storage.known_signals import KnownSignalStore
from sigrift.bridge.storage.audit import AuditStore
from sigrift.bridge.storage.base import ACTIVE_FILTER, SharedContext
from sigrift.bridge.storage.detection_analytics import DetectionAnalyticsStore
from sigrift.bridge.storage.detection_crud import DetectionCrudStore
from sigrift.bridge.storage.feedback import FeedbackStore
from sigrift.bridge.storage.geo_analytics import GeoAnalyticsStore
from sigrift.bridge.storage.rf_anomalies import RFAnomalyStore
from sigrift.bridge.storage.spectrum_analytics import SpectrumAnalyticsStore
from sigrift.bridge.storage.spectrum_snapshots import SpectrumSnapshotStore
from sigrift.bridge.storage.users import UserStore, VerifiedCredential
from sigrift.bridge.storage.bt_anomalies import BtAnomalyStore
from sigrift.bridge.storage.bt_metadata import BtMetadataStore
from sigrift.bridge.storage.emitter_store import EmitterStore
from sigrift.bridge.storage.fhss_store import FHSSStore

# TDOAStore is an optional storage module shipped only via the sentinel
# package. When sentinel isn't installed self._tdoa stays None and the
# delegation methods become no-ops.
try:
    from sigrift.bridge.storage.tdoa_store import TDOAStore

    _TDOA_AVAILABLE = True
except ImportError:
    TDOAStore = None  # type: ignore[assignment]
    _TDOA_AVAILABLE = False
from sigrift.bridge.storage.wifi_anomalies import WiFiAnomalyStore
from sigrift.bridge.storage.wifi_metadata import WiFiMetadataStore
from sigrift.bridge.storage.security_state import SecurityStateStore
from sigrift.bridge.storage.correlation_maintenance import CorrelationMaintenanceStore
from sigrift.bridge.storage.detection_summaries import DetectionSummaryStore
from sigrift.bridge.storage.device_lifecycle import DeviceLifecycleStore
from sigrift.bridge.storage.zigbee_metadata import ZigbeeMetadataStore


class DetectionStore:
    """Thread-safe SQLite storage for RF signal detections.

    This is a thin facade that composes domain-specific sub-stores
    while maintaining full backward compatibility with the original
    monolithic API.

    Parameters
    ----------
    db_path : str or Path or None
        Path to the SQLite database file.  Defaults to
        ``sigrift/bridge/data/detections.db``.
    """

    # Class-level constants preserved for external access
    _ACTIVE_FILTER = ACTIVE_FILTER

    _WIFI_ATTACK_LABELS = WiFiAnomalyStore._WIFI_ATTACK_LABELS
    _WIFI_ANOMALY_BASE_COLS = WiFiAnomalyStore._WIFI_ANOMALY_BASE_COLS
    _WIFI_ANOMALY_FRAME_COLS = WiFiAnomalyStore._WIFI_ANOMALY_FRAME_COLS

    def __init__(
        self,
        db_path: str | Path | None = None,
        tenant_id: str = "default",
    ) -> None:
        self._ctx = SharedContext(db_path=db_path, tenant_id=tenant_id)

        # Sub-stores
        self._crud = DetectionCrudStore(self._ctx)
        self._analytics = DetectionAnalyticsStore(self._ctx)
        self._feedback = FeedbackStore(self._ctx)
        self._audit = AuditStore(self._ctx)
        self.known_signals = KnownSignalStore(self._ctx)
        self._wifi_meta = WiFiMetadataStore(self._ctx)
        self._wifi_anomaly = WiFiAnomalyStore(self._ctx)
        self._rf_anomaly = RFAnomalyStore(self._ctx)
        self._spectrum = SpectrumAnalyticsStore(self._ctx)
        self._spectrum_snapshots = SpectrumSnapshotStore(self._ctx)
        self._geo = GeoAnalyticsStore(self._ctx)
        self._users = UserStore(self._ctx)
        self._bt_meta = BtMetadataStore(self._ctx)
        self._bt_anomaly = BtAnomalyStore(self._ctx)
        self._fhss = FHSSStore(self._ctx)
        self._emitter = EmitterStore(self._ctx)
        self._tdoa = TDOAStore(self._ctx) if _TDOA_AVAILABLE else None
        self._zigbee_meta = ZigbeeMetadataStore(self._ctx)
        self._security_state = SecurityStateStore(self._ctx)
        self._detection_summaries = DetectionSummaryStore(self._ctx)
        self._correlation_maintenance = CorrelationMaintenanceStore(self._ctx)
        self._device_lifecycle = DeviceLifecycleStore(self._ctx)

    # -- Public accessors for shared infrastructure --------------------------

    @property
    def db_path(self) -> str:
        """Return the database file path."""
        return self._ctx.db_path

    @property
    def tenant_id(self) -> str:
        """The fixed tenant configured for this store (never request mutable)."""
        return self._ctx.tenant_id

    def get_connection(self) -> sqlite3.Connection:
        """Return a thread-local SQLite connection."""
        return self._ctx.get_conn()

    # -- Backward-compatible shims (deprecated) -----------------------------

    @property
    def _db_path(self) -> str:
        return self._ctx.db_path

    @property
    def _write_lock(self):
        return self._ctx.write_lock

    @property
    def _cache(self):
        return self._ctx.cache

    def _get_conn(self) -> sqlite3.Connection:
        """Deprecated: use get_connection() instead."""
        return self._ctx.get_conn()

    def _ensure_rf_anomalies_table(self, conn: sqlite3.Connection) -> None:
        self._ctx.ensure_rf_anomalies_table(conn)

    # -- Detection CRUD (delegated to DetectionCrudStore) -------------------

    def insert_batch(self, detections: list[DetectionRecord]) -> int:
        return self._crud.insert_batch(detections)

    def insert_batch_new_ids(self, detections: list[DetectionRecord]) -> set[str]:
        return self._crud.insert_batch_new_ids(detections)

    def query(self, q: DetectionQuery) -> list[dict[str, Any]]:
        return self._crud.query(q)

    def get_recent(
        self,
        minutes: int = 5,
        node_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        return self._crud.get_recent(minutes=minutes, node_id=node_id, limit=limit)

    def get_detection_by_id(self, detection_id: str) -> dict[str, Any] | None:
        return self._crud.get_detection_by_id(detection_id)

    def set_has_iq_capture(self, detection_id: str, value: bool = True) -> None:
        self._crud.set_has_iq_capture(detection_id, value)

    def row_count(self) -> int:
        return self._crud.row_count()

    # -- Detection Analytics (delegated to DetectionAnalyticsStore) ---------

    def get_stats(
        self,
        hours: int = 24,
        node_id: str | None = None,
    ) -> DetectionStats:
        return self._analytics.get_stats(hours=hours, node_id=node_id)

    def get_timeline(
        self,
        range_hours: int = 24,
        resolution_seconds: int = 300,
        node_id: str | None = None,
    ) -> list[dict[str, Any]]:
        return self._analytics.get_timeline(
            range_hours=range_hours,
            resolution_seconds=resolution_seconds,
            node_id=node_id,
        )

    def get_heatmap(
        self,
        date: str = "",
        resolution_minutes: int = 15,
        hours: int | None = None,
    ) -> list[dict[str, Any]]:
        return self._analytics.get_heatmap(
            date=date, resolution_minutes=resolution_minutes, hours=hours
        )

    def get_distribution(
        self,
        range_hours: int = 24,
        min_confidence: float = 0.0,
    ) -> list[dict[str, Any]]:
        return self._analytics.get_distribution(
            range_hours=range_hours, min_confidence=min_confidence
        )

    def get_anomalies(
        self,
        min_score: float = 0.3,
        limit: int = 50,
        node_id: str | None = None,
        hours: int | None = None,
    ) -> list[dict[str, Any]]:
        return self._analytics.get_anomalies(
            min_score=min_score, limit=limit, node_id=node_id, hours=hours
        )

    def get_active_anomaly_count(self, threshold: float = 0.3) -> int:
        return self._analytics.get_active_anomaly_count(threshold=threshold)

    def get_active_frequency_count(self, hours: int = 1) -> int:
        return self._analytics.get_active_frequency_count(hours=hours)

    def get_active_frequencies(self, hours: int = 1) -> list[dict]:
        return self._analytics.get_active_frequencies(hours=hours)

    def get_threat_ribbon(
        self,
        hours: int = 1,
        threshold: float = 0.5,
        limit: int = 50,
    ) -> list[dict]:
        return self._analytics.get_threat_ribbon(
            hours=hours,
            threshold=threshold,
            limit=limit,
        )

    def aggregate_hourly(self) -> int:
        return self._analytics.aggregate_hourly(tenant_id=self._ctx.tenant_id)

    def cleanup(self, max_age_days: int = 7) -> int:
        return self._analytics.cleanup(
            tenant_id=self._ctx.tenant_id, max_age_days=max_age_days
        )

    # -- Feedback (delegated to FeedbackStore) ------------------------------

    def add_feedback(
        self,
        detection_id: str,
        label: str,
        note: str = "",
        operator: str = "",
    ) -> int:
        return self._feedback.add_feedback(
            detection_id=detection_id,
            label=label,
            note=note,
            operator=operator,
        )

    def get_feedback(self, detection_id: str) -> list[dict[str, Any]]:
        return self._feedback.get_feedback(detection_id)

    def get_feedback_by_label(
        self, label: str, limit: int = 100
    ) -> list[dict[str, Any]]:
        return self._feedback.get_feedback_by_label(label, limit=limit)

    def get_feedback_stats(self, days: int = 30) -> dict[str, int]:
        return self._feedback.get_feedback_stats(days=days)

    def get_fp_rate(self, days: int = 30) -> float:
        return self._feedback.get_fp_rate(days=days)

    # -- Audit (delegated to AuditStore) ------------------------------------

    def log_audit(
        self,
        action: str,
        target_id: str,
        signal_class: str = "",
        freq_hz: float = 0.0,
        node_id: str = "",
        operator: str = "",
        note: str = "",
        details: dict | None = None,
        target_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        return self._audit.log_audit(
            action=action,
            target_id=target_id,
            signal_class=signal_class,
            freq_hz=freq_hz,
            node_id=node_id,
            operator=operator,
            note=note,
            details=details,
            target_ids=target_ids,
        )

    def get_audit_log(
        self,
        limit: int = 200,
        offset: int = 0,
        action: str | None = None,
        target_id: str | None = None,
        operator: str | None = None,
        node_id: str | None = None,
        search: str | None = None,
        start: str | None = None,
        end: str | None = None,
        severity: str | None = None,
    ) -> list[dict[str, Any]]:
        return self._audit.get_audit_log(
            limit=limit,
            offset=offset,
            action=action,
            target_id=target_id,
            operator=operator,
            node_id=node_id,
            search=search,
            start=start,
            end=end,
            severity=severity,
        )

    def count_audit_log(self, **kwargs: Any) -> int:
        return self._audit.count_audit_log(**kwargs)

    def get_audit_actions(self) -> list[str]:
        return self._audit.get_audit_actions()

    def get_audit_operators(self) -> list[str]:
        return self._audit.get_audit_operators()

    def get_audit_node_ids(self) -> list[str]:
        return self._audit.get_audit_node_ids()

    def get_dismissed_ids(self) -> set[str]:
        return self._audit.get_dismissed_ids()

    def is_dismissed(self, detection_id: str) -> bool:
        return self._audit.is_dismissed(detection_id)

    def verify_audit_chain(self) -> dict[str, Any]:
        return self._audit.verify_chain()

    # -- WiFi Metadata (delegated to WiFiMetadataStore) ---------------------

    @staticmethod
    def _anonymize_mac(mac: str, secret: bytes) -> str:
        return WiFiMetadataStore._anonymize_mac(mac, secret)

    def insert_wifi_metadata(
        self,
        records: list[dict],
        mac_secret: bytes | None = None,
    ) -> int:
        return self._wifi_meta.insert_wifi_metadata(records, mac_secret=mac_secret)

    def get_wifi_networks(
        self,
        limit: int = 100,
        band: str | None = None,
        node_id: str | None = None,
    ) -> list[dict[str, Any]]:
        return self._wifi_meta.get_wifi_networks(
            limit=limit,
            band=band,
            node_id=node_id,
        )

    def get_wifi_network_detail(self, bssid: str) -> dict[str, Any] | None:
        return self._wifi_meta.get_wifi_network_detail(bssid)

    def get_wifi_clients(
        self,
        bssid: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        return self._wifi_meta.get_wifi_clients(
            bssid=bssid,
            limit=limit,
        )

    def get_wifi_channel_utilization(
        self,
        band: str = "2.4GHz",
        node_id: str | None = None,
    ) -> list[dict[str, Any]]:
        return self._wifi_meta.get_wifi_channel_utilization(
            band=band,
            node_id=node_id,
        )

    def get_wifi_timeline(
        self,
        bssid: str | None = None,
        hours: int = 24,
    ) -> list[dict[str, Any]]:
        return self._wifi_meta.get_wifi_timeline(
            bssid=bssid,
            hours=hours,
        )

    def get_wifi_stats(self) -> dict[str, Any]:
        # Match the default anomaly list's active, score >= 0.3 queue across
        # this tenant's nodes. Keep the count outside the metadata cache so
        # dismissals, other workers' writes and snooze expiry appear on refresh.
        stats = dict(self._wifi_meta.get_wifi_stats())
        stats["anomaly_count"] = self.count_wifi_anomalies()
        return stats

    def aggregate_wifi_hourly(self, cutoff_hours: int = 2) -> int:
        return self._wifi_meta.aggregate_wifi_hourly(cutoff_hours=cutoff_hours)

    def cleanup_wifi_metadata(self, max_age_hours: int = 24) -> int:
        return self._wifi_meta.cleanup_wifi_metadata(max_age_hours=max_age_hours)

    def cleanup_wifi_hourly(self, max_age_days: int = 90) -> int:
        return self._wifi_meta.cleanup_wifi_hourly(max_age_days=max_age_days)

    # -- WiFi Anomalies (delegated to WiFiAnomalyStore) ---------------------

    @staticmethod
    def _wifi_attack_type(dimensions: dict[str, float]) -> str:
        return WiFiAnomalyStore._wifi_attack_type(dimensions)

    def insert_wifi_anomalies_batch(
        self,
        anomalies: list[dict[str, Any]],
        *,
        auto_snooze_seen_count: int = 0,
        auto_snooze_max_score: float = 0.0,
        auto_snooze_hours: int = 0,
    ) -> list[int]:
        return self._wifi_anomaly.insert_wifi_anomalies_batch(
            anomalies,
            auto_snooze_seen_count=auto_snooze_seen_count,
            auto_snooze_max_score=auto_snooze_max_score,
            auto_snooze_hours=auto_snooze_hours,
        )

    def insert_wifi_anomaly(self, anomaly: dict[str, Any]) -> int:
        return self._wifi_anomaly.insert_wifi_anomaly(anomaly)

    def get_wifi_anomalies(
        self,
        min_score: float = 0.3,
        limit: int = 50,
        node_id: str | None = None,
        include_dismissed: bool = False,
        include_frames: bool = False,
    ) -> list[dict[str, Any]]:
        return self._wifi_anomaly.get_wifi_anomalies(
            min_score=min_score,
            limit=limit,
            node_id=node_id,
            include_dismissed=include_dismissed,
            include_frames=include_frames,
        )

    def count_wifi_anomalies(
        self,
        min_score: float = 0.3,
        include_dismissed: bool = False,
    ) -> int:
        return self._wifi_anomaly.count_wifi_anomalies(
            min_score=min_score,
            include_dismissed=include_dismissed,
        )

    def get_wifi_anomalies_by_ids(self, ids: list[int]) -> list[dict[str, Any]]:
        return self._wifi_anomaly.get_wifi_anomalies_by_ids(ids)

    def dismiss_wifi_anomaly(self, anomaly_id: int) -> None:
        self._wifi_anomaly.dismiss_wifi_anomaly(anomaly_id)

    def dismiss_wifi_anomalies_bulk(self, anomaly_ids: list[int]) -> int:
        return self._wifi_anomaly.dismiss_wifi_anomalies_bulk(anomaly_ids)

    def snooze_wifi_anomaly(self, anomaly_id: int, until: str) -> None:
        self._wifi_anomaly.snooze_wifi_anomaly(anomaly_id, until)

    def snooze_wifi_anomalies_bulk(self, anomaly_ids: list[int], until: str) -> int:
        return self._wifi_anomaly.snooze_wifi_anomalies_bulk(anomaly_ids, until)

    def set_wifi_anomaly_pcap(
        self,
        anomaly_id: int,
        has_pcap: bool = True,
        frame_count: int = 0,
    ) -> bool:
        return self._wifi_anomaly.set_wifi_anomaly_pcap(
            anomaly_id, has_pcap, frame_count
        )

    def cleanup_wifi_anomalies(self, max_age_days: int = 7) -> int:
        return self._wifi_anomaly.cleanup_wifi_anomalies(max_age_days=max_age_days)

    def compact_dismissed_wifi_anomalies(self) -> int:
        return self._wifi_anomaly.compact_dismissed_wifi_anomalies()

    # -- Bluetooth Metadata (delegated to BtMetadataStore) -------------------

    def insert_bt_devices(
        self,
        records: list[dict],
        mac_secret: str | None = None,
    ) -> int:
        return self._bt_meta.insert_bt_devices(records, mac_secret=mac_secret)

    def get_bt_devices(
        self,
        limit: int = 100,
        device_type: str | None = None,
        node_id: str | None = None,
    ) -> list[dict[str, Any]]:
        return self._bt_meta.get_bt_devices(
            limit=limit,
            device_type=device_type,
            node_id=node_id,
        )

    def get_bt_device_detail(self, device_addr: str) -> dict[str, Any] | None:
        return self._bt_meta.get_bt_device_detail(device_addr)

    def get_bt_stats(self) -> dict[str, Any]:
        return self._bt_meta.get_bt_stats()

    def get_bt_timeline(
        self,
        device_addr: str,
        hours: int = 24,
    ) -> list[dict[str, Any]]:
        return self._bt_meta.get_bt_timeline(
            device_addr=device_addr,
            hours=hours,
        )

    def aggregate_bt_hourly(self, cutoff_hours: int = 2) -> int:
        return self._bt_meta.aggregate_bt_hourly(cutoff_hours=cutoff_hours)

    def cleanup_bt_devices(self, max_age_hours: int = 4) -> int:
        return self._bt_meta.cleanup_bt_devices(max_age_hours=max_age_hours)

    def cleanup_bt_hourly(self, max_age_days: int = 30) -> int:
        return self._bt_meta.cleanup_bt_hourly(max_age_days=max_age_days)

    # -- Bluetooth Anomalies (delegated to BtAnomalyStore) -----------------

    def insert_bt_anomalies_batch(
        self,
        anomalies: list[dict[str, Any]],
    ) -> list[int]:
        return self._bt_anomaly.insert_bt_anomalies_batch(anomalies)

    def get_bt_anomalies(
        self,
        min_score: float = 0.0,
        limit: int = 50,
        node_id: str | None = None,
        include_dismissed: bool = False,
    ) -> list[dict[str, Any]]:
        return self._bt_anomaly.get_bt_anomalies(
            min_score=min_score,
            limit=limit,
            node_id=node_id,
            include_dismissed=include_dismissed,
        )

    def count_bt_anomalies(
        self,
        min_score: float = 0.0,
        include_dismissed: bool = False,
    ) -> int:
        return self._bt_anomaly.count_bt_anomalies(
            min_score=min_score,
            include_dismissed=include_dismissed,
        )

    def dismiss_bt_anomaly(self, anomaly_id: int) -> None:
        self._bt_anomaly.dismiss_bt_anomaly(anomaly_id)

    def dismiss_bt_anomalies_bulk(self, anomaly_ids: list[int]) -> int:
        return self._bt_anomaly.dismiss_bt_anomalies_bulk(anomaly_ids)

    def snooze_bt_anomaly(self, anomaly_id: int, until: str) -> None:
        self._bt_anomaly.snooze_bt_anomaly(anomaly_id, until)

    def snooze_bt_anomalies_bulk(self, anomaly_ids: list[int], until: str) -> int:
        return self._bt_anomaly.snooze_bt_anomalies_bulk(anomaly_ids, until)

    def cleanup_bt_anomalies(self, max_age_days: int = 30) -> int:
        return self._bt_anomaly.cleanup_bt_anomalies(max_age_days=max_age_days)

    def compact_dismissed_bt_anomalies(self) -> int:
        return self._bt_anomaly.compact_dismissed_bt_anomalies()

    # -- Zigbee metadata (delegated to ZigbeeMetadataStore) -------------------

    def insert_zigbee_devices(self, records: list[dict]) -> int:
        return self._zigbee_meta.insert_zigbee_devices(records)

    def get_zigbee_devices(
        self,
        *,
        limit: int = 100,
        device_type: str | None = None,
        pan_id: str | None = None,
        node_id: str | None = None,
    ) -> list[dict]:
        return self._zigbee_meta.get_zigbee_devices(
            limit=limit,
            device_type=device_type,
            pan_id=pan_id,
            node_id=node_id,
        )

    def get_zigbee_device_detail(self, ieee_addr: str) -> dict | None:
        return self._zigbee_meta.get_zigbee_device_detail(ieee_addr)

    def get_zigbee_stats(self) -> dict:
        return self._zigbee_meta.get_zigbee_stats()

    def aggregate_zigbee_hourly(self, cutoff_hours: int = 2) -> int:
        return self._zigbee_meta.aggregate_zigbee_hourly(cutoff_hours=cutoff_hours)

    def cleanup_zigbee_devices(self, max_age_hours: int = 24) -> int:
        return self._zigbee_meta.cleanup_zigbee_devices(max_age_hours=max_age_hours)

    def cleanup_zigbee_hourly(self, max_age_days: int = 90) -> int:
        return self._zigbee_meta.cleanup_zigbee_hourly(max_age_days=max_age_days)

    def insert_channel_energy(self, records: list[dict]) -> int:
        return self._zigbee_meta.insert_channel_energy(records)

    def get_channel_energy(
        self, hours: int = 1, node_id: str | None = None
    ) -> list[dict]:
        return self._zigbee_meta.get_channel_energy(hours=hours, node_id=node_id)

    def cleanup_channel_energy(self, max_age_hours: int = 24) -> int:
        return self._zigbee_meta.cleanup_channel_energy(max_age_hours=max_age_hours)

    def get_network_topology(self) -> list[dict]:
        return self._zigbee_meta.get_network_topology()

    # -- RF Anomalies (delegated to RFAnomalyStore) -------------------------

    @staticmethod
    def _rf_dedup_key(signal_class: str, freq_hz: float) -> str:
        return RFAnomalyStore._rf_dedup_key(signal_class, freq_hz)

    @staticmethod
    def _rf_priority(score: float) -> str:
        return RFAnomalyStore._rf_priority(score)

    @staticmethod
    def _bucket_to_band_label(freq_hz: float) -> str:
        return RFAnomalyStore._bucket_to_band_label(freq_hz)

    def insert_rf_anomalies_batch(
        self,
        anomalies: list[dict[str, Any]],
        *,
        auto_snooze_seen_count: int = 0,
        auto_snooze_max_score: float = 0.0,
        auto_snooze_hours: int = 0,
    ) -> list[int]:
        return self._rf_anomaly.insert_rf_anomalies_batch(
            anomalies,
            auto_snooze_seen_count=auto_snooze_seen_count,
            auto_snooze_max_score=auto_snooze_max_score,
            auto_snooze_hours=auto_snooze_hours,
        )

    def get_rf_anomalies(
        self,
        min_score: float = 0.3,
        limit: int = 50,
        node_id: str | None = None,
        include_dismissed: bool = False,
        family: str | None = None,
        signal_class: str | None = None,
        priority: str | None = None,
        freq_min_hz: float | None = None,
        freq_max_hz: float | None = None,
        sort_by: str = "score",
        sort_order: str = "desc",
    ) -> list[dict[str, Any]]:
        return self._rf_anomaly.get_rf_anomalies(
            min_score=min_score,
            limit=limit,
            node_id=node_id,
            include_dismissed=include_dismissed,
            family=family,
            signal_class=signal_class,
            priority=priority,
            freq_min_hz=freq_min_hz,
            freq_max_hz=freq_max_hz,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    def count_rf_anomalies(
        self,
        min_score: float = 0.3,
        include_dismissed: bool = False,
        node_id: str | None = None,
        family: str | None = None,
        signal_class: str | None = None,
        priority: str | None = None,
        freq_min_hz: float | None = None,
        freq_max_hz: float | None = None,
    ) -> int:
        return self._rf_anomaly.count_rf_anomalies(
            min_score=min_score,
            include_dismissed=include_dismissed,
            node_id=node_id,
            family=family,
            signal_class=signal_class,
            priority=priority,
            freq_min_hz=freq_min_hz,
            freq_max_hz=freq_max_hz,
        )

    def get_rf_anomaly_summary(
        self,
        min_score: float = 0.3,
    ) -> dict[str, Any]:
        return self._rf_anomaly.get_rf_anomaly_summary(min_score=min_score)

    def get_rf_anomalies_by_ids(self, ids: list[int]) -> list[dict[str, Any]]:
        return self._rf_anomaly.get_rf_anomalies_by_ids(ids)

    def dismiss_rf_anomaly(self, anomaly_id: int) -> None:
        self._rf_anomaly.dismiss_rf_anomaly(anomaly_id)

    def dismiss_rf_anomalies_bulk(self, anomaly_ids: list[int]) -> int:
        return self._rf_anomaly.dismiss_rf_anomalies_bulk(anomaly_ids)

    def snooze_rf_anomaly(self, anomaly_id: int, until: str) -> None:
        self._rf_anomaly.snooze_rf_anomaly(anomaly_id, until)

    def snooze_rf_anomalies_bulk(self, anomaly_ids: list[int], until: str) -> int:
        return self._rf_anomaly.snooze_rf_anomalies_bulk(anomaly_ids, until)

    def cleanup_rf_anomalies(self, max_age_days: int = 7) -> int:
        return self._rf_anomaly.cleanup_rf_anomalies(max_age_days=max_age_days)

    def auto_resolve_baseline_anomalies(
        self,
        max_score: float = 0.4,
        min_seen_count: int = 5,
    ) -> int:
        return self._rf_anomaly.auto_resolve_baseline_anomalies(
            max_score=max_score,
            min_seen_count=min_seen_count,
        )

    def resolve_stale_anomalies(
        self,
        max_age_hours: float = 1.0,
        max_score: float = 1.0,
        min_seen_count: int = 1,
    ) -> int:
        return self._rf_anomaly.resolve_stale_anomalies(
            max_age_hours=max_age_hours,
            max_score=max_score,
            min_seen_count=min_seen_count,
        )

    # -- Spectrum Analytics (delegated to SpectrumAnalyticsStore) -----------

    def get_spectrum_occupancy(
        self,
        hours: int = 24,
        bin_width_hz: int = 1_000_000,
        node_id: str | None = None,
    ) -> list[dict[str, Any]]:
        return self._spectrum.get_occupancy(
            hours=hours,
            bin_width_hz=bin_width_hz,
            node_id=node_id,
        )

    def get_spectrum_waterfall(
        self,
        hours: int = 1,
        freq_min_hz: float | None = None,
        freq_max_hz: float | None = None,
        time_resolution_sec: int = 60,
        bin_width_hz: int = 1_000_000,
        node_id: str | None = None,
    ) -> dict[str, Any]:
        return self._spectrum.get_waterfall(
            hours=hours,
            freq_min_hz=freq_min_hz,
            freq_max_hz=freq_max_hz,
            time_resolution_sec=time_resolution_sec,
            bin_width_hz=bin_width_hz,
            node_id=node_id,
        )

    def get_spectrum_bands(
        self,
        hours: int = 24,
        node_id: str | None = None,
    ) -> list[dict[str, Any]]:
        return self._spectrum.get_band_summary(hours=hours, node_id=node_id)

    def get_spectrum_activity(
        self,
        hours: int = 4,
        node_id: str | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        return self._spectrum.get_activity(
            hours=hours,
            node_id=node_id,
            limit=limit,
        )

    def get_bandwidth_distribution(
        self,
        hours: int = 24,
        node_id: str | None = None,
    ) -> list[dict[str, Any]]:
        return self._spectrum.get_bandwidth_distribution(
            hours=hours,
            node_id=node_id,
        )

    # -- Spectrum Snapshots (delegated to SpectrumSnapshotStore) -----------

    def insert_spectrum_snapshot(self, snapshot: dict[str, Any]) -> int:
        return self._spectrum_snapshots.insert_snapshot(snapshot)

    def get_spectrum_snapshots(
        self,
        node_id: str | None = None,
        hours: int = 1,
        center_freq_hz: float | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        return self._spectrum_snapshots.get_snapshots(
            node_id=node_id,
            hours=hours,
            center_freq_hz=center_freq_hz,
            limit=limit,
        )

    def get_spectrum_latest_per_node(self) -> list[dict[str, Any]]:
        return self._spectrum_snapshots.get_latest_per_node()

    def get_spectrum_wideband_view(
        self,
        node_id: str | None = None,
    ) -> list[dict[str, Any]]:
        return self._spectrum_snapshots.get_wideband_view(node_id=node_id)

    def detect_spectrum_peaks(
        self,
        hours: int = 4,
        threshold_db: float = 10.0,
        min_power_dbm: float | None = None,
    ) -> list[dict[str, Any]]:
        return self._spectrum_snapshots.detect_peaks(
            hours=hours,
            threshold_db=threshold_db,
            min_power_dbm=min_power_dbm,
        )

    def cleanup_spectrum_snapshots(self, max_age_hours: int = 24) -> int:
        return self._spectrum_snapshots.cleanup_old(max_age_hours=max_age_hours)

    def stitch_spectrum_sweeps(
        self,
        node_id: str,
        minutes: int = 5,
    ) -> dict[str, Any] | None:
        return self._spectrum_snapshots.stitch_sweeps(
            node_id=node_id,
            minutes=minutes,
        )

    def compare_spectrum_psd(
        self,
        node_id: str,
        hours: int = 4,
        center_freq_hz: float | None = None,
    ) -> dict[str, Any] | None:
        return self._spectrum_snapshots.compare_psd(
            node_id=node_id,
            hours=hours,
            center_freq_hz=center_freq_hz,
        )

    # -- Geo Analytics (delegated to GeoAnalyticsStore) --------------------

    def get_geo_node_summary(
        self,
        node_id: str,
        cutoff_iso: str,
    ) -> dict[str, Any]:
        return self._geo.get_node_detection_summary(
            node_id=node_id,
            cutoff_iso=cutoff_iso,
        )

    def get_geo_heatmap_weight(
        self,
        node_id: str,
        cutoff_iso: str,
        signal_class: str | None = None,
    ) -> int:
        return self._geo.get_heatmap_weight(
            node_id=node_id,
            cutoff_iso=cutoff_iso,
            signal_class=signal_class,
        )

    def get_geo_coverage_stats(
        self,
        node_id: str,
    ) -> dict[str, Any]:
        return self._geo.get_coverage_stats(node_id=node_id)

    def get_geo_activity_feed(
        self,
        node_ids: list[str],
        cutoff_iso: str,
        min_anomaly_score: float | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        return self._geo.get_activity_feed(
            node_ids=node_ids,
            cutoff_iso=cutoff_iso,
            min_anomaly_score=min_anomaly_score,
            limit=limit,
        )

    # -- FHSS Events (delegated to FHSSStore) --------------------------------

    def insert_fhss_events(self, events: list[dict[str, Any]]) -> list[str]:
        return self._fhss.insert_fhss_events(events)

    def get_fhss_events(
        self,
        hours: int = 24,
        node_id: str | None = None,
        min_hop_rate: float | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        return self._fhss.get_fhss_events(
            hours=hours,
            node_id=node_id,
            min_hop_rate=min_hop_rate,
            limit=limit,
            offset=offset,
        )

    def get_fhss_event_by_id(self, fhss_id: str) -> dict[str, Any] | None:
        return self._fhss.get_fhss_event_by_id(fhss_id)

    def count_fhss_events(
        self,
        hours: int = 24,
        node_id: str | None = None,
    ) -> int:
        return self._fhss.count_fhss_events(hours=hours, node_id=node_id)

    def cleanup_fhss_events(self, max_age_days: int = 30) -> int:
        return self._fhss.cleanup_fhss_events(max_age_days=max_age_days)

    # -- TDOA Estimates (delegated to TDOAStore when available) --------------
    # Community builds do not ship TDOAStore. Each method below returns a
    # safe empty / no-op value when the store is absent so callers that
    # don't gate on licence or provider.available still run without
    # crashing.

    def store_tdoa_estimate(self, estimate: dict[str, Any]) -> str:
        if self._tdoa is None:
            return ""
        return self._tdoa.store_tdoa_estimate(estimate)

    def get_tdoa_estimates(
        self,
        hours: int = 24,
        signal_class: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        if self._tdoa is None:
            return []
        return self._tdoa.get_tdoa_estimates(
            hours=hours,
            signal_class=signal_class,
            limit=limit,
        )

    def get_tdoa_estimate_by_id(self, estimate_id: str) -> dict[str, Any] | None:
        if self._tdoa is None:
            return None
        return self._tdoa.get_tdoa_estimate_by_id(estimate_id)

    def get_tdoa_heatmap(self, hours: int = 24) -> list[dict[str, Any]]:
        if self._tdoa is None:
            return []
        return self._tdoa.get_tdoa_heatmap(hours=hours)

    def count_tdoa_estimates(self, hours: int = 24) -> int:
        if self._tdoa is None:
            return 0
        return self._tdoa.count_tdoa_estimates(hours=hours)

    def cleanup_tdoa_estimates(self, max_age_days: int = 30) -> int:
        if self._tdoa is None:
            return 0
        return self._tdoa.cleanup_tdoa_estimates(max_age_days=max_age_days)

    # -- Maintenance --------------------------------------------------------

    # No audit-log purge here: a plain DELETE of old audit rows breaks the
    # HMAC chain and leaves no archive anchor.  Audit entries leave the
    # log only through the gateway's anchored archive
    # (POST /api/admin/audit/archive, then DELETE /api/admin/audit).

    def vacuum(self) -> dict[str, Any]:
        """Run VACUUM to reclaim disk space. Returns size info."""
        db_path = Path(self._ctx.db_path)
        size_before = db_path.stat().st_size if db_path.exists() else 0
        conn = self._ctx.get_conn()
        old_isolation = conn.isolation_level
        conn.isolation_level = None  # autocommit mode required for VACUUM
        try:
            conn.execute("VACUUM")
        finally:
            # Restore even when VACUUM fails, or this thread-local
            # connection would stay in autocommit mode and every later
            # transaction block on it would lose its atomicity.
            conn.isolation_level = old_isolation
        size_after = db_path.stat().st_size if db_path.exists() else 0
        return {
            "db_size_bytes": size_after,
            "reclaimed_bytes": max(0, size_before - size_after),
        }

    def wal_checkpoint(self) -> dict[str, Any]:
        """Force a WAL checkpoint (TRUNCATE mode)."""
        conn = self._ctx.get_conn()
        row = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        return {
            "wal_pages": row[1] if row else 0,
            "checkpointed": row[2] if row else 0,
        }

    def optimize(self) -> None:
        """Run PRAGMA optimize and ANALYZE."""
        conn = self._ctx.get_conn()
        conn.execute("PRAGMA optimize")
        conn.execute("ANALYZE")

    # -- User accounts (delegated to UserStore) ----------------------------

    @property
    def users(self) -> UserStore:
        """Return the UserStore sub-store for direct access."""
        return self._users

    @property
    def security_state(self) -> SecurityStateStore:
        """Return the SecurityStateStore sub-store for direct access."""
        return self._security_state

    def create_user(
        self, username: str, password: str, **kwargs: Any
    ) -> dict[str, Any]:
        return self._users.create_user(username, password, **kwargs)

    def get_user(self, username: str) -> dict[str, Any] | None:
        return self._users.get_user(username)

    def list_users(self) -> list[dict[str, Any]]:
        return self._users.list_users()

    def update_user(self, username: str, **kwargs: Any) -> dict[str, Any] | None:
        return self._users.update_user(username, **kwargs)

    def _account_audit_writer(
        self, action: str, username: str, operator: str, note: str
    ) -> Callable[[sqlite3.Connection], None]:
        # These public operations own the commit. Refuse an outer transaction
        # without committing/rolling it back or re-entering its write lock.
        if self._ctx.transaction_active:
            raise RuntimeError("Audited account changes require their own transaction")

        def append(conn: sqlite3.Connection) -> None:
            self._audit._log_audit_in_transaction(
                conn, action=action, target_id=username, operator=operator, note=note
            )

        return append

    def update_user_with_audit(
        self,
        username: str,
        *,
        action: str,
        operator: str,
        note: str = "",
        **kwargs: Any,
    ) -> dict[str, Any] | None:
        """Commit account fields, requested revocation and success audit together."""
        append = self._account_audit_writer(action, username, operator, note)
        user = self._users.update_user(username, _after_write=append, **kwargs)
        if user is not None:
            self._audit._after_commit(action, username)
        return user

    def set_password_with_audit(
        self,
        username: str,
        new_password: str,
        *,
        action: str,
        operator: str,
        note: str = "",
    ) -> bool:
        """Hash outside the lock; commit password, revocation and audit together."""
        append = self._account_audit_writer(action, username, operator, note)
        updated = self._users.set_password(
            username, new_password, revoke_sessions=True, _after_write=append
        )
        if updated:
            self._audit._after_commit(action, username)
        return updated

    def change_password_with_audit(
        self,
        username: str,
        new_password: str,
        *,
        credential: VerifiedCredential,
        session_token: str | None,
        action: str,
        operator: str,
        note: str = "",
    ) -> VerifiedCredential | None:
        """Commit a verified change, its revocation and its audit together.

        Only while *credential* is still stored, the account enabled and
        *session_token* alive (see :meth:`UserStore.change_password`, which
        raises ``CredentialChangedError`` / ``SessionEndedError`` and writes
        nothing otherwise). Returns the new credential, or ``None`` if the
        user is gone.
        """
        append = self._account_audit_writer(action, username, operator, note)
        changed = self._users.change_password(
            username,
            new_password,
            credential=credential,
            session_token=session_token,
            _after_write=append,
        )
        if changed is not None:
            self._audit._after_commit(action, username)
        return changed

    def disable_user(self, username: str) -> bool:
        return self._users.disable_user(username)

    def verify_password(self, username: str, password: str) -> bool:
        return self._users.verify_password(username, password)

    def verify_password_credential(
        self, username: str, password: str
    ) -> VerifiedCredential | None:
        return self._users.verify_password_credential(username, password)

    def create_session(self, user_id: int, **kwargs: Any) -> dict[str, Any]:
        return self._users.create_session(user_id, **kwargs)

    def get_session(self, session_token: str) -> dict[str, Any] | None:
        return self._users.get_session(session_token)

    def delete_session(self, session_token: str) -> bool:
        return self._users.delete_session(session_token)

    def cleanup_expired_sessions(self) -> int:
        return self._users.cleanup_expired_sessions()

    # -- Emitters (delegated to EmitterStore) --------------------------------

    def upsert_emitters(self, emitters: list[dict[str, Any]]) -> int:
        return self._emitter.upsert_emitters(emitters)

    def list_emitters(
        self,
        limit: int = 100,
        offset: int = 0,
        signal_class: str | None = None,
        min_detections: int = 0,
    ) -> list[dict[str, Any]]:
        return self._emitter.list_emitters(
            limit=limit,
            offset=offset,
            signal_class=signal_class,
            min_detections=min_detections,
        )

    def get_emitter(self, emitter_id: str) -> dict[str, Any] | None:
        return self._emitter.get_emitter(emitter_id)

    def delete_all_emitters(self) -> int:
        return self._emitter.delete_all()

    def count_emitters(self) -> int:
        return self._emitter.count()

    # -- Lifecycle ----------------------------------------------------------

    def cache_stats(self) -> dict[str, Any]:
        return self._ctx.cache_stats()

    def close(self) -> None:
        self._ctx.close()
