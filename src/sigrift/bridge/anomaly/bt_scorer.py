"""Bluetooth anomaly detection — baselines and scoring.

Tracks per-device_addr baselines using EWMA for signal strength.
Scores 6 threat dimensions: spoofed identity, rogue device, RSSI
anomaly, service change, BLE beacon spoof, and device surge.

Priority levels (same as RF and WiFi scorers):
    Normal      0.0 – 0.3
    Info        0.3 – 0.7
    Warning     0.7 – 0.85
    Critical    0.85 – 1.0
"""

from __future__ import annotations

import html
import json
import logging
import math
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from sigrift.bridge.anomaly.baseline import json_snapshot, write_json_atomic

logger = logging.getLogger(__name__)


def _same_text(observed: str, expected: str) -> bool:
    """True when an observed name equals the baseline's.

    Also when the baseline learned it html.escape()d, as
    /api/bluetooth/ingest stored names before it stored them as heard;
    BtBaseline.update() then keeps the name as heard.
    """
    return observed == expected or html.escape(observed) == expected


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MIN_LEARNING_OBSERVATIONS = 30

_DIMENSION_WEIGHTS: dict[str, float] = {
    "spoofed_identity": 0.25,
    "rogue_device": 0.20,
    "rssi_anomaly": 0.15,
    "service_change": 0.15,
    "ble_beacon_spoof": 0.15,
    "device_surge": 0.10,
}


# ---------------------------------------------------------------------------
# BtBaseline
# ---------------------------------------------------------------------------


@dataclass
class BtBaseline:
    """Tracks baseline statistics for a single Bluetooth device address.

    Parameters
    ----------
    alpha : float
        EWMA decay factor.  Smaller = slower adaptation.
    """

    alpha: float = 0.02

    expected_name: str = ""
    expected_device_class: int = 0
    expected_manufacturer: str = ""
    expected_service_uuids: set[str] = field(default_factory=set)

    rssi_ewma: float = 0.0
    rssi_m2: float = 0.0

    total_observations: int = 0
    first_seen: str = ""
    last_seen: str = ""

    def update(
        self,
        device_name: str,
        device_class: int,
        manufacturer: str,
        service_uuids: set[str],
        rssi_dbm: float,
    ) -> None:
        """Update all trackers with a new observation."""
        self.total_observations += 1
        now = datetime.now(timezone.utc).isoformat()
        if not self.first_seen:
            self.first_seen = now
        self.last_seen = now

        # Device name — track first-seen (one learned escaped is replaced by
        # the same name as heard; see _same_text)
        if device_name and (
            not self.expected_name or _same_text(device_name, self.expected_name)
        ):
            self.expected_name = device_name

        # Device class (CoD) — track first-seen
        if self.expected_device_class == 0 and device_class != 0:
            self.expected_device_class = device_class

        # Manufacturer — track first-seen (as for the name)
        if manufacturer and (
            not self.expected_manufacturer
            or _same_text(manufacturer, self.expected_manufacturer)
        ):
            self.expected_manufacturer = manufacturer

        # Service UUIDs — accumulate all seen UUIDs
        if service_uuids:
            self.expected_service_uuids.update(service_uuids)

        # RSSI EWMA + Welford online variance
        if self.total_observations == 1:
            self.rssi_ewma = rssi_dbm
            self.rssi_m2 = 0.0
        else:
            delta = rssi_dbm - self.rssi_ewma
            self.rssi_ewma = self.alpha * rssi_dbm + (1 - self.alpha) * self.rssi_ewma
            self.rssi_m2 = (1 - self.alpha) * (
                self.rssi_m2 + self.alpha * delta * delta
            )

    def is_learning(self) -> bool:
        """Return True if still in cold-start learning phase."""
        return self.total_observations < _MIN_LEARNING_OBSERVATIONS

    def rssi_zscore(self, rssi_dbm: float) -> float:
        """Return z-score of rssi_dbm vs the running baseline."""
        if self.total_observations < 2 or self.rssi_m2 <= 0:
            return 0.0
        std = math.sqrt(self.rssi_m2)
        if std < 1e-9:
            return 0.0
        return (rssi_dbm - self.rssi_ewma) / std

    def to_dict(self) -> dict[str, Any]:
        """Serialize baseline to a JSON-compatible dict."""
        return {
            "alpha": self.alpha,
            "expected_name": self.expected_name,
            "expected_device_class": self.expected_device_class,
            "expected_manufacturer": self.expected_manufacturer,
            "expected_service_uuids": sorted(self.expected_service_uuids),
            "rssi_ewma": self.rssi_ewma,
            "rssi_m2": self.rssi_m2,
            "total_observations": self.total_observations,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BtBaseline:
        """Deserialize baseline from a dict."""
        bl = cls(alpha=data.get("alpha", 0.02))
        bl.expected_name = data.get("expected_name", "")
        bl.expected_device_class = data.get("expected_device_class", 0)
        bl.expected_manufacturer = data.get("expected_manufacturer", "")
        bl.expected_service_uuids = set(data.get("expected_service_uuids", []))
        bl.rssi_ewma = data.get("rssi_ewma", 0.0)
        bl.rssi_m2 = data.get("rssi_m2", 0.0)
        bl.total_observations = data.get("total_observations", 0)
        bl.first_seen = data.get("first_seen", "")
        bl.last_seen = data.get("last_seen", "")
        return bl


# ---------------------------------------------------------------------------
# BtBaselineManager
# ---------------------------------------------------------------------------


class BtBaselineManager:
    """Manages per-device_addr baselines for Bluetooth anomaly detection."""

    SCHEMA_VERSION = 1

    def __init__(self, alpha: float = 0.02) -> None:
        self.alpha = alpha
        self.baselines: dict[str, BtBaseline] = {}
        self._batch_device_counts: list[int] = []
        # Unsaved-update counter for the bridge periodic autosave.
        self.updates_since_save = 0
        # Guards the baselines and batch counts.  score_batch() runs in a
        # worker thread while the autosave's prune()/save() run in another;
        # iterating the dict while a batch added devices raised "dictionary
        # changed size during iteration".  Held by update(), prune(),
        # save() (snapshot only), replace_state()/load() and by the scorer
        # for a whole batch.  Re-entrant.
        self._lock = threading.RLock()

    @property
    def lock(self) -> threading.RLock:
        """The manager lock (re-entrant)."""
        return self._lock

    @property
    def dirty(self) -> bool:
        """True if there are unsaved updates since the last save()."""
        return self.updates_since_save > 0

    def replace_state(
        self,
        baselines: dict[str, BtBaseline],
        batch_device_counts: list[int] | None = None,
        alpha: float | None = None,
    ) -> None:
        """Swap in a new baseline set (e.g. from a kind=export bundle apply).

        Swapped under the manager lock.
        """
        with self._lock:
            self.baselines = baselines
            if batch_device_counts is not None:
                self._batch_device_counts = batch_device_counts
            if alpha is not None:
                self.alpha = alpha
            self.updates_since_save += 1

    def update(self, device_addr: str, record: dict[str, Any]) -> BtBaseline:
        """Update or create baseline for a device address."""
        with self._lock:
            if device_addr not in self.baselines:
                self.baselines[device_addr] = BtBaseline(alpha=self.alpha)

            baseline = self.baselines[device_addr]
            baseline.update(
                device_name=record.get("device_name", ""),
                device_class=record.get("device_class", 0),
                manufacturer=record.get("manufacturer", ""),
                service_uuids=set(record.get("service_uuids", [])),
                rssi_dbm=record.get("rssi_dbm", 0.0),
            )
            self.updates_since_save += 1
        return baseline

    def get(self, device_addr: str) -> BtBaseline | None:
        """Get baseline for a device address, or None if not tracked."""
        return self.baselines.get(device_addr)

    def record_batch_size(self, count: int) -> None:
        """Record the number of unique devices in a batch for surge detection."""
        with self._lock:
            self._batch_device_counts.append(count)
            # Keep last 100 batch counts
            if len(self._batch_device_counts) > 100:
                self._batch_device_counts = self._batch_device_counts[-100:]

    def avg_batch_device_count(self) -> float:
        """Return average unique device count across recent batches."""
        with self._lock:
            if not self._batch_device_counts:
                return 0.0
            return sum(self._batch_device_counts) / len(self._batch_device_counts)

    def save(self, path: Path) -> None:
        """Serialize all baselines to JSON file (atomic write).

        The state is snapshotted under the manager lock and written after
        releasing it, so scoring is not blocked on file I/O.
        """
        with self._lock:
            data = {
                "schema_version": self.SCHEMA_VERSION,
                "alpha": self.alpha,
                "baselines": {
                    addr: json_snapshot(bl.to_dict())
                    for addr, bl in self.baselines.items()
                },
                "batch_device_counts": list(self._batch_device_counts),
                "saved_at": datetime.now(timezone.utc).isoformat(),
            }
            saved_updates = self.updates_since_save
        write_json_atomic(Path(path), data)
        with self._lock:
            # Updates made while writing stay pending for the next save.
            self.updates_since_save = max(0, self.updates_since_save - saved_updates)
        logger.info("BT baselines saved: %d devices → %s", len(data["baselines"]), path)

    def load(self, path: Path) -> None:
        """Load baselines from JSON file."""
        p = Path(path)
        if not p.exists():
            logger.warning("BT baseline file not found: %s", path)
            return
        try:
            with open(p, encoding="utf-8") as f:
                data = json.load(f)
            raw = data.get("baselines", {})
            loaded: dict[str, BtBaseline] = {}
            for addr, bl_data in raw.items():
                loaded[addr] = BtBaseline.from_dict(bl_data)
            with self._lock:
                self.alpha = data.get("alpha", self.alpha)
                self.baselines = loaded
                self._batch_device_counts = data.get("batch_device_counts", [])
            logger.info(
                "BT baselines loaded: %d devices from %s", len(self.baselines), path
            )
        except (json.JSONDecodeError, OSError, KeyError) as exc:
            logger.warning("Failed to load BT baselines from %s: %s", path, exc)

    def prune(self, max_age_hours: int = 168) -> int:
        """Remove baselines not seen within max_age_hours. Returns count removed."""
        cutoff = datetime.now(timezone.utc)
        removed = 0
        stale_addrs: list[str] = []
        with self._lock:
            for addr, bl in self.baselines.items():
                if not bl.last_seen:
                    stale_addrs.append(addr)
                    continue
                try:
                    last = datetime.fromisoformat(bl.last_seen)
                    age_hours = (cutoff - last).total_seconds() / 3600.0
                    if age_hours > max_age_hours:
                        stale_addrs.append(addr)
                except (ValueError, TypeError):
                    stale_addrs.append(addr)

            for addr in stale_addrs:
                del self.baselines[addr]
                removed += 1

        if removed:
            logger.info(
                "Pruned %d stale BT baselines (max_age=%dh)", removed, max_age_hours
            )
        return removed


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------


class BtAnomalyResult(BaseModel):
    """Result of anomaly scoring for a single Bluetooth device."""

    device_addr: str
    device_name: str = ""
    device_type: str = ""
    device_class: int = 0
    manufacturer: str = ""
    vendor: str = ""

    rssi_dbm: float = 0.0
    anomaly_score: float = Field(ge=0.0, le=1.0)
    priority: str = "normal"
    dimensions: dict[str, float] = Field(default_factory=dict)
    reasons: list[str] = Field(default_factory=list)

    baseline_status: str = "stable"
    expected_rssi: float | None = None
    rssi_zscore: float = 0.0
    baseline_observations: int = 0

    service_uuids: list[str] = Field(default_factory=list)
    node_id: str = ""
    timestamp: str = ""


# ---------------------------------------------------------------------------
# BtAnomalyScorer
# ---------------------------------------------------------------------------


class BtAnomalyScorer:
    """Scores Bluetooth observations against per-device baselines.

    Parameters
    ----------
    baseline_mgr : BtBaselineManager
        Manager holding per-device baselines.
    insert_threshold : float
        Minimum score to include in results.
    alert_threshold : float
        Score threshold for warning priority.
    critical_threshold : float
        Score threshold for critical priority.
    """

    def __init__(
        self,
        baseline_mgr: BtBaselineManager,
        insert_threshold: float = 0.3,
        alert_threshold: float = 0.7,
        critical_threshold: float = 0.85,
    ) -> None:
        self.baseline_mgr = baseline_mgr
        self.insert_threshold = insert_threshold
        self.alert_threshold = alert_threshold
        self.critical_threshold = critical_threshold

    def score_batch(
        self,
        records: list[dict[str, Any]],
        node_id: str,
    ) -> list[BtAnomalyResult]:
        """Score a batch of Bluetooth records.

        Groups records by device_addr, scores each device once per batch,
        updates baselines after scoring, and returns results for devices
        with anomaly_score > 0.

        Runs under the baseline manager's lock (concurrent batches and the
        autosave run in other threads).
        """
        with self.baseline_mgr.lock:
            return self._score_batch_locked(records, node_id)

    def _score_batch_locked(
        self,
        records: list[dict[str, Any]],
        node_id: str,
    ) -> list[BtAnomalyResult]:
        # Group by device_addr
        groups: dict[str, list[dict[str, Any]]] = {}
        for rec in records:
            addr = rec.get("device_addr", "")
            if not addr:
                continue
            groups.setdefault(addr, []).append(rec)

        # Record batch device count for surge detection
        unique_device_count = len(groups)
        self.baseline_mgr.record_batch_size(unique_device_count)

        results: list[BtAnomalyResult] = []
        now = datetime.now(timezone.utc).isoformat()

        for device_addr, recs in groups.items():
            # Aggregate: mean RSSI across batch records for this device
            rssi_vals = [r.get("rssi_dbm", 0.0) for r in recs]
            mean_rssi = sum(rssi_vals) / len(rssi_vals) if rssi_vals else 0.0

            # Use first record for metadata
            first = recs[0]
            device_name = first.get("device_name", "")
            device_type = first.get("device_type", "")
            device_class = first.get("device_class", 0)
            manufacturer = first.get("manufacturer", "")
            vendor = first.get("vendor", "")
            service_uuids = list(first.get("service_uuids", []))

            aggregate = {
                "device_addr": device_addr,
                "device_name": device_name,
                "device_type": device_type,
                "device_class": device_class,
                "manufacturer": manufacturer,
                "vendor": vendor,
                "rssi_dbm": mean_rssi,
                "service_uuids": service_uuids,
            }

            result = self._score_device(
                device_addr,
                aggregate,
                unique_device_count,
                node_id,
                now,
            )
            if result.anomaly_score > 0:
                results.append(result)

            # Update baseline AFTER scoring
            self.baseline_mgr.update(device_addr, aggregate)

        return results

    def reevaluate(self, record: dict[str, Any]) -> BtAnomalyResult:
        """Re-evaluate a single device record against current baselines.

        Parameters
        ----------
        record : dict
            Device record with at least ``device_addr``, ``device_name``,
            ``device_class``, ``manufacturer``, ``rssi_dbm``,
            ``service_uuids``, ``node_id``.

        Returns
        -------
        BtAnomalyResult with current scoring against baselines.
        """
        device_addr = record.get("device_addr", "")
        node_id = record.get("node_id", "")
        now = datetime.now(timezone.utc).isoformat()

        agg = {
            "device_addr": device_addr,
            "device_name": record.get("device_name", ""),
            "device_type": record.get("device_type", ""),
            "device_class": record.get("device_class", 0),
            "manufacturer": record.get("manufacturer", ""),
            "vendor": record.get("vendor", ""),
            "rssi_dbm": record.get("rssi_dbm", 0.0),
            "service_uuids": record.get("service_uuids", []),
        }

        # Use current batch avg for surge dimension (no surge in single re-eval)
        with self.baseline_mgr.lock:
            return self._score_device(device_addr, agg, 0, node_id, now)

    def _score_device(
        self,
        device_addr: str,
        agg: dict[str, Any],
        batch_device_count: int,
        node_id: str,
        timestamp: str,
    ) -> BtAnomalyResult:
        """Score a single Bluetooth device against its baseline."""
        baseline = self.baseline_mgr.get(device_addr)
        is_learning = baseline is None or baseline.is_learning()
        baseline_status = "learning" if is_learning else "stable"
        if baseline is None:
            baseline_status = "new"

        dimensions: dict[str, float] = {}
        reasons: list[str] = []

        device_name = agg.get("device_name", "")
        device_class = agg.get("device_class", 0)
        manufacturer = agg.get("manufacturer", "")
        rssi_dbm = agg.get("rssi_dbm", 0.0)
        service_uuids = set(agg.get("service_uuids", []))

        # 1. Spoofed identity — device name or class changed from baseline
        spoof = self._spoofed_identity_score(baseline, device_name, device_class)
        dimensions["spoofed_identity"] = spoof
        if spoof > 0.5:
            parts = []
            if (
                baseline
                and device_name
                and baseline.expected_name
                and not _same_text(device_name, baseline.expected_name)
            ):
                parts.append(f"name '{baseline.expected_name}' → '{device_name}'")
            if (
                baseline
                and device_class
                and baseline.expected_device_class
                and device_class != baseline.expected_device_class
            ):
                parts.append(
                    f"class 0x{baseline.expected_device_class:06X} → 0x{device_class:06X}"
                )
            reasons.append(
                "Spoofed identity: " + ", ".join(parts)
                if parts
                else f"Identity change on {device_addr}"
            )

        # 2. Rogue device — never seen before
        rogue = self._rogue_device_score(baseline)
        dimensions["rogue_device"] = rogue
        if rogue > 0.5:
            reasons.append(
                f"New device: {device_addr}"
                + (f" ({device_name})" if device_name else "")
            )

        # 3. RSSI anomaly — signal z-score after learning phase
        rssi_anom = self._rssi_anomaly_score(baseline, rssi_dbm)
        dimensions["rssi_anomaly"] = rssi_anom
        if rssi_anom > 0.5:
            reasons.append(f"Unusual RSSI: {rssi_dbm:.1f} dBm")

        # 4. Service change — service UUIDs changed from baseline
        svc = self._service_change_score(baseline, service_uuids)
        dimensions["service_change"] = svc
        if svc > 0.5:
            reasons.append("Service UUIDs changed from baseline")

        # 5. BLE beacon spoof — different manufacturer for known device name
        beacon = self._ble_beacon_spoof_score(baseline, device_name, manufacturer)
        dimensions["ble_beacon_spoof"] = beacon
        if beacon > 0.5:
            expected_mfr = baseline.expected_manufacturer if baseline else "?"
            reasons.append(
                f"BLE beacon spoof: manufacturer '{expected_mfr}' → '{manufacturer}'"
            )

        # 6. Device surge — device count in batch > 2x baseline avg
        surge = self._device_surge_score(batch_device_count)
        dimensions["device_surge"] = surge
        if surge > 0.5:
            avg = self.baseline_mgr.avg_batch_device_count()
            reasons.append(f"Device surge: {batch_device_count} vs avg {avg:.0f}")

        # Composite score
        composite = 0.0
        for dim, weight in _DIMENSION_WEIGHTS.items():
            composite += weight * dimensions.get(dim, 0.0)

        # Low observation count dampening
        obs = baseline.total_observations if baseline else 0
        if obs > 0:
            composite *= min(1.0, obs / 10.0)

        # Learning-phase dampening
        if is_learning:
            composite *= 0.5

        composite = max(0.0, min(1.0, composite))
        priority = self._priority_label(composite)

        # Baseline comparison snapshots
        expected_rssi: float | None = None
        rssi_z = 0.0
        baseline_obs = 0
        if baseline is not None:
            expected_rssi = baseline.rssi_ewma
            rssi_z = baseline.rssi_zscore(rssi_dbm)
            baseline_obs = baseline.total_observations

        return BtAnomalyResult(
            device_addr=device_addr,
            device_name=agg.get("device_name", ""),
            device_type=agg.get("device_type", ""),
            device_class=agg.get("device_class", 0),
            manufacturer=agg.get("manufacturer", ""),
            vendor=agg.get("vendor", ""),
            rssi_dbm=agg.get("rssi_dbm", 0.0),
            anomaly_score=round(composite, 4),
            priority=priority,
            dimensions={k: round(v, 4) for k, v in dimensions.items()},
            reasons=reasons,
            baseline_status=baseline_status,
            expected_rssi=expected_rssi,
            rssi_zscore=round(rssi_z, 4),
            baseline_observations=baseline_obs,
            service_uuids=list(agg.get("service_uuids", [])),
            node_id=node_id,
            timestamp=timestamp,
        )

    # -------------------------------------------------------------------
    # Dimension scorers
    # -------------------------------------------------------------------

    @staticmethod
    def _spoofed_identity_score(
        baseline: BtBaseline | None,
        device_name: str,
        device_class: int,
    ) -> float:
        """Score identity spoofing: name or CoD changed from baseline.

        Returns 1.0 if both name and class changed, 0.7 if only one
        changed.  Returns 0.0 during learning or if no change detected.
        """
        if baseline is None:
            return 0.0
        if baseline.total_observations < 2:
            return 0.0

        name_changed = (
            device_name
            and baseline.expected_name
            and not _same_text(device_name, baseline.expected_name)
        )
        class_changed = (
            device_class != 0
            and baseline.expected_device_class != 0
            and device_class != baseline.expected_device_class
        )

        if name_changed and class_changed:
            return 1.0
        if name_changed or class_changed:
            return 0.7
        return 0.0

    @staticmethod
    def _rogue_device_score(baseline: BtBaseline | None) -> float:
        """1.0 if device has never been seen before."""
        if baseline is None:
            return 1.0
        return 0.0

    @staticmethod
    def _rssi_anomaly_score(
        baseline: BtBaseline | None,
        rssi_dbm: float,
    ) -> float:
        """Sigmoid of rssi_dbm z-score vs EWMA: abs(z)/(abs(z)+3)."""
        if baseline is None:
            return 0.0
        z = baseline.rssi_zscore(rssi_dbm)
        abs_z = abs(z)
        return min(1.0, abs_z / (abs_z + 3.0))

    @staticmethod
    def _service_change_score(
        baseline: BtBaseline | None,
        current_uuids: set[str],
    ) -> float:
        """Score service UUID changes from baseline.

        Returns 1.0 if known UUIDs disappeared (potential spoof),
        0.5 if new UUIDs appeared (less suspicious — firmware update).
        """
        if baseline is None or not baseline.expected_service_uuids:
            return 0.0
        if not current_uuids:
            return 0.0

        removed = baseline.expected_service_uuids - current_uuids
        added = current_uuids - baseline.expected_service_uuids

        if removed:
            return 1.0
        if added:
            return 0.5
        return 0.0

    @staticmethod
    def _ble_beacon_spoof_score(
        baseline: BtBaseline | None,
        device_name: str,
        manufacturer: str,
    ) -> float:
        """Score BLE beacon spoofing: different manufacturer for known name.

        Returns 1.0 if manufacturer differs for a device with a known name
        and established manufacturer baseline.
        """
        if baseline is None:
            return 0.0
        if not device_name or not baseline.expected_name:
            return 0.0
        if not _same_text(device_name, baseline.expected_name):
            return 0.0  # Different name → handled by spoofed_identity
        if not manufacturer or not baseline.expected_manufacturer:
            return 0.0
        if not _same_text(manufacturer, baseline.expected_manufacturer):
            return 1.0
        return 0.0

    def _device_surge_score(self, batch_device_count: int) -> float:
        """Score device surges > 2x the baseline average, clamped to [0, 1].

        Maps 2x → 0, 5x → 1.
        """
        avg = self.baseline_mgr.avg_batch_device_count()
        if avg < 1:
            return 0.0
        ratio = batch_device_count / avg
        if ratio <= 2.0:
            return 0.0
        return min(1.0, (ratio - 2.0) / 3.0)

    # -------------------------------------------------------------------
    # Priority
    # -------------------------------------------------------------------

    def _priority_label(self, score: float) -> str:
        """Map composite score to priority label."""
        if score >= self.critical_threshold:
            return "critical"
        elif score >= self.alert_threshold:
            return "warning"
        elif score >= self.insert_threshold:
            return "info"
        return "normal"
