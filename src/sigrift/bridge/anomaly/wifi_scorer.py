"""WiFi anomaly detection — baselines and scoring.

Tracks per-BSSID baselines using EWMA for signal strength, client
count, and retry rate.  Scores 7 threat dimensions: evil twin,
security downgrade, signal anomaly, new network, channel change,
client surge, and deauth indicator.

Priority levels (same as RF scorer):
    Normal      0.0 – 0.3
    Interesting 0.3 – 0.5
    Anomalous   0.5 – 0.7
    Critical    0.7 – 1.0
"""

from __future__ import annotations

import json
import logging
import math
import re
import threading
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from sigrift.bridge.anomaly.baseline import json_snapshot, write_json_atomic

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MIN_LEARNING_OBSERVATIONS = 50

_SECURITY_HIERARCHY: dict[str, int] = {
    "WPA3": 4,
    "WPA2": 3,
    "WPA": 2,
    # Compatibility mode still advertises the older WPA protocol.
    "WPA2/WPA": 2,
    "WEP": 1,
    "Open": 0,
}

_DIMENSION_WEIGHTS: dict[str, float] = {
    "evil_twin": 0.25,
    "security_downgrade": 0.22,
    "signal_anomaly": 0.13,
    "deauth_indicator": 0.15,
    "new_network": 0.10,
    "channel_change": 0.08,
    "client_surge": 0.07,
}


# ---------------------------------------------------------------------------
# WifiBaseline
# ---------------------------------------------------------------------------


@dataclass
class WifiBaseline:
    """Tracks baseline statistics for a single BSSID.

    Parameters
    ----------
    alpha : float
        EWMA decay factor.  Smaller = slower adaptation.
    """

    alpha: float = 0.02

    expected_ssids: set[str] = field(default_factory=set)
    expected_channel: int | None = None
    expected_security: str = ""
    expected_vendor: str = ""
    seen_channels: set[int] = field(default_factory=set)

    signal_ewma: float = 0.0
    signal_var: float = 0.0

    client_count_ewma: float = 0.0
    retry_rate_ewma: float = 0.0

    total_observations: int = 0

    def update(
        self,
        ssid: str,
        channel: int,
        security: str,
        signal_dbm: float,
        client_count: int,
        retry_rate: float,
        hour: int,
        vendor: str = "",
    ) -> None:
        """Update all trackers with a new observation."""
        self.total_observations += 1

        # SSIDs
        if ssid:
            self.expected_ssids.add(ssid)

        # Channel — track first-seen and history
        if channel > 0:
            self.seen_channels.add(channel)
        if self.expected_channel is None and channel > 0:
            self.expected_channel = channel

        # Learn the first recognized protocol. Missing/unspecified metadata
        # cannot pin a baseline, including one restored from an older version.
        if (
            self.expected_security not in _SECURITY_HIERARCHY
            and security in _SECURITY_HIERARCHY
        ):
            self.expected_security = security

        # Vendor — track first-seen
        if not self.expected_vendor and vendor:
            self.expected_vendor = vendor

        # Signal EWMA + Welford online variance
        if self.total_observations == 1:
            self.signal_ewma = signal_dbm
            self.signal_var = 0.0
        else:
            delta = signal_dbm - self.signal_ewma
            self.signal_ewma = (
                self.alpha * signal_dbm + (1 - self.alpha) * self.signal_ewma
            )
            self.signal_var = (1 - self.alpha) * (
                self.signal_var + self.alpha * delta * delta
            )

        # Client count EWMA
        self.client_count_ewma = (
            self.alpha * client_count + (1 - self.alpha) * self.client_count_ewma
        )

        # Retry rate EWMA
        self.retry_rate_ewma = (
            self.alpha * retry_rate + (1 - self.alpha) * self.retry_rate_ewma
        )

    def is_learning(self) -> bool:
        """Return True if still in cold-start learning phase."""
        return self.total_observations < _MIN_LEARNING_OBSERVATIONS

    def signal_zscore(self, signal_dbm: float) -> float:
        """Return z-score of signal_dbm vs the running baseline."""
        if self.total_observations < 2 or self.signal_var <= 0:
            return 0.0
        std = math.sqrt(self.signal_var)
        if std < 1e-9:
            return 0.0
        return (signal_dbm - self.signal_ewma) / std

    def to_dict(self) -> dict[str, Any]:
        """Serialize baseline to a JSON-compatible dict."""
        return {
            "alpha": self.alpha,
            "expected_ssids": sorted(self.expected_ssids),
            "expected_channel": self.expected_channel,
            "expected_security": self.expected_security,
            "expected_vendor": self.expected_vendor,
            "seen_channels": sorted(self.seen_channels),
            "signal_ewma": self.signal_ewma,
            "signal_var": self.signal_var,
            "client_count_ewma": self.client_count_ewma,
            "retry_rate_ewma": self.retry_rate_ewma,
            "total_observations": self.total_observations,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WifiBaseline:
        """Deserialize baseline from a dict."""
        bl = cls(alpha=data.get("alpha", 0.02))
        bl.expected_ssids = set(data.get("expected_ssids", []))
        bl.expected_channel = data.get("expected_channel")
        bl.expected_security = data.get("expected_security", "")
        bl.expected_vendor = data.get("expected_vendor", "")
        bl.seen_channels = set(data.get("seen_channels", []))
        bl.signal_ewma = data.get("signal_ewma", 0.0)
        bl.signal_var = data.get("signal_var", 0.0)
        bl.client_count_ewma = data.get("client_count_ewma", 0.0)
        bl.retry_rate_ewma = data.get("retry_rate_ewma", 0.0)
        bl.total_observations = data.get("total_observations", 0)
        return bl


def stores_escaped_ssids(state: Any) -> bool:
    """True for a saved state (file or bundle) from before SSIDs were raw.

    Schema 1 states hold the SSIDs as every Wi-Fi ingest route stored them
    then: html.escape()d once.  Schema 2 states hold them as heard.
    """
    version = state.get("schema_version") if isinstance(state, dict) else None
    return not (isinstance(version, int) and version >= 2)


# The five entities html.escape() writes, and nothing else.
_ESCAPED_ENTITIES = {
    "&amp;": "&",
    "&lt;": "<",
    "&gt;": ">",
    "&quot;": '"',
    "&#x27;": "'",
}
_ESCAPED_ENTITY_RE = re.compile("|".join(_ESCAPED_ENTITIES))


def unescape_once(text: str) -> str:
    """Undo one html.escape(): the exact inverse for text escaped once.

    Unlike html.unescape(), it decodes only the five entities html.escape()
    writes, in one pass.  A schema 1 file saved by an older bridge after a
    rollback can mix escaped SSIDs with raw ones, and html.unescape() would
    also rewrite raw text such as "Bob&copy" (a legacy entity name) or
    "AP&#38;1".
    """
    return _ESCAPED_ENTITY_RE.sub(lambda m: _ESCAPED_ENTITIES[m.group(0)], text)


def decode_escaped_ssids(
    baselines: dict[str, WifiBaseline], ssid_to_bssids: dict[str, set[str]]
) -> dict[str, set[str]]:
    """Undo the one html.escape() layer of a schema 1 state.

    Decodes each baseline's expected SSIDs in place and returns the SSID
    index re-keyed (see unescape_once).
    """
    for baseline in baselines.values():
        baseline.expected_ssids = {unescape_once(s) for s in baseline.expected_ssids}
    decoded: dict[str, set[str]] = {}
    for ssid, bssids in ssid_to_bssids.items():
        decoded.setdefault(unescape_once(ssid), set()).update(bssids)
    return decoded


# ---------------------------------------------------------------------------
# WifiBaselineManager
# ---------------------------------------------------------------------------


class WifiBaselineManager:
    """Manages per-BSSID baselines for WiFi anomaly detection."""

    # 2: SSIDs as heard (schema 1 held them HTML-escaped; see
    # stores_escaped_ssids).
    SCHEMA_VERSION = 2

    def __init__(self, alpha: float = 0.02) -> None:
        self.alpha = alpha
        self.baselines: dict[str, WifiBaseline] = {}
        self._ssid_to_bssids: dict[str, set[str]] = {}
        # Unsaved-update counter for the bridge periodic autosave.
        self.updates_since_save = 0
        # Guards the baselines and the SSID index.  score_batch() runs in a
        # worker thread (asyncio.to_thread) while the autosave's save() runs
        # in another: without one lock, save iterating these dicts while a
        # batch adds BSSIDs raised "dictionary changed size during
        # iteration" and the baselines stopped being persisted.  Held by
        # update(), save() (snapshot only), replace_state()/load() and by
        # the scorer for a whole batch.  Re-entrant.
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
        baselines: dict[str, WifiBaseline],
        ssid_to_bssids: dict[str, set[str]] | None = None,
        alpha: float | None = None,
    ) -> None:
        """Swap in a new baseline set (e.g. from a kind=export bundle apply).

        Swapped under the manager lock.
        """
        with self._lock:
            self.baselines = baselines
            if ssid_to_bssids is not None:
                self._ssid_to_bssids = ssid_to_bssids
            if alpha is not None:
                self.alpha = alpha
            self.updates_since_save += 1

    def update(
        self,
        bssid: str,
        ssid: str,
        channel: int,
        security: str,
        signal_dbm: float,
        client_count: int,
        retry_rate: float,
        hour: int,
        vendor: str = "",
    ) -> WifiBaseline:
        """Update or create baseline for a BSSID."""
        with self._lock:
            if bssid not in self.baselines:
                self.baselines[bssid] = WifiBaseline(alpha=self.alpha)

            baseline = self.baselines[bssid]
            baseline.update(
                ssid,
                channel,
                security,
                signal_dbm,
                client_count,
                retry_rate,
                hour,
                vendor=vendor,
            )

            # Maintain reverse SSID→BSSID index
            if ssid:
                if ssid not in self._ssid_to_bssids:
                    self._ssid_to_bssids[ssid] = set()
                self._ssid_to_bssids[ssid].add(bssid)

            self.updates_since_save += 1
        return baseline

    def get_baseline(self, bssid: str) -> WifiBaseline | None:
        """Get baseline for a BSSID, or None if not tracked."""
        return self.baselines.get(bssid)

    def get_bssids_for_ssid(self, ssid: str) -> set[str]:
        """Return all BSSIDs known to broadcast a given SSID (a copy)."""
        with self._lock:
            return set(self._ssid_to_bssids.get(ssid, ()))

    def save(self, path: str) -> None:
        """Serialize all baselines to JSON file (atomic write).

        The state is snapshotted under the manager lock and written after
        releasing it, so scoring is not blocked on file I/O.
        """
        with self._lock:
            data = {
                "schema_version": self.SCHEMA_VERSION,
                "alpha": self.alpha,
                "baselines": {
                    bssid: json_snapshot(bl.to_dict())
                    for bssid, bl in self.baselines.items()
                },
                "ssid_to_bssids": {
                    ssid: sorted(bssids)
                    for ssid, bssids in self._ssid_to_bssids.items()
                },
                "saved_at": datetime.now(timezone.utc).isoformat(),
            }
            saved_updates = self.updates_since_save
        write_json_atomic(Path(path), data)
        with self._lock:
            # Updates made while writing stay pending for the next save.
            self.updates_since_save = max(0, self.updates_since_save - saved_updates)
        logger.info(
            "WiFi baselines saved: %d BSSIDs → %s", len(data["baselines"]), path
        )

    def load(self, path: str) -> None:
        """Load baselines from JSON file."""
        p = Path(path)
        if not p.exists():
            logger.warning("WiFi baseline file not found: %s", path)
            return
        try:
            with open(p, encoding="utf-8") as f:
                data = json.load(f)
            self.alpha = data.get("alpha", self.alpha)
            raw = data.get("baselines", {})
            self.baselines = {}
            for bssid, bl_data in raw.items():
                self.baselines[bssid] = WifiBaseline.from_dict(bl_data)
            raw_ssid = data.get("ssid_to_bssids", {})
            self._ssid_to_bssids = {
                ssid: set(bssids) for ssid, bssids in raw_ssid.items()
            }
            if stores_escaped_ssids(data):
                # Matched against SSIDs as heard from now on; saved as
                # schema 2 on the next save.
                self._ssid_to_bssids = decode_escaped_ssids(
                    self.baselines, self._ssid_to_bssids
                )
                self.updates_since_save += 1
            logger.info(
                "WiFi baselines loaded: %d BSSIDs from %s", len(self.baselines), path
            )
        except (json.JSONDecodeError, OSError, KeyError) as exc:
            logger.warning("Failed to load WiFi baselines from %s: %s", path, exc)


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------


_MANAGEMENT_FRAME_TYPES = frozenset(
    {
        "deauth",
        "disassociation",
        "authentication",
        "association",
        "probe_response",
    }
)


class WifiAnomalyResult(BaseModel):
    """Result of anomaly scoring for a single BSSID."""

    bssid: str
    ssid: str = ""
    channel: int = 0
    band: str = "2.4GHz"
    security: str = ""
    signal_dbm: float = 0.0
    score: float = Field(ge=0.0, le=1.0)
    priority: str = "normal"
    dimensions: dict[str, float] = Field(default_factory=dict)
    reasons: list[str] = Field(default_factory=list)
    baseline_status: str = "stable"

    # Aggregated batch metrics
    client_count: int = 0
    retry_rate: float = 0.0
    noise_dbm_max: float = 0.0
    data_rate_min: float = 0.0
    data_rate_max: float = 0.0
    channel_width: int = 0
    frame_count: int = 0
    deauth_count: int = 0
    frame_type_counts: dict[str, int] = Field(default_factory=dict)

    # Baseline comparison snapshots
    expected_signal: float | None = None
    signal_zscore: float = 0.0
    expected_channel: int | None = None
    expected_security: str = ""
    expected_client_count: float = 0.0
    expected_retry_rate: float = 0.0
    baseline_observations: int = 0

    # Forensic captures
    client_macs: list[str] = Field(default_factory=list)
    frame_capture: list[dict] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# WifiAnomalyScorer
# ---------------------------------------------------------------------------


class WifiAnomalyScorer:
    """Scores WiFi observations against per-BSSID baselines.

    Parameters
    ----------
    baseline_manager : WifiBaselineManager
        Manager holding per-BSSID baselines.
    max_frame_capture : int
        Maximum number of frames to capture per anomaly result.
    """

    def __init__(
        self,
        baseline_manager: WifiBaselineManager,
        max_frame_capture: int = 50,
    ) -> None:
        self.baseline_manager = baseline_manager
        self.max_frame_capture = max_frame_capture
        self._whitelisted_bssids: set[str] = set()

    def set_whitelist(self, entries: list[dict[str, Any]]) -> None:
        """Update the set of whitelisted BSSIDs from persistence data."""
        self._whitelisted_bssids = {
            e["bssid"].upper() for e in entries if e.get("bssid")
        }

    def update_weights(self, weights: dict[str, float]) -> None:
        """Update dimension weights at runtime.

        Parameters
        ----------
        weights : dict[str, float]
            New dimension weights (must sum to ~1.0).  Keys should match
            the existing dimension names.
        """
        global _DIMENSION_WEIGHTS
        _DIMENSION_WEIGHTS = dict(weights)

    def score_batch(
        self,
        records: list[dict[str, Any]],
        node_id: str,
    ) -> list[WifiAnomalyResult]:
        """Score a batch of WiFi records, grouped by BSSID.

        Groups records by BSSID, aggregates (mean signal, unique clients,
        retry rate), scores each BSSID once per batch, updates baselines
        after scoring, and returns results for BSSIDs with score > 0.

        Runs under the baseline manager's lock (concurrent batches and the
        autosave run in other threads).
        """
        with self.baseline_manager.lock:
            return self._score_batch_locked(records, node_id)

    def _score_batch_locked(
        self,
        records: list[dict[str, Any]],
        node_id: str,
    ) -> list[WifiAnomalyResult]:
        # Group by BSSID
        groups: dict[str, list[dict[str, Any]]] = {}
        for rec in records:
            bssid = rec.get("bssid", "")
            if not bssid:
                continue
            groups.setdefault(bssid, []).append(rec)

        results: list[WifiAnomalyResult] = []
        hour = datetime.now(timezone.utc).hour

        for bssid, recs in groups.items():
            # Aggregate
            signals = [r.get("signal_dbm", 0.0) for r in recs]
            mean_signal = sum(signals) / len(signals) if signals else 0.0
            unique_clients = len(
                {r.get("client_mac", "") for r in recs if r.get("client_mac")}
            )
            retry_flags = [r.get("retry_flag", 0) for r in recs]
            retry_rate = sum(retry_flags) / len(retry_flags) if retry_flags else 0.0

            # Use first record for metadata
            first = recs[0]
            ssid = first.get("ssid", "")
            channel = first.get("channel", 0)
            band = first.get("band", "2.4GHz")
            security = first.get("security", "")

            # Enrichment metrics
            noise_vals = [
                r.get("noise_dbm", 0.0) for r in recs if r.get("noise_dbm", 0.0) != 0
            ]
            noise_dbm_max = max(noise_vals) if noise_vals else 0.0
            rate_vals = [
                r.get("data_rate_mbps", 0.0)
                for r in recs
                if r.get("data_rate_mbps", 0.0) > 0
            ]
            data_rate_min = min(rate_vals) if rate_vals else 0.0
            data_rate_max = max(rate_vals) if rate_vals else 0.0
            ch_widths = [
                r.get("channel_width", 0) for r in recs if r.get("channel_width", 0) > 0
            ]
            max_channel_width = max(ch_widths) if ch_widths else 0
            frame_count = len(recs)
            deauth_count = sum(
                1
                for r in recs
                if r.get("frame_type", "") in ("deauth", "disassociation")
            )
            frame_type_counts = dict(
                Counter(
                    r.get("frame_type", "") for r in recs if r.get("frame_type", "")
                )
            )
            client_macs = sorted(
                {r.get("client_mac", "") for r in recs if r.get("client_mac", "")}
            )

            # Prioritized frame capture: management frames first, then by
            # signal deviation from mean, capped at max_frame_capture
            mgmt = [
                r for r in recs if r.get("frame_type", "") in _MANAGEMENT_FRAME_TYPES
            ]
            non_mgmt = [
                r
                for r in recs
                if r.get("frame_type", "") not in _MANAGEMENT_FRAME_TYPES
            ]
            non_mgmt.sort(
                key=lambda r: abs(r.get("signal_dbm", 0.0) - mean_signal), reverse=True
            )
            prioritized = (mgmt + non_mgmt)[: self.max_frame_capture]
            frame_capture = [
                {
                    "frame_type": r.get("frame_type", ""),
                    "client_mac": r.get("client_mac", ""),
                    "signal_dbm": r.get("signal_dbm", 0.0),
                    "data_rate_mbps": r.get("data_rate_mbps", 0.0),
                    "retry_flag": r.get("retry_flag", 0),
                    "ssid": r.get("ssid", ""),
                    "security": r.get("security", ""),
                }
                for r in prioritized
            ]

            # Extract vendor from first record (all recs same BSSID = same vendor)
            vendor = first.get("vendor", "")

            aggregate = {
                "bssid": bssid,
                "ssid": ssid,
                "channel": channel,
                "band": band,
                "security": security,
                "signal_dbm": mean_signal,
                "client_count": unique_clients,
                "retry_rate": retry_rate,
                "noise_dbm_max": noise_dbm_max,
                "data_rate_min": data_rate_min,
                "data_rate_max": data_rate_max,
                "channel_width": max_channel_width,
                "frame_count": frame_count,
                "deauth_count": deauth_count,
                "frame_type_counts": frame_type_counts,
                "client_macs": client_macs,
                "frame_capture": frame_capture,
                "vendor": vendor,
            }

            result = self._score_bssid(bssid, aggregate)
            if result.score > 0:
                results.append(result)

            # Update baseline AFTER scoring
            self.baseline_manager.update(
                bssid=bssid,
                ssid=ssid,
                channel=channel,
                security=security,
                signal_dbm=mean_signal,
                client_count=unique_clients,
                retry_rate=retry_rate,
                hour=hour,
                vendor=vendor,
            )

        return results

    def _score_bssid(
        self,
        bssid: str,
        agg: dict[str, Any],
    ) -> WifiAnomalyResult:
        """Score a single BSSID against its baseline."""
        baseline = self.baseline_manager.get_baseline(bssid)
        is_learning = baseline is None or baseline.is_learning()
        baseline_status = "learning" if is_learning else "stable"
        if baseline is None:
            baseline_status = "new"

        dimensions: dict[str, float] = {}
        reasons: list[str] = []

        ssid = agg["ssid"]
        channel = agg["channel"]
        security = agg["security"]
        signal_dbm = agg["signal_dbm"]
        client_count = agg["client_count"]
        retry_rate = agg["retry_rate"]

        # 1. Evil twin (enhanced with vendor comparison)
        vendor = agg.get("vendor", "")
        evil = self._evil_twin_score(bssid, ssid, vendor=vendor)
        dimensions["evil_twin"] = evil
        if evil > 0.5:
            if vendor:
                reasons.append(
                    f"Possible evil twin: SSID '{ssid}' on different BSSID (vendor: {vendor})"
                )
            else:
                reasons.append(
                    f"Possible evil twin: SSID '{ssid}' seen on different BSSID"
                )

        # 2. Security downgrade
        sec_down = self._security_downgrade_score(baseline, security)
        dimensions["security_downgrade"] = sec_down
        if sec_down > 0.5:
            expected = baseline.expected_security if baseline else "?"
            reasons.append(f"Security downgrade: {expected} → {security or 'Open'}")

        # 3. Signal anomaly
        sig = self._signal_anomaly_score(baseline, signal_dbm)
        dimensions["signal_anomaly"] = sig
        if sig > 0.5:
            reasons.append(f"Unusual signal strength: {signal_dbm:.1f} dBm")

        # 4. New network
        new_net = self._new_network_score(baseline)
        dimensions["new_network"] = new_net
        if new_net > 0.5:
            reasons.append(f"New network: {bssid}")

        # 5. Channel change
        ch_change = self._channel_change_score(baseline, channel)
        dimensions["channel_change"] = ch_change
        if ch_change > 0.5:
            expected_ch = baseline.expected_channel if baseline else "?"
            reasons.append(f"Channel change: {expected_ch} → {channel}")

        # 6. Client surge
        surge = self._client_surge_score(baseline, client_count)
        dimensions["client_surge"] = surge
        if surge > 0.5:
            reasons.append(
                f"Client surge: {client_count} vs expected {baseline.client_count_ewma:.0f}"
                if baseline
                else f"Client surge: {client_count}"
            )

        # 7. Deauth indicator
        deauth_count = agg.get("deauth_count", 0)
        frame_count = agg.get("frame_count", 0)
        deauth = self._deauth_indicator_score(retry_rate, deauth_count, frame_count)
        dimensions["deauth_indicator"] = deauth
        if deauth > 0.3:
            parts = []
            if deauth_count > 0:
                parts.append(f"{deauth_count} deauth frames")
            if frame_count >= 5 and retry_rate > 0.3:
                parts.append(f"retry rate {retry_rate:.1%}")
            reasons.append(
                "Deauth/disruption: " + ", ".join(parts)
                if parts
                else f"High retry rate: {retry_rate:.1%}"
            )

        # Whitelisted AP: suppress new_network, dampen benign dimensions
        is_whitelisted = bssid.upper() in self._whitelisted_bssids
        if is_whitelisted:
            dimensions["new_network"] = 0.0
            reasons = [r for r in reasons if not r.startswith("New network:")]

        # Composite score
        composite = 0.0
        for dim, weight in _DIMENSION_WEIGHTS.items():
            composite += weight * dimensions.get(dim, 0.0)

        # Low frame count dampening — single-frame observations are noisy
        if frame_count <= 2:
            composite *= 0.4
        elif frame_count <= 5:
            composite *= 0.7

        # Learning-phase dampening
        if is_learning:
            composite *= 0.5

        # Whitelisted AP dampening — only alert on high-confidence attacks
        if is_whitelisted:
            composite *= 0.3

        composite = max(0.0, min(1.0, composite))
        priority = self._priority_label(composite)

        # Baseline comparison snapshots
        expected_signal: float | None = None
        sig_zscore = 0.0
        expected_ch: int | None = None
        expected_sec = ""
        expected_client_count = 0.0
        expected_retry_rate = 0.0
        baseline_obs = 0
        if baseline is not None:
            expected_signal = baseline.signal_ewma
            sig_zscore = baseline.signal_zscore(signal_dbm)
            expected_ch = baseline.expected_channel
            expected_sec = baseline.expected_security
            expected_client_count = baseline.client_count_ewma
            expected_retry_rate = baseline.retry_rate_ewma
            baseline_obs = baseline.total_observations

        return WifiAnomalyResult(
            bssid=bssid,
            ssid=agg.get("ssid", ""),
            channel=agg.get("channel", 0),
            band=agg.get("band", "2.4GHz"),
            security=agg.get("security", ""),
            signal_dbm=agg.get("signal_dbm", 0.0),
            score=round(composite, 4),
            priority=priority,
            dimensions={k: round(v, 4) for k, v in dimensions.items()},
            reasons=reasons,
            baseline_status=baseline_status,
            # Enrichment — batch metrics
            client_count=agg.get("client_count", 0),
            retry_rate=agg.get("retry_rate", 0.0),
            noise_dbm_max=agg.get("noise_dbm_max", 0.0),
            data_rate_min=agg.get("data_rate_min", 0.0),
            data_rate_max=agg.get("data_rate_max", 0.0),
            channel_width=agg.get("channel_width", 0),
            frame_count=agg.get("frame_count", 0),
            deauth_count=agg.get("deauth_count", 0),
            frame_type_counts=agg.get("frame_type_counts", {}),
            # Enrichment — baseline snapshots
            expected_signal=expected_signal,
            signal_zscore=round(sig_zscore, 4),
            expected_channel=expected_ch,
            expected_security=expected_sec,
            expected_client_count=round(expected_client_count, 4),
            expected_retry_rate=round(expected_retry_rate, 4),
            baseline_observations=baseline_obs,
            # Enrichment — forensic captures
            client_macs=agg.get("client_macs", []),
            frame_capture=agg.get("frame_capture", []),
        )

    # -------------------------------------------------------------------
    # Dimension scorers
    # -------------------------------------------------------------------

    def _evil_twin_score(self, bssid: str, ssid: str, vendor: str = "") -> float:
        """Score evil twin likelihood using SSID duplication and vendor mismatch.

        Returns 1.0 if BSSID is new for a known SSID and vendor differs
        from established BSSIDs (confirmed evil twin). Returns 0.7 if
        same vendor (likely multi-AP deployment). Returns 1.0 if no
        vendor info available (preserves existing behavior).
        """
        if not ssid:
            return 0.0
        existing = self.baseline_manager.get_bssids_for_ssid(ssid)
        if not existing:
            return 0.0
        # If this BSSID is not yet in the known set for this SSID
        if bssid not in existing:
            # Use vendor comparison to refine score
            if vendor:
                for known_bssid in existing:
                    bl = self.baseline_manager.get_baseline(known_bssid)
                    if bl and bl.expected_vendor:
                        if bl.expected_vendor != vendor:
                            return 1.0  # Different vendor = confirmed evil twin
                        else:
                            return 0.7  # Same vendor = likely multi-AP
            return 1.0  # No vendor info = preserve existing behavior
        return 0.0

    @staticmethod
    def _security_downgrade_score(
        baseline: WifiBaseline | None,
        current_security: str,
    ) -> float:
        """Score security downgrades.

        1.0 for WPA2/WPA3 → Open/WEP, 0.5 for WPA3 → WPA2.
        Empty/unknown security is NOT treated as a downgrade — the scanner
        may fail to extract security info from data/probe/management frames.
        """
        if baseline is None:
            return 0.0
        expected_level = _SECURITY_HIERARCHY.get(baseline.expected_security)
        current_level = _SECURITY_HIERARCHY.get(current_security)
        # Only comparable, recognized protocols can establish a downgrade.
        # Unknown and privacy-without-protocol observations are not Open.
        if expected_level is None or current_level is None:
            return 0.0
        if current_level >= expected_level:
            return 0.0
        # Full downgrade: WPA2/3 → Open/WEP
        if expected_level >= 3 and current_level <= 1:
            return 1.0
        # Partial downgrade: WPA3 → WPA2
        if expected_level >= 4 and current_level == 3:
            return 0.5
        # Generic downgrade
        return 0.5

    @staticmethod
    def _signal_anomaly_score(
        baseline: WifiBaseline | None,
        signal_dbm: float,
    ) -> float:
        """Sigmoid of signal_dbm z-score vs EWMA: abs(z)/(abs(z)+3)."""
        if baseline is None:
            return 0.0
        z = baseline.signal_zscore(signal_dbm)
        abs_z = abs(z)
        return min(1.0, abs_z / (abs_z + 3.0))

    @staticmethod
    def _new_network_score(baseline: WifiBaseline | None) -> float:
        """1.0 if BSSID has never been seen before."""
        if baseline is None:
            return 1.0
        return 0.0

    @staticmethod
    def _channel_change_score(
        baseline: WifiBaseline | None,
        current_channel: int,
    ) -> float:
        """Score channel changes using channel history.

        1.0 only if the channel has NEVER been seen before for this BSSID.
        0.0 if the channel is in the baseline's seen_channels set (normal
        roaming, DFS, or multi-channel AP behavior).
        """
        if baseline is None or baseline.expected_channel is None:
            return 0.0
        if current_channel <= 0:
            return 0.0
        if current_channel == baseline.expected_channel:
            return 0.0
        # Channel previously observed → normal roaming / DFS
        if current_channel in baseline.seen_channels:
            return 0.0
        return 1.0

    @staticmethod
    def _client_surge_score(
        baseline: WifiBaseline | None,
        current_client_count: int,
    ) -> float:
        """Score client surges >2x the EWMA, clamped to [0, 1]."""
        if baseline is None or baseline.client_count_ewma < 1:
            return 0.0
        ratio = current_client_count / baseline.client_count_ewma
        if ratio <= 2.0:
            return 0.0
        # Map 2x→0, 5x→1
        return min(1.0, (ratio - 2.0) / 3.0)

    @staticmethod
    def _deauth_indicator_score(
        retry_rate: float,
        deauth_count: int = 0,
        frame_count: int = 0,
    ) -> float:
        """Score deauth/disruption indicator from actual deauth frames and retry rate.

        Actual deauth/disassociation frames are weighted heavily.  High retry
        rate is only meaningful with enough frames to be statistically relevant.
        """
        score = 0.0
        # Actual deauth frames are strong evidence
        if deauth_count > 0:
            # 1 deauth → 0.5, 3+ → 0.8, 10+ → ~1.0
            score = min(1.0, deauth_count / (deauth_count + 3.0))
        # Retry rate only meaningful with enough frames
        if frame_count >= 5 and retry_rate > 0.3:
            retry_score = (retry_rate - 0.3) / 0.7  # map 0.3→0, 1.0→1.0
            score = max(score, min(1.0, retry_score))
        return score

    # -------------------------------------------------------------------
    # Re-evaluation
    # -------------------------------------------------------------------

    def reevaluate(self, anomaly: dict[str, Any]) -> dict[str, Any]:
        """Re-evaluate a stored anomaly against current baselines.

        Parameters
        ----------
        anomaly : dict
            Stored anomaly row with at least ``bssid``, ``ssid``, ``channel``,
            ``band``, ``security``, ``signal_dbm``, ``client_count``,
            ``retry_rate``, ``deauth_count``, ``frame_count``, ``timestamp``.

        Returns
        -------
        dict with ``still_anomalous``, ``new_score``, ``new_priority``,
        ``new_dimensions``, ``new_reasons``, ``baseline_status``,
        ``baseline_observations``, ``original_score``, ``score_delta``,
        ``normal_since`` (ISO timestamp when baseline began considering
        this pattern normal, or None).
        """
        with self.baseline_manager.lock:
            return self._reevaluate_locked(anomaly)

    def _reevaluate_locked(self, anomaly: dict[str, Any]) -> dict[str, Any]:
        def _v(key: str, default: Any) -> Any:
            """Get value from anomaly, falling back to default if None."""
            val = anomaly.get(key)
            return val if val is not None else default

        bssid = _v("bssid", "")
        agg = {
            "bssid": bssid,
            "ssid": _v("ssid", ""),
            "channel": _v("channel", 0),
            "band": _v("band", "2.4GHz"),
            "security": _v("security", ""),
            "signal_dbm": _v("signal_dbm", 0.0),
            "client_count": _v("client_count", 0),
            "retry_rate": _v("retry_rate", 0.0),
            "noise_dbm_max": _v("noise_dbm_max", 0.0),
            "data_rate_min": _v("data_rate_min", 0.0),
            "data_rate_max": _v("data_rate_max", 0.0),
            "channel_width": _v("channel_width", 0),
            "frame_count": _v("frame_count", 0),
            "deauth_count": _v("deauth_count", 0),
            "frame_type_counts": anomaly.get("frame_type_counts")
            if isinstance(anomaly.get("frame_type_counts"), dict)
            else {},
            "client_macs": anomaly.get("client_macs")
            if isinstance(anomaly.get("client_macs"), list)
            else [],
            "frame_capture": [],
        }

        result = self._score_bssid(bssid, agg)
        original_score = _v("anomaly_score", 0.0)

        # Estimate when baseline would have started considering this normal.
        # If the baseline has enough observations and the new score < 0.3,
        # the pattern has been absorbed. We approximate the "normal since"
        # time from the baseline observation count and EWMA alpha.
        normal_since = None
        baseline = self.baseline_manager.get_baseline(bssid)
        if baseline is not None and result.score < 0.3:
            obs_since_anomaly = baseline.total_observations
            anomaly_ts = anomaly.get("timestamp", "")
            if anomaly_ts and obs_since_anomaly > _MIN_LEARNING_OBSERVATIONS:
                normal_since = anomaly_ts

        return {
            "still_anomalous": result.score >= 0.3,
            "new_score": result.score,
            "new_priority": result.priority,
            "new_dimensions": result.dimensions,
            "new_reasons": result.reasons,
            "baseline_status": result.baseline_status,
            "baseline_observations": result.baseline_observations,
            "original_score": original_score,
            "score_delta": round(result.score - original_score, 4),
            "normal_since": normal_since,
        }

    # -------------------------------------------------------------------
    # Priority
    # -------------------------------------------------------------------

    @staticmethod
    def _priority_label(score: float) -> str:
        """Map composite score to priority label."""
        if score < 0.3:
            return "normal"
        elif score < 0.5:
            return "interesting"
        elif score < 0.7:
            return "anomalous"
        return "critical"
