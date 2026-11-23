"""RSS geolocation provider — wraps multilateration as a GeoProvider.

Community-tier geolocation using Received Signal Strength (RSS)
triangulation. Requires at least 2 receivers with known positions.

Receiver positions come from ``observation.metadata["node_position"]`` in
one of two frames (see :func:`sigrift.providers.adapters.detections_to_observations`):

* geographic -- ``{"lat": deg, "lon": deg}``. The solver works in metres,
  so the positions are projected onto a local east/north plane centred on
  the receivers' centroid (equirectangular projection: accurate to well
  under a metre over the few-kilometre baselines RSS ranging is useful
  for), solved there, and the estimate is projected back to lat/lon.
* local metric -- ``{"x_m": m, "y_m": m}``. Solved as-is; the estimate is
  returned as ``metadata["location"] = {"x_m": ..., "y_m": ...}`` and
  ``latitude``/``longitude`` stay ``None`` (metres are not degrees).

Observations whose position is in the other frame than the majority, or
is missing / non-numeric / out of range, are skipped.
"""

from __future__ import annotations

import logging
import math
from typing import Any

from sigrift.providers.base import GeoEstimate, GeoProvider, SignalObservation

logger = logging.getLogger(__name__)

# Mean Earth radius (IUGG), metres.
_EARTH_RADIUS_M = 6_371_008.8

# Below this |cos(latitude)| the east/west scale collapses (within ~0.06 deg
# of a pole) and the local projection is meaningless.
_MIN_COS_LAT = 1e-3


def _finite(value: Any) -> float | None:
    """*value* as a finite float, or None (bools and non-numbers rejected)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    value = float(value)
    return value if math.isfinite(value) else None


def _wrap_lon(lon: float) -> float:
    """Wrap a longitude (degrees) into [-180, 180)."""
    return (lon + 180.0) % 360.0 - 180.0


def _parse_position(pos: Any) -> tuple[str, float, float] | None:
    """Classify a node_position dict as ("geo", lat, lon) or ("xy", x, y)."""
    if not isinstance(pos, dict):
        return None
    if "lat" in pos or "lon" in pos:
        lat, lon = _finite(pos.get("lat")), _finite(pos.get("lon"))
        if lat is None or lon is None or not -90.0 <= lat <= 90.0:
            return None
        if not -180.0 <= lon <= 180.0:
            return None
        return "geo", lat, lon
    if "x_m" in pos or "y_m" in pos:
        x, y = _finite(pos.get("x_m")), _finite(pos.get("y_m"))
        if x is None or y is None:
            return None
        return "xy", x, y
    return None


class _LocalTangentPlane:
    """Equirectangular east/north projection (metres) around an origin."""

    def __init__(self, lat0: float, lon0: float) -> None:
        self.lat0 = lat0
        self.lon0 = lon0
        self._cos_lat0 = math.cos(math.radians(lat0))
        if abs(self._cos_lat0) < _MIN_COS_LAT:
            raise ValueError(f"receivers too close to a pole (lat {lat0:.4f})")

    @classmethod
    def around(cls, points: list[tuple[float, float]]) -> _LocalTangentPlane:
        """Plane centred on the centroid of (lat, lon) *points*.

        Longitudes are averaged as unit vectors so a set of receivers that
        straddles the antimeridian gets a centroid next to them, not on the
        other side of the planet.
        """
        lat0 = sum(lat for lat, _ in points) / len(points)
        sin_sum = sum(math.sin(math.radians(lon)) for _, lon in points)
        cos_sum = sum(math.cos(math.radians(lon)) for _, lon in points)
        lon0 = math.degrees(math.atan2(sin_sum, cos_sum))
        return cls(lat0, lon0)

    def to_xy(self, lat: float, lon: float) -> tuple[float, float]:
        dlon = _wrap_lon(lon - self.lon0)
        x = _EARTH_RADIUS_M * self._cos_lat0 * math.radians(dlon)
        y = _EARTH_RADIUS_M * math.radians(lat - self.lat0)
        return x, y

    def to_latlon(self, x: float, y: float) -> tuple[float, float]:
        lat = self.lat0 + math.degrees(y / _EARTH_RADIUS_M)
        lon = self.lon0 + math.degrees(x / (_EARTH_RADIUS_M * self._cos_lat0))
        return max(-90.0, min(90.0, lat)), _wrap_lon(lon)


class RSSGeoProvider(GeoProvider):
    """GeoProvider implementation using RSS-based trilateration."""

    def __init__(self) -> None:
        self._path_loss_exponent = 2.5
        self._reference_rssi_dbm = -30.0
        self._reference_distance_m = 1.0

    def configure(self, config: dict[str, Any]) -> None:
        self._path_loss_exponent = config.get("path_loss_exponent", 2.5)
        self._reference_rssi_dbm = config.get("reference_rssi_dbm", -30.0)
        self._reference_distance_m = config.get("reference_distance_m", 1.0)

    @property
    def min_receivers(self) -> int:
        return 2

    @property
    def name(self) -> str:
        return "RSSGeoProvider"

    def estimate(self, observations: list[SignalObservation]) -> GeoEstimate:
        if len(observations) < self.min_receivers:
            return GeoEstimate(confidence=0.0, method="rss")

        try:
            from sigrift.lib.dsp.multilateration import (
                NodePosition,
                RSSIMeasurement,
                estimate_position,
            )
        except ImportError:
            logger.warning("multilateration module not available")
            return GeoEstimate(confidence=0.0, method="rss")

        # One entry per receiver: its parsed position plus every power and
        # timestamp it reported for this signal.
        receivers: dict[str, dict[str, Any]] = {}
        for obs in observations:
            if not obs.node_id:
                continue
            parsed = _parse_position(obs.metadata.get("node_position"))
            power = _finite(obs.power_dbm)
            if parsed is None or power is None:
                continue
            entry = receivers.setdefault(
                obs.node_id,
                {"pos": parsed, "powers": [], "times": [], "freq": obs.frequency_hz},
            )
            if entry["pos"] != parsed:
                logger.debug(
                    "RSS: node %s reported two positions; keeping the first",
                    obs.node_id,
                )
            entry["powers"].append(power)
            entry["times"].append(obs.timestamp_ns / 1e9)

        # All positions must share one frame; keep the frame most receivers use.
        geo_ids = [n for n, e in receivers.items() if e["pos"][0] == "geo"]
        xy_ids = [n for n, e in receivers.items() if e["pos"][0] == "xy"]
        frame, node_ids = (
            ("geo", geo_ids) if len(geo_ids) >= len(xy_ids) else ("xy", xy_ids)
        )
        if geo_ids and xy_ids:
            logger.warning(
                "RSS: %d receivers have lat/lon and %d have x/y metres; "
                "using only the %s ones",
                len(geo_ids),
                len(xy_ids),
                "lat/lon" if frame == "geo" else "x/y",
            )

        if len(node_ids) < self.min_receivers:
            return GeoEstimate(confidence=0.0, method="rss")

        plane: _LocalTangentPlane | None = None
        if frame == "geo":
            try:
                plane = _LocalTangentPlane.around(
                    [receivers[n]["pos"][1:] for n in node_ids]
                )
            except ValueError as exc:
                logger.warning("RSS estimation skipped: %s", exc)
                return GeoEstimate(confidence=0.0, method="rss")

        measurements: list[RSSIMeasurement] = []
        positions: dict[str, NodePosition] = {}
        for node_id in node_ids:
            entry = receivers[node_id]
            _, a, b = entry["pos"]
            x, y = plane.to_xy(a, b) if plane is not None else (a, b)
            positions[node_id] = NodePosition(node_id=node_id, x=x, y=y)
            measurements.append(
                RSSIMeasurement(
                    node_id=node_id,
                    # Several observations from one receiver: average them
                    # (one geometric constraint per receiver).
                    rssi_dbm=sum(entry["powers"]) / len(entry["powers"]),
                    frequency_hz=entry["freq"],
                    timestamp=max(entry["times"]),
                )
            )

        try:
            result = estimate_position(
                measurements=measurements,
                node_positions=positions,
                path_loss_exponent=self._path_loss_exponent,
                reference_rssi_dbm=self._reference_rssi_dbm,
                reference_distance_m=self._reference_distance_m,
            )
        except (ValueError, ArithmeticError) as exc:
            logger.warning("RSS estimation failed: %s", exc)
            return GeoEstimate(confidence=0.0, method="rss")

        metadata: dict[str, Any] = {
            "node_count": len(measurements),
            "contributing_nodes": list(node_ids),
            "path_loss_exponent": self._path_loss_exponent,
            "solver_method": result.method,
            "coordinate_mode": "geo" if plane is not None else "2d",
        }
        if plane is not None:
            lat, lon = plane.to_latlon(result.x, result.y)
            metadata["location"] = {"lat": lat, "lon": lon}
            return GeoEstimate(
                latitude=lat,
                longitude=lon,
                confidence=result.confidence,
                error_radius_m=result.error_radius_m,
                method="rss",
                metadata=metadata,
            )
        metadata["location"] = {"x_m": result.x, "y_m": result.y}
        return GeoEstimate(
            confidence=result.confidence,
            error_radius_m=result.error_radius_m,
            method="rss",
            metadata=metadata,
        )
