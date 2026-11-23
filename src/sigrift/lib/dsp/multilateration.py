"""RSSI-based multilateration for emitter position estimation.

Provides position estimation from RSSI (Received Signal Strength Indicator)
measurements at multiple receiver nodes using the log-distance path loss
model and least-squares trilateration.

No GPS or hardware changes required -- only node positions in a local
coordinate system and RSSI values from each node.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class NodePosition:
    """Position of a receiver node in a local coordinate system (metres)."""

    node_id: str
    x: float  # metres
    y: float  # metres
    z: float = 0.0  # metres (optional height)


@dataclass
class RSSIMeasurement:
    """A single RSSI observation from one node."""

    node_id: str
    rssi_dbm: float
    frequency_hz: float
    timestamp: float  # unix epoch seconds


@dataclass
class PositionEstimate:
    """Result of a multilateration position estimate."""

    x: float
    y: float
    z: float
    confidence: float  # 0..1
    error_radius_m: float  # estimated error circle radius
    method: str  # "rssi_trilateration" or "rssi_weighted_centroid"
    n_nodes: int
    path_loss_model: str
    measurements: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Path-loss helpers
# ---------------------------------------------------------------------------


def rssi_to_distance(
    rssi_dbm: float,
    reference_rssi_dbm: float = -30.0,
    path_loss_exponent: float = 2.5,
    reference_distance_m: float = 1.0,
) -> float:
    """Convert RSSI to estimated distance using the log-distance path loss model.

    Formula: d = d0 * 10^((RSSI_ref - RSSI) / (10 * n))

    Parameters
    ----------
    rssi_dbm : float
        Measured RSSI in dBm.
    reference_rssi_dbm : float
        RSSI at the reference distance (default -30 dBm at 1 m).
    path_loss_exponent : float
        Path-loss exponent *n* (2.0 = free space, 2.5-4.0 indoor).
    reference_distance_m : float
        Reference distance d0 in metres.

    Returns
    -------
    float
        Estimated distance in metres (always >= 0.01).
    """
    exponent = (reference_rssi_dbm - rssi_dbm) / (10.0 * path_loss_exponent)
    distance = reference_distance_m * math.pow(10.0, exponent)
    return max(distance, 0.01)


def _free_space_path_loss(frequency_hz: float, distance_m: float) -> float:
    """Free-space path loss (FSPL) in dB.

    FSPL(dB) = 20*log10(d) + 20*log10(f) + 20*log10(4*pi/c)

    Parameters
    ----------
    frequency_hz : float
        Carrier frequency in Hz.
    distance_m : float
        Distance in metres (must be > 0).

    Returns
    -------
    float
        Path loss in dB.
    """
    if distance_m <= 0:
        return 0.0
    c = 299_792_458.0  # speed of light m/s
    fspl = (
        20.0 * math.log10(distance_m)
        + 20.0 * math.log10(frequency_hz)
        + 20.0 * math.log10(4.0 * math.pi / c)
    )
    return fspl


# ---------------------------------------------------------------------------
# Geometric solvers
# ---------------------------------------------------------------------------


def _trilaterate_2d(
    positions: list[tuple[float, float]],
    distances: list[float],
) -> tuple[float, float]:
    """Least-squares 2D trilateration from positions and distances.

    Linearises the circle equations by subtracting the last equation from
    each of the others, then solves via the normal equations (A^T A)^{-1} A^T b.

    Parameters
    ----------
    positions : list of (x, y) tuples
        At least 3 node positions.
    distances : list of float
        Corresponding distance estimates.

    Returns
    -------
    tuple[float, float]
        Estimated (x, y) position.

    Raises
    ------
    ValueError
        If fewer than 3 positions or the system is singular.
    """
    n = len(positions)
    if n < 3:
        raise ValueError(f"Trilateration requires >= 3 positions, got {n}")

    # Use the last point as the reference to linearise
    xn, yn = positions[-1]
    dn = distances[-1]

    # Build linear system: A * [x, y]^T = b
    # For each i < n-1:
    #   2*(xn - xi)*x + 2*(yn - yi)*y = dn^2 - di^2 - xn^2 + xi^2 - yn^2 + yi^2
    rows_a: list[list[float]] = []
    rows_b: list[float] = []

    for i in range(n - 1):
        xi, yi = positions[i]
        di = distances[i]
        rows_a.append(
            [
                2.0 * (xn - xi),
                2.0 * (yn - yi),
            ]
        )
        rows_b.append(di * di - dn * dn - xi * xi + xn * xn - yi * yi + yn * yn)

    # Solve via normal equations: x = (A^T A)^{-1} A^T b
    # A is (n-1) x 2,  b is (n-1) x 1
    m = len(rows_a)
    # A^T A  (2x2)
    ata00 = sum(rows_a[i][0] * rows_a[i][0] for i in range(m))
    ata01 = sum(rows_a[i][0] * rows_a[i][1] for i in range(m))
    ata11 = sum(rows_a[i][1] * rows_a[i][1] for i in range(m))

    # A^T b  (2x1)
    atb0 = sum(rows_a[i][0] * rows_b[i] for i in range(m))
    atb1 = sum(rows_a[i][1] * rows_b[i] for i in range(m))

    det = ata00 * ata11 - ata01 * ata01
    if abs(det) < 1e-12:
        raise ValueError("Singular system -- nodes may be collinear")

    inv_det = 1.0 / det
    x_est = inv_det * (ata11 * atb0 - ata01 * atb1)
    y_est = inv_det * (ata00 * atb1 - ata01 * atb0)

    return (x_est, y_est)


def _weighted_centroid(
    positions: list[tuple[float, float]],
    weights: list[float],
) -> tuple[float, float]:
    """Weighted centroid of a set of 2D positions.

    Fallback method when trilateration is not possible (e.g. only 2 nodes).

    Parameters
    ----------
    positions : list of (x, y) tuples
        Node positions.
    weights : list of float
        Non-negative weights (e.g. 1/distance).

    Returns
    -------
    tuple[float, float]
        Weighted centroid (x, y).
    """
    total_w = sum(weights)
    if total_w == 0:
        # Equal weighting fallback
        n = len(positions)
        return (
            sum(p[0] for p in positions) / n,
            sum(p[1] for p in positions) / n,
        )
    wx = sum(w * p[0] for w, p in zip(weights, positions))
    wy = sum(w * p[1] for w, p in zip(weights, positions))
    return (wx / total_w, wy / total_w)


# ---------------------------------------------------------------------------
# Error estimation
# ---------------------------------------------------------------------------


def compute_error_estimate(
    measurements: list[RSSIMeasurement],
    position: tuple[float, float],
    node_positions: dict[str, NodePosition],
    path_loss_exponent: float,
    reference_rssi_dbm: float = -30.0,
    reference_distance_m: float = 1.0,
) -> float:
    """Estimate position error radius from RSSI residuals.

    Computes the RMS difference between the estimated distance (from the
    path-loss model) and the geometric distance from the estimated position
    to each node.

    Returns
    -------
    float
        Estimated error radius in metres (>= 0.1).
    """
    residuals_sq: list[float] = []

    for m in measurements:
        np_ = node_positions.get(m.node_id)
        if np_ is None:
            continue
        d_estimated = rssi_to_distance(
            m.rssi_dbm,
            reference_rssi_dbm=reference_rssi_dbm,
            path_loss_exponent=path_loss_exponent,
            reference_distance_m=reference_distance_m,
        )
        dx = position[0] - np_.x
        dy = position[1] - np_.y
        d_geometric = math.sqrt(dx * dx + dy * dy)
        residuals_sq.append((d_estimated - d_geometric) ** 2)

    if not residuals_sq:
        return 10.0  # fallback

    rms = math.sqrt(sum(residuals_sq) / len(residuals_sq))
    return max(rms, 0.1)


# ---------------------------------------------------------------------------
# Main estimation entry point
# ---------------------------------------------------------------------------


def estimate_position(
    measurements: list[RSSIMeasurement],
    node_positions: dict[str, NodePosition],
    path_loss_model: str = "log_distance",
    path_loss_exponent: float = 2.5,
    reference_distance_m: float = 1.0,
    reference_rssi_dbm: float = -30.0,
    frequency_hz: float | None = None,
) -> PositionEstimate:
    """Estimate emitter position from RSSI measurements at multiple nodes.

    Algorithm:
      1. Convert each RSSI to estimated distance via log-distance path loss.
      2. If >= 3 nodes with known positions: least-squares trilateration.
      3. If 2 nodes: weighted centroid fallback.
      4. Compute residuals to estimate error radius.
      5. Confidence = 1 / (1 + error_radius / baseline), clamped [0, 1].

    Parameters
    ----------
    measurements : list[RSSIMeasurement]
        RSSI readings from different nodes.
    node_positions : dict[str, NodePosition]
        Mapping of node_id to its known position.
    path_loss_model : str
        Model name (currently only ``"log_distance"`` supported).
    path_loss_exponent : float
        Path loss exponent *n*.
    reference_distance_m : float
        Reference distance d0.
    reference_rssi_dbm : float
        RSSI at reference distance.
    frequency_hz : float or None
        Optional carrier frequency (informational).

    Returns
    -------
    PositionEstimate
        Estimated position with error and confidence metrics.

    Raises
    ------
    ValueError
        If fewer than 2 measurements with known node positions are available.
    """
    # Filter to measurements that have known node positions
    valid: list[RSSIMeasurement] = [
        m for m in measurements if m.node_id in node_positions
    ]

    if len(valid) < 2:
        raise ValueError(
            f"Need at least 2 measurements from nodes with known positions, "
            f"got {len(valid)}"
        )

    # Convert RSSI to distances
    positions: list[tuple[float, float]] = []
    distances: list[float] = []
    meas_summary: list[dict[str, Any]] = []

    for m in valid:
        np_ = node_positions[m.node_id]
        d = rssi_to_distance(
            m.rssi_dbm,
            reference_rssi_dbm=reference_rssi_dbm,
            path_loss_exponent=path_loss_exponent,
            reference_distance_m=reference_distance_m,
        )
        positions.append((np_.x, np_.y))
        distances.append(d)
        meas_summary.append(
            {
                "node_id": m.node_id,
                "rssi_dbm": m.rssi_dbm,
                "estimated_distance_m": round(d, 3),
            }
        )

    # Choose method
    method: str
    x_est: float
    y_est: float

    if len(valid) >= 3:
        try:
            x_est, y_est = _trilaterate_2d(positions, distances)
            method = "rssi_trilateration"
        except ValueError:
            # Fallback to weighted centroid if system is singular
            weights = [1.0 / max(d, 0.01) for d in distances]
            x_est, y_est = _weighted_centroid(positions, weights)
            method = "rssi_weighted_centroid"
    else:
        weights = [1.0 / max(d, 0.01) for d in distances]
        x_est, y_est = _weighted_centroid(positions, weights)
        method = "rssi_weighted_centroid"

    # Error estimate
    error_radius = compute_error_estimate(
        valid,
        (x_est, y_est),
        node_positions,
        path_loss_exponent,
        reference_rssi_dbm=reference_rssi_dbm,
        reference_distance_m=reference_distance_m,
    )

    # Confidence: 1 / (1 + error_radius / baseline)
    baseline = 10.0  # 10m baseline
    confidence = 1.0 / (1.0 + error_radius / baseline)
    confidence = max(0.0, min(1.0, confidence))

    return PositionEstimate(
        x=round(x_est, 4),
        y=round(y_est, 4),
        z=0.0,
        confidence=round(confidence, 4),
        error_radius_m=round(error_radius, 4),
        method=method,
        n_nodes=len(valid),
        path_loss_model=path_loss_model,
        measurements=meas_summary,
    )
