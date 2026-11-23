"""Kalman filter-based emitter position tracker.

Takes sequential position estimates and produces smoothed, predicted
emitter tracks.  Uses a constant-velocity model with 4D state
[x, y, vx, vy].

Designed to consume output from :mod:`sigrift.lib.dsp.multilateration` but
works with any (x, y, timestamp) stream.
"""

from __future__ import annotations

import math
import uuid
from dataclasses import dataclass

import numpy as np


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class TrackPoint:
    """A single filtered position observation on a track."""

    x: float
    y: float
    vx: float  # velocity x (m/s)
    vy: float  # velocity y (m/s)
    timestamp: float  # unix timestamp
    covariance: np.ndarray  # 4x4 state covariance matrix
    confidence: float  # 0-1
    source_estimate_id: str | None = None


@dataclass
class EmitterTrack:
    """Summary of a tracked emitter with full point history."""

    track_id: str
    emitter_id: str | None  # associated emitter if known
    points: list[TrackPoint]
    status: str  # "active", "lost", "completed"
    first_seen: float
    last_seen: float
    total_distance_m: float
    mean_velocity_mps: float
    is_stationary: bool
    classification: str | None  # "stationary", "walking", "vehicle", "unknown"


# ---------------------------------------------------------------------------
# Internal Kalman filter state
# ---------------------------------------------------------------------------


class _KalmanState:
    """4D Kalman filter: state = [x, y, vx, vy]."""

    def __init__(
        self,
        x0: float,
        y0: float,
        timestamp: float,
        process_noise: float,
        measurement_noise: float,
    ) -> None:
        self.state = np.array([x0, y0, 0.0, 0.0], dtype=np.float64)
        self.P = np.eye(4) * 100.0  # initial covariance (high uncertainty)
        self.Q_base = process_noise  # process noise intensity
        self.R = np.eye(2) * measurement_noise**2  # measurement noise
        self.last_time = timestamp
        self.history: list[TrackPoint] = []
        self.track_id = uuid.uuid4().hex[:12]

    def predict(self, dt: float) -> None:
        """State prediction: x_k = F @ x_{k-1}."""
        if dt <= 0:
            return

        F = np.eye(4)
        F[0, 2] = dt  # x += vx * dt
        F[1, 3] = dt  # y += vy * dt

        # Process noise (continuous white noise acceleration model)
        q = self.Q_base
        Q = np.zeros((4, 4))
        Q[0, 0] = dt**3 / 3 * q
        Q[1, 1] = dt**3 / 3 * q
        Q[2, 2] = dt * q
        Q[3, 3] = dt * q
        Q[0, 2] = dt**2 / 2 * q
        Q[2, 0] = dt**2 / 2 * q
        Q[1, 3] = dt**2 / 2 * q
        Q[3, 1] = dt**2 / 2 * q

        self.state = F @ self.state
        self.P = F @ self.P @ F.T + Q

    def update(self, z: np.ndarray, R_override: np.ndarray | None = None) -> None:
        """Measurement update: z = [x_meas, y_meas]."""
        H = np.zeros((2, 4))
        H[0, 0] = 1.0  # observe x
        H[1, 1] = 1.0  # observe y

        R = R_override if R_override is not None else self.R

        y = z - H @ self.state  # innovation
        S = H @ self.P @ H.T + R  # innovation covariance
        K = self.P @ H.T @ np.linalg.inv(S)  # Kalman gain

        self.state = self.state + K @ y
        self.P = (np.eye(4) - K @ H) @ self.P

    def get_confidence(self) -> float:
        """Compute a 0-1 confidence from the position covariance.

        Lower covariance = higher confidence.  Maps the trace of the
        position sub-covariance (P[0,0] + P[1,1]) to [0, 1] using a
        sigmoid-like curve.
        """
        pos_var = self.P[0, 0] + self.P[1, 1]
        # confidence = 1 / (1 + sqrt(pos_var) / 10)
        confidence = 1.0 / (1.0 + math.sqrt(max(pos_var, 0.0)) / 10.0)
        return min(max(confidence, 0.0), 1.0)


# ---------------------------------------------------------------------------
# EmitterTracker
# ---------------------------------------------------------------------------


class EmitterTracker:
    """Kalman filter-based emitter position tracker.

    Uses a constant-velocity model with 4D state [x, y, vx, vy].

    Parameters
    ----------
    process_noise : float
        Acceleration noise intensity (m/s^2).
    measurement_noise : float
        Default position measurement noise (metres).
    lost_timeout_s : float
        Seconds without update before a track becomes "lost".
    stationary_threshold_mps : float
        Speed below which an emitter is considered stationary.
    min_points_for_track : int
        Minimum observations before classification is attempted.
    """

    def __init__(
        self,
        process_noise: float = 0.5,
        measurement_noise: float = 5.0,
        lost_timeout_s: float = 60.0,
        stationary_threshold_mps: float = 0.5,
        min_points_for_track: int = 3,
    ) -> None:
        self.process_noise = process_noise
        self.measurement_noise = measurement_noise
        self.lost_timeout_s = lost_timeout_s
        self.stationary_threshold_mps = stationary_threshold_mps
        self.min_points_for_track = min_points_for_track
        self._tracks: dict[str, _KalmanState] = {}

    # ----- public API ------

    def update(
        self,
        emitter_id: str,
        x: float,
        y: float,
        timestamp: float,
        measurement_noise: float | None = None,
        estimate_id: str | None = None,
    ) -> TrackPoint:
        """Update track with new position measurement.

        Creates a new track if *emitter_id* has not been seen before.
        Returns the filtered (smoothed) position.
        """
        kf = self._tracks.get(emitter_id)

        if kf is None:
            # Create a new Kalman filter for this emitter
            kf = _KalmanState(
                x0=x,
                y0=y,
                timestamp=timestamp,
                process_noise=self.process_noise,
                measurement_noise=self.measurement_noise,
            )
            self._tracks[emitter_id] = kf
        else:
            dt = timestamp - kf.last_time
            if dt > 0:
                kf.predict(dt)

            # Measurement update
            z = np.array([x, y], dtype=np.float64)
            if measurement_noise is not None:
                R = np.eye(2) * measurement_noise**2
                kf.update(z, R_override=R)
            else:
                kf.update(z)

        kf.last_time = timestamp

        point = TrackPoint(
            x=float(kf.state[0]),
            y=float(kf.state[1]),
            vx=float(kf.state[2]),
            vy=float(kf.state[3]),
            timestamp=timestamp,
            covariance=kf.P.copy(),
            confidence=kf.get_confidence(),
            source_estimate_id=estimate_id,
        )
        kf.history.append(point)
        return point

    def predict(self, emitter_id: str, timestamp: float) -> TrackPoint | None:
        """Predict position at given timestamp (extrapolate).

        Returns ``None`` if the emitter has no track.
        """
        kf = self._tracks.get(emitter_id)
        if kf is None:
            return None

        dt = timestamp - kf.last_time
        # Create a temporary copy for prediction (don't alter real state)
        state_copy = kf.state.copy()
        P_copy = kf.P.copy()

        if dt > 0:
            F = np.eye(4)
            F[0, 2] = dt
            F[1, 3] = dt

            q = kf.Q_base
            Q = np.zeros((4, 4))
            Q[0, 0] = dt**3 / 3 * q
            Q[1, 1] = dt**3 / 3 * q
            Q[2, 2] = dt * q
            Q[3, 3] = dt * q
            Q[0, 2] = dt**2 / 2 * q
            Q[2, 0] = dt**2 / 2 * q
            Q[1, 3] = dt**2 / 2 * q
            Q[3, 1] = dt**2 / 2 * q

            state_copy = F @ state_copy
            P_copy = F @ P_copy @ F.T + Q

        pos_var = P_copy[0, 0] + P_copy[1, 1]
        confidence = 1.0 / (1.0 + math.sqrt(max(pos_var, 0.0)) / 10.0)
        confidence = min(max(confidence, 0.0), 1.0)

        return TrackPoint(
            x=float(state_copy[0]),
            y=float(state_copy[1]),
            vx=float(state_copy[2]),
            vy=float(state_copy[3]),
            timestamp=timestamp,
            covariance=P_copy,
            confidence=confidence,
        )

    def get_track(self, emitter_id: str) -> EmitterTrack | None:
        """Get full track history for an emitter."""
        kf = self._tracks.get(emitter_id)
        if kf is None:
            return None
        return self._build_track(emitter_id, kf)

    def get_all_tracks(self) -> list[EmitterTrack]:
        """Get all active and recent tracks."""
        return [self._build_track(eid, kf) for eid, kf in self._tracks.items()]

    def prune_lost_tracks(self, current_time: float) -> list[str]:
        """Mark tracks as lost if not updated within timeout.

        Returns list of pruned emitter IDs.
        """
        pruned: list[str] = []
        for emitter_id, kf in self._tracks.items():
            age = current_time - kf.last_time
            if age > self.lost_timeout_s:
                pruned.append(emitter_id)
        return pruned

    def classify_motion(self, emitter_id: str) -> str:
        """Classify motion pattern: stationary, walking, vehicle, unknown."""
        kf = self._tracks.get(emitter_id)
        if kf is None or len(kf.history) < self.min_points_for_track:
            return "unknown"

        speeds = [math.sqrt(p.vx**2 + p.vy**2) for p in kf.history]
        mean_speed = sum(speeds) / len(speeds) if speeds else 0.0

        if mean_speed < self.stationary_threshold_mps:
            return "stationary"
        elif mean_speed < 3.0:
            return "walking"
        elif mean_speed >= 10.0:
            return "vehicle"
        return "unknown"

    # ----- internal helpers ------

    def _build_track(self, emitter_id: str, kf: _KalmanState) -> EmitterTrack:
        """Build an EmitterTrack from Kalman state."""
        points = kf.history
        total_dist = 0.0
        for i in range(1, len(points)):
            dx = points[i].x - points[i - 1].x
            dy = points[i].y - points[i - 1].y
            total_dist += math.sqrt(dx**2 + dy**2)

        speeds = [math.sqrt(p.vx**2 + p.vy**2) for p in points]
        mean_vel = sum(speeds) / len(speeds) if speeds else 0.0
        is_stat = mean_vel < self.stationary_threshold_mps

        first_seen = points[0].timestamp if points else kf.last_time
        last_seen = points[-1].timestamp if points else kf.last_time

        classification = self.classify_motion(emitter_id)

        # Determine status
        status = "active"

        return EmitterTrack(
            track_id=kf.track_id,
            emitter_id=emitter_id,
            points=points,
            status=status,
            first_seen=first_seen,
            last_seen=last_seen,
            total_distance_m=total_dist,
            mean_velocity_mps=mean_vel,
            is_stationary=is_stat,
            classification=classification,
        )
