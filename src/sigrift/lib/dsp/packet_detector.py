"""Packet boundary detection using energy, entropy, and timing analysis.

Detects packet boundaries in IQ captures by combining sliding-window
energy detection with Shannon entropy edge refinement. Supports
periodicity analysis of inter-packet gaps via autocorrelation.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np


@dataclass
class PacketBoundary:
    """A detected packet within an IQ capture."""

    start_sample: int
    end_sample: int
    duration_samples: int
    duration_seconds: float
    peak_energy_db: float
    mean_energy_db: float
    mean_entropy: float
    snr_estimate_db: float
    confidence: float


@dataclass
class TimingAnalysis:
    """Timing analysis of inter-packet gaps."""

    n_packets: int
    inter_packet_gaps: list[float] = field(default_factory=list)
    mean_gap_seconds: float = 0.0
    std_gap_seconds: float = 0.0
    is_periodic: bool = False
    estimated_period_seconds: float | None = None
    duty_cycle: float = 0.0


def _sliding_power_db(iq: np.ndarray, window: int) -> np.ndarray:
    """Compute sliding-window power in dB.

    Parameters
    ----------
    iq : np.ndarray
        Complex IQ samples.
    window : int
        Sliding window length.

    Returns
    -------
    np.ndarray
        Power in dB for each window position (length = len(iq) - window + 1).
    """
    mag_sq = np.abs(iq).astype(np.float64) ** 2
    # Cumulative sum trick for sliding window mean
    cumsum = np.cumsum(mag_sq)
    cumsum = np.insert(cumsum, 0, 0.0)
    window_power = (cumsum[window:] - cumsum[:-window]) / window
    # Convert to dB, floor at -100 dB
    return 10.0 * np.log10(np.maximum(window_power, 1e-10))


def _shannon_entropy(values: np.ndarray, n_bins: int) -> float:
    """Compute Shannon entropy of a 1-D array.

    Parameters
    ----------
    values : np.ndarray
        Input values.
    n_bins : int
        Number of histogram bins.

    Returns
    -------
    float
        Shannon entropy in nats.
    """
    if len(values) < 2:
        return 0.0
    counts, _ = np.histogram(values, bins=n_bins)
    probs = counts / counts.sum()
    probs = probs[probs > 0]
    return -float(np.sum(probs * np.log(probs)))


def _find_edges(energy_profile: np.ndarray, threshold: float) -> list[tuple[int, int]]:
    """Find rising/falling edges where energy crosses *threshold*.

    Returns list of (start, end) index pairs.
    """
    above = energy_profile > threshold
    edges: list[tuple[int, int]] = []
    in_segment = False
    start = 0
    for i, v in enumerate(above):
        if v and not in_segment:
            start = i
            in_segment = True
        elif not v and in_segment:
            edges.append((start, i))
            in_segment = False
    if in_segment:
        edges.append((start, len(above)))
    return edges


def _estimate_noise_floor(energy_profile: np.ndarray) -> float:
    """Robust noise floor estimation using median of lowest 20%."""
    if len(energy_profile) == 0:
        return -100.0
    sorted_vals = np.sort(energy_profile)
    n_low = max(1, len(sorted_vals) // 5)
    return float(np.median(sorted_vals[:n_low]))


def _detect_periodicity(
    gaps: list[float],
) -> tuple[bool, float | None]:
    """Detect periodicity in inter-packet gap sequence.

    Uses coefficient of variation: if std/mean < 0.25 the gaps are
    considered periodic.

    Returns
    -------
    tuple[bool, float | None]
        (is_periodic, estimated_period) where period is mean gap if periodic.
    """
    if len(gaps) < 2:
        return False, None
    arr = np.array(gaps, dtype=np.float64)
    mean_gap = float(arr.mean())
    std_gap = float(arr.std())
    if mean_gap <= 0:
        return False, None
    cv = std_gap / mean_gap
    is_periodic = cv < 0.25
    return is_periodic, mean_gap if is_periodic else None


class PacketDetector:
    """Detect packet boundaries in IQ captures using energy and entropy.

    Parameters
    ----------
    energy_threshold_db : float
        Energy threshold in dB above noise floor for packet detection.
    min_packet_samples : int
        Minimum packet length in samples.
    min_gap_samples : int
        Minimum gap between packets; shorter gaps cause merge.
    entropy_window : int
        Window size for entropy computation.
    """

    def __init__(
        self,
        energy_threshold_db: float = -20.0,
        min_packet_samples: int = 64,
        min_gap_samples: int = 32,
        entropy_window: int = 64,
    ) -> None:
        self.energy_threshold_db = energy_threshold_db
        self.min_packet_samples = min_packet_samples
        self.min_gap_samples = min_gap_samples
        self.entropy_window = entropy_window

    def compute_energy_profile(self, iq: np.ndarray, window: int = 64) -> np.ndarray:
        """Compute sliding-window energy profile in dB."""
        window = min(window, len(iq))
        if window < 1:
            return np.array([], dtype=np.float64)
        return _sliding_power_db(iq, window)

    def compute_entropy_profile(
        self, iq: np.ndarray, window: int = 64, n_bins: int = 16
    ) -> np.ndarray:
        """Compute sliding-window Shannon entropy of IQ magnitude."""
        mag = np.abs(iq).astype(np.float64)
        n = len(mag)
        window = min(window, n)
        if window < 2:
            return np.array([], dtype=np.float64)
        out_len = n - window + 1
        result = np.empty(out_len, dtype=np.float64)
        for i in range(out_len):
            result[i] = _shannon_entropy(mag[i : i + window], n_bins)
        return result

    def detect_packets(
        self, iq: np.ndarray, sample_rate: float = 1.0
    ) -> list[PacketBoundary]:
        """Detect all packet boundaries in an IQ capture.

        Algorithm:
        1. Energy detection via sliding-window power
        2. Edge refinement using entropy transitions
        3. Merge segments separated by < min_gap_samples
        4. Filter segments shorter than min_packet_samples
        5. Compute per-packet statistics
        """
        n = len(iq)
        if n < self.min_packet_samples:
            return []

        win = min(self.entropy_window, n)

        # Step 1: energy detection
        energy = self.compute_energy_profile(iq, window=win)
        if len(energy) == 0:
            return []

        noise_floor = _estimate_noise_floor(energy)
        threshold = noise_floor + abs(self.energy_threshold_db)

        raw_edges = _find_edges(energy, threshold)
        if not raw_edges:
            return []

        # Step 2: entropy-based edge refinement
        entropy = self.compute_entropy_profile(iq, window=win)
        refined: list[tuple[int, int]] = []
        for start, end in raw_edges:
            # Refine start: look backwards for entropy transition
            new_start = start
            if len(entropy) > 0 and start > 0:
                look_back = max(0, start - win)
                window_ent = entropy[look_back : start + 1]
                if len(window_ent) > 1:
                    # Find steepest entropy rise
                    diffs = np.diff(window_ent)
                    if len(diffs) > 0:
                        best = int(np.argmax(np.abs(diffs)))
                        new_start = look_back + best

            # Refine end similarly
            new_end = min(end, n)
            if len(entropy) > 0 and end < len(entropy):
                look_fwd = min(len(entropy), end + win)
                window_ent = entropy[end:look_fwd]
                if len(window_ent) > 1:
                    diffs = np.diff(window_ent)
                    if len(diffs) > 0:
                        best = int(np.argmax(np.abs(diffs)))
                        new_end = end + best + 1

            new_end = min(new_end, n)
            if new_end > new_start:
                refined.append((new_start, new_end))

        if not refined:
            return []

        # Step 3: merge close segments
        merged: list[tuple[int, int]] = [refined[0]]
        for start, end in refined[1:]:
            prev_start, prev_end = merged[-1]
            if start - prev_end < self.min_gap_samples:
                merged[-1] = (prev_start, max(prev_end, end))
            else:
                merged.append((start, end))

        # Step 4: filter short segments
        filtered = [(s, e) for s, e in merged if (e - s) >= self.min_packet_samples]

        if not filtered:
            return []

        # Step 5: compute per-packet statistics
        packets: list[PacketBoundary] = []
        for start, end in filtered:
            seg = iq[start:end]
            seg_power = np.abs(seg).astype(np.float64) ** 2
            seg_power_db = 10.0 * np.log10(np.maximum(seg_power, 1e-10))

            peak_e = float(np.max(seg_power_db))
            mean_e = float(np.mean(seg_power_db))

            # Entropy of the packet segment
            seg_mag = np.abs(seg).astype(np.float64)
            pkt_entropy = _shannon_entropy(seg_mag, n_bins=16)

            snr = mean_e - noise_floor
            # Confidence based on SNR
            confidence = float(np.clip(snr / 30.0, 0.0, 1.0))

            dur_samples = end - start
            dur_seconds = dur_samples / sample_rate

            packets.append(
                PacketBoundary(
                    start_sample=int(start),
                    end_sample=int(end),
                    duration_samples=dur_samples,
                    duration_seconds=dur_seconds,
                    peak_energy_db=round(peak_e, 2),
                    mean_energy_db=round(mean_e, 2),
                    mean_entropy=round(pkt_entropy, 4),
                    snr_estimate_db=round(snr, 2),
                    confidence=round(confidence, 4),
                )
            )

        return packets

    def analyze_timing(
        self, packets: list[PacketBoundary], sample_rate: float = 1.0
    ) -> TimingAnalysis:
        """Analyze inter-packet timing for periodicity detection."""
        n = len(packets)
        if n == 0:
            return TimingAnalysis(n_packets=0)

        # Compute inter-packet gaps
        gaps: list[float] = []
        for i in range(1, n):
            gap_samples = packets[i].start_sample - packets[i - 1].end_sample
            gaps.append(gap_samples / sample_rate)

        total_duration = (
            packets[-1].end_sample - packets[0].start_sample
        ) / sample_rate
        total_tx = sum(p.duration_seconds for p in packets)
        duty_cycle = total_tx / total_duration if total_duration > 0 else 0.0

        if not gaps:
            return TimingAnalysis(
                n_packets=n,
                inter_packet_gaps=[],
                mean_gap_seconds=0.0,
                std_gap_seconds=0.0,
                is_periodic=False,
                estimated_period_seconds=None,
                duty_cycle=round(duty_cycle, 4),
            )

        arr = np.array(gaps)
        mean_gap = float(arr.mean())
        std_gap = float(arr.std())
        is_periodic, period = _detect_periodicity(gaps)

        return TimingAnalysis(
            n_packets=n,
            inter_packet_gaps=[round(g, 6) for g in gaps],
            mean_gap_seconds=round(mean_gap, 6),
            std_gap_seconds=round(std_gap, 6),
            is_periodic=is_periodic,
            estimated_period_seconds=round(period, 6) if period is not None else None,
            duty_cycle=round(duty_cycle, 4),
        )
