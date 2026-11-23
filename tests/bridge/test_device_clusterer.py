"""Public device-group behavior, using the real DBSCAN implementation.

Group identifiers describe the current fingerprint/MAC membership. They are
not durable physical-device identities when later observations add new MACs.
The density and missing-timing assignment policies are separate contracts.
"""

from datetime import datetime, timezone
from itertools import permutations
import sys

import pytest
from sklearn.cluster import DBSCAN

from sigrift.lib.dsp.device_clusterer import (
    DeviceClusterer,
    _average_timing_sig,
    _hamming_ratio,
    _timing_l2_distance,
)


def run(observations, **options):
    clusterer = DeviceClusterer(**options)
    for observation in observations:
        clusterer.add_observation(**observation)
    return clusterer, clusterer.run_clustering()


def separated_groups():
    return [
        {
            "mac": mac,
            "ie_fingerprint": "001cabcd",
            "timing_sig": {"mean_ifat_us": timing},
            "timestamp": f"2026-11-06T19:00:0{index}+00:00",
        }
        for mac, timing in (
            ("02:00:00:00:00:01", 10.0),
            ("02:00:00:00:00:02", 12.0),
            ("02:00:00:00:00:03", 100.0),
            ("02:00:00:00:00:04", 102.0),
        )
        for index in range(3)
    ]


def group_ids(clusters):
    return {tuple(cluster.mac_addresses): cluster.cluster_id for cluster in clusters}


def test_timing_subdivisions_have_distinct_group_ids():
    _, clusters = run(separated_groups(), timing_threshold=20.0)
    assert len(clusters) == 2
    assert {tuple(c.mac_addresses) for c in clusters} == {
        ("02:00:00:00:00:01", "02:00:00:00:00:02"),
        ("02:00:00:00:00:03", "02:00:00:00:00:04"),
    }
    assert len({cluster.cluster_id for cluster in clusters}) == 2


def test_each_mac_lookup_returns_its_actual_timing_group():
    clusterer, clusters = run(separated_groups(), timing_threshold=20.0)
    for expected in clusters:
        for mac in expected.mac_addresses:
            found = clusterer.get_cluster_for_mac(mac)
            assert found is not None
            assert found.mac_addresses == expected.mac_addresses
            assert mac in found.mac_addresses
    assert clusterer.get_cluster_for_mac("02:00:00:00:ff:ff") is None


def test_resolved_membership_ids_survive_reordering_and_duplicate_observations():
    observations = separated_groups()
    _, original = run(observations, timing_threshold=20.0)
    for order in (list(reversed(observations)), observations[6:] + observations[:6]):
        _, reordered = run(order, timing_threshold=20.0)
        assert group_ids(reordered) == group_ids(original)
    _, duplicated = run(observations * 2, timing_threshold=20.0)
    assert group_ids(duplicated) == group_ids(original)
    assert all(cluster.observation_count == 12 for cluster in duplicated)


def test_duplicate_records_changing_fingerprint_mode_do_not_change_membership_id():
    first = {"mac": "02:00:00:00:00:01", "ie_fingerprint": "001c0000"}
    second = {"mac": "02:00:00:00:00:02", "ie_fingerprint": "001c0001"}
    _, original = run([first, first, first, second])
    _, duplicated = run([first, first, first, second, second, second, second])
    assert len(original) == len(duplicated) == 1
    assert original[0].ie_fingerprint == first["ie_fingerprint"]
    assert duplicated[0].ie_fingerprint == second["ie_fingerprint"]
    assert original[0].cluster_id == duplicated[0].cluster_id


def test_representative_fingerprint_ties_are_canonical():
    observations = [
        {"mac": "02:00:00:00:00:01", "ie_fingerprint": "001c0000"},
        {"mac": "02:00:00:00:00:02", "ie_fingerprint": "001c0001"},
    ]
    for order in (observations, list(reversed(observations))):
        _, clusters = run(order, min_samples=1)
        assert len(clusters) == 1
        assert clusters[0].ie_fingerprint == "001c0000"


@pytest.mark.parametrize("eps,expected", [(0.249, 2), (0.25, 1), (0.5, 1)])
def test_real_dbscan_respects_hand_computed_hamming_boundary(eps, expected):
    # One differing nibble out of four: distance 1/4, inclusive DBSCAN eps.
    assert DBSCAN.__module__.startswith("sklearn.")
    _, clusters = run(
        [
            {"mac": "a", "ie_fingerprint": "abcd"},
            {"mac": "b", "ie_fingerprint": "abce"},
        ],
        eps=eps,
        min_samples=1,
    )
    assert len(clusters) == expected


def test_missing_optional_dbscan_uses_actual_import_fallback(monkeypatch):
    observations = [
        {"mac": "a", "ie_fingerprint": "abcd"},
        {"mac": "b", "ie_fingerprint": "abce"},
    ]
    _, normal = run(observations, eps=0.5, min_samples=1)
    assert len(normal) == 1
    # Exercise an unavailable optional import, not fabricated clustering labels.
    monkeypatch.setitem(sys.modules, "sklearn.cluster", None)
    _, fallback = run(observations, eps=0.5, min_samples=1)
    assert {tuple(c.mac_addresses) for c in fallback} == {("a",), ("b",)}


def test_initial_state_and_observation_threshold():
    clusterer = DeviceClusterer(min_samples=3)
    assert clusterer.run_clustering() == []
    assert clusterer.get_all_clusters() == []
    assert clusterer.get_cluster_for_mac("a") is None
    for _ in range(2):
        clusterer.add_observation("a", "abcd")
    assert clusterer.run_clustering() == []
    clusterer.add_observation("a", "abcd")
    cluster = clusterer.run_clustering()[0]
    assert cluster.mac_addresses == ["a"]
    assert cluster.observation_count == 3
    assert cluster.confidence == pytest.approx(0.1)
    assert datetime.fromisoformat(cluster.first_seen).tzinfo == timezone.utc
    snapshot = clusterer.get_all_clusters()
    snapshot.clear()
    assert len(clusterer.get_all_clusters()) == 1


def test_zero_observation_threshold_still_accepts_empty_input():
    # The public constructor currently accepts zero; preserve that behavior
    # without imposing a new parameter-validation or density policy here.
    clusterer = DeviceClusterer(min_samples=0)
    assert clusterer.run_clustering() == []
    assert clusterer.get_all_clusters() == []
    assert clusterer.get_cluster_for_mac("a") is None


@pytest.mark.parametrize("distance,expected", [(9.0, 1), (10.0, 2), (11.0, 2)])
def test_timing_refinement_uses_strict_euclidean_threshold(distance, expected):
    _, clusters = run(
        [
            {"mac": "a", "ie_fingerprint": "abcd", "timing_sig": {"mean_ifat_us": 1.0}},
            {
                "mac": "b",
                "ie_fingerprint": "abcd",
                "timing_sig": {"mean_ifat_us": 1.0 + distance},
            },
        ],
        min_samples=1,
        timing_threshold=10.0,
    )
    assert len(clusters) == expected


def test_missing_timing_never_loses_observations_or_corrupts_mac_lookup():
    observations = [
        {"mac": "unknown", "ie_fingerprint": "abcd"},
        {"mac": "near", "ie_fingerprint": "abcd", "timing_sig": {"mean_ifat_us": 1.0}},
        {"mac": "far", "ie_fingerprint": "abcd", "timing_sig": {"mean_ifat_us": 100.0}},
    ]
    for order in permutations(observations):
        clusterer, clusters = run(order, min_samples=1, timing_threshold=10.0)
        # Missing timing assignment is currently order-dependent. Require
        # conservation and correct lookup without blessing a particular group
        # assignment or claiming this policy is order-independent.
        assert sorted(mac for c in clusters for mac in c.mac_addresses) == [
            "far",
            "near",
            "unknown",
        ]
        assert sum(c.observation_count for c in clusters) == 3
        assert len({c.cluster_id for c in clusters}) == len(clusters)
        for observation in order:
            found = clusterer.get_cluster_for_mac(observation["mac"])
            assert found is not None
            assert observation["mac"] in found.mac_addresses


def test_cluster_summary_preserves_counts_time_range_and_averages():
    _, clusters = run(separated_groups(), timing_threshold=20.0)
    by_macs = {tuple(c.mac_addresses): c for c in clusters}
    first = by_macs[("02:00:00:00:00:01", "02:00:00:00:00:02")]
    assert first.observation_count == 6
    assert first.timing_signature["mean_ifat_us"] == 11.0
    assert first.first_seen == "2026-11-06T19:00:00+00:00"
    assert first.last_seen == "2026-11-06T19:00:02+00:00"
    assert first.confidence == pytest.approx(0.6)
    assert first.device_class == "Apple iOS Device"


def test_confidence_saturates_with_sufficient_support_and_distinct_macs():
    _, clusters = run(
        [
            {"mac": mac, "ie_fingerprint": "abcd"}
            for mac in ("a", "b", "c")
            for _ in range(10)
        ]
    )
    assert len(clusters) == 1
    assert clusters[0].confidence == 1.0
    assert clusters[0].timing_signature == {}
    assert clusters[0].device_class == "Unknown Device"


@pytest.mark.parametrize(
    "first,second,expected",
    [("", "", 0.0), ("a", "a0", 0.0), ("a", "b0", 0.5), ("abcd", "abce", 0.25)],
)
def test_hamming_distance_counts_nibbles_and_zero_padding(first, second, expected):
    assert _hamming_ratio(first, second) == expected
    assert _hamming_ratio(second, first) == expected


def test_timing_distance_and_averages_have_independent_numeric_oracles():
    assert _timing_l2_distance({"mean_ifat_us": 3.0, "std_ifat_us": 4.0}, {}) == 5.0
    assert _average_timing_sig([]) == {}
    average = _average_timing_sig(
        [{"mean_ifat_us": 10.0}, {"mean_ifat_us": 30.0, "burst_size_mean": 4.0}]
    )
    assert average == {
        "mean_ifat_us": 20.0,
        "std_ifat_us": 0.0,
        "mean_ibt_us": 0.0,
        "std_ibt_us": 0.0,
        "burst_size_mean": 2.0,
        "burst_size_std": 0.0,
        "burst_freq_hz": 0.0,
    }
