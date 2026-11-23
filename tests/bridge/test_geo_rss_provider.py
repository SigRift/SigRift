"""RSSGeoProvider must produce real estimates (review finding D7).

It used to build ``RSSIMeasurement`` without ``timestamp`` and
``NodePosition`` without ``node_id`` (both required) outside its try block,
so every call with usable observations raised TypeError; and it fed
latitude/longitude degrees to the metric solver as if they were metres.
"""

from __future__ import annotations

import math

import pytest

from sigrift.lib.dsp.multilateration import rssi_to_distance
from sigrift.providers.adapters import detections_to_observations
from sigrift.providers.base import GeoEstimate, SignalObservation
from sigrift.providers.geo_rss import RSSGeoProvider

_REF_RSSI = -30.0
_N = 2.5
_EARTH_R = 6_371_008.8


def _haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * _EARTH_R * math.asin(math.sqrt(a))


def _rssi_for(distance_m: float) -> float:
    """Exact log-distance RSSI for *distance_m* (inverse of rssi_to_distance)."""
    return _REF_RSSI - 10.0 * _N * math.log10(distance_m)


def _obs(node_id: str, power: float, pos: dict, t: float = 1_700_000_000.0):
    return SignalObservation(
        frequency_hz=433.92e6,
        timestamp_ns=int(t * 1e9),
        power_dbm=power,
        node_id=node_id,
        metadata={"node_position": pos},
    )


def _geo_observations(nodes: dict[str, tuple[float, float]], target):
    return [
        _obs(nid, _rssi_for(_haversine_m(lat, lon, *target)), {"lat": lat, "lon": lon})
        for nid, (lat, lon) in nodes.items()
    ]


# A ~300 m square of receivers in central London and an emitter inside it.
_LONDON = {
    "n-sw": (51.5000, -0.1250),
    "n-se": (51.5000, -0.1210),
    "n-nw": (51.5027, -0.1250),
    "n-ne": (51.5027, -0.1210),
}
_LONDON_TARGET = (51.5011, -0.1236)


def test_sanity_rssi_helper_round_trips() -> None:
    assert rssi_to_distance(_rssi_for(123.0)) == pytest.approx(123.0)


class TestGeographicFrame:
    def test_four_node_square_recovers_emitter(self) -> None:
        result = RSSGeoProvider().estimate(_geo_observations(_LONDON, _LONDON_TARGET))

        assert isinstance(result, GeoEstimate)
        assert result.method == "rss"
        assert result.confidence > 0.5
        assert result.latitude is not None and result.longitude is not None
        miss = _haversine_m(result.latitude, result.longitude, *_LONDON_TARGET)
        assert miss < 2.0, f"estimate is {miss:.1f} m from the emitter"
        # Error radius is in metres, not degrees.
        assert result.error_radius_m is not None and result.error_radius_m < 5.0
        assert result.metadata["coordinate_mode"] == "geo"
        assert result.metadata["node_count"] == 4
        assert result.metadata["solver_method"] == "rssi_trilateration"
        assert result.metadata["location"] == {
            "lat": result.latitude,
            "lon": result.longitude,
        }

    def test_three_node_triangle(self) -> None:
        nodes = {
            "a": (40.7480, -73.9860),
            "b": (40.7480, -73.9820),
            "c": (40.7510, -73.9840),
        }
        target = (40.7492, -73.9845)
        result = RSSGeoProvider().estimate(_geo_observations(nodes, target))
        assert result.latitude is not None
        assert _haversine_m(result.latitude, result.longitude, *target) < 2.0

    def test_two_nodes_fall_back_to_a_point_between_them(self) -> None:
        nodes = {"a": (48.8580, 2.2940), "b": (48.8580, 2.2980)}
        target = (48.8580, 2.2950)
        result = RSSGeoProvider().estimate(_geo_observations(nodes, target))
        assert result.metadata["solver_method"] == "rssi_weighted_centroid"
        assert result.latitude == pytest.approx(48.8580, abs=1e-6)
        assert 2.2940 < result.longitude < 2.2980
        # Weighted towards the nearer receiver.
        assert result.longitude < 2.2960

    def test_receivers_straddling_the_antimeridian(self) -> None:
        nodes = {
            "w": (-17.0000, 179.9990),
            "e": (-17.0000, -179.9990),
            "n": (-16.9980, 179.9995),
        }
        target = (-16.9993, 179.9998)
        result = RSSGeoProvider().estimate(_geo_observations(nodes, target))
        assert result.latitude is not None
        assert _haversine_m(result.latitude, result.longitude, *target) < 2.0
        assert -180.0 <= result.longitude < 180.0

    def test_via_detection_adapter(self) -> None:
        """The bridge's detection -> observation adapter feeds lat/lon dicts."""
        detections = [
            {
                "node_id": nid,
                "timestamp": "2026-11-05T12:00:00Z",
                "freq_hz": 433.92e6,
                "power_dbm": _rssi_for(_haversine_m(lat, lon, *_LONDON_TARGET)),
            }
            for nid, (lat, lon) in _LONDON.items()
        ]
        positions = {
            nid: {"lat": lat, "lon": lon} for nid, (lat, lon) in _LONDON.items()
        }
        obs = detections_to_observations(detections, positions)
        result = RSSGeoProvider().estimate(obs)
        assert _haversine_m(result.latitude, result.longitude, *_LONDON_TARGET) < 2.0


class TestMetricFrame:
    def test_local_xy_metres(self) -> None:
        nodes = {
            "a": (0.0, 0.0),
            "b": (100.0, 0.0),
            "c": (0.0, 100.0),
            "d": (100.0, 100.0),
        }
        target = (30.0, 40.0)
        obs = [
            _obs(nid, _rssi_for(math.dist((x, y), target)), {"x_m": x, "y_m": y})
            for nid, (x, y) in nodes.items()
        ]
        result = RSSGeoProvider().estimate(obs)
        assert result.confidence > 0.5
        # Metres are not degrees: no fake lat/lon.
        assert result.latitude is None and result.longitude is None
        assert result.metadata["coordinate_mode"] == "2d"
        loc = result.metadata["location"]
        assert loc["x_m"] == pytest.approx(30.0, abs=0.05)
        assert loc["y_m"] == pytest.approx(40.0, abs=0.05)


class TestInputHandling:
    def test_too_few_observations(self) -> None:
        result = RSSGeoProvider().estimate([_obs("a", -60.0, {"lat": 1.0, "lon": 1.0})])
        assert result.confidence == 0.0 and result.method == "rss"

    def test_repeated_observations_from_one_receiver_count_once(self) -> None:
        obs = [
            _obs("a", -60.0, {"lat": 1.0, "lon": 1.0}),
            _obs("a", -62.0, {"lat": 1.0, "lon": 1.0}),
        ]
        result = RSSGeoProvider().estimate(obs)
        assert result.confidence == 0.0

    def test_repeated_observations_are_averaged(self) -> None:
        target = (51.5011, -0.1236)
        obs = _geo_observations(_LONDON, target)
        # Two extra readings for one receiver, symmetric around the true value.
        lat, lon = _LONDON["n-sw"]
        true = _rssi_for(_haversine_m(lat, lon, *target))
        obs += [
            _obs("n-sw", true + 3.0, {"lat": lat, "lon": lon}),
            _obs("n-sw", true - 3.0, {"lat": lat, "lon": lon}),
        ]
        result = RSSGeoProvider().estimate(obs)
        assert result.metadata["node_count"] == 4
        assert _haversine_m(result.latitude, result.longitude, *target) < 2.0

    def test_unusable_positions_are_skipped(self) -> None:
        good = _geo_observations(_LONDON, _LONDON_TARGET)
        bad = [
            _obs("no-pos", -50.0, {}),
            _obs("nan", -50.0, {"lat": float("nan"), "lon": 0.0}),
            _obs("str", -50.0, {"lat": "51.5", "lon": "-0.12"}),
            _obs("range", -50.0, {"lat": 95.0, "lon": 0.0}),
            _obs("", -50.0, {"lat": 51.5, "lon": -0.12}),
            _obs("nan-power", float("nan"), {"lat": 51.5, "lon": -0.12}),
        ]
        result = RSSGeoProvider().estimate(good + bad)
        assert result.metadata["node_count"] == 4
        assert _haversine_m(result.latitude, result.longitude, *_LONDON_TARGET) < 2.0

    def test_mixed_frames_use_the_majority_frame(self) -> None:
        obs = _geo_observations(_LONDON, _LONDON_TARGET)
        obs.append(_obs("xy-node", -40.0, {"x_m": 0.0, "y_m": 0.0}))
        result = RSSGeoProvider().estimate(obs)
        assert result.metadata["coordinate_mode"] == "geo"
        assert "xy-node" not in result.metadata["contributing_nodes"]
        assert _haversine_m(result.latitude, result.longitude, *_LONDON_TARGET) < 2.0

    def test_receivers_at_a_pole_are_refused(self) -> None:
        nodes = {"a": (90.0, 0.0), "b": (90.0, 90.0), "c": (90.0, 180.0)}
        result = RSSGeoProvider().estimate(_geo_observations(nodes, (89.9999, 0.0)))
        assert result.confidence == 0.0

    def test_configured_path_loss_is_used(self) -> None:
        provider = RSSGeoProvider()
        provider.configure({"path_loss_exponent": 3.0, "reference_rssi_dbm": -40.0})
        obs = [
            _obs(
                nid,
                -40.0 - 30.0 * math.log10(_haversine_m(lat, lon, *_LONDON_TARGET)),
                {"lat": lat, "lon": lon},
            )
            for nid, (lat, lon) in _LONDON.items()
        ]
        result = provider.estimate(obs)
        assert result.metadata["path_loss_exponent"] == 3.0
        assert _haversine_m(result.latitude, result.longitude, *_LONDON_TARGET) < 2.0
