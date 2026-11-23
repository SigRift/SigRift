"""IQ consumers analyse a bounded window and return bounded results (review P8).

Decompression was capped (32 Mi samples), but all-zero IQ compresses
about 1000:1, so a ~260 KB upload stores a cap-sized capture.  The
consumers then processed all of it: ``compute_visualization`` ran a
full-length FFT and returned one PSD value (as a Python float, twice)
per sample; ``GET /spectrogram`` accepted ``overlap = nfft - 1`` and
built an nfft x n_segments matrix with no row limit.  One VIEWER GET
after one SENSOR upload cost gigabytes.
"""

from __future__ import annotations

import gzip
import tracemalloc
import zlib
from pathlib import Path

import numpy as np
import pytest
from fastapi.testclient import TestClient
from scipy.signal import spectrogram as scipy_spectrogram

import sigrift.bridge.iq_store as iq_mod
from sigrift.bridge.iq_store import IQStore, decompress_iq

_MiB = 1024 * 1024


def _zero_bomb(n_samples: int) -> bytes:
    """Gzip of *n_samples* all-zero complex64 samples, built in steps."""
    comp = zlib.compressobj(9, zlib.DEFLATED, 31)
    chunk = b"\0" * _MiB
    parts, remaining = [], n_samples * 8
    while remaining:
        step = min(remaining, len(chunk))
        parts.append(comp.compress(chunk[:step]))
        remaining -= step
    parts.append(comp.flush())
    return b"".join(parts)


def _noise(n: int, seed: int = 1) -> np.ndarray:
    rng = np.random.default_rng(seed)
    return (rng.standard_normal(n) + 1j * rng.standard_normal(n)).astype(np.complex64)


@pytest.fixture
def bomb_store(tmp_path: Path) -> IQStore:
    """A store holding an 8 Mi-sample (64 MiB) capture uploaded as ~64 KB."""
    store = IQStore(base_dir=tmp_path)
    payload = _zero_bomb(8 * _MiB)
    assert len(payload) < 128 * 1024
    store.store("bomb", payload)
    return store


def _peak(fn) -> tuple[object, int]:
    tracemalloc.start()
    try:
        result = fn()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return result, peak


class TestBoundedLoading:
    def test_truncated_decompression_returns_the_prefix(self) -> None:
        iq = _noise(10_000)
        out = decompress_iq(gzip.compress(iq.tobytes()), 4096, truncate=True)
        np.testing.assert_array_equal(out, iq[:4096])
        # Under the limit: the whole capture, as without truncate.
        out = decompress_iq(gzip.compress(iq.tobytes()), 20_000, truncate=True)
        np.testing.assert_array_equal(out, iq)

    def test_truncated_decompression_stops_inflating(self) -> None:
        bomb = _zero_bomb(32 * _MiB)  # 256 MiB decompressed
        out, peak = _peak(lambda: decompress_iq(bomb, _MiB, truncate=True))
        assert len(out) == _MiB
        assert peak < 8 * _MiB + 4 * _MiB, peak

    def test_load_iq_max_samples(self, tmp_path: Path) -> None:
        store = IQStore(base_dir=tmp_path)
        iq = _noise(5000)
        store.store("d", gzip.compress(iq.tobytes()))
        np.testing.assert_array_equal(store.load_iq("d", max_samples=1000), iq[:1000])
        np.testing.assert_array_equal(store.load_iq("d"), iq)

    def test_analysis_cap_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert iq_mod.analysis_max_samples() == 2 * _MiB
        monkeypatch.setenv("BRIDGE_IQ_ANALYSIS_MAX_SAMPLES", "4096")
        assert iq_mod.analysis_max_samples() == 4096
        monkeypatch.setenv("BRIDGE_IQ_ANALYSIS_MAX_SAMPLES", "nope")
        assert iq_mod.analysis_max_samples() == 2 * _MiB
        # Never above the decompression cap.
        monkeypatch.setenv("BRIDGE_IQ_ANALYSIS_MAX_SAMPLES", str(10**12))
        assert iq_mod.analysis_max_samples() == iq_mod.max_iq_samples()

    def test_sample_count_does_not_hold_the_samples(self, bomb_store) -> None:
        count, peak = _peak(lambda: bomb_store.sample_count("bomb"))
        assert count == 8 * _MiB
        assert peak < 4 * _MiB, peak
        assert bomb_store.sample_count("missing") is None


class TestBoundedVisualization:
    def test_bomb_visualization_is_bounded(self, bomb_store) -> None:
        viz, peak = _peak(lambda: bomb_store.compute_visualization("bomb"))
        assert len(viz["psd_db"]) == len(viz["psd_freq_hz"]) == 2048
        assert len(viz["constellation_x"]) <= 2048
        assert len(viz["dsp_features"]) == 16
        # 8 Mi samples used to cost > 1 GB here (FFT + two 8 Mi-float lists).
        assert peak < 200 * _MiB, peak

    def test_small_capture_keeps_its_full_periodogram(self, tmp_path: Path) -> None:
        store = IQStore(base_dir=tmp_path)
        iq = _noise(1024)
        store.store("small", gzip.compress(iq.tobytes()))
        viz = store.compute_visualization("small")
        expected = 10 * np.log10(
            np.abs(np.fft.fftshift(np.fft.fft(iq))) ** 2 / 1024 + 1e-12
        )
        np.testing.assert_allclose(viz["psd_db"], expected, rtol=1e-5, atol=1e-4)

    @pytest.mark.parametrize("n", [1000, 100_000])
    def test_tone_peak_at_its_frequency(self, tmp_path: Path, n: int) -> None:
        store = IQStore(base_dir=tmp_path)
        tone = np.exp(2j * np.pi * 0.125 * np.arange(n)).astype(np.complex64)
        store.store("tone", gzip.compress((tone + 0.01 * _noise(n)).tobytes()))
        viz = store.compute_visualization("tone")
        peak_freq = viz["psd_freq_hz"][int(np.argmax(viz["psd_db"]))]
        assert peak_freq == pytest.approx(0.125, abs=2 / min(n, 2048))


class TestBoundedSpectrogram:
    def test_bomb_spectrogram_with_maximal_overlap(self, bomb_store) -> None:
        result, peak = _peak(
            lambda: bomb_store.compute_spectrogram("bomb", nfft=64, overlap=63)
        )
        cells = result["n_segments"] * len(result["freq_axis"])
        assert len(result["freq_axis"]) == 64
        assert cells <= iq_mod.SPECTROGRAM_MAX_CELLS
        assert len(result["spectrogram"]) == result["n_segments"]
        assert result["truncated"] is True
        assert result["n_samples"] == iq_mod.analysis_max_samples()
        # The hop was raised to keep the STFT work bounded.
        assert result["overlap"] < 63
        n_seg = 1 + (result["n_samples"] - 64) // (64 - result["overlap"])
        assert n_seg * 64 <= iq_mod.SPECTROGRAM_MAX_FFT_CELLS
        assert peak < 300 * _MiB, peak

    def test_matches_scipy_segment_for_segment(self, tmp_path: Path) -> None:
        store = IQStore(base_dir=tmp_path)
        iq = _noise(40_000, seed=3)
        store.store("s", gzip.compress(iq.tobytes()))
        result = store.compute_spectrogram("s", nfft=256, overlap=200)
        f, t, sxx = scipy_spectrogram(
            iq, fs=1.0, nperseg=256, noverlap=200, window="hann", return_onesided=False
        )
        db = 10 * np.log10(np.maximum(np.fft.fftshift(sxx, axes=0), 1e-12))
        db = np.clip(db - db.max(), -60, 0).T
        assert result["overlap"] == 200
        np.testing.assert_allclose(result["spectrogram"], db, atol=1e-3)
        np.testing.assert_allclose(result["time_axis"], t)
        np.testing.assert_allclose(result["freq_axis"], np.fft.fftshift(f))

    def test_row_averaging_matches_averaged_scipy(self, tmp_path: Path) -> None:
        store = IQStore(base_dir=tmp_path)
        iq = _noise(256 * 999, seed=4)
        store.store("s", gzip.compress(iq.tobytes()))
        result = store.compute_spectrogram("s", nfft=256, overlap=128, max_segments=50)
        _, t, sxx = scipy_spectrogram(
            iq, fs=1.0, nperseg=256, noverlap=128, window="hann", return_onesided=False
        )
        factor = -(-sxx.shape[1] // 50)
        edges = np.arange(0, sxx.shape[1], factor)
        counts = np.diff(np.append(edges, sxx.shape[1]))
        avg = np.add.reduceat(sxx, edges, axis=1) / counts
        db = 10 * np.log10(np.maximum(np.fft.fftshift(avg, axes=0), 1e-12))
        db = np.clip(db - db.max(), -60, 0).T
        assert result["n_segments"] == len(edges) <= 50
        np.testing.assert_allclose(result["spectrogram"], db, atol=1e-3)
        np.testing.assert_allclose(
            result["time_axis"], np.add.reduceat(t, edges) / counts
        )

    def test_default_rows_fill_the_cell_budget(self, tmp_path: Path) -> None:
        store = IQStore(base_dir=tmp_path)
        store.store("s", gzip.compress(_noise(2 * _MiB).tobytes(), 1))
        result = store.compute_spectrogram("s", nfft=64, overlap=32)
        assert result["n_segments"] * 64 <= iq_mod.SPECTROGRAM_MAX_CELLS
        assert result["n_segments"] > iq_mod.SPECTROGRAM_MAX_CELLS // 64 // 2

    def test_bad_overlap_is_refused(self, tmp_path: Path) -> None:
        store = IQStore(base_dir=tmp_path)
        store.store("s", gzip.compress(_noise(4096).tobytes()))
        with pytest.raises(ValueError):
            store.compute_spectrogram("s", nfft=256, overlap=256)


class TestRoutes:
    """The failure scenario: a SENSOR uploads a bomb, a VIEWER GETs it."""

    @pytest.fixture
    def bomb_id(self, client: TestClient, registered_node: str) -> str:
        resp = client.put(
            "/api/detections/det-bomb/iq",
            content=_zero_bomb(8 * _MiB),
            headers={"Content-Encoding": "gzip", "X-Node-Id": registered_node},
        )
        assert resp.status_code == 201, resp.text
        return "det-bomb"

    def test_visualization_json_is_bounded(self, client: TestClient, bomb_id) -> None:
        resp = client.get(f"/api/detections/{bomb_id}/iq")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert len(body["psd_db"]) == 2048  # was one value per sample (8 Mi)
        assert len(resp.content) < 1 * _MiB

    def test_spectrogram_with_maximal_overlap_is_bounded(
        self, client: TestClient, bomb_id
    ) -> None:
        resp = client.get(f"/api/detections/{bomb_id}/spectrogram?nfft=64&overlap=63")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert (
            body["n_segments"] * len(body["freq_axis"]) <= iq_mod.SPECTROGRAM_MAX_CELLS
        )
        flat = [v for row in body["spectrogram"][:50] for v in row]
        assert all(round(v, 1) == v for v in flat)  # 0.1 dB, as the viewer shows

    def test_unknown_window_is_a_client_error(
        self, client: TestClient, bomb_id
    ) -> None:
        resp = client.get(f"/api/detections/{bomb_id}/spectrogram?window=nonsense")
        assert resp.status_code == 422

    def test_sigmf_counts_the_whole_capture(self, client: TestClient, bomb_id) -> None:
        resp = client.get(f"/api/detections/{bomb_id}/sigmf")
        assert resp.status_code == 200, resp.text
        assert resp.json()["annotations"][0]["core:sample_count"] == 8 * _MiB

    def test_modulation_is_bounded(self, client: TestClient, bomb_id) -> None:
        resp = client.get(f"/api/detections/{bomb_id}/modulation")
        assert resp.status_code == 200, resp.text
        assert resp.json()["n_samples"] == iq_mod.analysis_max_samples()


class TestLibraryConsumers:
    """Signature matching / creation and bitstream extraction (BR2-V2).

    ``POST /api/signatures/match`` (VIEWER), ``POST
    /api/signatures/from-detection/{id}`` and ``POST /api/bitstreams/extract``
    inflated the whole capture and ran the DSP features (or the extractor)
    over it: 32 Mi samples cost ~25 s and 2.6 GB per request.
    """

    @pytest.fixture
    def bomb_id(self, client: TestClient, registered_node: str) -> str:
        resp = client.put(
            "/api/detections/det-bomb/iq",
            content=_zero_bomb(8 * _MiB),
            headers={"Content-Encoding": "gzip", "X-Node-Id": registered_node},
        )
        assert resp.status_code == 201, resp.text
        return "det-bomb"

    @pytest.fixture
    def window(self, monkeypatch: pytest.MonkeyPatch) -> int:
        monkeypatch.setenv("BRIDGE_IQ_ANALYSIS_MAX_SAMPLES", str(256 * 1024))
        return iq_mod.analysis_max_samples()

    @pytest.fixture
    def embedded(self, monkeypatch: pytest.MonkeyPatch) -> list[int]:
        """Lengths the embedding is computed over (the computation stubbed)."""
        import sigrift.bridge.routers.signature_library as sig_mod

        lengths: list[int] = []

        def embed(iq: np.ndarray) -> tuple[list[float], list[float]]:
            lengths.append(len(iq))
            return [1.0] + [0.0] * 31, [0.0] * 49

        monkeypatch.setattr(sig_mod, "_compute_embedding_from_iq", embed)
        return lengths

    @staticmethod
    def _client_with_role(bridge_app, role: str) -> TestClient:
        from sigrift.lib.security.credentials import generate_api_key, hash_credential

        raw = generate_api_key(length=32)
        h, s = hash_credential(raw)
        key_id = f"{role}_bounds"
        bridge_app.state.persistence.set_key(key_id, h, s)
        bridge_app.state.persistence.set_key_meta(key_id, {"role": role})
        return TestClient(bridge_app, headers={"X-API-Key": raw})

    def test_viewer_match_analyses_the_window(
        self, bridge_app, bomb_id, window, embedded
    ) -> None:
        viewer = self._client_with_role(bridge_app, "viewer")
        resp, peak = _peak(
            lambda: viewer.post("/api/signatures/match", json={"detection_id": bomb_id})
        )
        assert resp.status_code == 200, resp.text
        assert embedded == [window]  # was the whole capture (8 Mi samples)
        assert peak < 24 * _MiB, f"{peak / _MiB:.0f} MiB"

    def test_from_detection_analyses_the_window_and_counts_all(
        self, bridge_app, bomb_id, window, embedded
    ) -> None:
        analyst = self._client_with_role(bridge_app, "analyst")
        resp, peak = _peak(
            lambda: analyst.post(
                f"/api/signatures/from-detection/{bomb_id}",
                json={"name": "bomb", "protocol": "custom"},
            )
        )
        assert resp.status_code == 201, resp.text
        assert embedded == [window]
        assert resp.json()["iq_samples"] == 8 * _MiB
        assert peak < 24 * _MiB, f"{peak / _MiB:.0f} MiB"

    def test_reference_upload_analyses_the_window(
        self, client: TestClient, window, embedded
    ) -> None:
        resp = client.post(
            "/api/signatures/",
            data={"name": "Bomb", "protocol": "custom", "signal_class": "bpsk"},
            files={"iq_file": ("x.iq.gz", _zero_bomb(_MiB), "application/gzip")},
        )
        assert resp.status_code == 201, resp.text
        assert embedded == [window]
        assert resp.json()["iq_samples"] == _MiB

    def test_short_capture_is_analysed_whole(
        self, client: TestClient, window, embedded
    ) -> None:
        resp = client.post(
            "/api/signatures/",
            data={"name": "Short", "protocol": "custom", "signal_class": "bpsk"},
            files={"iq_file": ("x.iq", _noise(1000).tobytes(), "application/x")},
        )
        assert resp.status_code == 201, resp.text
        assert embedded == [1000]
        assert resp.json()["iq_samples"] == 1000

    def test_bitstream_extraction_analyses_the_window(
        self, bridge_app, bomb_id, window, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import sigrift.lib.dsp.bitstream_extractor as extractor

        lengths: list[int] = []
        real = extractor.extract_bitstream

        def extract(iq, **kwargs):
            lengths.append(len(iq))
            return real(iq=iq, **kwargs)

        monkeypatch.setattr(extractor, "extract_bitstream", extract)
        analyst = self._client_with_role(bridge_app, "analyst")
        resp, peak = _peak(
            lambda: analyst.post(
                "/api/bitstreams/extract",
                json={
                    "detection_id": bomb_id,
                    "modulation": "bpsk",
                    "symbol_rate": 100_000.0,
                },
            )
        )
        assert lengths == [window], resp.text
        assert peak < 64 * _MiB, f"{peak / _MiB:.0f} MiB"
