"""Regression tests for IQ store hardening (review C1, C9, C9b, C2 spectrogram).

* C1: gzip uploads are decompressed with a sample cap, so a small "bomb"
  cannot inflate into gigabytes.
* C9: deleting / expiring a capture removes its ``.quality.json`` and
  ``.sigmf-meta`` sidecars; orphans left by older releases are swept.
* C9b: the detection-id -> file-name mapping is injective.
* C2: the job-queue spectrogram can be bounded in size.
"""

from __future__ import annotations

import gzip
import os
import time
import tracemalloc
import zlib
from pathlib import Path

import numpy as np
import pytest

from sigrift.bridge.iq_store import (
    IQDecompressionError,
    IQSampleLimitError,
    IQStore,
    capture_stem,
    decompress_iq,
)
from sigrift.bridge.sigmf import save_sigmf_meta


def _iq_bytes(n_samples: int, seed: int = 1) -> tuple[bytes, np.ndarray]:
    rng = np.random.default_rng(seed)
    iq = (rng.standard_normal(n_samples) + 1j * rng.standard_normal(n_samples)).astype(
        np.complex64
    )
    return iq.tobytes(), iq


def _zero_bomb(total_bytes: int) -> bytes:
    """Gzip of *total_bytes* zero bytes, built without holding them in memory."""
    comp = zlib.compressobj(9, zlib.DEFLATED, 31)
    chunk = b"\0" * (1 << 20)
    parts = []
    remaining = total_bytes
    while remaining:
        n = min(remaining, len(chunk))
        parts.append(comp.compress(chunk[:n]))
        remaining -= n
    parts.append(comp.flush())
    return b"".join(parts)


class TestBoundedDecompression:
    def test_roundtrip_matches_interleaved_float32(self) -> None:
        raw, iq = _iq_bytes(4096)
        out = decompress_iq(gzip.compress(raw))
        assert out.dtype == np.complex64
        np.testing.assert_array_equal(out, iq)

    def test_bomb_rejected_without_inflating_it(self) -> None:
        # 128 MiB of zeros compress to ~130 KB; the old gzip.decompress()
        # inflated all of it (an upload this size inflated to ~10 GB).
        bomb = _zero_bomb(128 * 1024 * 1024)
        assert len(bomb) < 1024 * 1024
        tracemalloc.start()
        try:
            with pytest.raises(IQSampleLimitError, match="exceeds the limit"):
                decompress_iq(bomb, max_samples=1024 * 1024)  # 8 MiB cap
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert peak < 40 * 1024 * 1024, f"peak {peak} bytes"

    def test_env_cap_applies_to_store_and_nothing_is_written(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BRIDGE_IQ_MAX_SAMPLES", "1000")
        store = IQStore(base_dir=tmp_path)
        raw, _ = _iq_bytes(1001)
        with pytest.raises(IQSampleLimitError):
            store.store("bomb-1", gzip.compress(raw))
        assert not store.exists("bomb-1")
        assert list(tmp_path.iterdir()) == []

    def test_at_cap_is_accepted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BRIDGE_IQ_MAX_SAMPLES", "1000")
        store = IQStore(base_dir=tmp_path)
        raw, iq = _iq_bytes(1000)
        store.store("ok-1", gzip.compress(raw))
        np.testing.assert_array_equal(store.load_iq("ok-1"), iq)

    def test_load_iq_refuses_over_cap_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = IQStore(base_dir=tmp_path)
        # A file stored before the cap existed (written directly here).
        store._path_for("old-big").write_bytes(_zero_bomb(64 * 1024))
        monkeypatch.setenv("BRIDGE_IQ_MAX_SAMPLES", "1024")
        assert store.load_iq("old-big") is None

    def test_multi_member_and_trailing_zeros_like_gzip_module(self) -> None:
        a, iq_a = _iq_bytes(100, seed=2)
        b, iq_b = _iq_bytes(50, seed=3)
        data = gzip.compress(a) + gzip.compress(b) + b"\0" * 16
        assert gzip.decompress(data) == a + b
        np.testing.assert_array_equal(decompress_iq(data), np.concatenate([iq_a, iq_b]))

    @pytest.mark.parametrize(
        "payload",
        [
            b"",
            b"not gzip at all",
            gzip.compress(b"\0" * 12)[:-6],
            gzip.compress(b"\0" * 12),
        ],
        ids=["empty", "garbage", "truncated", "partial-sample"],
    )
    def test_invalid_payloads_raise_decompression_error(self, payload: bytes) -> None:
        with pytest.raises(IQDecompressionError):
            decompress_iq(payload)

    def test_invalid_gzip_still_stored_without_quality(self, tmp_path: Path) -> None:
        store = IQStore(base_dir=tmp_path)
        store.store("raw-1", b"not gzip")
        assert store.load_raw("raw-1") == b"not gzip"
        assert store.get_quality("raw-1") is None
        assert store.load_iq("raw-1") is None


class TestInjectiveIds:
    def test_distinct_ids_never_share_a_file(self, tmp_path: Path) -> None:
        store = IQStore(base_dir=tmp_path)
        raw_a, iq_a = _iq_bytes(64, seed=4)
        raw_b, iq_b = _iq_bytes(64, seed=5)
        store.store("ab", gzip.compress(raw_a))
        store.store("a.b", gzip.compress(raw_b))  # stripped to "ab" before
        np.testing.assert_array_equal(store.load_iq("ab"), iq_a)
        np.testing.assert_array_equal(store.load_iq("a.b"), iq_b)

    @pytest.mark.parametrize(
        "ids",
        [("a.b", "ab"), ("a/b", "ab"), ("a b", "a_b"), ("ü", "~c3bc"), ("x:1", "x1")],
    )
    def test_stems_are_distinct(self, ids: tuple[str, str]) -> None:
        assert capture_stem(ids[0]) != capture_stem(ids[1])

    def test_plain_ids_keep_their_file_name(self, tmp_path: Path) -> None:
        store = IQStore(base_dir=tmp_path)
        assert store._path_for("det-01_AB").name == "det-01_AB.iq.gz"

    @pytest.mark.parametrize("bad", ["", "é" * 200])
    def test_empty_or_overlong_id_rejected(self, bad: str) -> None:
        with pytest.raises(ValueError, match="Invalid detection_id"):
            capture_stem(bad)

    def test_traversal_stays_inside_base_dir(self, tmp_path: Path) -> None:
        store = IQStore(base_dir=tmp_path)
        path = store._path_for("../../etc/passwd")
        assert path.parent == tmp_path.resolve()


class TestSidecarCleanup:
    def _store_with_sidecars(self, tmp_path: Path, det_id: str) -> IQStore:
        store = IQStore(base_dir=tmp_path)
        raw, _ = _iq_bytes(256)
        store.store(det_id, gzip.compress(raw))
        save_sigmf_meta(det_id, {"global": {}}, base_dir=tmp_path)
        return store

    def _sidecars(self, tmp_path: Path) -> list[str]:
        return sorted(
            p.name
            for p in tmp_path.iterdir()
            if p.name.endswith((".quality.json", ".sigmf-meta"))
        )

    def test_delete_removes_sidecars(self, tmp_path: Path) -> None:
        store = self._store_with_sidecars(tmp_path, "det-del")
        assert self._sidecars(tmp_path) == [
            "det-del.quality.json",
            "det-del.sigmf-meta",
        ]
        assert store.delete("det-del") is True
        assert list(tmp_path.iterdir()) == []

    def test_delete_of_encoded_id_removes_its_sidecars(self, tmp_path: Path) -> None:
        store = self._store_with_sidecars(tmp_path, "node:1/det")
        assert store.delete("node:1/det") is True
        assert list(tmp_path.iterdir()) == []

    def test_cleanup_removes_sidecars_of_aged_captures(self, tmp_path: Path) -> None:
        store = self._store_with_sidecars(tmp_path, "old")
        old = time.time() - 10 * 86400
        os.utime(store._path_for("old"), (old, old))
        assert store.cleanup(max_age_days=7) == 1
        assert list(tmp_path.iterdir()) == []

    def test_orphans_swept_at_startup_and_on_cleanup(self, tmp_path: Path) -> None:
        old = time.time() - 3600
        for name in ("gone.quality.json", "gone.sigmf-meta"):
            (tmp_path / name).write_text("{}")
            os.utime(tmp_path / name, (old, old))
        IQStore(base_dir=tmp_path)  # startup sweep
        assert self._sidecars(tmp_path) == []

        store = self._store_with_sidecars(tmp_path, "kept")
        (tmp_path / "gone2.quality.json").write_text("{}")
        os.utime(tmp_path / "gone2.quality.json", (old, old))
        store.cleanup(max_age_days=7)
        assert self._sidecars(tmp_path) == ["kept.quality.json", "kept.sigmf-meta"]

    def test_recent_orphan_left_alone(self, tmp_path: Path) -> None:
        (tmp_path / "inflight.quality.json").write_text("{}")
        IQStore(base_dir=tmp_path)
        assert self._sidecars(tmp_path) == ["inflight.quality.json"]


class TestBoundedSpectrogram:
    def test_max_segments_bounds_rows_and_keeps_time_span(self, tmp_path: Path) -> None:
        store = IQStore(base_dir=tmp_path)
        raw, _ = _iq_bytes(256 * 2000)
        store.store("spec", gzip.compress(raw))
        full = store.compute_spectrogram("spec", nfft=256, overlap=128)
        small = store.compute_spectrogram(
            "spec", nfft=256, overlap=128, max_segments=100
        )
        assert full["n_segments"] > 1000
        assert small["n_segments"] <= 100
        assert len(small["spectrogram"]) == small["n_segments"]
        assert len(small["spectrogram"][0]) == 256
        # Rows are averages of consecutive segments: the span is preserved.
        times = small["time_axis"]
        assert times == sorted(times)
        assert full["time_axis"][0] <= times[0] < times[-1] <= full["time_axis"][-1]
        assert times[-1] - times[0] > 0.9 * (
            full["time_axis"][-1] - full["time_axis"][0]
        )


class TestDecompressionWorkBounds:
    """Repair of C1: linear work, peak ~ cap, bounded member count."""

    def test_peak_memory_is_about_the_cap_not_twice_it(self) -> None:
        # The first fix inflated up to the whole cap in one call and then
        # copied it into the output buffer: the peak was ~2x the cap.
        cap_samples = 4 * 1024 * 1024  # 32 MiB
        cap_bytes = cap_samples * 8
        bomb = _zero_bomb(256 * 1024 * 1024)
        tracemalloc.start()
        try:
            with pytest.raises(IQSampleLimitError):
                decompress_iq(bomb, max_samples=cap_samples)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert peak < 1.25 * cap_bytes + 2 * 1024 * 1024, f"peak {peak} bytes"

    def test_too_many_gzip_members_rejected_quickly(self) -> None:
        # Tiny members used to cost a copy of the whole remaining input
        # each (quadratic CPU): 10 MB of them took minutes on the loop.
        member = gzip.compress(b"")
        payload = member * (10_000_000 // len(member))
        started = time.perf_counter()
        with pytest.raises(IQDecompressionError, match="gzip members"):
            decompress_iq(payload)
        assert time.perf_counter() - started < 1.0

    def test_up_to_the_member_limit_is_accepted(self) -> None:
        from sigrift.bridge.iq_store import _MAX_GZIP_MEMBERS

        parts, expected = [], []
        for i in range(_MAX_GZIP_MEMBERS):
            raw, iq = _iq_bytes(10, seed=100 + i)
            parts.append(gzip.compress(raw) + b"\0" * (i % 3))
            expected.append(iq)
        out = decompress_iq(b"".join(parts))
        np.testing.assert_array_equal(out, np.concatenate(expected))

    def test_zlib_is_fed_bounded_input_slices(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import sigrift.bridge.iq_store as iq_mod

        fed: list[int] = []
        real = zlib.decompressobj

        class Recording:
            def __init__(self, *args, **kwargs) -> None:
                self._d = real(*args, **kwargs)

            def decompress(self, data, max_length=0):
                fed.append(len(data))
                return self._d.decompress(data, max_length)

            def __getattr__(self, name):
                return getattr(self._d, name)

        monkeypatch.setattr(iq_mod.zlib, "decompressobj", Recording)
        raw, iq = _iq_bytes(1024 * 1024)  # 8 MiB of incompressible samples
        payload = gzip.compress(raw, 1) + gzip.compress(raw[:800], 1)
        out = decompress_iq(payload)
        assert len(out) == len(iq) + 100
        assert max(fed) <= iq_mod._INFLATE_INPUT_CHUNK

    @pytest.mark.parametrize("n_samples", [131_071, 131_072, 1_000_003])
    def test_roundtrip_across_output_steps(self, n_samples: int) -> None:
        # Mostly-zero data inflates in many max_length-limited steps; the
        # output held back inside zlib at the end must still be drained.
        iq = np.zeros(n_samples, dtype=np.complex64)
        iq[::4096] = 1 + 1j
        iq[-1] = 2 - 2j
        out = decompress_iq(gzip.compress(iq.tobytes(), 9), max_samples=n_samples)
        np.testing.assert_array_equal(out, iq)

    def test_long_zero_padding_is_linear(self) -> None:
        raw, iq = _iq_bytes(1000)
        payload = gzip.compress(raw) + b"\0" * 10_000_000 + gzip.compress(raw)
        started = time.perf_counter()
        out = decompress_iq(payload)
        assert time.perf_counter() - started < 1.0
        np.testing.assert_array_equal(out, np.concatenate([iq, iq]))


class TestSpectrogramJobHandler:
    """Repair of C2: every accepted nfft yields a result under the cap."""

    @pytest.fixture
    def long_capture(self, tmp_path: Path) -> IQStore:
        store = IQStore(base_dir=tmp_path)
        raw, _ = _iq_bytes(2 * 1024 * 1024)
        store.store("long", gzip.compress(raw, 1))
        return store

    @pytest.mark.parametrize("nfft", [256, 1024, 4096, 100_000])
    def test_job_completes_under_the_default_result_cap(
        self, long_capture: IQStore, nfft: int
    ) -> None:
        import asyncio

        from sigrift.bridge.iq_store import spectrogram_job_handler
        from sigrift.bridge.job_queue import AnalysisJobQueue

        async def run() -> dict:
            queue = AnalysisJobQueue(max_workers=1)
            queue.register_handler(
                "spectrogram",
                spectrogram_job_handler(
                    long_capture, max_result_bytes=queue.max_result_bytes
                ),
            )
            await queue.start()
            try:
                job_id = await queue.submit(
                    "spectrogram", {"detection_id": "long", "nfft": nfft}
                )
                for _ in range(600):
                    job = queue.get_job_status(job_id)
                    if job["status"] in ("completed", "failed"):
                        return job
                    await asyncio.sleep(0.05)
                raise AssertionError("job did not finish")
            finally:
                await queue.stop()

        job = asyncio.run(run())
        assert job["status"] == "completed", job["error"]
        result = job["result"]
        bins = min(nfft, 4096)
        assert result["nfft"] == bins
        assert len(result["spectrogram"][0]) == bins
        assert len(result["spectrogram"]) * bins <= 256 * 1024
        assert len(result["spectrogram"]) >= 1

    def test_db_values_rounded_and_in_range(self, long_capture: IQStore) -> None:
        from sigrift.bridge.iq_store import spectrogram_job_handler

        result = spectrogram_job_handler(long_capture)("j", {"detection_id": "long"})
        flat = [v for row in result["spectrogram"] for v in row]
        assert all(-60.0 <= v <= 0.0 for v in flat)
        assert all(round(v, 1) == v for v in flat)

    def test_small_result_cap_shrinks_the_rows(self, long_capture: IQStore) -> None:
        import json

        from sigrift.bridge.iq_store import spectrogram_job_handler

        handler = spectrogram_job_handler(long_capture, max_result_bytes=512 * 1024)
        result = handler("j", {"detection_id": "long", "nfft": 512})
        assert len(json.dumps(result)) < 512 * 1024

    def test_bad_env_value_does_not_break_startup(
        self, long_capture: IQStore, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from sigrift.bridge.iq_store import spectrogram_job_handler

        monkeypatch.setenv("BRIDGE_JOB_SPECTROGRAM_MAX_SEGMENTS", "lots")
        handler = spectrogram_job_handler(long_capture)  # used to raise
        result = handler("j", {"detection_id": "long", "nfft": 256})
        assert len(result["spectrogram"]) == 512
        monkeypatch.setenv("BRIDGE_JOB_SPECTROGRAM_MAX_SEGMENTS", "8")
        result = spectrogram_job_handler(long_capture)("j", {"detection_id": "long"})
        assert len(result["spectrogram"]) == 8

    def test_bad_params(self, long_capture: IQStore) -> None:
        from sigrift.bridge.iq_store import spectrogram_job_handler

        handler = spectrogram_job_handler(long_capture)
        with pytest.raises(ValueError, match="detection_id"):
            handler("j", {})
        with pytest.raises(ValueError, match="nfft"):
            handler("j", {"detection_id": "long", "nfft": "big"})
        with pytest.raises(ValueError, match="No IQ data"):
            handler("j", {"detection_id": "missing"})
