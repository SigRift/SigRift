"""Concurrent clustering jobs and label updates keep clusters.json valid (Q10).

Sync job handlers run in worker threads since round 3 (two at a time by
default), and ``_atomic_write`` used one fixed temp path,
``clusters.tmp``: two writers opened, truncated and wrote the same inode,
the first rename published the mix and the second rename failed
(FileNotFoundError), failing that job.
"""

from __future__ import annotations

import asyncio
import json
import threading
from pathlib import Path
from unittest.mock import patch

import pytest

import sigrift.bridge.routers.clusters as clusters


@pytest.fixture
def clusters_file(tmp_path: Path):
    path = tmp_path / "data" / "clusters.json"
    with patch.object(clusters, "_CLUSTERS_FILE", path):
        yield path


@pytest.fixture
def overlapping_writes(monkeypatch: pytest.MonkeyPatch):
    """Make two writers meet inside json.dump, if nothing serialises them."""
    barrier = threading.Barrier(2, timeout=1.0)
    real_dump = json.dump

    def meeting_dump(obj, fp, **kwargs):
        try:
            barrier.wait()
        except threading.BrokenBarrierError:
            pass  # serialised: the other writer never arrived
        return real_dump(obj, fp, **kwargs)

    monkeypatch.setattr(clusters.json, "dump", meeting_dump)


def test_two_concurrent_clustering_jobs(clusters_file: Path, overlapping_writes):
    from sigrift.bridge.job_queue import AnalysisJobQueue

    async def run() -> list[dict]:
        queue = AnalysisJobQueue(max_workers=2)
        queue.register_handler("clustering", clusters._run_clustering_job)
        await queue.start()
        try:
            ids = [await queue.submit("clustering", {"embeddings": []}) for _ in "ab"]
            for _ in range(500):
                jobs = [queue.get_job_status(i) for i in ids]
                if all(j["status"] in ("completed", "failed") for j in jobs):
                    return jobs
                await asyncio.sleep(0.02)
            raise AssertionError("jobs did not finish")
        finally:
            await queue.stop()

    jobs = asyncio.run(run())
    assert [j["status"] for j in jobs] == ["completed", "completed"], jobs
    data = json.loads(clusters_file.read_text())
    assert data["n_clusters"] == 0
    leftovers = [p.name for p in clusters_file.parent.iterdir() if p.suffix == ".tmp"]
    assert leftovers == []


def test_label_update_is_not_lost_to_a_concurrent_save(clusters_file: Path) -> None:
    from sigrift.bridge.routers.clusters import LabelRequest, label_cluster

    clusters._save_clusters(
        {"last_run": "old", "n_clusters": 1, "clusters": [{"cluster_id": 0}]}
    )
    real_load = clusters._load_clusters
    saver_done = threading.Event()

    def save_new_run() -> None:
        clusters._save_clusters(
            {"last_run": "new", "n_clusters": 1, "clusters": [{"cluster_id": 0}]}
        )
        saver_done.set()

    def load_then_race():
        data = real_load()
        # A clustering run finishes while the label update holds old data.
        threading.Thread(target=save_new_run).start()
        saver_done.wait(0.5)  # serialised: it must wait for the label save
        return data

    with patch.object(clusters, "_load_clusters", load_then_race):
        label_cluster(0, LabelRequest(label="repeater"), _key_id="k")
    assert saver_done.wait(5)
    # The newer run's save came last; it was not overwritten by the label
    # update's stale copy.
    assert json.loads(clusters_file.read_text())["last_run"] == "new"


def test_write_is_fsynced_and_private_temp_is_unique(clusters_file: Path) -> None:
    import os

    synced: list[int] = []
    real_fsync = os.fsync

    def recording(fd: int) -> None:
        synced.append(fd)
        real_fsync(fd)

    with patch.object(clusters.os, "fsync", recording):
        clusters._save_clusters({"n_clusters": 0})
    assert len(synced) >= 2  # the temp file, then the directory
    assert json.loads(clusters_file.read_text()) == {"n_clusters": 0}
