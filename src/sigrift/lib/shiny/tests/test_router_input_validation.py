"""Input validation and error paths of the Shiny dashboard routers.

Everything goes through HTTP (``test_app`` from conftest, the production
routers on their production prefixes) and is checked through the responses
and the persistence API.  The client returns a 500 response for an
unhandled exception instead of raising it, so a crash is an assertion
failure that names the status code.

Tests marked ``xfail(strict=True)`` with a ``BUG:`` reason pin a defect that
is not fixed here; they start passing (and so fail as XPASS) once it is.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, AsyncIterator

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI

from sigrift.lib.security import credentials
from sigrift.lib.security.credentials import generate_api_key, hash_credential
from sigrift.lib.shiny import dependencies as deps
from sigrift.lib.shiny.models import JobStatus
from sigrift.lib.shiny.persistence import PersistenceManager
from sigrift.lib.shiny.routers import signals, training

pytestmark = pytest.mark.asyncio

_XSS = "<img src=x onerror=alert(1)>"
_XSS_ESCAPED = "&lt;img src=x onerror=alert(1)&gt;"


@pytest.fixture(autouse=True)
def _fast_hashing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Cheap PBKDF2 for every key hashed here (conftest's keys included)."""
    monkeypatch.setattr(credentials, "_PBKDF2_ITERATIONS", 1_000)
    monkeypatch.setattr(deps, "_fast_hash_index", {})


@pytest_asyncio.fixture()
async def client(test_app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=test_app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.fixture()
def search_dirs(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Path]:
    """Point the training routes' log/model search paths at test directories."""
    dirs = {name: tmp_path / name for name in ("models", "logs", "outside")}
    for d in dirs.values():
        d.mkdir()
    monkeypatch.setattr(training, "_MODEL_SEARCH_DIRS", [dirs["models"]])
    monkeypatch.setattr(training, "_LOG_SEARCH_DIRS", [dirs["logs"]])
    return dirs


def _add_key(pm: PersistenceManager, key_id: str, **meta: Any) -> dict[str, str]:
    raw = generate_api_key()
    hash_hex, salt = hash_credential(raw)
    pm.set_key(key_id, hash_hex, salt, meta=meta or None)
    return {"X-API-Key": raw}


def _iso(delta: timedelta = timedelta()) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def _csv_cells(text: str) -> list[str]:
    return [cell for row in csv.reader(io.StringIO(text)) for cell in row]


def _segment(path_param: str) -> str:
    """*path_param* as a URL path segment that reaches the route as sent.

    httpx removes dot segments, so ``/models/..`` would be sent as
    ``/api/training``, but a client that does not normalise (``curl
    --path-as-is``) can send ``..`` as is.  Percent-encoded dots survive
    httpx and are decoded into the path the route matches, so the probe
    reaches the handler.
    """
    return "%2E%2E" if path_param == ".." else path_param


# ---------------------------------------------------------------------------
# Signals
# ---------------------------------------------------------------------------


class TestSignals:
    async def test_unknown_class_is_refused_with_an_escaped_detail(
        self, client: httpx.AsyncClient, api_key_header: dict[str, str]
    ) -> None:
        for path in ("/api/signals/generate", "/api/signals/dsp-features"):
            resp = await client.get(
                path, headers=api_key_header, params={"class": _XSS}
            )
            assert resp.status_code == 400, path
            assert resp.json()["detail"] == f"Unknown signal class: {_XSS_ESCAPED}"

    async def test_compare_bounds_the_number_of_classes(
        self, client: httpx.AsyncClient, api_key_header: dict[str, str]
    ) -> None:
        async def compare(body: Any, n: int = 256) -> httpx.Response:
            return await client.post(
                "/api/signals/compare",
                headers=api_key_header,
                params={"n": n},
                json=body,
            )

        resp = await compare(["qpsk"] * 7)
        assert (resp.status_code, resp.json()["detail"]) == (
            400,
            "Maximum 6 classes for comparison",
        )
        # The cap itself is allowed (smallest n: six waveforms stay cheap).
        resp = await compare(["qpsk"] * 6, n=64)
        assert resp.status_code == 200, resp.text
        assert [len(w["iq_real"]) for w in resp.json()] == [64] * 6
        resp = await compare([])
        assert (resp.status_code, resp.json()["detail"]) == (
            400,
            "At least one class is required",
        )
        resp = await compare(["qpsk", _XSS])
        assert (resp.status_code, resp.json()["detail"]) == (
            400,
            f"Unknown signal class: {_XSS_ESCAPED}",
        )
        assert (await compare({"classes": ["qpsk"]})).status_code == 422

        resp = await compare(["BPSK ", "qpsk"])  # normalised, then generated
        assert resp.status_code == 200
        waves = resp.json()
        assert [w["signal_class"] for w in waves] == ["bpsk", "qpsk"]
        assert all(len(w["iq_real"]) == 256 for w in waves)

    @pytest.mark.parametrize(
        "params",
        [
            {"n": 32769},  # above _MAX_SAMPLES: bounds the work per request
            {"n": 63},
            {"snr": 40.5},
            {"snr": -20.5},
            {"snr": "nan"},
            {"snr": "inf"},
        ],
    )
    async def test_sample_count_and_snr_are_bounded(
        self,
        client: httpx.AsyncClient,
        api_key_header: dict[str, str],
        params: dict[str, Any],
    ) -> None:
        query = {"class": "qpsk", **params}
        resp = await client.get(
            "/api/signals/generate", headers=api_key_header, params=query
        )
        assert resp.status_code == 422
        resp = await client.post(
            "/api/signals/compare",
            headers=api_key_header,
            params=params,
            json=["qpsk"],
        )
        assert resp.status_code == 422
        if "snr" in params:
            resp = await client.get(
                "/api/signals/dsp-features", headers=api_key_header, params=query
            )
            assert resp.status_code == 422

    async def test_generation_failure_is_a_500_with_an_escaped_detail(
        self,
        client: httpx.AsyncClient,
        api_key_header: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def broken(class_name: str, snr: float, n: int) -> Any:
            raise ValueError(_XSS)

        monkeypatch.setattr(signals, "_generate_iq", broken)
        detail = f"Signal generation failed: {_XSS_ESCAPED}"
        for method, path, kwargs in (
            ("GET", "/api/signals/generate", {"params": {"class": "qpsk"}}),
            ("GET", "/api/signals/dsp-features", {"params": {"class": "qpsk"}}),
            ("POST", "/api/signals/compare", {"json": ["qpsk"]}),
        ):
            resp = await client.request(method, path, headers=api_key_header, **kwargs)
            assert (resp.status_code, resp.json()["detail"]) == (500, detail), path


# ---------------------------------------------------------------------------
# Training: which files the routes expose
# ---------------------------------------------------------------------------


class TestTrainingFiles:
    async def test_models_are_only_pth_files_inside_the_search_dirs(
        self,
        client: httpx.AsyncClient,
        api_key_header: dict[str, str],
        analyst_key_header: dict[str, str],
        search_dirs: dict[str, Path],
    ) -> None:
        models = search_dirs["models"]
        (models / "edge-v1.pth").write_bytes(b"12345")
        (models / "server.key").write_text("secret")
        (models / "notes.txt").write_text("notes")
        (models / "folder.pth").mkdir()
        (search_dirs["outside"] / "stolen.pth").write_bytes(b"x")

        resp = await client.get("/api/training/models", headers=api_key_header)
        assert resp.status_code == 200
        assert [m["model_id"] for m in resp.json()] == ["edge-v1"]

        resp = await client.get("/api/training/models/edge-v1", headers=api_key_header)
        assert resp.status_code == 200
        assert resp.json()["size_bytes"] == 5
        for model_id in ("stolen", "server", "notes", "folder", "..", "edge-v1.pth"):
            # The handler's own 404 (not the router's "Not Found"): the probe
            # reached it.  See _segment for why ".." is percent-encoded.
            detail = f"Model {model_id!r} not found"
            resp = await client.get(
                f"/api/training/models/{_segment(model_id)}", headers=api_key_header
            )
            assert (resp.status_code, resp.json().get("detail")) == (404, detail)
            resp = await client.post(
                f"/api/training/models/{_segment(model_id)}/evaluate",
                headers=analyst_key_header,
            )
            assert (resp.status_code, resp.json().get("detail")) == (404, detail)

    async def test_evaluation_is_queued_only_for_a_listed_model(
        self,
        client: httpx.AsyncClient,
        analyst_key_header: dict[str, str],
        search_dirs: dict[str, Path],
        mock_persistence: PersistenceManager,
    ) -> None:
        (search_dirs["outside"] / "stolen.pth").write_bytes(b"x")
        resp = await client.post(
            "/api/training/models/stolen/evaluate", headers=analyst_key_header
        )
        assert resp.status_code == 404
        assert mock_persistence.get_jobs() == {}

        model = search_dirs["models"] / "edge-v1.pth"
        model.write_bytes(b"weights")
        resp = await client.post(
            "/api/training/models/edge-v1/evaluate", headers=analyst_key_header
        )
        assert resp.status_code == 200
        job = resp.json()
        assert job["job_id"].startswith("eval-edge-v1-")
        assert mock_persistence.get_jobs() == {job["job_id"]: job}
        assert job["state"] == "queued"
        assert job["model_path"] == str(model)

    async def test_job_list_survives_a_queued_evaluation(
        self,
        client: httpx.AsyncClient,
        api_key_header: dict[str, str],
        analyst_key_header: dict[str, str],
        search_dirs: dict[str, Path],
    ) -> None:
        (search_dirs["models"] / "edge-v1.pth").write_bytes(b"weights")
        job_id = (
            await client.post(
                "/api/training/models/edge-v1/evaluate", headers=analyst_key_header
            )
        ).json()["job_id"]
        assert (
            await client.get("/api/jobs/", headers=api_key_header)
        ).status_code == 200
        resp = await client.get(f"/api/jobs/{job_id}", headers=api_key_header)
        assert resp.status_code == 200

    async def test_run_detail_reads_only_logs_inside_the_search_dirs(
        self,
        client: httpx.AsyncClient,
        api_key_header: dict[str, str],
        search_dirs: dict[str, Path],
    ) -> None:
        line = "Epoch 3/10 | Total 2.5 | cls 1.0 mt 0.5 fam 0.4 sf 0.3 cons 0.2\n"
        (search_dirs["logs"] / "run-7.log").write_text(line)
        (search_dirs["logs"] / "run-8.txt").write_text(line)
        (search_dirs["outside"] / "run-9.log").write_text(line)

        resp = await client.get("/api/training/runs/run-7", headers=api_key_header)
        assert resp.status_code == 200
        body = resp.json()
        assert body["run_id"] == "run-7"
        assert [e["epoch"] for e in body["epochs"]] == [3]
        for run_id in ("run-8", "run-9", "..", "run-7.log"):
            resp = await client.get(
                f"/api/training/runs/{_segment(run_id)}", headers=api_key_header
            )
            assert (resp.status_code, resp.json().get("detail")) == (
                404,
                f"Training run {run_id!r} not found",
            )

        # The "current run" is the only .log in the search dirs, too.
        resp = await client.get("/api/training/current", headers=api_key_header)
        assert resp.status_code == 200
        assert (resp.json()["run_id"], resp.json()["current_epoch"]) == ("run-7", 3)

    @pytest.mark.parametrize("route", ["history", "run-detail"])
    async def test_stored_training_history_can_be_read(
        self,
        client: httpx.AsyncClient,
        api_key_header: dict[str, str],
        search_dirs: dict[str, Path],
        mock_persistence: PersistenceManager,
        route: str,
    ) -> None:
        mock_persistence.add_history_entry(
            "edge-01", {"run_id": "r1", "best_val_acc": 0.5}
        )
        if route == "history":
            resp = await client.get("/api/training/history", headers=api_key_header)
            assert resp.status_code == 200, resp.status_code
            assert [run.get("run_id") for run in resp.json()] == ["r1"]
        else:
            # A node id is not a run id: any answer but a crash.
            resp = await client.get(
                "/api/training/runs/edge-01", headers=api_key_header
            )
            assert resp.status_code in (200, 404), resp.status_code
            # "Looks in persistence first": the stored run is found by its id.
            resp = await client.get("/api/training/runs/r1", headers=api_key_header)
            assert resp.status_code == 200, resp.status_code
            assert resp.json()["run_id"] == "r1"

    async def test_history_lists_every_node_s_runs(
        self,
        client: httpx.AsyncClient,
        api_key_header: dict[str, str],
        search_dirs: dict[str, Path],
        mock_persistence: PersistenceManager,
    ) -> None:
        """history.json in the store's own format, loaded as at startup.

        Each run carries the node it ran on; an entry that is not an object
        (a hand-edited file) is skipped, and so is a node whose value is not
        a list.
        """
        mock_persistence.save_all()  # keep the test keys across the reload
        (mock_persistence.data_dir / "history.json").write_text(
            json.dumps(
                {
                    "history": {
                        "edge-01": [{"run_id": "r1"}, "junk", {"run_id": "r2"}],
                        "edge-02": [{"run_id": "r3", "node_id": "spoofed"}],
                        "edge-03": "not a list",
                    }
                }
            )
        )
        mock_persistence.load_all()

        resp = await client.get("/api/training/history", headers=api_key_header)
        assert resp.status_code == 200
        assert [(r["node_id"], r["run_id"]) for r in resp.json()] == [
            ("edge-01", "r1"),
            ("edge-01", "r2"),
            ("edge-02", "r3"),
        ]
        resp = await client.get("/api/training/runs/r3", headers=api_key_header)
        assert resp.status_code == 200
        assert resp.json() == {"run_id": "r3", "node_id": "edge-02"}
        for not_a_run in ("edge-01", "edge-03", "junk"):
            resp = await client.get(
                f"/api/training/runs/{not_a_run}", headers=api_key_header
            )
            assert resp.status_code == 404, not_a_run

    async def test_run_detail_serves_the_last_stored_run_with_that_id(
        self,
        client: httpx.AsyncClient,
        api_key_header: dict[str, str],
        search_dirs: dict[str, Path],
        mock_persistence: PersistenceManager,
    ) -> None:
        """A run stored twice (re-reported) is served as it was stored last."""
        mock_persistence.add_history_entry("edge-01", {"run_id": "r1", "acc": 0.1})
        mock_persistence.add_history_entry("edge-01", {"run_id": "r2", "acc": 0.5})
        mock_persistence.add_history_entry("edge-01", {"run_id": "r1", "acc": 0.9})
        resp = await client.get("/api/training/runs/r1", headers=api_key_header)
        assert resp.json() == {"run_id": "r1", "acc": 0.9, "node_id": "edge-01"}

    async def test_stored_runs_skip_whatever_is_not_a_list_of_runs(self) -> None:
        """The helper the history and export routes share, on any store value.

        The store's own loader drops a node value that is not a list; the
        helper does not rely on that (an int, null or object is no run list).
        """
        history: dict[str, Any] = {
            "a": [{"run_id": "r1"}, "junk", 3, None, [{"run_id": "nested"}]],
            "b": 5,
            "c": None,
            "d": {"run_id": "not-in-a-list"},
            "e": "not a list",
            "f": [],
        }
        assert training.stored_runs_by_node(history) == {
            "a": [{"run_id": "r1"}],
            "f": [],
        }
        assert training._stored_runs(history) == [{"run_id": "r1", "node_id": "a"}]

    async def test_evaluation_is_stored_as_a_complete_job(
        self,
        client: httpx.AsyncClient,
        api_key_header: dict[str, str],
        analyst_key_header: dict[str, str],
        search_dirs: dict[str, Path],
        mock_persistence: PersistenceManager,
    ) -> None:
        """Listed, served and rerun (as an evaluation) like any other job."""
        (search_dirs["models"] / "edge-v1.pth").write_bytes(b"weights")
        job = (
            await client.post(
                "/api/training/models/edge-v1/evaluate", headers=analyst_key_header
            )
        ).json()
        assert (job["name"], job["priority"], job["params"]) == (
            "evaluate-edge-v1",
            0,
            {},
        )
        # Every job field, as a job created with POST /api/jobs/ has, in the
        # answer and in the store.
        assert set(JobStatus.model_fields) <= set(job)
        lifecycle = ("started_at", "finished_at", "result", "error")
        assert {k: job[k] for k in lifecycle} == dict.fromkeys(lifecycle)
        assert mock_persistence.get_jobs()[job["job_id"]] == job
        resp = await client.get("/api/jobs/", headers=api_key_header)
        assert [(j["job_id"], j["name"]) for j in resp.json()] == [
            (job["job_id"], "evaluate-edge-v1")
        ]
        resp = await client.post(
            f"/api/jobs/{job['job_id']}/rerun", headers=analyst_key_header
        )
        assert resp.status_code == 201
        rerun = mock_persistence.get_jobs()[resp.json()["job_id"]]
        assert {k: rerun[k] for k in ("name", "type", "model_id", "state")} == {
            "name": "evaluate-edge-v1",
            "type": "evaluate",
            "model_id": "edge-v1",
            "state": "queued",
        }
        assert rerun["model_path"] == job["model_path"]

    async def test_job_list_serves_old_evaluations_and_skips_broken_records(
        self,
        client: httpx.AsyncClient,
        api_key_header: dict[str, str],
        analyst_key_header: dict[str, str],
        mock_persistence: PersistenceManager,
    ) -> None:
        """An evaluation queued before the fix (no name) no longer breaks the list.

        It is listed under a name derived from it; a record that still is not
        a job (a hand-edited jobs.json) is left out instead of a 500.
        """
        old_eval = {
            "job_id": "eval-m1-0001",
            "type": "evaluate",
            "model_id": "m1",
            "model_path": "/models/m1.pth",
            "state": "queued",
            "created_at": "2026-01-01T00:00:00+00:00",
        }
        mock_persistence.set_job("eval-m1-0001", old_eval)
        mock_persistence.set_job("no-id", {"name": "nameless-id", "state": "failed"})
        mock_persistence.set_job("bad-state", {"name": "x", "state": "exploded"})
        mock_persistence.set_job("bad-priority", {"name": "y", "priority": "high"})
        mock_persistence.set_job("not-a-dict", ["queued"])  # type: ignore[arg-type]

        resp = await client.get("/api/jobs/", headers=api_key_header)
        assert resp.status_code == 200
        assert sorted((j["job_id"], j["name"]) for j in resp.json()) == [
            ("eval-m1-0001", "evaluate-m1"),
            ("no-id", "nameless-id"),
        ]
        resp = await client.get(
            "/api/jobs/", headers=api_key_header, params={"state": "failed"}
        )
        assert [j["job_id"] for j in resp.json()] == ["no-id"]
        resp = await client.get("/api/jobs/eval-m1-0001", headers=api_key_header)
        assert (resp.status_code, resp.json()["name"]) == (200, "evaluate-m1")
        resp = await client.put(
            "/api/jobs/eval-m1-0001/priority",
            headers=analyst_key_header,
            json={"priority": 7},
        )
        assert (resp.status_code, resp.json()["name"]) == (200, "evaluate-m1")
        resp = await client.post(
            "/api/jobs/eval-m1-0001/rerun", headers=analyst_key_header
        )
        assert (resp.status_code, resp.json()["name"]) == (201, "evaluate-m1")
        # The stored record is not rewritten by being served.
        assert "name" not in mock_persistence.get_jobs()["eval-m1-0001"]


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


class TestAlerts:
    @pytest.mark.parametrize(
        "body",
        [
            {"name": "   "},
            {"name": "x" * 129},
            {"name": "ok", "severity": "fatal"},
            {"name": "ok", "thresholds": {"cpu_percent": 101}},
            {"name": "ok", "thresholds": {"memory_mb": -1}},
            {"name": "ok", "thresholds": {"shell": "rm -rf /"}},
            {"name": "ok", "is_rule": False},
        ],
    )
    async def test_invalid_rules_are_refused_and_not_stored(
        self,
        client: httpx.AsyncClient,
        analyst_key_header: dict[str, str],
        mock_persistence: PersistenceManager,
        body: dict[str, Any],
    ) -> None:
        resp = await client.post(
            "/api/alerts/rules", headers=analyst_key_header, json=body
        )
        assert resp.status_code == 422
        assert mock_persistence.get_alerts() == []

    async def test_rule_text_is_html_escaped_everywhere_it_is_served(
        self,
        client: httpx.AsyncClient,
        api_key_header: dict[str, str],
        analyst_key_header: dict[str, str],
    ) -> None:
        resp = await client.post(
            "/api/alerts/rules",
            headers=analyst_key_header,
            json={"name": _XSS, "node_id": "<b>n</b>"},
        )
        assert resp.status_code == 201
        assert resp.json()["name"] == _XSS_ESCAPED
        assert resp.json()["node_id"] == "&lt;b&gt;n&lt;/b&gt;"
        # The alert routes serve what this router stored.  The activity feed
        # escapes every message again itself (see
        # test_activity_feed_escapes_text_a_router_logs_raw), so the feed
        # passes here whatever this router does.
        for path in ("/api/alerts/", "/api/alerts/history", "/api/nodes/activity"):
            text = (await client.get(path, headers=api_key_header)).text
            assert "alert(1)" in text, path  # the rule is listed ...
            assert "<img" not in text and "<b>" not in text, path  # ... inert

    async def test_list_filters(
        self,
        client: httpx.AsyncClient,
        api_key_header: dict[str, str],
        analyst_key_header: dict[str, str],
    ) -> None:
        ids = {}
        for name, node in (("a", "<b>n</b>"), ("b", "edge-01"), ("c", None)):
            resp = await client.post(
                "/api/alerts/rules",
                headers=analyst_key_header,
                json={"name": name, "node_id": node, "severity": "critical"},
            )
            ids[name] = resp.json()["alert_id"]
        await client.put(f"/api/alerts/{ids['b']}/ack", headers=analyst_key_header)

        async def names(**params: Any) -> list[str]:
            resp = await client.get(
                "/api/alerts/", headers=api_key_header, params=params
            )
            assert resp.status_code == 200
            return [a["name"] for a in resp.json()]

        # The raw filter matches the stored (escaped) node id.
        assert await names(node_id="<b>n</b>") == ["a"]
        assert await names(node_id="&lt;b&gt;n&lt;/b&gt;") == []
        assert await names(acknowledged="true") == ["b"]
        assert await names(acknowledged="false") == ["a", "c"]
        assert await names(severity="critical", limit=1) == ["c"]
        assert await names(severity="info") == []
        for bad in ({"limit": 0}, {"limit": 501}, {"severity": "fatal"}):
            resp = await client.get("/api/alerts/", headers=api_key_header, params=bad)
            assert resp.status_code == 422, bad

    async def test_history_range_and_invalid_bounds(
        self,
        client: httpx.AsyncClient,
        api_key_header: dict[str, str],
        mock_persistence: PersistenceManager,
    ) -> None:
        def alert(alert_id: str, triggered_at: Any) -> dict[str, Any]:
            return {
                "alert_id": alert_id,
                "name": alert_id,
                "triggered_at": triggered_at,
            }

        mock_persistence.add_alert(alert("jan", "2026-01-01T00:00:00+00:00"))
        mock_persistence.add_alert(
            alert("jun", datetime(2026, 6, 1, tzinfo=timezone.utc))
        )
        # A corrupt stored timestamp sorts as 1970: a start bound drops it.
        mock_persistence.add_alert(alert("bad", "last week"))
        mock_persistence.add_alert(alert("missing", None))

        async def ids(**params: str) -> list[str]:
            resp = await client.get(
                "/api/alerts/history", headers=api_key_header, params=params
            )
            assert resp.status_code == 200, resp.text
            return [a["alert_id"] for a in resp.json()]

        assert await ids(start="2026-03-01T00:00:00+00:00") == ["jun"]
        assert await ids(
            start="2025-12-01T00:00:00+00:00", end="2026-03-01T00:00:00+00:00"
        ) == ["jan"]
        for param in ("start", "end"):
            resp = await client.get(
                "/api/alerts/history",
                headers=api_key_header,
                params={param: "not-a-date"},
            )
            assert resp.status_code == 400
            assert resp.json()["detail"] == f"Invalid {param} datetime (use ISO 8601)"

    @pytest.mark.parametrize(
        ("param", "expected"), [("start", ["jun"]), ("end", ["jan"])]
    )
    async def test_history_accepts_a_bound_without_an_offset(
        self,
        client: httpx.AsyncClient,
        api_key_header: dict[str, str],
        mock_persistence: PersistenceManager,
        param: str,
        expected: list[str],
    ) -> None:
        for alert_id, ts in (
            ("jan", "2026-01-01T00:00:00+00:00"),
            ("jun", "2026-06-01T00:00:00+00:00"),
        ):
            mock_persistence.add_alert(
                {"alert_id": alert_id, "name": alert_id, "triggered_at": ts}
            )
        # Read as UTC, like the same bound on /api/export/alerts.
        resp = await client.get(
            "/api/alerts/history", headers=api_key_header, params={param: "2026-03-01"}
        )
        assert resp.status_code == 200, resp.status_code
        assert [a["alert_id"] for a in resp.json()] == expected

    async def test_history_reads_stored_times_without_an_offset_as_utc(
        self,
        client: httpx.AsyncClient,
        api_key_header: dict[str, str],
        mock_persistence: PersistenceManager,
    ) -> None:
        """Naive and aware on either side of the comparison: never a 500."""
        for alert_id, ts in (
            ("jan-naive", "2026-01-01T00:00:00"),
            ("feb-naive-dt", datetime(2026, 2, 1)),
            ("jun", "2026-06-01T00:00:00+00:00"),
            # 2026-03-01T01:00 UTC: after a 00:00 UTC bound, though its
            # local wall time (23:00 on 28 Feb) is before it.
            ("mar-offset", "2026-02-28T23:00:00-02:00"),
        ):
            mock_persistence.add_alert(
                {"alert_id": alert_id, "name": alert_id, "triggered_at": ts}
            )

        async def ids(**params: str) -> list[str]:
            resp = await client.get(
                "/api/alerts/history", headers=api_key_header, params=params
            )
            assert resp.status_code == 200, resp.text
            return [a["alert_id"] for a in resp.json()]

        for start in ("2026-03-01", "2026-03-01T00:00:00+00:00"):
            assert await ids(start=start) == ["jun", "mar-offset"], start
        for end in ("2026-03-01", "2026-03-01T00:00:00Z"):
            assert await ids(end=end) == ["jan-naive", "feb-naive-dt"], end
        assert await ids(start="2026-01-15", end="2026-03-01T02:00") == [
            "feb-naive-dt",
            "mar-offset",
        ]

    async def test_unknown_ids_get_an_escaped_404(
        self,
        client: httpx.AsyncClient,
        analyst_key_header: dict[str, str],
        master_key_header: dict[str, str],
    ) -> None:
        resp = await client.put("/api/alerts/%3Cb%3E/ack", headers=analyst_key_header)
        assert (resp.status_code, resp.json()["detail"]) == (
            404,
            "Alert &lt;b&gt; not found",
        )
        resp = await client.delete(
            "/api/alerts/rules/%3Cb%3E", headers=master_key_header
        )
        assert (resp.status_code, resp.json()["detail"]) == (
            404,
            "Alert rule &lt;b&gt; not found",
        )


# ---------------------------------------------------------------------------
# Jobs and schedules
# ---------------------------------------------------------------------------


class TestJobs:
    async def test_unknown_preset_is_refused_and_nothing_is_queued(
        self,
        client: httpx.AsyncClient,
        analyst_key_header: dict[str, str],
        mock_persistence: PersistenceManager,
    ) -> None:
        resp = await client.post(
            "/api/jobs/",
            headers=analyst_key_header,
            json={"name": "j", "preset": "turbo"},
        )
        assert (resp.status_code, resp.json()["detail"]) == (
            400,
            "Unknown preset: 'turbo'",
        )
        assert mock_persistence.get_jobs() == {}

    async def test_explicit_params_override_the_preset(
        self, client: httpx.AsyncClient, analyst_key_header: dict[str, str]
    ) -> None:
        resp = await client.post(
            "/api/jobs/",
            headers=analyst_key_header,
            json={"name": "j", "preset": "fast", "params": {"epochs": 3}},
        )
        assert resp.status_code == 201
        params = resp.json()["params"]
        assert params["epochs"] == 3
        assert params["learning_rate"] == 3e-3
        assert "name" not in params

    @pytest.mark.parametrize(
        "body",
        [
            {"name": "two words"},
            {"name": "../../etc/passwd"},
            {"name": "<script>"},
            {"name": ""},
            {"name": "x" * 129},
            {"name": "j", "priority": 101},
            {"name": "j", "priority": -1},
            {"name": "j", "state": "running"},
        ],
    )
    async def test_invalid_jobs_are_refused_and_not_stored(
        self,
        client: httpx.AsyncClient,
        analyst_key_header: dict[str, str],
        mock_persistence: PersistenceManager,
        body: dict[str, Any],
    ) -> None:
        resp = await client.post("/api/jobs/", headers=analyst_key_header, json=body)
        assert resp.status_code == 422
        assert mock_persistence.get_jobs() == {}

    async def test_priority_update_validation(
        self,
        client: httpx.AsyncClient,
        api_key_header: dict[str, str],
        analyst_key_header: dict[str, str],
    ) -> None:
        job_id = (
            await client.post(
                "/api/jobs/", headers=analyst_key_header, json={"name": "j"}
            )
        ).json()["job_id"]
        for body in ({"priority": 101}, {"priority": -1}, {"priority": 5, "x": 1}):
            resp = await client.put(
                f"/api/jobs/{job_id}/priority", headers=analyst_key_header, json=body
            )
            assert resp.status_code == 422, body
        resp = await client.put(
            "/api/jobs/no-such-job/priority",
            headers=analyst_key_header,
            json={"priority": 5},
        )
        assert resp.status_code == 404
        resp = await client.get(f"/api/jobs/{job_id}", headers=api_key_header)
        assert resp.json()["priority"] == 0

    async def test_schedule_validation_and_updates(
        self,
        client: httpx.AsyncClient,
        analyst_key_header: dict[str, str],
        master_key_header: dict[str, str],
        mock_persistence: PersistenceManager,
    ) -> None:
        good = {"name": "s", "node_id": "edge-01", "interval": "daily"}
        for bad in (
            {**good, "interval": "minutely"},
            {**good, "node_id": ""},
            {**good, "node_id": "n" * 65},
            {**good, "name": "x" * 129},
            {**good, "run_count": 99},
        ):
            resp = await client.post(
                "/api/jobs/schedules", headers=analyst_key_header, json=bad
            )
            assert resp.status_code == 422, bad
        assert mock_persistence.get_schedules() == {}

        sid = (
            await client.post(
                "/api/jobs/schedules", headers=analyst_key_header, json=good
            )
        ).json()["schedule_id"]
        resp = await client.put(
            f"/api/jobs/schedules/{sid}",
            headers=analyst_key_header,
            json={"interval": "weekly", "params": {"duration_s": 30}},
        )
        assert resp.status_code == 200
        assert mock_persistence.get_schedules()[sid]["interval"] == "weekly"
        assert mock_persistence.get_schedules()[sid]["params"] == {"duration_s": 30}
        assert mock_persistence.get_schedules()[sid]["enabled"] is True
        for bad in ({"interval": "minutely"}, {"node_id": "other"}):
            resp = await client.put(
                f"/api/jobs/schedules/{sid}", headers=analyst_key_header, json=bad
            )
            assert resp.status_code == 422, bad
        assert mock_persistence.get_schedules()[sid]["node_id"] == "edge-01"

        resp = await client.put(
            "/api/jobs/schedules/nope",
            headers=analyst_key_header,
            json={"enabled": False},
        )
        assert resp.status_code == 404
        resp = await client.delete(
            "/api/jobs/schedules/nope", headers=master_key_header
        )
        assert resp.status_code == 404
        assert sid in mock_persistence.get_schedules()

    @pytest.mark.parametrize(
        ("state", "removable"),
        [
            ("running", False),
            ("completed", False),
            ("queued", True),
            ("failed", True),
            ("cancelled", True),
        ],
    )
    async def test_only_finished_or_waiting_jobs_can_be_removed(
        self,
        client: httpx.AsyncClient,
        analyst_key_header: dict[str, str],
        master_key_header: dict[str, str],
        mock_persistence: PersistenceManager,
        state: str,
        removable: bool,
    ) -> None:
        job = (
            await client.post(
                "/api/jobs/", headers=analyst_key_header, json={"name": "j"}
            )
        ).json()
        mock_persistence.set_job(job["job_id"], {**job, "state": state})

        resp = await client.delete(
            f"/api/jobs/{job['job_id']}", headers=master_key_header
        )

        if removable:
            assert resp.status_code == 200
            assert mock_persistence.get_jobs() == {}
        else:
            assert (resp.status_code, resp.json()["detail"]) == (
                409,
                f"Cannot remove job in state: {state}",
            )
            assert job["job_id"] in mock_persistence.get_jobs()

    async def test_job_list_is_by_priority_then_oldest_first(
        self,
        client: httpx.AsyncClient,
        api_key_header: dict[str, str],
        mock_persistence: PersistenceManager,
    ) -> None:
        """Highest priority first; equal priorities by creation time, oldest first.

        Times are compared as instants: one with another offset, and one
        stored without an offset (read as UTC), sort where they happened.
        """
        created = {
            "low": (1, "2026-01-01T00:00:00+00:00"),
            "high": (9, "2026-01-03T00:00:00+00:00"),
            "mid-new": (5, "2026-01-02T12:00:00+00:00"),
            "mid-old": (5, "2026-01-02T15:00:00+05:00"),  # 10:00 UTC
            "mid-naive": (5, "2026-01-02T11:00:00"),  # 11:00 UTC
        }
        for job_id, (priority, at) in created.items():
            mock_persistence.set_job(
                job_id, {"name": job_id, "priority": priority, "created_at": at}
            )

        resp = await client.get("/api/jobs/", headers=api_key_header)
        assert [j["job_id"] for j in resp.json()] == [
            "high",
            "mid-old",
            "mid-naive",
            "mid-new",
            "low",
        ]
        resp = await client.get(
            "/api/jobs/", headers=api_key_header, params={"limit": 2}
        )
        assert [j["job_id"] for j in resp.json()] == ["high", "mid-old"]

    async def test_a_job_is_served_under_its_store_key(
        self,
        client: httpx.AsyncClient,
        api_key_header: dict[str, str],
        analyst_key_header: dict[str, str],
        mock_persistence: PersistenceManager,
    ) -> None:
        """A stored job_id that differs from the key is not what the job goes by.

        Detail, priority, rerun and delete look a job up by its key, so the
        list must give that key (a hand-edited jobs.json can disagree).
        """
        mock_persistence.set_job("k1", {"job_id": "other", "name": "j"})
        resp = await client.get("/api/jobs/", headers=api_key_header)
        assert [j["job_id"] for j in resp.json()] == ["k1"]
        resp = await client.get("/api/jobs/k1", headers=api_key_header)
        assert (resp.status_code, resp.json()["job_id"]) == (200, "k1")
        resp = await client.put(
            "/api/jobs/k1/priority", headers=analyst_key_header, json={"priority": 4}
        )
        assert (resp.status_code, resp.json()["job_id"]) == (200, "k1")
        resp = await client.get("/api/jobs/other", headers=api_key_header)
        assert resp.status_code == 404

    async def test_a_malformed_record_is_409_left_as_it_is_and_removable(
        self,
        client: httpx.AsyncClient,
        api_key_header: dict[str, str],
        analyst_key_header: dict[str, str],
        master_key_header: dict[str, str],
        mock_persistence: PersistenceManager,
    ) -> None:
        """What the list leaves out is not a 500 anywhere else either.

        Detail, priority and rerun answer 409 and change nothing (priority
        used to store the new value and then fail); the master key can
        remove the record whatever it holds.
        """
        stored: dict[str, Any] = {
            "bad-state": {"name": "x", "state": "exploded", "priority": 2},
            "bad-priority": {"name": "y", "state": "running", "priority": "high"},
            "not-a-dict": ["queued"],
        }
        for job_id, record in stored.items():
            mock_persistence.set_job(job_id, json.loads(json.dumps(record)))

        for job_id in stored:
            for method, path, headers, body in (
                ("GET", f"/api/jobs/{job_id}", api_key_header, None),
                (
                    "PUT",
                    f"/api/jobs/{job_id}/priority",
                    analyst_key_header,
                    {"priority": 9},
                ),
                ("POST", f"/api/jobs/{job_id}/rerun", analyst_key_header, None),
            ):
                resp = await client.request(method, path, headers=headers, json=body)
                assert resp.status_code == 409, (method, path, resp.status_code)
                assert resp.json()["detail"].startswith(
                    "Stored job record is malformed"
                ), resp.json()
        assert mock_persistence.get_jobs() == stored

        for job_id in stored:
            resp = await client.delete(f"/api/jobs/{job_id}", headers=master_key_header)
            assert resp.status_code == 200, (job_id, resp.status_code)
        assert mock_persistence.get_jobs() == {}

    async def test_a_malformed_record_is_logged_once_per_defect(
        self,
        client: httpx.AsyncClient,
        api_key_header: dict[str, str],
        mock_persistence: PersistenceManager,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        caplog.set_level(logging.WARNING, logger="sigrift.lib.shiny.routers.jobs")

        def logged() -> list[str]:
            return [
                r.getMessage()
                for r in caplog.records
                if r.name == "sigrift.lib.shiny.routers.jobs"
            ]

        async def serve() -> None:
            for _ in range(3):
                assert (
                    await client.get("/api/jobs/", headers=api_key_header)
                ).status_code == 200
            await client.get("/api/jobs/bad", headers=api_key_header)

        mock_persistence.set_job("bad", {"name": "x", "state": "exploded"})
        await serve()
        assert len(logged()) == 1
        assert "'bad'" in logged()[0] and "state" in logged()[0]

        # Another defect is logged; a fixed record is not.
        mock_persistence.set_job("bad", {"name": "x", "priority": "high"})
        await serve()
        assert len(logged()) == 2 and "priority" in logged()[1]
        mock_persistence.set_job("bad", {"name": "x"})
        await serve()
        assert len(logged()) == 2
        # Broken again (the defect logged before it was fixed), or removed
        # and stored again: logged again.
        mock_persistence.set_job("bad", {"name": "x", "priority": "high"})
        await serve()
        assert len(logged()) == 3 and "priority" in logged()[2]
        mock_persistence.set_job("bad", ["queued"])
        await serve()
        assert len(logged()) == 4 and "not an object (list)" in logged()[3]
        mock_persistence.remove_job("bad")
        await serve()
        mock_persistence.set_job("bad", ["queued"])
        await serve()
        assert len(logged()) == 5


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


class TestExport:
    async def test_training_export_skips_entries_that_are_not_runs(
        self,
        client: httpx.AsyncClient,
        api_key_header: dict[str, str],
        mock_persistence: PersistenceManager,
    ) -> None:
        """The runs /api/training/history serves: no 500, no miscount."""
        mock_persistence.save_all()  # keep the test keys across the reload
        (mock_persistence.data_dir / "history.json").write_text(
            json.dumps(
                {
                    "history": {
                        "edge-01": [
                            {"run_id": "r1"},
                            "junk",
                            5,
                            None,
                            {"run_id": "r2"},
                        ],
                        "edge-02": ["only junk"],
                        "edge-03": "not a list",
                    }
                }
            )
        )
        mock_persistence.load_all()

        resp = await client.get(
            "/api/export/training", headers=api_key_header, params={"format": "csv"}
        )
        assert resp.status_code == 200
        rows = list(csv.DictReader(io.StringIO(resp.text)))
        assert [(r["node_id"], r["run_id"]) for r in rows] == [
            ("edge-01", "r1"),
            ("edge-01", "r2"),
        ]
        body = (await client.get("/api/export/training", headers=api_key_header)).json()
        assert body["meta"]["record_count"] == 2
        assert body["history"] == {
            "edge-01": [{"run_id": "r1"}, {"run_id": "r2"}],
            "edge-02": [],
        }

    async def test_training_export_escapes_every_string(
        self,
        client: httpx.AsyncClient,
        api_key_header: dict[str, str],
        mock_persistence: PersistenceManager,
    ) -> None:
        mock_persistence.add_history_entry(
            "<node>",
            {"run_id": _XSS, "best_val_acc": 0.9, "config": {"note": "<b>"}},
        )
        resp = await client.get("/api/export/training", headers=api_key_header)
        assert resp.status_code == 200
        body = resp.json()
        assert body["meta"]["record_count"] == 1
        assert body["history"] == {
            "&lt;node&gt;": [
                {
                    "run_id": _XSS_ESCAPED,
                    "best_val_acc": 0.9,
                    "config": {"note": "&lt;b&gt;"},
                }
            ]
        }
        resp = await client.get(
            "/api/export/training", headers=api_key_header, params={"format": "csv"}
        )
        assert resp.status_code == 200
        assert resp.headers["content-disposition"].startswith("attachment;")
        cells = _csv_cells(resp.text)
        assert "&lt;node&gt;" in cells and _XSS_ESCAPED in cells
        assert "<" not in resp.text

    async def test_node_export_escapes_lists_and_keys(
        self,
        client: httpx.AsyncClient,
        api_key_header: dict[str, str],
        admin_key_header: dict[str, str],
        sample_node: dict[str, Any],
    ) -> None:
        capabilities = {"tags": [_XSS], "<k>": "v"}
        resp = await client.post(
            "/api/nodes/register",
            headers=admin_key_header,
            json={**sample_node, "capabilities": capabilities},
        )
        assert resp.status_code == 200
        resp = await client.get("/api/export/nodes", headers=api_key_header)
        assert resp.status_code == 200
        assert "<" not in resp.text, resp.json()["nodes"]["edge-01"]["capabilities"]

    async def test_alert_export_date_filter(
        self,
        client: httpx.AsyncClient,
        api_key_header: dict[str, str],
        mock_persistence: PersistenceManager,
    ) -> None:
        for alert_id, ts in (
            ("jan", "2026-01-01T00:00:00+00:00"),
            ("jun-naive", "2026-06-01T00:00:00"),  # no offset: read as UTC
            ("corrupt", "last week"),  # kept: unparseable timestamps are included
        ):
            mock_persistence.add_alert({"alert_id": alert_id, "triggered_at": ts})

        async def ids(**params: str) -> list[str]:
            resp = await client.get(
                "/api/export/alerts", headers=api_key_header, params=params
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["meta"]["filters"] == params
            return [a["alert_id"] for a in body["alerts"]]

        assert await ids(start_date="2026-03-01") == ["jun-naive", "corrupt"]
        assert await ids(end_date="2026-03-01T00:00:00+00:00") == ["jan", "corrupt"]
        assert await ids(start_date="2026-02-01", end_date="2026-05-01") == ["corrupt"]
        resp = await client.get(
            "/api/export/alerts", headers=api_key_header, params={"end_date": "soon"}
        )
        assert (resp.status_code, resp.json()["detail"]) == (
            400,
            "Invalid end_date: 'soon'",
        )

    async def test_csv_export_neutralises_spreadsheet_formulas(
        self,
        client: httpx.AsyncClient,
        analyst_key_header: dict[str, str],
        admin_key_header: dict[str, str],
    ) -> None:
        # Any analyst can name an alert rule; an admin later opens the export.
        resp = await client.post(
            "/api/alerts/rules",
            headers=analyst_key_header,
            json={"name": '=HYPERLINK("http://evil.example","open")'},
        )
        assert resp.status_code == 201
        resp = await client.post(
            "/api/nodes/register",
            headers=admin_key_header,
            json={"node_id": "edge-01", "host": "@SUM(1+1)*cmd|' /C calc'!A0"},
        )
        assert resp.status_code == 200
        cells = []
        for path in ("/api/export/alerts", "/api/export/nodes"):
            resp = await client.get(
                path, headers=admin_key_header, params={"format": "csv"}
            )
            assert resp.status_code == 200
            cells += _csv_cells(resp.text)
        formulas = [c for c in cells if c[:1] in ("=", "+", "-", "@")]
        assert not formulas, formulas
        assert "'@SUM(1+1)*cmd|&#x27; /C calc&#x27;!A0" in cells

    @pytest.mark.parametrize("prefix", ["=", "+", "-", "@", "\t", "\r"])
    async def test_every_csv_export_neutralises_every_formula_prefix(
        self,
        client: httpx.AsyncClient,
        api_key_header: dict[str, str],
        mock_persistence: PersistenceManager,
        prefix: str,
    ) -> None:
        """Every text cell of every export, numbers left as numbers."""
        payload = prefix + "1+1"
        mock_persistence.set_node(
            "edge-01", {"host": payload, "status": payload, "port": 8080}
        )
        mock_persistence.add_alert(
            {"alert_id": "a1", "name": payload, "message": payload, "severity": "info"}
        )
        mock_persistence.add_history_entry(
            "edge-01",
            {"run_id": payload, "started_at": payload, "best_val_acc": -0.5},
        )
        for kind, cell_count in (("nodes", 2), ("alerts", 2), ("training", 2)):
            resp = await client.get(
                f"/api/export/{kind}", headers=api_key_header, params={"format": "csv"}
            )
            assert resp.status_code == 200
            cells = _csv_cells(resp.text)
            assert cells.count("'" + payload) == cell_count, (kind, cells)
            assert payload not in cells, kind
        # -0.5 is data: no quote.
        assert "-0.5" in cells and "'-0.5" not in cells

    @pytest.mark.parametrize(
        "cell",
        [
            '=HYPERLINK("http://x","y")',
            "+cmd",
            "-2+3",
            "@SUM(A1)",
            "\tx",
            "\rx",
            "-85.5",
            "+3",
            "1e-3",
            "-.5",
            "plain",
            "",
            -85.5,
            0,
            True,
            None,
        ],
    )
    async def test_csv_cell_rule_is_the_bridge_s(self, cell: Any) -> None:
        """Shiny and the bridge neutralise exactly the same cells."""
        from sigrift.bridge.routers import export as bridge_export
        from sigrift.lib.shiny.routers import export as shiny_export

        assert shiny_export._csv_safe(cell) == bridge_export._csv_safe(cell)
        assert shiny_export._CSV_FORMULA_PREFIXES == (
            bridge_export._CSV_FORMULA_PREFIXES
        )
        assert shiny_export._CSV_NUMBER_RE.pattern == (
            bridge_export._CSV_NUMBER_RE.pattern
        )

    async def test_json_exports_escape_every_string_at_any_depth(
        self,
        client: httpx.AsyncClient,
        api_key_header: dict[str, str],
        mock_persistence: PersistenceManager,
    ) -> None:
        nested = {
            "<k>": [_XSS, {"<k2>": [[_XSS]], "n": 1}, ("<t>", None)],
            "ok": {"deep": {"<k3>": _XSS}},
        }
        escaped = {
            "&lt;k&gt;": [
                _XSS_ESCAPED,
                {"&lt;k2&gt;": [[_XSS_ESCAPED]], "n": 1},
                ["&lt;t&gt;", None],
            ],
            "ok": {"deep": {"&lt;k3&gt;": _XSS_ESCAPED}},
        }
        mock_persistence.set_node("edge-01", {"capabilities": nested})
        mock_persistence.add_alert({"alert_id": "a1", "thresholds": nested})
        mock_persistence.add_history_entry("edge-01", {"run_id": "r", "cfg": nested})

        body = (await client.get("/api/export/nodes", headers=api_key_header)).json()
        assert body["nodes"]["edge-01"]["capabilities"] == escaped
        body = (await client.get("/api/export/alerts", headers=api_key_header)).json()
        assert body["alerts"][0]["thresholds"] == escaped
        resp = await client.get("/api/export/training", headers=api_key_header)
        assert resp.json()["history"]["edge-01"][0]["cfg"] == escaped
        assert "<" not in resp.text


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


class TestNodes:
    async def test_heartbeat_for_an_unregistered_node_binds_nothing(
        self,
        client: httpx.AsyncClient,
        mock_persistence: PersistenceManager,
        admin_key_header: dict[str, str],
    ) -> None:
        fresh = _add_key(mock_persistence, "fresh-node", purpose="node")
        resp = await client.post(
            "/api/nodes/heartbeat", headers=fresh, json={"node_id": "ghost"}
        )
        assert resp.status_code == 404
        assert "node_id" not in mock_persistence.get_key_meta("fresh-node")

        # Once the node exists the same key claims it: the 404 was the guard.
        await client.post(
            "/api/nodes/register", headers=admin_key_header, json={"node_id": "ghost"}
        )
        resp = await client.post(
            "/api/nodes/heartbeat", headers=fresh, json={"node_id": "ghost"}
        )
        assert resp.status_code == 200
        assert mock_persistence.get_key_meta("fresh-node")["node_id"] == "ghost"

    async def test_admin_heartbeat_does_not_claim_the_node(
        self,
        client: httpx.AsyncClient,
        mock_persistence: PersistenceManager,
        admin_key_header: dict[str, str],
        sample_node: dict[str, Any],
    ) -> None:
        await client.post(
            "/api/nodes/register", headers=admin_key_header, json=sample_node
        )
        resp = await client.post(
            "/api/nodes/heartbeat",
            headers=admin_key_header,
            json={"node_id": "edge-01"},
        )
        assert resp.status_code == 200
        assert "node_id" not in mock_persistence.get_key_meta("test-admin")
        node = _add_key(mock_persistence, "edge-01-key", purpose="node")
        resp = await client.post(
            "/api/nodes/heartbeat", headers=node, json={"node_id": "edge-01"}
        )
        assert resp.status_code == 200
        assert mock_persistence.get_key_meta("edge-01-key")["node_id"] == "edge-01"

    async def test_commands_for_an_unknown_node_are_not_queued(
        self,
        client: httpx.AsyncClient,
        admin_key_header: dict[str, str],
        master_key_header: dict[str, str],
    ) -> None:
        resp = await client.post(
            "/api/nodes/ghost/command",
            headers=admin_key_header,
            json={"command": "restart"},
        )
        assert (resp.status_code, resp.json()["detail"]) == (
            404,
            "Node 'ghost' not found",
        )
        # Whoever registers that node id later receives nothing.
        await client.post(
            "/api/nodes/register", headers=admin_key_header, json={"node_id": "ghost"}
        )
        resp = await client.post(
            "/api/nodes/heartbeat", headers=admin_key_header, json={"node_id": "ghost"}
        )
        assert resp.json()["pending_commands"] == []

        resp = await client.delete("/api/nodes/nope", headers=master_key_header)
        assert resp.status_code == 404

    async def test_activity_feed_escapes_text_a_router_logs_raw(
        self,
        client: httpx.AsyncClient,
        admin_key_header: dict[str, str],
        api_key_header: dict[str, str],
    ) -> None:
        # Registration logs the free-text host as given: the feed's own
        # escaping is all that stands between it and the dashboard.
        resp = await client.post(
            "/api/nodes/register",
            headers=admin_key_header,
            json={"node_id": "edge-01", "host": _XSS},
        )
        assert resp.status_code == 200
        resp = await client.get("/api/nodes/activity", headers=api_key_header)
        assert resp.status_code == 200
        assert resp.json()[-1]["message"] == (
            f"Node edge-01 registered from {_XSS_ESCAPED}:0"
        )

    async def test_monitor_metrics_are_reported_as_capabilities(
        self,
        client: httpx.AsyncClient,
        admin_key_header: dict[str, str],
        node_key_header: dict[str, str],
        api_key_header: dict[str, str],
        sample_node: dict[str, Any],
    ) -> None:
        await client.post(
            "/api/nodes/register", headers=admin_key_header, json=sample_node
        )
        extra = {
            "agent_version": "1.4.2",
            "disk_percent": 40.0,
            "cpu_temp": 51.5,
            "load_1m": 0.3,
            "uptime_seconds": 120,
        }
        resp = await client.post(
            "/api/nodes/heartbeat",
            headers=node_key_header,
            json={"node_id": "edge-01", "metrics": {"cpu_percent": 12.5, **extra}},
        )
        assert resp.status_code == 200
        node = (await client.get("/api/nodes/edge-01", headers=api_key_header)).json()
        assert node["cpu_percent"] == 12.5
        assert {k: node["capabilities"][k] for k in extra} == extra
        assert node["capabilities"]["sdr"] == "rtl-sdr"

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("last_seen", "not-a-date"),
            ("registered_at", "not-a-date"),
            ("capabilities", "not-a-dict"),
            ("host", "203.0.113.9"),
            ("port", 1),
        ],
    )
    async def test_heartbeat_metrics_cannot_rewrite_the_node_record(
        self,
        client: httpx.AsyncClient,
        admin_key_header: dict[str, str],
        node_key_header: dict[str, str],
        api_key_header: dict[str, str],
        sample_node: dict[str, Any],
        field: str,
        value: Any,
    ) -> None:
        registered = (
            await client.post(
                "/api/nodes/register", headers=admin_key_header, json=sample_node
            )
        ).json()
        resp = await client.post(
            "/api/nodes/heartbeat",
            headers=node_key_header,
            json={"node_id": "edge-01", "metrics": {field: value}},
        )
        # Dropping the metric (200) or refusing the reserved name (422) are
        # both fixes; either way the record keeps the server's value.
        assert resp.status_code in (200, 422), resp.status_code
        resp = await client.get("/api/nodes/", headers=api_key_header)
        assert resp.status_code == 200, resp.status_code
        node = resp.json()[0]
        if field == "last_seen":  # refreshed by the heartbeat itself
            assert isinstance(node[field], str), node[field]
            assert datetime.fromisoformat(node[field].replace("Z", "+00:00"))
        elif field == "capabilities":
            caps = node[field]
            assert {k: caps.get(k) for k in sample_node[field]} == sample_node[field]
        else:
            assert node[field] == registered[field]

    async def test_heartbeat_metrics_of_the_wrong_type_or_range_are_not_stored(
        self,
        client: httpx.AsyncClient,
        admin_key_header: dict[str, str],
        node_key_header: dict[str, str],
        api_key_header: dict[str, str],
        mock_persistence: PersistenceManager,
        sample_node: dict[str, Any],
    ) -> None:
        await client.post(
            "/api/nodes/register", headers=admin_key_header, json=sample_node
        )
        good = {"cpu_temp": 51.5, "disk_percent": 40.0, "uptime_seconds": 120}
        resp = await client.post(
            "/api/nodes/heartbeat",
            headers=node_key_header,
            json={"node_id": "edge-01", "metrics": {"agent_version": "1.4", **good}},
        )
        assert resp.status_code == 200
        bad = {
            "cpu_temp": "hot",
            "disk_percent": "full",
            "mem_percent": "99",
            "uptime_seconds": -1,
            "load_1m": True,
            "agent_version": "v" * 257,
            "gpu_temp": {"value": 99},
        }
        resp = await client.post(
            "/api/nodes/heartbeat",
            headers=node_key_header,
            json={"node_id": "edge-01", "metrics": {"cpu_percent": 12.5, **bad}},
        )
        # The heartbeat is accepted: a bad metric is cleared, not stored.
        assert resp.status_code == 200, resp.text
        stored = mock_persistence.get_nodes()["edge-01"]
        assert not set(bad) & set(stored)
        assert not set(bad) & set(stored["capabilities"])
        assert mock_persistence.get_alerts() == []
        node = (await client.get("/api/nodes/edge-01", headers=api_key_header)).json()
        assert node["cpu_percent"] == 12.5
        assert node["capabilities"] == sample_node["capabilities"]

    async def test_a_record_saved_with_bad_values_still_lists(
        self,
        client: httpx.AsyncClient,
        admin_key_header: dict[str, str],
        api_key_header: dict[str, str],
        mock_persistence: PersistenceManager,
    ) -> None:
        # What a heartbeat could store before its metrics were checked.
        mock_persistence.set_node(
            "edge-01",
            {
                "host": 5,
                "port": "8080",
                "last_seen": "never",
                "registered_at": ["x"],
                "cpu_percent": "high",
                "memory_mb": float("nan"),
                "capabilities": {"cpu_temp": "hot", "sdr": "rtl-sdr"},
                "disk_percent": "full",
            },
        )
        mock_persistence.set_node("edge-02", {"last_seen": _iso(timedelta(days=3650))})
        resp = await client.get("/api/nodes/", headers=api_key_header)
        assert resp.status_code == 200, resp.text
        first, future = resp.json()
        assert {k: first[k] for k in ("host", "port", "status", "cpu_percent")} == {
            "host": "",
            "port": 0,
            "status": "unknown",
            "cpu_percent": 0.0,
        }
        assert (first["last_seen"], first["registered_at"]) == (None, None)
        assert first["capabilities"] == {"sdr": "rtl-sdr"}
        # A last_seen the server cannot have written does not keep a node active.
        assert future["status"] == "unknown"
        resp = await client.get("/api/status", headers=api_key_header)
        assert resp.status_code == 200, resp.text
        assert resp.json()["active_nodes"] == 0
        # The alert checks read the saved disk_percent too.
        resp = await client.post(
            "/api/nodes/heartbeat",
            headers=admin_key_header,
            json={"node_id": "edge-01"},
        )
        assert resp.status_code == 200, resp.text
        assert mock_persistence.get_alerts() == []

    @pytest.mark.parametrize("saved", ["x", ["agent_version"]])
    async def test_a_heartbeat_replaces_saved_capabilities_that_are_not_a_dict(
        self,
        client: httpx.AsyncClient,
        admin_key_header: dict[str, str],
        node_key_header: dict[str, str],
        mock_persistence: PersistenceManager,
        sample_node: dict[str, Any],
        saved: Any,
    ) -> None:
        await client.post(
            "/api/nodes/register", headers=admin_key_header, json=sample_node
        )
        data = mock_persistence.get_nodes()["edge-01"]
        data["capabilities"] = saved
        mock_persistence.set_node("edge-01", data)
        resp = await client.post(
            "/api/nodes/heartbeat",
            headers=node_key_header,
            json={"node_id": "edge-01", "metrics": {"agent_version": "1.4"}},
        )
        assert resp.status_code == 200, resp.text
        stored = mock_persistence.get_nodes()["edge-01"]["capabilities"]
        assert stored == {"agent_version": "1.4"}

    async def test_registered_capabilities_named_like_another_metric_are_listed(
        self,
        client: httpx.AsyncClient,
        admin_key_header: dict[str, str],
        api_key_header: dict[str, str],
        mock_persistence: PersistenceManager,
    ) -> None:
        # The same read rule as the bridge (node_metrics.stored_capabilities):
        # only the monitor fields a heartbeat copies are checked.
        capabilities = {
            "status": "lab",
            "gpu_temp": "warm",
            "cpu_percent": "n/a",
            "hardware": {"sdr": "hackrf"},
            "cpu_temp": "hot",
            "sdr": "hackrf",
        }
        resp = await client.post(
            "/api/nodes/register",
            headers=admin_key_header,
            json={"node_id": "edge-01", "capabilities": capabilities},
        )
        assert resp.status_code == 200, resp.text
        expected = {
            "status": "lab",
            "gpu_temp": "warm",
            "cpu_percent": "n/a",
            "sdr": "hackrf",
        }
        resp = await client.get("/api/nodes/", headers=api_key_header)
        assert resp.json()[0]["capabilities"] == expected
        assert mock_persistence.get_nodes()["edge-01"]["capabilities"] == capabilities


# ---------------------------------------------------------------------------
# Identifiers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["node_id", "job_name", "key_id"])
async def test_identifiers_refuse_a_trailing_newline(
    client: httpx.AsyncClient,
    admin_key_header: dict[str, str],
    master_key_header: dict[str, str],
    kind: str,
) -> None:
    if kind == "node_id":
        resp = await client.post(
            "/api/nodes/register",
            headers=admin_key_header,
            json={"node_id": "edge-01\n"},
        )
    elif kind == "job_name":
        resp = await client.post(
            "/api/jobs/", headers=admin_key_header, json={"name": "nightly\n"}
        )
    else:
        resp = await client.post(
            "/api/keys/", headers=master_key_header, json={"key_id": "ops\n"}
        )
    assert resp.status_code == 422, resp.status_code


@pytest.mark.parametrize("suffix", ["\n", "\r\n", "\n\n"])
async def test_every_id_field_refuses_a_newline(
    client: httpx.AsyncClient,
    admin_key_header: dict[str, str],
    master_key_header: dict[str, str],
    node_key_header: dict[str, str],
    mock_persistence: PersistenceManager,
    sample_node: dict[str, Any],
    suffix: str,
) -> None:
    """Every field checked against the id/job-name patterns, nothing stored."""
    resp = await client.post(
        "/api/nodes/register", headers=admin_key_header, json=sample_node
    )
    assert resp.status_code == 200
    keys_before = set(mock_persistence.get_key_store())
    jobs_before = mock_persistence.get_jobs()
    for headers, method, path, body in (
        (admin_key_header, "POST", "/api/nodes/register", {"node_id": "\nedge-01"}),
        (
            node_key_header,
            "POST",
            "/api/nodes/heartbeat",
            {"node_id": "edge-01" + suffix},
        ),
        (admin_key_header, "POST", "/api/jobs/", {"name": "nightly" + suffix}),
        (master_key_header, "POST", "/api/keys/", {"key_id": "ops" + suffix}),
        (
            master_key_header,
            "POST",
            "/api/keys/",
            {"key_id": "ops", "node_id": "edge-01" + suffix},
        ),
        (
            master_key_header,
            "PATCH",
            "/api/keys/test-node",
            {"node_id": "edge-01" + suffix},
        ),
    ):
        resp = await client.request(method, path, headers=headers, json=body)
        assert resp.status_code == 422, (path, body, resp.status_code)
    assert list(mock_persistence.get_nodes()) == ["edge-01"]
    assert set(mock_persistence.get_key_store()) == keys_before
    assert mock_persistence.get_jobs() == jobs_before
    assert mock_persistence.get_key_meta("test-node")["node_id"] == "edge-01"


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/api/nodes/register", {"node_id": "edge 01"}),
        ("/api/nodes/register", {"node_id": "edge-01;rm"}),
        ("/api/nodes/register", {"node_id": "n" * 65}),
        ("/api/nodes/register", {"node_id": "edge-01", "role": "admin"}),
        ("/api/nodes/heartbeat", {"node_id": "../edge-01"}),
        ("/api/nodes/heartbeat", {"node_id": "edge-01", "extra": 1}),
        ("/api/nodes/edge-01/command", {"command": "rm -rf /"}),
        ("/api/nodes/edge-01/command", {"command": "ping", "node_id": "x"}),
    ],
)
async def test_node_payloads_are_validated(
    client: httpx.AsyncClient,
    admin_key_header: dict[str, str],
    mock_persistence: PersistenceManager,
    mock_app_state: Any,
    path: str,
    body: dict[str, Any],
) -> None:
    mock_persistence.set_node("edge-01", {"last_seen": _iso()})
    resp = await client.post(path, headers=admin_key_header, json=body)
    assert resp.status_code == 422
    assert list(mock_persistence.get_nodes()) == ["edge-01"]
    assert mock_app_state.pending_commands == {}


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


async def test_status_counts_nodes_and_jobs(
    client: httpx.AsyncClient,
    api_key_header: dict[str, str],
    mock_persistence: PersistenceManager,
) -> None:
    # 60 s / 120 s are the active/stale limits; each age is >= 25 s from one.
    mock_persistence.set_node("a", {"last_seen": _iso(-timedelta(seconds=5))})
    mock_persistence.set_node("b", {"last_seen": _iso(-timedelta(seconds=90))})
    mock_persistence.set_node("c", {"last_seen": _iso(-timedelta(hours=1))})
    mock_persistence.set_node("d", {})  # never seen
    mock_persistence.set_job("q", {"state": "queued"})
    mock_persistence.set_job("r", {"state": "running"})
    mock_persistence.set_job("f", {"state": "failed"})
    # A hand-edited record that is not an object is no job (and no 500).
    mock_persistence.set_job("junk", ["queued"])  # type: ignore[arg-type]

    resp = await client.get("/api/status", headers=api_key_header)

    assert resp.status_code == 200
    body = resp.json()
    assert {k: body[k] for k in ("node_count", "active_nodes", "stale_nodes")} == {
        "node_count": 4,
        "active_nodes": 1,
        "stale_nodes": 1,
    }
    assert body["offline_nodes"] == 1
    assert (body["pending_jobs"], body["running_jobs"]) == (1, 1)
