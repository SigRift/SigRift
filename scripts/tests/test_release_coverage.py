"""Fail-closed release decisions using real validation and API pagination."""

import copy
import importlib.util
import io
from pathlib import Path
import runpy
import sys
import urllib.error

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check-release-coverage.py"
SPEC = importlib.util.spec_from_file_location("release_coverage", SCRIPT)
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)
COMMIT = "a" * 40
OTHER = "b" * 40
TAG = "v1.2.3-rc1"
REPOSITORY = "SigRift/SigRift"
PATHS = list(gate.REQUIREMENTS)


def run(path, number=1, attempt=1):
    index = PATHS.index(path) + 1
    return {
        "id": index * 100 + number,
        "run_number": number,
        "run_attempt": attempt,
        "workflow_id": index,
        "path": path,
        "repository": {"full_name": REPOSITORY},
        "head_repository": {"full_name": REPOSITORY},
        "head_sha": COMMIT,
        "head_branch": "main",
        "event": "push",
        "status": "completed",
        "conclusion": "success",
    }


class Evidence(gate.GitHub):
    def __init__(self):
        self.repository = REPOSITORY
        self.runs = [run(path) for path in PATHS]
        self.current = {item["id"]: copy.deepcopy(item) for item in self.runs}
        self.jobs = {}
        for item in self.runs:
            self.jobs[item["id"]] = [
                {
                    "id": item["id"] * 100 + index,
                    "name": name,
                    "run_id": item["id"],
                    "run_attempt": item["run_attempt"],
                    "head_sha": COMMIT,
                    "head_branch": "main",
                    "status": "completed",
                    "conclusion": "success",
                }
                for index, name in enumerate(gate.REQUIREMENTS[item["path"]], 1)
            ]
        self.reference = {
            "ref": "refs/tags/" + TAG,
            "object": {"type": "commit", "sha": COMMIT},
        }
        self.tags = {}
        self.calls = []

    def get(self, endpoint, **query):
        self.calls.append((endpoint, query))
        if endpoint.startswith("git/ref/"):
            return copy.deepcopy(self.reference)
        if endpoint.startswith("git/tags/"):
            return copy.deepcopy(self.tags[endpoint.rsplit("/", 1)[1]])
        if endpoint == "actions/runs":
            assert {key: query[key] for key in ("head_sha", "event", "branch")} == {
                "head_sha": COMMIT,
                "event": "push",
                "branch": "main",
            }
            items, key = self.runs, "workflow_runs"
        elif "/attempts/" in endpoint:
            parts = endpoint.split("/")
            assert int(parts[4]) == self.current[int(parts[2])]["run_attempt"]
            items, key = self.jobs[int(parts[2])], "jobs"
        else:
            return copy.deepcopy(self.current[int(endpoint.rsplit("/", 1)[1])])
        offset = (query["page"] - 1) * query["per_page"]
        return {
            "total_count": len(items),
            key: copy.deepcopy(items[offset : offset + query["per_page"]]),
        }


def test_all_scopes_and_exact_attempt_jobs_are_required():
    api = Evidence()
    result = gate.verify(api, TAG, COMMIT)
    assert result == {path: (run(path)["id"], 1) for path in PATHS}
    assert (
        len([endpoint for endpoint, _ in api.calls if "/attempts/1/jobs" in endpoint])
        == len(PATHS)
    )
    assert api.calls[0][0] == api.calls[-1][0] == "git/ref/tags/" + TAG


@pytest.mark.parametrize("missing", PATHS)
def test_missing_workflow_blocks_even_when_every_other_language_passes(missing):
    api = Evidence()
    api.runs = [item for item in api.runs if item["path"] != missing]
    with pytest.raises(gate.GateError, match="Missing trusted coverage workflow"):
        gate.verify(api, TAG, COMMIT)


@pytest.mark.parametrize(
    "field,value",
    [
        ("head_sha", OTHER),
        ("head_branch", "feature"),
        ("event", "pull_request"),
        ("repository", {"full_name": "attacker/SigRift"}),
        ("repository", None),
        ("head_repository", {"full_name": "attacker/SigRift"}),
        ("head_repository", None),
        ("run_attempt", 0),
        ("run_number", True),
        ("workflow_id", None),
        ("id", -1),
    ],
)
def test_run_source_identity_cannot_be_substituted(field, value):
    api = Evidence()
    api.runs[0][field] = value
    with pytest.raises(gate.GateError):
        gate.verify(api, TAG, COMMIT)


def test_wrong_workflow_path_does_not_supply_the_aggregate():
    api = Evidence()
    api.runs[0]["path"] = ".github/workflows/lookalike.yml"
    with pytest.raises(gate.GateError, match="Missing trusted"):
        gate.verify(api, TAG, COMMIT)


@pytest.mark.parametrize("suffix", ["@main", "@refs/heads/main"])
def test_documented_main_path_suffixes_preserve_workflow_identity(suffix):
    api = Evidence()
    for item in api.runs:
        item["path"] += suffix
        api.current[item["id"]]["path"] += suffix
    assert len(gate.verify(api, TAG, COMMIT)) == len(PATHS)


@pytest.mark.parametrize(
    "status,conclusion",
    [
        ("queued", None),
        ("in_progress", None),
        ("completed", "skipped"),
        ("completed", "failure"),
        ("completed", "cancelled"),
        ("completed", "neutral"),
        ("completed", "timed_out"),
    ],
)
def test_unsuccessful_latest_run_never_falls_back_to_old_success(status, conclusion):
    api = Evidence()
    latest = run(PATHS[0], number=2)
    latest.update(status=status, conclusion=conclusion)
    api.runs.append(latest)
    api.current[latest["id"]] = latest
    with pytest.raises(
        gate.GateError, match="Latest coverage workflow did not succeed"
    ):
        gate.verify(api, TAG, COMMIT)


def test_a_failed_older_run_does_not_override_latest_success():
    api = Evidence()
    old = copy.deepcopy(api.runs[0])
    old.update(id=100, run_number=0, status="completed", conclusion="failure")
    # Valid positive run numbers: existing success is now the second run.
    api.runs[0]["run_number"] = api.current[101]["run_number"] = 2
    old["run_number"] = 1
    api.runs.append(old)
    assert gate.verify(api, TAG, COMMIT)[PATHS[0]] == (101, 1)


def test_recreated_workflow_cannot_reuse_an_old_successful_identity():
    api = Evidence()
    recreated = run(PATHS[0], number=2)
    recreated["workflow_id"] = 999
    api.runs.append(recreated)
    with pytest.raises(gate.GateError, match="workflow identity changed"):
        gate.verify(api, TAG, COMMIT)


@pytest.mark.parametrize(
    "field,value",
    [
        ("run_id", 999),
        ("run_attempt", 2),
        ("head_sha", OTHER),
        ("head_branch", "feature"),
        ("status", "queued"),
        ("conclusion", "failure"),
        ("conclusion", "skipped"),
        ("conclusion", "neutral"),
    ],
)
def test_required_job_must_really_pass_in_the_exact_run_attempt(field, value):
    api = Evidence()
    api.jobs[101][0][field] = value
    with pytest.raises(gate.GateError, match="Required coverage job"):
        gate.verify(api, TAG, COMMIT)


@pytest.mark.parametrize("kind", ["missing", "ambiguous", "duplicate_id", "invalid_id"])
def test_missing_or_duplicate_job_evidence_is_rejected(kind):
    api = Evidence()
    if kind == "missing":
        api.jobs[101] = []
    elif kind == "invalid_id":
        api.jobs[101][0]["id"] = False
    else:
        duplicate = copy.deepcopy(api.jobs[101][0])
        if kind == "ambiguous":
            duplicate["id"] += 1
        api.jobs[101].append(duplicate)
    with pytest.raises(gate.GateError):
        gate.verify(api, TAG, COMMIT)


def test_duplicate_run_ids_fail_closed():
    api = Evidence()
    api.runs.append(copy.deepcopy(api.runs[0]))
    with pytest.raises(gate.GateError, match="run IDs"):
        gate.verify(api, TAG, COMMIT)


@pytest.mark.parametrize(
    "change", ["attempt_pending", "id", "path", "number", "workflow"]
)
def test_fresh_run_read_detects_changes_since_listing(change):
    api = Evidence()
    item = api.current[101]
    if change == "attempt_pending":
        item.update(run_attempt=2, status="in_progress", conclusion=None)
    else:
        field = {
            "id": "id",
            "path": "path",
            "number": "run_number",
            "workflow": "workflow_id",
        }[change]
        item[field] = ".github/workflows/other.yml" if change == "path" else 999
    with pytest.raises(gate.GateError):
        gate.verify(api, TAG, COMMIT)


@pytest.mark.parametrize("change", ["new_run", "new_attempt", "pending", "tag"])
def test_final_recheck_detects_evidence_or_tag_changes(change):
    api = Evidence()
    original = api.get
    listings = 0

    def changing(endpoint, **query):
        nonlocal listings
        if endpoint == "actions/runs":
            listings += 1
            if listings == 2:
                if change == "new_run":
                    api.runs.append(run(PATHS[0], number=2))
                elif change == "new_attempt":
                    api.runs[0]["run_attempt"] = 2
                elif change == "pending":
                    api.runs[0]["status"] = "in_progress"
                else:
                    api.reference["object"]["sha"] = OTHER
        return original(endpoint, **query)

    api.get = changing
    with pytest.raises(gate.GateError):
        gate.verify(api, TAG, COMMIT)


def test_successful_rerun_uses_latest_attempt_not_old_jobs():
    api = Evidence()
    api.runs[0]["run_attempt"] = api.current[101]["run_attempt"] = 2
    for job in api.jobs[101]:
        job["run_attempt"] = 2
    assert gate.verify(api, TAG, COMMIT)[PATHS[0]] == (101, 2)
    assert any("/attempts/2/jobs" in endpoint for endpoint, _ in api.calls)


def test_jobs_and_runs_beyond_the_first_page_are_not_omitted():
    api = Evidence()
    api.runs = [
        dict(run(PATHS[0]), id=1000 + i, path=".github/workflows/unrelated.yml")
        for i in range(100)
    ] + api.runs
    extra = [
        dict(api.jobs[101][0], id=2000 + i, name=f"unrelated-{i}") for i in range(100)
    ]
    api.jobs[101] = extra + api.jobs[101]
    assert len(gate.verify(api, TAG, COMMIT)) == len(PATHS)
    assert sum(query.get("page") == 2 for _, query in api.calls) == 3


@pytest.mark.parametrize(
    "payload",
    [
        {"total_count": True, "jobs": []},
        {"total_count": -1, "jobs": []},
        {"total_count": 1001, "jobs": []},
        {"total_count": 1, "jobs": None},
        {"total_count": 1, "jobs": [None]},
        {"total_count": 1, "jobs": []},
        {"total_count": 0, "jobs": [{}]},
    ],
)
def test_malformed_or_incomplete_pagination_is_rejected(payload):
    api = Evidence()
    api.get = lambda *_args, **_kwargs: payload
    with pytest.raises(gate.GateError):
        api.pages("anything", "jobs")


@pytest.mark.parametrize("change_count", [True, False])
def test_changed_or_excessive_pagination_is_rejected(change_count):
    api = Evidence()
    api.get = lambda _endpoint, **query: {
        "total_count": 20 + (query["page"] if change_count else 0),
        "jobs": [{}],
    }
    with pytest.raises(gate.GateError, match="pagination"):
        api.pages("anything", "jobs")


@pytest.mark.parametrize(
    "reference",
    [
        {"ref": "refs/heads/main"},
        {"ref": "refs/tags/" + TAG, "object": None},
        {"ref": "refs/tags/" + TAG, "object": {"type": "commit", "sha": None}},
        {"ref": "refs/tags/" + TAG, "object": {"type": "tree", "sha": COMMIT}},
        {"ref": "refs/tags/" + TAG, "object": {"type": "commit", "sha": OTHER}},
    ],
)
def test_tag_must_resolve_to_exact_checked_out_commit(reference):
    api = Evidence()
    api.reference = reference
    with pytest.raises(gate.GateError):
        gate.verify(api, TAG, COMMIT)


def test_nested_annotated_tags_are_dereferenced_to_the_commit():
    api = Evidence()
    api.reference["object"] = {"type": "tag", "sha": OTHER}
    api.tags[OTHER] = {"sha": OTHER, "object": {"type": "tag", "sha": "c" * 40}}
    api.tags["c" * 40] = {"sha": "c" * 40, "object": {"type": "commit", "sha": COMMIT}}
    assert len(gate.verify(api, TAG, COMMIT)) == len(PATHS)


@pytest.mark.parametrize("kind", ["mismatch", "cycle", "depth"])
def test_invalid_annotated_tag_graph_is_rejected(kind):
    api = Evidence()
    api.reference["object"] = {"type": "tag", "sha": OTHER}
    if kind == "depth":
        previous = OTHER
        for index in range(9):
            following = f"{index:040x}"
            api.tags[previous] = {
                "sha": previous,
                "object": {"type": "tag", "sha": following},
            }
            previous = following
    else:
        api.tags[OTHER] = {
            "sha": COMMIT if kind == "mismatch" else OTHER,
            "object": {"type": "tag", "sha": OTHER},
        }
    with pytest.raises(gate.GateError):
        gate.verify(api, TAG, COMMIT)


@pytest.mark.parametrize("tag,commit", [("main", COMMIT), (TAG, "not-a-sha")])
def test_invalid_release_arguments_fail_before_api_reads(tag, commit):
    api = Evidence()
    with pytest.raises(gate.GateError):
        gate.verify(api, tag, commit)
    assert api.calls == []


class Response(io.BytesIO):
    status = 200


def test_client_uses_fixed_https_origin_read_only_request_and_bounded_io():
    api = gate.GitHub(REPOSITORY, "synthetic-token")

    def opening(request, timeout):
        assert (
            request.full_url
            == "https://api.github.com/repos/SigRift/SigRift/actions/runs?branch=main"
        )
        assert request.get_method() == "GET" and request.data is None
        assert request.get_header("Authorization") == "Bearer synthetic-token"
        assert timeout == 30
        return Response(b'{"ok":true}')

    api.opener.open = opening
    assert api.get("actions/runs", branch="main") == {"ok": True}
    api.opener.open = lambda *_args, **_kwargs: Response(b"{}")
    assert api.get("actions/runs") == {}


@pytest.mark.parametrize(
    "kind", ["status", "oversize", "invalid_json", "not_object", "network"]
)
def test_api_failures_are_closed_and_never_dump_response_or_token(kind, capsys):
    api = gate.GitHub(REPOSITORY, "synthetic-token")
    response = Response(b"secret-response")
    if kind == "status":
        response.status = 503
    elif kind == "oversize":
        response = Response(b"x" * (8 * 1024 * 1024 + 1))
    elif kind == "not_object":
        response = Response(b"[]")

    def opening(*_args, **_kwargs):
        if kind == "network":
            raise urllib.error.URLError("secret-response synthetic-token")
        return response

    api.opener.open = opening
    with pytest.raises(gate.GateError) as caught:
        api.get("actions/runs")
    assert "secret-response" not in str(caught.value)
    assert "synthetic-token" not in str(caught.value)
    assert capsys.readouterr() == ("", "")


def test_redirect_never_forwards_credentials_to_another_origin():
    with pytest.raises(gate.GateError, match="redirect refused"):
        gate.NoRedirect().redirect_request(
            None, None, 302, "moved", {}, "https://attacker.invalid"
        )


@pytest.mark.parametrize(
    "repository,token", [("bad/path/extra", "token"), (REPOSITORY, "")]
)
def test_client_rejects_invalid_identity_or_absent_credentials(repository, token):
    with pytest.raises(gate.GateError):
        gate.GitHub(repository, token)


def test_cli_records_only_successful_verified_commit(monkeypatch, tmp_path, capsys):
    output = tmp_path / "output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setattr(gate, "GitHub", lambda *_args: Evidence())
    args = ["--repository", REPOSITORY, "--tag", TAG, "--commit", COMMIT]
    assert gate.main(args) == 0
    assert output.read_text() == "commit=" + COMMIT + "\n"
    assert "verified" in capsys.readouterr().out
    monkeypatch.delenv("GITHUB_OUTPUT")
    assert gate.main(args) == 0
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "missing" / "output"))
    assert gate.main(args) == 1
    assert "Cannot record" in capsys.readouterr().err


def test_cli_missing_full_scope_fails_without_writing_commit(
    monkeypatch, tmp_path, capsys
):
    api = Evidence()
    api.runs.pop(0)
    monkeypatch.setattr(gate, "GitHub", lambda *_args: api)
    output = tmp_path / "output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    assert (
        gate.main(["--repository", REPOSITORY, "--tag", TAG, "--commit", COMMIT]) == 1
    )
    assert not output.exists()
    error = capsys.readouterr().err
    assert "Release blocked" in error and "coverage floor gate" in error


def test_entrypoint_without_token_fails_without_network(monkeypatch, capsys):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        [str(SCRIPT), "--repository", REPOSITORY, "--tag", TAG, "--commit", COMMIT],
    )
    with pytest.raises(SystemExit) as caught:
        runpy.run_path(str(SCRIPT), run_name="__main__")
    assert caught.value.code == 1
    assert "read-only" in capsys.readouterr().err


def test_publication_jobs_depend_on_gate_and_use_only_verified_bytes():
    workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
    jobs = workflow["jobs"]

    def ancestors(name):
        needs = jobs[name].get("needs", [])
        needs = [needs] if isinstance(needs, str) else needs
        return set(needs).union(*(ancestors(item) for item in needs))

    for name, job in jobs.items():
        if "write" in job.get("permissions", {}).values():
            assert "coverage-preflight" in ancestors(name)
            assert "if" not in job  # No always() path around failed prerequisites.
    for name in ("coverage-preflight", "verify-release-ref"):
        assert jobs[name]["permissions"] == {"contents": "read", "actions": "read"}
        scripts = [step["run"] for step in jobs[name]["steps"] if "run" in step]
        assert len(scripts) == 1 and "check-release-coverage.py" in scripts[0]
        assert '--commit "$COMMIT"' in scripts[0]
    pinned = "${{ needs.coverage-preflight.outputs.commit }}"
    for name in ("build-images", "build-tarballs", "sbom", "verify-release-ref"):
        checkout = next(
            step
            for step in jobs[name]["steps"]
            if step.get("uses", "").startswith("actions/checkout@")
        )
        assert checkout["with"] == {"ref": pinned, "persist-credentials": False}
    tarballs = jobs["build-tarballs"]
    assert tarballs["env"]["COMMIT"] == pinned
    archive = next(
        step["run"]
        for step in tarballs["steps"]
        if step.get("name") == "Source archive"
    )
    assert '"$COMMIT"' in archive and "refs/tags" not in archive
    for name in ("merge-manifest", "sign-and-release"):
        assert "verify-release-ref" in ancestors(name)


def test_release_preflight_requires_exactly_the_per_language_floor_jobs():
    floor_jobs = {
        ".github/workflows/ci.yml": "Release coverage — Python (floor)",
        ".github/workflows/rust-coverage.yml": "rust-coverage",
        ".github/workflows/javascript-coverage.yml": (
            "Release coverage — JavaScript (floor)"
        ),
    }
    assert set(gate.REQUIREMENTS) == set(floor_jobs)
    coverage_jobs = {
        name
        for names in gate.REQUIREMENTS.values()
        for name in names
        if name.startswith("Release coverage") or name == "rust-coverage"
    }
    assert coverage_jobs == set(floor_jobs.values())
    assert not any("100%" in name for names in gate.REQUIREMENTS.values() for name in names)
    for path, required in floor_jobs.items():
        assert required in gate.REQUIREMENTS[path]
        # The required job must exist in the committed workflow under that name.
        jobs = yaml.safe_load((ROOT / path).read_text())["jobs"]
        names = {job.get("name", key) for key, job in jobs.items()}
        assert required in names
