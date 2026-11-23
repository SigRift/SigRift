#!/usr/bin/env python3
"""Block releases without exact-commit coverage evidence at the committed floor.

Each language gate (Python, Rust, JavaScript) must have succeeded on the exact
release commit. Those gates fail closed on any measurement-integrity problem
(provenance, source inventory, commit binding, invalid counts) and require the
measured line and branch percentages to be at or above the ratchet floor in
scripts/coverage-floors.json. Floors may be raised as coverage improves and are
never lowered. Missing or unsuccessful evidence blocks publication; do not
replace a gate with an always-green job.
This guards versioned/signed releases; development :main images use a separate
workflow and are not coverage-qualified releases.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.parse
import urllib.request


REQUIREMENTS = {
    ".github/workflows/ci.yml": (
        "Install/deploy scripts (shellcheck + tests)",
        "Shiny dashboard tests",
        *(f"Python bridge tests (shard {i}/4)" for i in range(1, 5)),
        "Python coverage inventory and baseline",
        "Release coverage — Python (floor)",
    ),
    ".github/workflows/rust-coverage.yml": ("rust-coverage",),
    ".github/workflows/javascript-coverage.yml": (
        "Release coverage — JavaScript (floor)",
    ),
}
SHA = re.compile(r"[0-9a-f]{40}")


class GateError(Exception):
    """A safe diagnostic that never contains a token or API response body."""


def require(condition, message):
    if not condition:
        raise GateError(message)


def positive(value):
    return type(value) is int and value > 0


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise GateError("GitHub API redirect refused")


class GitHub:
    def __init__(self, repository, token):
        require(
            re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository),
            "Invalid repository identity",
        )
        require(
            bool(token),
            "GITHUB_TOKEN with read-only Actions/Contents access is required",
        )
        self.repository = repository
        self.token = token
        self.opener = urllib.request.build_opener(NoRedirect())

    def get(self, endpoint, **query):
        url = f"https://api.github.com/repos/{self.repository}/{endpoint}"
        if query:
            url += "?" + urllib.parse.urlencode(query)
        request = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "sigrift-release-coverage",
            },
        )
        try:
            with self.opener.open(request, timeout=30) as response:
                require(response.status == 200, "GitHub API request did not succeed")
                raw = response.read(8 * 1024 * 1024 + 1)
                require(
                    len(raw) <= 8 * 1024 * 1024,
                    "GitHub API response exceeded its limit",
                )
                result = json.loads(raw)
        except (OSError, ValueError, urllib.error.URLError):
            raise GateError(
                "GitHub API request failed; release coverage cannot be verified"
            ) from None
        require(isinstance(result, dict), "Malformed GitHub API response")
        return result

    def pages(self, endpoint, key, **query):
        results, total = [], None
        for page in range(1, 11):
            payload = self.get(endpoint, per_page=100, page=page, **query)
            count, items = payload.get("total_count"), payload.get(key)
            require(
                type(count) is int and 0 <= count <= 1000,
                "Invalid or excessive API pagination count",
            )
            require(
                isinstance(items, list)
                and all(isinstance(item, dict) for item in items),
                "Malformed API result page",
            )
            require(
                total is None or count == total,
                "API results changed during pagination; retry preflight",
            )
            total = count
            results.extend(items)
            require(
                len(results) <= total, "API pagination returned inconsistent results"
            )
            if len(results) == total:
                return results
            require(bool(items), "API pagination ended before all results were read")
        raise GateError("API pagination exceeded its limit")


def tag_commit(api, tag):
    reference = api.get("git/ref/tags/" + tag)
    require(
        reference.get("ref") == "refs/tags/" + tag, "Release tag reference mismatch"
    )
    target, seen = reference.get("object"), set()
    for _ in range(8):
        require(isinstance(target, dict), "Malformed release tag object")
        sha = target.get("sha")
        require(
            isinstance(sha, str) and SHA.fullmatch(sha),
            "Invalid release tag object SHA",
        )
        if target.get("type") == "commit":
            return sha
        require(
            target.get("type") == "tag" and sha not in seen,
            "Release tag does not resolve to a commit",
        )
        seen.add(sha)
        annotated = api.get("git/tags/" + sha)
        require(annotated.get("sha") == sha, "Annotated tag object mismatch")
        target = annotated.get("object")
    raise GateError("Release tag nesting exceeded its limit")


def run_identity(run, repository, commit, path):
    require(
        run.get("path") in (path, path + "@main", path + "@refs/heads/main")
        and run.get("head_sha") == commit
        and run.get("head_branch") == "main"
        and run.get("event") == "push"
        and isinstance(run.get("repository"), dict)
        and run["repository"].get("full_name") == repository
        and isinstance(run.get("head_repository"), dict)
        and run["head_repository"].get("full_name") == repository
        and all(
            positive(run.get(key))
            for key in ("id", "run_number", "run_attempt", "workflow_id")
        ),
        "Coverage workflow source identity mismatch: " + path,
    )


def latest_runs(runs, repository, commit):
    selected = {}
    ids = [run.get("id") for run in runs]
    require(
        all(positive(item) for item in ids) and len(ids) == len(set(ids)),
        "Duplicate or invalid workflow run IDs",
    )
    for path in REQUIREMENTS:
        candidates = [
            run
            for run in runs
            if run.get("path") in (path, path + "@main", path + "@refs/heads/main")
        ]
        require(
            bool(candidates),
            "Missing trusted coverage workflow: "
            + path
            + "; every per-language coverage floor gate is a mandatory prerequisite",
        )
        for run in candidates:
            run_identity(run, repository, commit, path)
        require(
            len({run["workflow_id"] for run in candidates}) == 1,
            "Coverage workflow identity changed; fresh evidence required",
        )
        selected[path] = max(candidates, key=lambda run: (run["run_number"], run["id"]))
    return selected


def successful(run, path):
    require(
        run.get("status") == "completed" and run.get("conclusion") == "success",
        "Latest coverage workflow did not succeed: " + path,
    )


def validate_jobs(jobs, run, path, commit):
    ids = [job.get("id") for job in jobs]
    require(
        all(positive(item) for item in ids) and len(ids) == len(set(ids)),
        "Duplicate or invalid coverage job IDs",
    )
    for name in REQUIREMENTS[path]:
        matches = [job for job in jobs if job.get("name") == name]
        require(
            len(matches) == 1, "Missing or ambiguous required coverage job: " + name
        )
        job = matches[0]
        require(
            job.get("run_id") == run["id"]
            and job.get("run_attempt") == run["run_attempt"]
            and job.get("head_sha") == commit
            and job.get("head_branch") == "main"
            and job.get("status") == "completed"
            and job.get("conclusion") == "success",
            "Required coverage job is untrusted, incomplete or unsuccessful: " + name,
        )


def verify(api, tag, commit):
    require(
        re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-rc[0-9]+)?", tag),
        "Invalid release tag",
    )
    require(SHA.fullmatch(commit), "Invalid release commit")
    require(
        tag_commit(api, tag) == commit,
        "Release tag moved or differs from the checked-out commit",
    )
    query = {"head_sha": commit, "event": "push", "branch": "main"}
    selected = latest_runs(
        api.pages("actions/runs", "workflow_runs", **query), api.repository, commit
    )
    verified = {}
    for path, listed in selected.items():
        run = api.get(f"actions/runs/{listed['id']}")
        run_identity(run, api.repository, commit, path)
        require(
            all(run[key] == listed[key] for key in ("id", "run_number", "workflow_id")),
            "Coverage run identity changed",
        )
        successful(run, path)
        jobs = api.pages(
            f"actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs", "jobs"
        )
        validate_jobs(jobs, run, path, commit)
        verified[path] = (run["id"], run["run_attempt"])
    # Do not let a newly queued run/rerun or a moved tag inherit old success.
    final = latest_runs(
        api.pages("actions/runs", "workflow_runs", **query), api.repository, commit
    )
    for path, run in final.items():
        successful(run, path)
        require(
            (run["id"], run["run_attempt"]) == verified[path],
            "Coverage evidence changed during preflight; retry",
        )
    require(
        tag_commit(api, tag) == commit, "Release tag moved during coverage verification"
    )
    return verified


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args(argv)
    try:
        api = GitHub(args.repository, os.environ.get("GITHUB_TOKEN", ""))
        verify(api, args.tag, args.commit)
        if output := os.environ.get("GITHUB_OUTPUT"):
            with Path(output).open("a") as stream:
                stream.write(f"commit={args.commit}\n")
    except (GateError, OSError) as error:
        message = (
            str(error)
            if isinstance(error, GateError)
            else "Cannot record verified release commit"
        )
        print("Release blocked: " + message, file=sys.stderr)
        return 1
    print("Release coverage floors verified for " + args.commit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
