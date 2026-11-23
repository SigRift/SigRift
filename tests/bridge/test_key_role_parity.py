"""Role default parity: the bridge and the gateway read keys.json roles alike.

Both services authenticate API keys against the keys.json the bridge
writes, and each resolves the key's role itself: the bridge in
``dependencies.stored_key_role`` (after ``persistence`` loads the file),
the gateway in ``effective_role`` (``auth/api_key.rs``).  When the two
disagree, one key is authorised differently on gateway-owned routes than
on proxied bridge routes; the gateway read a missing or unknown role as
SENSOR (a node credential) where the bridge reads VIEWER.

The table both sides are pinned to lives in the gateway crate
(``testdata/key_role_parity.json``); the gateway's
``stored_roles_read_as_on_the_bridge`` test reads the same file.  CI runs
this file also for a PR that touches only that table or ``api_key.rs``
(the ``python`` paths filter in ``.github/workflows/ci.yml``).
"""

from __future__ import annotations

import fnmatch
import json
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from sigrift.bridge import persistence as persistence_module
from sigrift.bridge.dependencies import Role, _resolve_key_role, stored_key_role
from sigrift.bridge.persistence import PersistenceManager
from sigrift.lib.security import credentials
from sigrift.lib.security.credentials import compute_lookup_hash, hash_credential

_REPO_ROOT = Path(__file__).resolve().parents[2]
_TABLE_PATH = (
    _REPO_ROOT
    / "src"
    / "gateway"
    / "crates"
    / "sigrift-gateway-core"
    / "testdata"
    / "key_role_parity.json"
)
_GATEWAY_SOURCE = _TABLE_PATH.parents[1] / "src" / "auth" / "api_key.rs"
_CI_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "ci.yml"
#: The table's size when last extended; the gateway's test
#: (``ROLE_PARITY_CASES``) has the same floor.
_MIN_CASES = 47

_CASES: list[dict[str, Any]] = json.loads(_TABLE_PATH.read_text(encoding="utf-8"))[
    "cases"
]


@pytest.fixture(autouse=True)
def _fast_pbkdf2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(credentials, "_PBKDF2_ITERATIONS", 1_000)


def _case_id(case: dict[str, Any]) -> str:
    return f"{case['key_id']}-{json.dumps(case['entry'], sort_keys=True)}"


def _entry(case: dict[str, Any]) -> dict[str, Any]:
    """A keys.json entry, as the bridge writes it, plus the case's fields."""
    return {"hash": "ab", "salt": "cd", **case["entry"]}


def _resolved(case: dict[str, Any]) -> tuple[str | None, Role | None]:
    """What API-key auth resolves for the case's key once its hash matched:
    its role, or nothing when the key is revoked, disabled or expired."""
    if not case.get("usable", True):
        return None, None
    return case["key_id"], Role[case["role"].upper()]


def _load(data_dir: Path, entries: dict[str, Any]) -> PersistenceManager:
    data_dir.mkdir(exist_ok=True)
    (data_dir / "keys.json").write_text(json.dumps({"keys": entries}))
    pm = PersistenceManager(data_dir=data_dir, auto_save_interval=0)
    pm.load_all()
    return pm


def _kind(key_id: str) -> str:
    if key_id == "master":
        return "master"
    if persistence_module.is_edge_key_id(key_id):
        return "edge"
    return "plain"


_MISSING = "<missing>"


def _stored_form(entry: dict[str, Any]) -> str:
    return json.dumps(entry["role"], sort_keys=True) if "role" in entry else _MISSING


def test_the_table_is_the_one_the_gateway_reads() -> None:
    source = _GATEWAY_SOURCE.read_text(encoding="utf-8")
    assert 'include_str!("../../testdata/key_role_parity.json")' in source
    assert "fn stored_roles_read_as_on_the_bridge()" in source
    assert f"const ROLE_PARITY_CASES: usize = {_MIN_CASES};" in source
    assert len(_CASES) >= _MIN_CASES, "the shared table lost cases"
    assert {Role[case["role"].upper()] for case in _CASES} == set(Role)
    assert {case.get("usable", True) for case in _CASES} == {True, False}


def _ci_path_filters() -> dict[str, list[str]]:
    workflow = yaml.safe_load(_CI_WORKFLOW.read_text(encoding="utf-8"))
    for step in workflow["jobs"]["changes"]["steps"]:
        if step.get("id") == "filter":
            return yaml.safe_load(step["with"]["filters"])
    raise AssertionError("ci.yml: no paths filter step in the changes job")


#: Glob syntax picomatch reads that :func:`_paths_filter_matches` does not
#: implement: braces, negation and extglobs.
_UNSUPPORTED_GLOB = ("{", "}", "!", "+(", "@(", "*(", "?(")


def _match_segments(path: list[str], pattern: list[str]) -> bool:
    if not pattern:
        return not path
    head, rest = pattern[0], pattern[1:]
    if head == "**":
        return any(_match_segments(path[i:], rest) for i in range(len(path) + 1))
    return (
        bool(path)
        and fnmatch.fnmatchcase(path[0], head)
        and _match_segments(path[1:], rest)
    )


def _paths_filter_matches(path: str, pattern: str) -> bool:
    """Whether dorny/paths-filter's *pattern* matches repo-relative *path*.

    dorny matches with picomatch (``dot: true``): ``*``, ``?`` and ``[...]``
    never match ``/``, and a ``**`` path segment matches any number of
    segments, none included. :func:`fnmatch.fnmatchcase` alone lets ``*``
    match ``/``, so ``src/gateway/*`` would seem to cover every file below
    it. Each segment is matched with ``fnmatchcase`` (it holds no ``/``);
    syntax not implemented here raises ``ValueError`` instead of guessing.
    """
    if any(token in pattern for token in _UNSUPPORTED_GLOB):
        raise ValueError(f"unsupported paths-filter pattern syntax: {pattern!r}")
    return _match_segments(path.split("/"), pattern.split("/"))


def test_ci_runs_this_check_when_only_the_gateway_half_changes() -> None:
    """The Rust job alone passes against an edited table (a dropped case, a
    renamed gateway test): only this file notices, so a PR that touches
    only the gateway's half must still run the Python jobs."""
    python_paths = _ci_path_filters()["python"]
    for path in (_TABLE_PATH, _GATEWAY_SOURCE, Path(__file__).resolve()):
        relative = path.relative_to(_REPO_ROOT).as_posix()
        assert any(_paths_filter_matches(relative, p) for p in python_paths), (
            f"ci.yml: the python paths filter misses {relative}"
        )


@pytest.mark.parametrize(
    "narrowed",
    [
        ["src/gateway/*"],
        ["src/gateway/crates/sigrift-gateway-core/*"],
        ["src/gateway/crates/*/testdata/*", "src/gateway/crates/*/api_key.rs"],
        ["src/*/key_role_parity.json", "src/*/api_key.rs"],
    ],
)
def test_the_ci_guard_matches_paths_as_the_paths_filter_does(
    monkeypatch: pytest.MonkeyPatch, narrowed: list[str]
) -> None:
    """dorny/paths-filter matches with picomatch, where ``*`` stops at ``/``.

    Regression: the guard matched with ``fnmatch``, where ``*`` also matches
    ``/``, so it passed for a filter like ``src/gateway/*`` that the real
    filter does not apply to the shared table or ``api_key.rs``: gateway-only
    PRs editing them would skip the Python jobs with the guard green.
    """
    filters = {"python": [*narrowed, "tests/bridge/**"]}
    monkeypatch.setattr(sys.modules[__name__], "_ci_path_filters", lambda: filters)
    with pytest.raises(AssertionError, match="the python paths filter misses"):
        test_ci_runs_this_check_when_only_the_gateway_half_changes()


@pytest.mark.parametrize(
    ("pattern", "path", "matches"),
    [
        ("src/gateway/**", "src/gateway/crates/a/b.rs", True),
        ("src/gateway/**", "src/gateway", True),
        ("**/testdata/**", "src/gateway/crates/core/testdata/t.json", True),
        ("src/**/api_key.rs", "src/gateway/crates/core/src/auth/api_key.rs", True),
        ("src/**/api_key.rs", "src/api_key.rs", True),
        ("src/*/x.rs", "src/a/x.rs", True),
        ("src/*/x.rs", "src/a/b/x.rs", False),
        ("src/gateway/*", "src/gateway/README.md", True),
        ("src/gateway/*", "src/gateway/crates/x.rs", False),
        ("tests/bridge/**", "tests/bridge/.hidden/x.py", True),  # dot: true
        ("src/*.rs", "src/.x.rs", True),
        ("src/a?.rs", "src/ab.rs", True),
        ("src/a?.rs", "src/a/.rs", False),
        ("src/[ab].rs", "src/b.rs", True),
        ("src/**", "srcx/a.rs", False),
        ("a/**/b", "a/b", True),
        ("a/**/b", "a/x/y/b", True),
    ],
)
def test_paths_filter_glob(pattern: str, path: str, matches: bool) -> None:
    # Cross-checked against picomatch 4 with {dot: true}, as dorny uses it.
    assert _paths_filter_matches(path, pattern) is matches


def test_paths_filter_glob_refuses_syntax_it_does_not_implement() -> None:
    for pattern in ("src/{a,b}/**", "!src/**", "src/+(a|b)/x", "src/@(a)/x"):
        with pytest.raises(ValueError, match="paths-filter pattern"):
            _paths_filter_matches("src/a/x", pattern)


@pytest.mark.parametrize("case", _CASES, ids=_case_id)
def test_stored_roles_read_as_on_the_gateway(tmp_path: Path, case: dict) -> None:
    key_id = case["key_id"]
    pm = _load(tmp_path / "data", {key_id: _entry(case)})
    meta = pm.get_key_meta()
    expected = Role[case["role"].upper()]
    assert stored_key_role(key_id, meta.get(key_id)) is expected
    # The role API-key auth resolves after a match (HTTP, WebSocket and
    # the verified-key cache all go through it), or nothing for a revoked,
    # disabled or expired key, the master key included.
    assert _resolve_key_role(key_id, meta) == _resolved(case)


@pytest.mark.parametrize("case", _CASES, ids=_case_id)
def test_a_bridge_save_keeps_the_role_both_sides_read(
    tmp_path: Path, case: dict
) -> None:
    """Another key change rewrites every entry (a missing role becomes
    ``"viewer"``, an edge key's operator role ``"node"``).  The rewritten
    entry must still read as before, here and — since its stored form is
    itself a case of the shared table — on the gateway."""
    key_id = case["key_id"]
    data_dir = tmp_path / "data"
    pm = _load(data_dir, {key_id: _entry(case)})
    raw = "unrelated-key-raw"
    hash_hex, salt = hash_credential(raw)
    assert pm.add_key(
        "unrelated",
        hash_hex,
        salt,
        lookup_hash=compute_lookup_hash(raw),
        meta={"role": "viewer"},
    )
    rewritten = json.loads((data_dir / "keys.json").read_text())["keys"][key_id]

    expected = Role[case["role"].upper()]
    reread = PersistenceManager(data_dir=data_dir, auto_save_interval=0)
    reread.load_all()
    assert stored_key_role(key_id, reread.get_key_meta().get(key_id)) is expected
    assert _resolve_key_role(key_id, reread.get_key_meta()) == _resolved(case)

    pinned = {(_kind(c["key_id"]), _stored_form(c["entry"])): c["role"] for c in _CASES}
    form = (_kind(key_id), _stored_form(rewritten))
    assert form in pinned, f"the shared table has no case for {form}"
    assert pinned[form] == case["role"]


def test_the_master_key_the_bridge_writes_on_first_run_is_admin(
    tmp_path: Path,
) -> None:
    """``set_key("master")`` writes the entry without a role: the gateway
    must read it as the bridge does (ADMIN), not as a role-less key."""
    data_dir = tmp_path / "data"
    pm = PersistenceManager(data_dir=data_dir, auto_save_interval=0)
    pm.load_all()
    pm.set_key("master", *hash_credential("master-raw"))
    on_disk = json.loads((data_dir / "keys.json").read_text())["keys"]["master"]
    assert "role" not in on_disk
    assert ("master", _MISSING) in {
        (_kind(c["key_id"]), _stored_form(c["entry"])) for c in _CASES
    }
    assert stored_key_role("master", pm.get_key_meta().get("master")) is Role.ADMIN
