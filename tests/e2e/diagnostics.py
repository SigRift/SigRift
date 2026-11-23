"""Allowlisted E2E decisions, with a strict public-log summarizer.

HTTP content, exception text, identities, headers and dynamic paths never enter
this recorder. Raw pytest output remains a separate private runner artifact.
"""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import sys

METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "NONE", "OTHER"}
STAGES = {
    "session",
    "request",
    "scanner_register",
    "scanner_client",
    "scanner_key",
    "scanner_detection",
    "scanner_wifi",
    "scanner_iq",
    "scanner_status",
    "scanner_cleanup",
    "scanner_revocation",
    "test_setup",
    "test_call",
    "test_teardown",
    "unknown",
}
CATEGORIES = {
    "begin",
    "complete",
    "ok",
    "cooldown",
    "unexpected_status",
    "transport",
    "invalid_json",
    "request_contract",
    "fixture_contract",
    "fixture_error",
    "test_failure",
    "internal",
}
ROUTES = {
    "/api/auth/login",
    "/api/auth/logout",
    "/api/auth/me",
    "/api/auth/change-password",
    "/api/auth/mfa/verify",
    "/api/auth/mfa/setup",
    "/api/auth/mfa/enable",
    "/api/nodes/register",
    "/api/admin/keys",
    "/api/admin/users",
    "/api/detections/batch",
    "/api/wifi/ingest",
    "/api/wifi/networks",
    "/api/wifi/stats",
    "/api/admin/wifi-whitelist",
    "/api/alerts/rules/conditions",
    "unknown",
    "none",
}
DYNAMIC_ROUTES = (
    (r"/api/nodes/[^/]+/scanner-status", "/api/nodes/{node_id}/scanner-status"),
    (r"/api/detections/[^/]+/iq", "/api/detections/{detection_id}/iq"),
    (r"/api/admin/keys/[^/]+", "/api/admin/keys/{key_id}"),
    (r"/api/admin/users/[^/]+", "/api/admin/users/{username}"),
    (r"/api/alerts/rules/conditions/[^/]+", "/api/alerts/rules/conditions/{rule_id}"),
)
ROUTES.update(template for _, template in DYNAMIC_ROUTES)
FIELDS = {"method", "route", "status", "expected", "stage", "category"}
MAX_EVENTS = 1000
_writer = None


def route_template(path):
    if not isinstance(path, str) or len(path) > 2048:
        return "unknown"
    path = path.split("?", 1)[0].split("#", 1)[0]
    if path in ROUTES:
        return path
    for pattern, template in DYNAMIC_ROUTES:
        if re.fullmatch(pattern, path):
            return template
    return "unknown"


def valid_status(value):
    return type(value) is int and 100 <= value <= 599


def event(
    method="NONE",
    path="none",
    *,
    status=None,
    expected=(),
    stage="request",
    category="internal",
):
    return {
        "method": method if type(method) is str and method in METHODS else "OTHER",
        "route": route_template(path),
        "status": status if valid_status(status) else None,
        "expected": list(expected)
        if isinstance(expected, (list, tuple))
        and len(expected) <= 8
        and all(valid_status(n) for n in expected)
        else [],
        "stage": stage if type(stage) is str and stage in STAGES else "unknown",
        "category": category
        if type(category) is str and category in CATEGORIES
        else "internal",
    }


class Recorder:
    def __init__(self, path):
        self.path = path
        self.stream = None
        self.failed = False
        self.count = 0
        try:
            # The caller designates a fresh private path. Never overwrite or
            # follow an existing file/symlink, including stale prior evidence.
            fd = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            self.stream = os.fdopen(fd, "w", encoding="utf-8")
        except OSError:
            self.failed = True
        self.write(event(stage="session", category="begin"))

    def write(self, record):
        if self.failed:
            return
        try:
            if self.count >= MAX_EVENTS:
                raise OSError("diagnostic limit")
            self.stream.write(json.dumps(record, sort_keys=True) + "\n")
            self.stream.flush()
            self.count += 1
        except (OSError, ValueError):
            self.failed = True

    def close(self):
        if self.stream is not None:
            try:
                self.stream.close()
            except OSError:
                self.failed = True


def record(method="NONE", path="none", **values):
    global _writer
    path_setting = os.environ.get("SIGRIFT_E2E_DIAGNOSTICS")
    if not path_setting:
        return
    if _writer is None or _writer.path != path_setting:
        if _writer is not None:
            _writer.close()
        _writer = Recorder(path_setting)
    _writer.write(event(method, path, **values))


def finish():
    """Seal the log; recording failures never replace the original test error."""
    global _writer
    record(stage="session", category="complete")
    if _writer is None:
        return True
    _writer.close()
    success = not _writer.failed
    _writer = None
    return success


@contextmanager
def fixture_stage(stage):
    try:
        yield
    except Exception as error:
        category = (
            "fixture_contract"
            if isinstance(error, (AssertionError, KeyError, TypeError, ValueError))
            else "fixture_error"
        )
        record(stage=stage, category=category)
        raise


def validate(records):
    if not records or len(records) > MAX_EVENTS:
        raise ValueError("invalid diagnostics")
    for row in records:
        if not isinstance(row, dict) or set(row) != FIELDS:
            raise ValueError("invalid diagnostics")
        if not all(
            type(row[key]) is str for key in ("method", "route", "stage", "category")
        ):
            raise ValueError("invalid diagnostics")
        if (
            row["method"] not in METHODS
            or row["route"] not in ROUTES
            or row["stage"] not in STAGES
            or row["category"] not in CATEGORIES
        ):
            raise ValueError("invalid diagnostics")
        if row["status"] is not None and not valid_status(row["status"]):
            raise ValueError("invalid diagnostics")
        if (
            not isinstance(row["expected"], list)
            or len(row["expected"]) > 8
            or not all(valid_status(n) for n in row["expected"])
        ):
            raise ValueError("invalid diagnostics")
    if records[0] != event(stage="session", category="begin") or records[-1] != event(
        stage="session", category="complete"
    ):
        raise ValueError("incomplete diagnostics")


def summarize(path):
    try:
        with Path(path).open("rb") as source:
            raw = source.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError("oversized diagnostics")
        records = [json.loads(line) for line in raw.splitlines()]
        validate(records)
    except (OSError, ValueError, TypeError, RecursionError):
        print(
            "E2E diagnostics unavailable, incomplete, or invalid; raw output remains private."
        )
        return 1
    # Validate the whole input before emitting even its first record.
    for row in records[1:-1]:
        print(json.dumps(row, sort_keys=True))
    print(f"{len(records) - 2} safe E2E diagnostic events recorded.")
    return 0


if __name__ == "__main__":
    sys.exit(summarize(sys.argv[1] if len(sys.argv) == 2 else ""))
