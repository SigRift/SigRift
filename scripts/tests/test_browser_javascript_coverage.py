"""Browser coverage preserves source identity without retaining session data."""

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.e2e.javascript_coverage import BrowserCoverage, shipped_source

ORIGIN = "https://fixture.invalid"
SOURCE = "function login() { return true; }\nlogin();\n"


class CDP:
    def __init__(self, source=SOURCE):
        self.source, self.handlers, self.count = source, {}, 1

    def on(self, name, callback):
        self.handlers[name] = callback

    def send(self, command, params=None):
        if command == "Debugger.getScriptSource":
            return {"scriptSource": self.source}
        if command == "Profiler.takePreciseCoverage":
            return {
                "result": [
                    {
                        "scriptId": "1",
                        "functions": [
                            {
                                "functionName": "login",
                                "isBlockCoverage": True,
                                "ranges": [
                                    {
                                        "startOffset": 0,
                                        "endOffset": len(SOURCE),
                                        "count": self.count,
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        return {}

    def detach(self):
        pass


class Page:
    def __init__(self, cdp):
        self.context = SimpleNamespace(new_cdp_session=lambda page: cdp)
        self.handlers = {}
        self.main_frame = object()

    def on(self, name, callback):
        self.handlers[name] = callback

    def remove_listener(self, name, callback):
        assert self.handlers.pop(name) == callback


def fixture_source(root):
    path = root / "src/sigrift/bridge/static/login.js"
    path.parent.mkdir(parents=True)
    path.write_text(SOURCE)
    return path


def test_only_same_origin_owned_source_paths_are_mapped(tmp_path):
    source = fixture_source(tmp_path)
    assert shipped_source(ORIGIN + "/static/login.js?v=1", ORIGIN, tmp_path) == source
    for url in [
        "https://external.invalid/static/login.js",
        ORIGIN + "/login",
        ORIGIN + "/static/%2e%2e/private.js",
        ORIGIN + "/static/vendor/leaflet.js",
    ]:
        assert shipped_source(url, ORIGIN, tmp_path) is None
    with pytest.raises(ValueError, match="no matching"):
        shipped_source(ORIGIN + "/static/unknown.js", ORIGIN, tmp_path)


def test_navigation_and_final_counts_are_private_and_source_verified(tmp_path):
    source = fixture_source(tmp_path)
    cdp, output = CDP(), tmp_path / "private/coverage"
    page = Page(cdp)
    collector = BrowserCoverage(page, ORIGIN, tmp_path, output)
    cdp.handlers["Debugger.scriptParsed"](
        {
            "scriptId": "1",
            "url": ORIGIN + "/static/login.js?private=do-not-store",
            "hash": hashlib.sha256(cdp.source.encode()).hexdigest(),
        }
    )
    page.handlers["request"](
        SimpleNamespace(is_navigation_request=lambda: True, frame=page.main_frame)
    )
    cdp.count = 2
    collector.finish()
    reports = list(output.glob("coverage-browser-*.json"))
    assert len(reports) == 2
    assert output.stat().st_mode & 0o777 == 0o700
    assert all(report.stat().st_mode & 0o777 == 0o600 for report in reports)
    documents = [json.loads(report.read_text()) for report in reports]
    assert sorted(
        doc["result"][0]["functions"][0]["ranges"][0]["count"] for doc in documents
    ) == [1, 2]
    for document in documents:
        assert document["result"][0]["url"] == "src/sigrift/bridge/static/login.js"
        assert document["sigrift"]["source_sha256"] == {
            "src/sigrift/bridge/static/login.js": hashlib.sha256(
                source.read_bytes()
            ).hexdigest()
        }
        assert "do-not-store" not in json.dumps(document)


def test_changed_or_unmeasured_source_refuses_a_coverage_report(tmp_path):
    fixture_source(tmp_path)
    for actual, parsed in [(SOURCE + "changed();", True), (SOURCE, False)]:
        cdp, output = CDP(actual), tmp_path / "private/coverage"
        collector = BrowserCoverage(Page(cdp), ORIGIN, tmp_path, output)
        if parsed:
            cdp.handlers["Debugger.scriptParsed"](
                {
                    "scriptId": "1",
                    "url": ORIGIN + "/static/login.js",
                    "hash": hashlib.sha256(cdp.source.encode()).hexdigest(),
                }
            )
        with pytest.raises(AssertionError):
            collector.finish()
        assert not output.exists()


def test_relative_coverage_destination_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="absolute"):
        BrowserCoverage(Page(CDP()), ORIGIN, tmp_path, "public-relative-directory")


@pytest.mark.parametrize(
    "category",
    [
        "source_resolution",
        "source_event",
        "source_read",
        "source_mismatch",
        "cdp_drain",
        "coverage_payload",
    ],
)
def test_collection_failures_expose_only_fixed_phase_counts(
    tmp_path, monkeypatch, capsys, category
):
    source = fixture_source(tmp_path)
    private = "private-token-cookie-password-URL\nUNTRUSTED: injected"

    class FailingCDP(CDP):
        def send(self, command, params=None):
            if command == "Profiler.takePreciseCoverage":
                if category == "cdp_drain":
                    raise RuntimeError(private)
                if category == "coverage_payload":
                    return {"result": [{"scriptId": "1", "secret": private}]}
            return super().send(command, params)

    cdp = FailingCDP()
    output = tmp_path / "private/coverage"
    collector = BrowserCoverage(Page(cdp), ORIGIN, tmp_path, output)
    event = {
        "scriptId": "1",
        "url": ORIGIN + "/static/login.js?secret=" + private,
        "hash": hashlib.sha256(SOURCE.encode()).hexdigest(),
    }
    if category == "source_mismatch":
        event["hash"] = hashlib.sha256((SOURCE + private).encode()).hexdigest()
    if category == "source_resolution":
        event["url"] = ORIGIN + "/static/missing.js?secret=" + private
    elif category == "source_event":
        del event["scriptId"]
    elif category == "source_read":
        original = Path.read_bytes

        def unreadable(path):
            if path == source:
                raise PermissionError(private)
            return original(path)

        monkeypatch.setattr(Path, "read_bytes", unreadable)
    cdp.handlers["Debugger.scriptParsed"](event)
    with pytest.raises(AssertionError) as failure:
        collector.finish()
    prefix = "Browser coverage source/collection verification failed: "
    assert str(failure.value).startswith(prefix)
    assert json.loads(str(failure.value)[len(prefix) :]) == {category: 1}
    assert not output.exists(), "Failed collection must not publish usable coverage"
    captured = capsys.readouterr()
    public = str(failure.value) + captured.out + captured.err
    for forbidden in (private, "private-token", ORIGIN, "missing.js", "secret="):
        assert forbidden not in public


def test_repeated_collection_failures_keep_bounded_category_counts(tmp_path):
    fixture_source(tmp_path)
    cdp = CDP(SOURCE + "unexpected();")
    output = tmp_path / "private/coverage"
    collector = BrowserCoverage(Page(cdp), ORIGIN, tmp_path, output)
    for _ in range(10_005):
        collector.parsed(
            {
                "scriptId": "1",
                "url": ORIGIN + "/static/login.js",
                "hash": hashlib.sha256(cdp.source.encode()).hexdigest(),
            }
        )
    with pytest.raises(AssertionError) as failure:
        collector.finish()
    assert str(failure.value).endswith('{"source_mismatch": 9999}')
    assert not output.exists()


def test_parsed_hash_verifies_source_after_document_context_is_destroyed(tmp_path):
    source = fixture_source(tmp_path)

    class DestroyedContext(CDP):
        def send(self, command, params=None):
            if command == "Debugger.getScriptSource":
                raise RuntimeError("Script context no longer exists")
            return super().send(command, params)

    output = tmp_path / "private/coverage"
    collector = BrowserCoverage(Page(DestroyedContext()), ORIGIN, tmp_path, output)
    collector.parsed(
        {
            "scriptId": "1",
            "url": ORIGIN + "/static/login.js",
            "hash": hashlib.sha256(source.read_bytes()).hexdigest(),
        }
    )
    collector.finish()
    reports = list(output.glob("coverage-browser-*.json"))
    assert len(reports) == 1
    data = json.loads(reports[0].read_text())
    assert data["sigrift"]["source_sha256"] == {
        "src/sigrift/bridge/static/login.js": hashlib.sha256(
            source.read_bytes()
        ).hexdigest()
    }
    assert data["result"][0]["functions"][0]["ranges"][0]["count"] == 1


@pytest.mark.parametrize(
    "parsed_hash",
    [None, "", "a" * 63, "a" * 65, "g" * 64, "A" * 64, 123, [], "0" * 64],
)
def test_invalid_or_wrong_parsed_hash_is_fatal_even_if_source_lookup_would_match(
    tmp_path, parsed_hash
):
    fixture_source(tmp_path)
    output = tmp_path / "private/coverage"
    collector = BrowserCoverage(Page(CDP()), ORIGIN, tmp_path, output)
    event = {"scriptId": "1", "url": ORIGIN + "/static/login.js"}
    if parsed_hash is not None:
        event["hash"] = parsed_hash
    collector.parsed(event)
    with pytest.raises(AssertionError, match="source/collection verification failed"):
        collector.finish()
    assert not output.exists()


def test_external_or_vendor_script_cannot_supply_owned_coverage(tmp_path):
    fixture_source(tmp_path)
    collector = BrowserCoverage(Page(CDP()), ORIGIN, tmp_path, tmp_path / "coverage")
    for url in [
        "https://external.invalid/static/login.js",
        ORIGIN + "/static/vendor/leaflet.js",
    ]:
        collector.parsed({"scriptId": "1", "url": url})
    assert collector.sources == {}
    assert collector.errors == {}
    with pytest.raises(AssertionError, match="No owned JavaScript"):
        collector.finish()
    assert not (tmp_path / "coverage").exists()


def test_only_main_frame_navigation_drains_coverage(tmp_path):
    class RecordingCDP(CDP):
        drains = 0

        def send(self, command, params=None):
            if command == "Profiler.takePreciseCoverage":
                self.drains += 1
            return super().send(command, params)

    cdp = RecordingCDP()
    page = Page(cdp)
    collector = BrowserCoverage(page, ORIGIN, tmp_path, tmp_path / "coverage")
    collector.request(
        SimpleNamespace(is_navigation_request=lambda: False, frame=page.main_frame)
    )
    collector.request(
        SimpleNamespace(is_navigation_request=lambda: True, frame=object())
    )
    assert cdp.drains == 0
    collector.request(
        SimpleNamespace(is_navigation_request=lambda: True, frame=page.main_frame)
    )
    assert cdp.drains == 1


def test_nested_navigation_event_during_cdp_send_does_not_collect_twice(tmp_path):
    source = fixture_source(tmp_path)

    class ReentrantCDP(CDP):
        drains = 0

        def send(self, command, params=None):
            if command == "Profiler.takePreciseCoverage":
                self.drains += 1
                # Playwright dispatches browser callbacks while a synchronous
                # CDP call waits. A nested navigation must not reenter the call.
                if "request" in page.handlers:
                    page.handlers["request"](
                        SimpleNamespace(
                            is_navigation_request=lambda: True, frame=page.main_frame
                        )
                    )
            return super().send(command, params)

    cdp = ReentrantCDP()
    page = Page(cdp)
    output = tmp_path / "coverage"
    collector = BrowserCoverage(page, ORIGIN, tmp_path, output)
    collector.parsed(
        {
            "scriptId": "1",
            "url": ORIGIN + "/static/login.js",
            "hash": hashlib.sha256(source.read_bytes()).hexdigest(),
        }
    )
    page.handlers["request"](
        SimpleNamespace(is_navigation_request=lambda: True, frame=page.main_frame)
    )
    assert cdp.drains == 1
    collector.finish()
    assert cdp.drains == 2
    assert len(list(output.glob("coverage-browser-*.json"))) == 2
