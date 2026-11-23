"""Keep inline JavaScript and newly added source files visible to the gate."""

import importlib.util
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "javascript_inventory", ROOT / "tests/bridge/js/inventory.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_inline_scripts_handlers_and_javascript_urls_are_unmeasured():
    parser = MODULE.InlineBehavior("src/example.html")
    parser.feed("""<!-- <script>ignored()</script> -->
<script src="/external.js"></script>
<script type="application/json">{"data": true}</script>
<script>actualRuntime();</script>
<button onclick="writeRecord()">Save</button>
<a href="javascript:openPanel()">Open</a>
""")
    assert [(entry["kind"], entry["line"]) for entry in parser.entries] == [
        ("inline-script", 4),
        ("event-handler", 5),
        ("javascript-url", 6),
    ]
    assert all(len(entry["sha256"]) == 64 for entry in parser.entries)


def test_unknown_script_type_is_not_silently_treated_as_measured():
    parser = MODULE.InlineBehavior("src/example.html")
    parser.feed('<script type="new-runtime-type">unknownRuntime()</script>')
    assert len(parser.entries) == 1


def test_new_source_outside_src_and_inline_behavior_enter_inventory(tmp_path):
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    files = {
        "src/app.js": "runApp();",
        "scripts/new.mjs": "export const helper = true;",
        "src/new.cjs": "module.exports = true;",
        "src/page.html": '<button onclick="runApp()">Run</button>',
        "tests/fixture.js": "testOnly();",
        "scripts/tests/fixture.cjs": "testOnly();",
        "src/sigrift/bridge/static/vendor/leaflet.js": "vendor();",
    }
    for relative, content in files.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    inventory = MODULE.inventory(tmp_path)
    assert inventory["files"] == [
        "scripts/new.mjs",
        "scripts/tests/fixture.cjs",
        "src/app.js",
        "src/new.cjs",
        "tests/fixture.js",
    ]
    assert len(inventory["unmeasured_inline"]) == 1
    assert inventory["unmeasured_inline"][0]["path"] == "src/page.html"


def test_browser_guard_reports_failed_owned_assets_without_sensitive_queries():
    from tests.e2e.conftest import failed_static_asset

    origin = "https://fixture.invalid"
    assert (
        failed_static_asset(origin + "/static/missing.js?token=private", 404, origin)
        == "HTTP 404 /static/missing.js"
    )
    assert failed_static_asset(origin + "/static/style.css", 500, origin)
    assert failed_static_asset(origin + "/static/login.js", 200, origin) is None
    assert failed_static_asset(origin + "/api/auth/me", 401, origin) is None
    assert (
        failed_static_asset("https://third-party.invalid/static/x.js", 404, origin)
        is None
    )


def test_authored_tools_under_tests_remain_in_source_inventory(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    files = {
        "tests/bridge/js/coverage.cjs": "module.exports = () => true;\n",
        "tests/new_tool.mjs": "export const enabled = true;\n",
        "scripts/tests/helper.js": "export const enabled = true;\n",
        "tests/bridge/js/example.test.cjs": "require('node:test')('example', () => {});\n",
        "src/app.js": "console.log('app');\n",
        "src/helper.test.cjs": "module.exports = () => true;\n",
        "tests/uncollected.test.mjs": "export const enabled = true;\n",
    }
    for relative, source in files.items():
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source)
    result = MODULE.inventory(tmp_path)
    assert result["files"] == sorted(files)
    assert result["test_exclusions"] == []


def test_actual_coverage_runner_is_in_the_repository_inventory():
    result = MODULE.inventory()
    assert "tests/bridge/js/coverage.cjs" in result["files"]
    assert any(
        Path(name).parent == Path("tests/bridge/js") and name.endswith(".test.cjs")
        for name in result["files"]
    )
    # The pages run under script-src 'self', which refuses inline script:
    # none is left to measure (tests/bridge/test_csp_static_lock.py). The
    # parser still reports any that is added (the tests above).
    assert result["unmeasured_inline"] == [], "Inline script under a strict CSP"
