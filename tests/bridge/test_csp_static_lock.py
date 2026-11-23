"""No inline script anywhere the dashboard serves: the strict script CSP holds.

The gateway sends ``script-src 'self'`` (no ``'unsafe-inline'``), as the
bridge and the Shiny app do. Under it the browser refuses an inline
``<script>`` block, an event-handler attribute (``onclick=``), a
``javascript:`` URL and ``eval``-style code, so any of them in a page is a
control that silently does nothing. This lock finds them before a browser
does:

- the HTML the services serve (Jinja templates, static pages) has no
  inline script (only JSON data blocks are inert: an inline import map or
  speculation rules is refused too), handler attribute or ``javascript:``
  URL;
- the shipped JavaScript builds no markup with a handler attribute or a
  ``javascript:`` URL, also not a tag built from several strings across
  lines, sets no ``on…`` attribute by name (a computed ``"on" + type``
  included), and runs no code from a string (``eval``, ``new Function``,
  string timers);
- the HTML the bridge builds in Python (the documentation index, report
  and export pages) has no inline script or handler attribute either,
  read from each string value the code builds (literals joined across
  lines, ``+`` and f-strings), not only line by line;
- FastAPI's generated documentation pages, which load script from a CDN
  and run an inline one, are not served.

Assigning a handler property (``button.onclick = function …``) is not
inline script and stays allowed. Vendored code (Leaflet) and test files,
whose payloads hold handler markup on purpose, are out of scope. The
JavaScript checks read lines: a tag whose handler attribute is built from
a variable (``' ' + name + '="go()"'``) is beyond them, and the browser
suite's CSP watcher (``tests/e2e/conftest.py``) is the backstop.
"""

from __future__ import annotations

import ast
import importlib.util
import re
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location(
    "javascript_inventory", _ROOT / "tests/bridge/js/inventory.py"
)
_INVENTORY = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_INVENTORY)


def _shipped(*suffixes: str) -> list[str]:
    """Files under src/sigrift with these suffixes, minus vendor and tests.

    New files count before they are committed, as in the JavaScript
    inventory (tests/bridge/js/inventory.py).
    """
    tracked = subprocess.check_output(
        [
            "git",
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            "src/sigrift",
        ],
        cwd=_ROOT,
    ).decode()
    return sorted(
        name
        for name in tracked.split("\0")
        if name.endswith(suffixes)
        and "/vendor/" not in name
        and "/tests/" not in name
        and (_ROOT / name).is_file()
    )


_HTML = _shipped(".html", ".htm")
_JS = _shipped(".js", ".mjs", ".cjs")
_PY = _shipped(".py")

#: An event-handler attribute inside a tag: `<button onclick="…">`,
#: `<img src=x onerror=run()>`, `<a onmouseover=${…}>`, also in a JS or
#: Python string. Code outside a tag (`el.onclick = …`, `var online = …`)
#: is not matched.
_HANDLER_ATTRIBUTE = re.compile(r"<[a-z][^<>]*?\son[a-z]+\s*=", re.I)
#: A JavaScript string that starts with a handler attribute: the rest of a
#: tag built from several strings (`'<button class="x"' +` then, on the
#: next line or after a variable, `' onclick="go()">'`), or after a
#: template placeholder (`${attrs} onclick=`). A string that only starts
#: with such a name (`'online=' + value`) is not matched.
_HANDLER_PIECE = re.compile(
    r"""["'`}]\s+on[a-z]+\s*="""
    r"""|'on[a-z]+\s*=\s*(?:"|\\')"""
    r"""|"on[a-z]+\s*=\s*(?:'|\\")"""
    r"""|`on[a-z]+\s*=\s*(?:["']|\$\{)""",
    re.I,
)
_JAVASCRIPT_URL = re.compile(r"""["'`(=]\s*javascript:""", re.I)
_INLINE_SCRIPT_TAG = re.compile(r"<script\b(?![^>]*\bsrc\s*=)[^>]*>", re.I)
#: Code run from a string (`eval(x)`, not a comment's "no eval()"), or a
#: handler attribute set by name, also a computed one (`"on" + type`).
_STRING_CODE = re.compile(
    r"""\beval\s*\((?!\s*\))|\bnew\s+Function\s*\(|\bset(?:Timeout|Interval)\s*\(\s*["'`]"""
    r"""|\.setAttribute\s*\(\s*["'`](?i:on)"""
    r"""|\.setAttributeNS\s*\([^,()]*,\s*["'`](?i:on)"""
    r"""|["'`](?i:on)["'`]\s*\+"""
)
#: The same, for a whole Python string value (literals joined by the
#: parser, `+` or an f-string), which may span lines: one that starts
#: with a handler attribute is the rest of a tag built in pieces.
_VALUE_HANDLER_PIECE = re.compile(r"""^\s+on[a-z]+\s*=|^on[a-z]+\s*=\s*["'{]""", re.I)
#: The only inline `<script>` types the CSP leaves alone: data blocks the
#: browser never runs. Every other inline script is refused under
#: `script-src 'self'`, an import map and speculation rules included
#: (the JavaScript inventory counts those two as not-JavaScript only).
_CSP_DATA_SCRIPT_TYPES = frozenset({"application/json", "application/ld+json"})


class _CspInlineBehavior(_INVENTORY.InlineBehavior):
    """The inventory's parser, with only JSON data blocks inert."""

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "script" and not values.get("src"):
            kind = (values.get("type") or "").strip().lower()
            attrs = [(name, value) for name, value in attrs if name != "type"]
            if kind in _CSP_DATA_SCRIPT_TYPES:
                attrs.append(("type", kind))
        super().handle_starttag(tag, attrs)


def _inline_html(text: str, path: str = "<test>") -> list[str]:
    parser = _CspInlineBehavior(path)
    parser.feed(text)
    parser.close()
    assert parser.script is None, f"{path}: unclosed <script>"
    return [f"{e['kind']} at line {e['line']}" for e in parser.entries]


def test_the_scan_covers_the_served_files() -> None:
    assert "src/sigrift/bridge/templates/index.html" in _HTML
    assert "src/sigrift/bridge/templates/admin.html" in _HTML
    assert "src/sigrift/bridge/templates/login.html" in _HTML
    assert "src/sigrift/lib/shiny/templates/index.html" in _HTML
    assert "src/sigrift/bridge/static/docs/api_reference.html" in _HTML
    assert "src/sigrift/bridge/static/dashboard.js" in _JS
    assert "src/sigrift/bridge/static/docs_dropdown.js" in _JS
    assert "src/sigrift/bridge/static/vendor/leaflet.js" not in _JS
    assert "src/sigrift/bridge/app.py" in _PY


@pytest.mark.parametrize("path", _HTML)
def test_html_has_no_inline_script(path: str) -> None:
    found = _inline_html((_ROOT / path).read_text(encoding="utf-8"), path)
    assert not found, f"{path}: move these into a static .js file: {found}"


@pytest.mark.parametrize(
    ("markup", "found"),
    [
        ('<script type="importmap">{"imports": {}}</script>', True),
        ('<script type="speculationrules">{"prefetch": []}</script>', True),
        ('<script type="module">run()</script>', True),
        ("<script type>run()</script>", True),
        ("<script>run()</script>", True),
        ('<script type="application/json">{"a": 1}</script>', False),
        ('<script type="Application/LD+JSON">{"a": 1}</script>', False),
        ('<script src="/static/app.js?v=1"></script>', False),
        ('<button onclick="go()">x</button>', True),
        ('<a href="javascript:go()">x</a>', True),
    ],
)
def test_the_html_parser_finds_what_the_csp_refuses(markup: str, found: bool) -> None:
    assert bool(_inline_html(markup)) is found, markup


_JS_PATTERNS = (
    _HANDLER_ATTRIBUTE,
    _HANDLER_PIECE,
    _JAVASCRIPT_URL,
    _INLINE_SCRIPT_TAG,
    _STRING_CODE,
)


def _matches(path: str, *patterns: re.Pattern[str]) -> list[str]:
    text = (_ROOT / path).read_text(encoding="utf-8")
    return [
        f"line {number}: {line.strip()[:120]}"
        for number, line in enumerate(text.splitlines(), 1)
        if any(pattern.search(line) for pattern in patterns)
    ]


@pytest.mark.parametrize("path", _JS)
def test_javascript_builds_no_inline_script(path: str) -> None:
    found = _matches(path, *_JS_PATTERNS)
    assert not found, (
        f"{path}: bind handlers with addEventListener, never in markup or code "
        f"strings: {found}"
    )


def _static_text(node: ast.AST) -> str | None:
    """The text a string expression builds, a dynamic part as ``\\x00``;
    None if *node* builds no string."""
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.JoinedStr):
        return "".join(
            part.value if isinstance(part, ast.Constant) else "\x00"
            for part in node.values
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        left, right = _static_text(node.left), _static_text(node.right)
        if left is None and (right is None or isinstance(node.op, ast.Mod)):
            return None
        return (left if left is not None else "\x00") + (
            right if right is not None else "\x00"
        )
    return None


def _python_strings(text: str) -> list[tuple[int, str]]:
    """(line, text) of each string expression in Python *text*."""
    found = []
    for node in ast.walk(ast.parse(text)):
        value = _static_text(node)
        if value is not None:
            found.append((node.lineno, value))
    return found


def _python_findings(text: str) -> list[str]:
    patterns = (_HANDLER_ATTRIBUTE, _JAVASCRIPT_URL, _INLINE_SCRIPT_TAG)
    lines = [
        f"line {number}: {line.strip()[:120]}"
        for number, line in enumerate(text.splitlines(), 1)
        if any(pattern.search(line) for pattern in patterns)
    ]
    strings = sorted(
        {
            f"string at line {number}: {value.strip()[:120]!r}"
            for number, value in _python_strings(text)
            if _VALUE_HANDLER_PIECE.search(value)
            or any(pattern.search(value) for pattern in patterns)
        }
    )
    return lines + strings


@pytest.mark.parametrize("path", _PY)
def test_python_rendered_html_has_no_inline_script(path: str) -> None:
    found = _python_findings((_ROOT / path).read_text(encoding="utf-8"))
    assert not found, f"{path}: served HTML must not carry inline script: {found}"


@pytest.mark.parametrize(
    "source",
    [
        'html = "<button class=\\"x\\"" \' onclick="go()">\'',
        'html = (\n    "<button class=\\"x\\""\n    \' onclick="go()">\'\n)',
        "html = ('<img src=x' + extra +\n        ' onerror=\"bad()\">')",
        "html = f'<a {attrs} onmouseover={handler}>'",
        "html = ('<td class=\"c\"' + cells +\n        'onclick=\"x()\">')",
        "html = '<p>' + '<script>' + code + '</script>'",
        "html = '<a href=\"%s\">' % 'javascript:go()'",
    ],
)
def test_the_python_check_finds_markup_built_in_pieces(source: str) -> None:
    assert _python_findings(source), source


@pytest.mark.parametrize(
    "source",
    [
        "button = {'onclick': handler}",
        "query = 'online=' + str(value)",
        "label = f'{count} online'",
        "html = '<script src=\"/static/app.js?v=1\"></script>'",
        "html = '<button class=\"x\">' + text + '</button>'",
        '"""Bind the handler (no onclick= in markup)."""',
    ],
)
def test_the_python_check_allows_markup_without_handlers(source: str) -> None:
    assert not _python_findings(source), source


@pytest.mark.parametrize(
    "line",
    [
        '<button onclick="go()">',
        "html += '<td onclick=\\'x()\\'>';",
        'el.innerHTML = "<img src=x onerror=\\"bad()\\">";',
        "`<a onmouseover=${handler}>`",
        "html += '<img src=x onerror=report(1)>';",
        "<a href='javascript:void(0)'>",
        "<script>run()</script>",
        '<script type="text/javascript">run()</script>',
        "eval(code)",
        "new Function('return 1')",
        "setTimeout('tick()', 10)",
        "node.setAttribute('onclick', 'x()')",
        'node.setAttribute("ONCLICK", "x()")',
        'node.setAttributeNS(null, "onclick", "x()")',
        # A handler name built from parts.
        'el.setAttribute("on" + "click", "go()")',
        "var name = 'on' + type;",
        # The rest of a tag built from several strings, on its own line.
        "    ' onclick=\"go()\">x</button>' +",
        "    'onclick=\"go()\">x</button>';",
        "    + \"onclick='go()'>\";",
        "    + 'onerror=\\'bad()\\'>';",
        "`<img src=${src} ${extra} onerror=${run}>`",
        '    `onclick="${handler}">`',
    ],
)
def test_the_patterns_find_inline_script(line: str) -> None:
    assert any(pattern.search(line) for pattern in _JS_PATTERNS), line


def test_a_tag_split_across_lines_is_found() -> None:
    """Each line of a split tag, as a JavaScript file builds one."""
    built = """
        var html = '<button class="btn"' +
            ' onclick="go()">x</button>';
        var other = '<button class="btn" ' +
            'onclick="go()">x</button>';
    """
    found = [
        line
        for line in built.splitlines()
        if any(pattern.search(line) for pattern in _JS_PATTERNS)
    ]
    assert [line.strip() for line in found] == [
        "' onclick=\"go()\">x</button>';",
        "'onclick=\"go()\">x</button>';",
    ]


@pytest.mark.parametrize(
    "line",
    [
        "button.onclick = function() { go(); };",
        "el.onload = handler;",
        "img.onerror = fallback(img);",
        "    onload = function() { start(); };",
        '<script src="/static/app.js?v=1"></script>',
        '<script src=\'{{ url_for("static", path="x.js") }}\'></script>',
        "setTimeout(function() { tick(); }, 10)",
        "setTimeout(tick, 10)",
        "row.addEventListener('click', onRowClick)",
        "var isOnline = online === true;",
        'var online = "yes", onlineNodes = Array.isArray(nodes);',
        '<div class="x" data-on-close="x" title="turn on = off">',
        "* Security: No eval(), no innerHTML with untrusted data.",
        "var query = 'online=' + value;",
        "params += '&online=' + (online ? 1 : 0);",
        "if (state === 'on') { light.on = true; }",
        "el.setAttribute('open', '');",
        "el.setAttribute('aria-label', 'Turn on')",
        "var label = mode === 'online' ? 'Online' : 'Offline';",
    ],
)
def test_the_patterns_allow_bound_handlers(line: str) -> None:
    assert not any(pattern.search(line) for pattern in _JS_PATTERNS), line


def test_the_bridge_serves_no_generated_documentation_pages() -> None:
    """FastAPI's /docs (Swagger UI) and /redoc load their script from a CDN
    and /docs runs an inline one: neither service's policy ever allowed
    either, so both pages were blank. The API schema stays served."""
    from fastapi.testclient import TestClient

    from sigrift.bridge import app as bridge_app_module

    app = bridge_app_module.app
    assert app.docs_url is None
    assert app.redoc_url is None
    client = TestClient(app)
    for path in ("/docs", "/docs/oauth2-redirect", "/redoc"):
        response = client.get(path)
        assert response.status_code == 404, path
        assert "<script" not in response.text, path
    assert client.get("/openapi.json").status_code == 200
