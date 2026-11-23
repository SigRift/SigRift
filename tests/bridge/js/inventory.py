"""Inventory authored JavaScript and uninstrumented inline HTML behavior."""

from hashlib import sha256
from html.parser import HTMLParser
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
VENDOR = {"src/sigrift/bridge/static/vendor/leaflet.js"}
JS_EXTENSIONS = {".js", ".mjs", ".cjs"}
INERT_SCRIPT_TYPES = {
    "application/json",
    "application/ld+json",
    "importmap",
    "speculationrules",
}


class InlineBehavior(HTMLParser):
    def __init__(self, source_path):
        super().__init__(convert_charrefs=True)
        self.source_path = source_path
        self.entries = []
        self.script = None

    def record(self, kind, code, position):
        if code.strip():
            self.entries.append(
                {
                    "path": self.source_path,
                    "kind": kind,
                    "line": position[0],
                    "column": position[1] + 1,
                    "sha256": sha256(code.encode()).hexdigest(),
                }
            )

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        for name, value in attrs:
            if value and name.startswith("on"):
                self.record("event-handler", value, self.getpos())
            if value and value.lstrip().lower().startswith("javascript:"):
                self.record("javascript-url", value, self.getpos())
        if tag == "script" and not values.get("src"):
            kind = values.get("type", "").strip().lower()
            if kind not in INERT_SCRIPT_TYPES:
                self.script = {"code": "", "position": self.getpos()}

    def handle_data(self, data):
        if self.script is not None:
            self.script["code"] += data

    def handle_endtag(self, tag):
        if tag == "script" and self.script is not None:
            self.record("inline-script", self.script["code"], self.script["position"])
            self.script = None


def inventory(root=ROOT):
    tracked = (
        subprocess.check_output(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=root,
        )
        .decode()
        .split("\0")
    )
    sources, inline = [], []
    for relative in sorted(set(tracked)):
        path = root / relative
        if not relative or relative in VENDOR:
            continue
        if not path.is_file():
            continue
        if path.suffix in JS_EXTENSIONS:
            sources.append(relative)
        elif path.suffix in {".html", ".htm"}:
            parser = InlineBehavior(relative)
            parser.feed(path.read_text())
            parser.close()
            if parser.script is not None:
                raise ValueError(f"Unclosed inline script in {relative}")
            inline.extend(parser.entries)
    return {
        "files": sources,
        "unmeasured_inline": inline,
        "exclusions": sorted(VENDOR),
        "test_exclusions": [],
        "scope": "All repository-authored .js/.mjs/.cjs files and HTML inline behavior, including test drivers and embedded helpers; only vendored Leaflet excluded.",
    }


if __name__ == "__main__":
    print(json.dumps(inventory(), indent=2))
