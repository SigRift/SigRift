"""Optional precise V8 coverage of byte-identical shipped JavaScript.

Reports contain source identifiers and execution counts, never HTTP headers,
responses, DOM state, or browser storage. Inline HTML remains unmeasured.
"""

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import time
from urllib.parse import unquote, urlsplit
import uuid


def shipped_source(url, origin, root):
    target, base = urlsplit(url), urlsplit(origin)
    if (target.scheme, target.netloc) != (base.scheme, base.netloc):
        return None
    path = unquote(target.path)
    if not path.startswith("/static/") or not path.endswith(".js"):
        return None
    relative = PurePosixPath(path[len("/static/") :])
    if relative.is_absolute() or ".." in relative.parts:
        return None
    if str(relative) == "vendor/leaflet.js":
        return None
    static = (root / "src/sigrift/bridge/static").resolve()
    source = (static / str(relative)).resolve()
    if not source.is_relative_to(static) or not source.is_file():
        raise ValueError("Loaded JavaScript has no matching repository source")
    return source


class BrowserCoverage:
    def __init__(self, page, origin, root, output):
        self.page, self.origin, self.root = page, origin, Path(root).resolve()
        self.output = Path(output)
        if not self.output.is_absolute():
            raise ValueError("SIGRIFT_E2E_JS_COVERAGE must be an absolute private path")
        self.sources, self.batches, self.errors = {}, [], {}
        self.draining = False
        self.session = page.context.new_cdp_session(page)
        self.session.on("Debugger.scriptParsed", self.parsed)
        self.session.send("Profiler.enable")
        self.session.send(
            "Profiler.startPreciseCoverage",
            {
                "callCount": True,
                "detailed": True,
            },
        )
        self.session.send("Debugger.enable")
        self.session.send("Debugger.setSkipAllPauses", {"skip": True})
        page.on("request", self.request)

    def parsed(self, event):
        phase = "source_resolution"
        try:
            source = shipped_source(event.get("url", ""), self.origin, self.root)
            if source is None:
                return
            phase = "source_event"
            script_id = event["scriptId"]
            # CDP scriptParsed carries the parsed source's SHA-256. Validate it
            # synchronously: a later getScriptSource round trip can outlive the
            # document context during navigation. Missing or different hashes
            # remain fatal; coverage keeps the exact repository-byte digest.
            actual_hash = event["hash"]
            if (
                not isinstance(actual_hash, str)
                or len(actual_hash) != 64
                or any(c not in "0123456789abcdef" for c in actual_hash)
            ):
                raise ValueError("Invalid loaded JavaScript source hash")
            phase = "source_read"
            expected_hash = hashlib.sha256(source.read_bytes()).hexdigest()
            phase = "source_mismatch"
            if actual_hash != expected_hash:
                raise ValueError("Loaded JavaScript differs from repository source")
            phase = "source_event"
            self.sources[script_id] = {
                "path": source.relative_to(self.root).as_posix(),
                "sha256": expected_hash,
            }
        except Exception:
            # Only hardcoded phase names and capped counts survive. CDP errors
            # may contain URLs, arguments or credentials; never retain them.
            self.errors[phase] = min(self.errors.get(phase, 0) + 1, 9999)

    def delta(self, event):
        result, hashes = [], {}
        for script in event.get("result", []):
            source = self.sources.get(script.get("scriptId"))
            if source is None:
                continue
            result.append(
                {
                    "scriptId": script["scriptId"],
                    "url": source["path"],
                    "functions": script["functions"],
                }
            )
            hashes[source["path"]] = source["sha256"]
        if result:
            self.batches.append(
                {
                    "result": result,
                    "timestamp": time.monotonic(),
                    "sigrift": {"complete": True, "source_sha256": hashes},
                }
            )

    def request(self, request):
        # Drain the departing document before a login/logout navigation can
        # discard its JavaScript context. Counts reset after each drain.
        if request.is_navigation_request() and request.frame == self.page.main_frame:
            self.drain()

    def drain(self):
        if self.draining:
            return
        self.draining = True
        phase = "cdp_drain"
        try:
            response = self.session.send("Profiler.takePreciseCoverage")
            phase = "coverage_payload"
            self.delta(response)
        except Exception:
            self.errors[phase] = min(self.errors.get(phase, 0) + 1, 9999)
        finally:
            self.draining = False

    def finish(self):
        self.page.remove_listener("request", self.request)
        self.drain()
        self.session.send("Profiler.stopPreciseCoverage")
        self.session.detach()
        if self.errors:
            raise AssertionError(
                "Browser coverage source/collection verification failed: "
                + json.dumps(self.errors, sort_keys=True)
            )
        if not self.batches:
            raise AssertionError("No owned JavaScript was measured in the browser test")
        self.output.mkdir(parents=True, exist_ok=True, mode=0o700)
        for batch in self.batches:
            target = self.output / ("coverage-browser-" + uuid.uuid4().hex + ".json")
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w") as stream:
                json.dump(batch, stream)
