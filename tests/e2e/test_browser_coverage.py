"""Real CDP source identity survives navigation and rejects changed script text."""

import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
from urllib.parse import urlsplit

import pytest

from .conftest import navigate
from .javascript_coverage import BrowserCoverage, shipped_source


def test_browser_coverage_verifies_departed_documents_and_original_source(
    page, browser, settings, tmp_path
):
    # Keep the normal application's automatic coverage fixture active. The
    # collector contract below uses another context/session, so its deliberate
    # source failures cannot reset or contaminate that application's counters.
    navigate(page, settings.base_url + "/login")
    root = Path(__file__).resolve().parents[2]
    relative = "src/sigrift/bridge/static/html_text.js"
    shipped = (root / relative).read_bytes()
    unicode_source = shipped + "\n// café Ελληνικά 漢字 🛰️\r\n".encode()
    state = {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            if urlsplit(self.path).path == "/static/html_text.js":
                data = state["response"]
                content_type = "text/javascript; charset=" + state["charset"]
            else:
                data = (
                    b'<script src="/static/html_text.js?private=dummy-token"></script>'
                )
                content_type = "text/html; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

    class ObservedCollector(BrowserCoverage):
        owned_entries = 0
        unverified_entries = 0

        def delta(self, event):
            for script in event.get("result", []):
                if (
                    shipped_source(script.get("url", ""), self.origin, self.root)
                    is not None
                ):
                    self.owned_entries += 1
                    if script["scriptId"] not in self.sources:
                        self.unverified_entries += 1
            super().delta(event)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    try:
        for name, expected, response, charset, rejected in [
            ("shipped", shipped, shipped, "utf-8", False),
            ("changed", shipped, shipped + b"\n// changed\n", "utf-8", True),
            ("unicode", unicode_source, unicode_source, "utf-8", False),
            ("wrong-charset", unicode_source, unicode_source, "iso-8859-1", True),
        ]:
            # These are synthetic source-verification fixtures, not extra
            # application coverage. The shipped case uses unmodified bytes.
            fixture = tmp_path / name / "source"
            source = fixture / relative
            source.parent.mkdir(parents=True)
            source.write_bytes(expected)
            output = tmp_path / name / "reports"
            state.update(response=response, charset=charset)
            context = browser.new_context()
            try:
                local = context.new_page()
                collector = ObservedCollector(local, origin, fixture, output)
                for index in range(1 if rejected else 12):
                    result = local.goto(
                        origin + f"/document-{index}", wait_until="commit"
                    )
                    assert result is not None and result.status == 200
                local.wait_for_load_state("domcontentloaded")
                assert local.evaluate('decodeHtmlEscapedText("&lt;x&gt;")') == "<x>"
                if rejected:
                    with pytest.raises(AssertionError, match="source_mismatch"):
                        collector.finish()
                    assert not output.exists()
                    continue
                collector.finish()
                assert collector.owned_entries > 0
                assert collector.unverified_entries == 0
                reports = list(output.glob("coverage-browser-*.json"))
                assert reports
                for report in reports:
                    text = report.read_text()
                    assert origin not in text and "dummy-token" not in text
                    data = json.loads(text)
                    assert data["sigrift"] == {
                        "complete": True,
                        "source_sha256": {
                            relative: hashlib.sha256(expected).hexdigest()
                        },
                    }
                    assert all(entry["url"] == relative for entry in data["result"])
            finally:
                context.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()
