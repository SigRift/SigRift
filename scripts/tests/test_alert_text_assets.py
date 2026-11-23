"""Pages load the encoded-text helper before its consumers, under existing CSP."""

from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_alert_text_helper_precedes_every_page_consumer():
    class Scripts(HTMLParser):
        def __init__(self):
            super().__init__()
            self.sources = []

        def handle_starttag(self, tag, attrs):
            if tag == "script":
                self.sources.append(dict(attrs).get("src", ""))

    for page, consumer in (("admin.html", "admin.js"), ("index.html", "dashboard.js")):
        parser = Scripts()
        parser.feed((ROOT / "src/sigrift/bridge/templates" / page).read_text())
        helper = [i for i, src in enumerate(parser.sources) if "html_text.js" in src]
        users = [
            i for i, src in enumerate(parser.sources) if f"path='{consumer}'" in src
        ]
        assert len(helper) == len(users) == 1
        assert helper[0] < users[0]
        if page == "index.html":
            assert helper[0] < next(
                i for i, src in enumerate(parser.sources) if "alerts.js" in src
            )
