"""Run all JavaScript controller and coverage-tool regressions in mandatory CI."""

from html.parser import HTMLParser
from pathlib import Path
import re
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.timeout(630)
def test_login_controller():
    node = shutil.which("node")
    assert node, "Node.js 22.12+ is required for the JavaScript regression suite"
    result = subprocess.run(
        [
            node,
            "--test",
            *sorted(
                str(path) for path in (ROOT / "tests/bridge/js").glob("*.test.cjs")
            ),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        # This is the complete suite, including real AST instrumentation,
        # subprocess/worker lifecycle and importer regressions. The 278-case
        # hosted Node 24 suite passed in 180-290s under c8; the old 120s wrapper
        # expired on both corresponding script jobs. Keep a finite budget with
        # room for runner variation, below pytest's outer guard. Every
        # discovered driver and assertion remains required.
        timeout=600,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_login_input_accepts_totp_and_full_backup_codes():
    class Inputs(HTMLParser):
        mfa = None

        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if tag == "input" and attrs.get("id") == "mfa-code":
                self.mfa = attrs

    page = Inputs()
    page.feed((ROOT / "src/sigrift/bridge/templates/login.html").read_text())
    assert page.mfa is not None
    for code in ("123456", "ABCD1234"):
        assert int(page.mfa.get("maxlength", len(code))) >= len(code)
        if "pattern" in page.mfa:
            assert re.fullmatch(page.mfa["pattern"], code)
