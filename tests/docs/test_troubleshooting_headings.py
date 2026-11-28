"""Every TROUBLESHOOTING.md heading a message names exists.

The installers' and the edge script's messages say `Next: TROUBLESHOOTING.md
"Heading"` (phase2-spec 11.1, 13); a renamed or missing section would send
the operator nowhere. A quoted name may be split across string literals, so
it only has to begin a heading.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCES = [ROOT / "scripts" / "install-release.sh", ROOT / "scripts" / "quickstart.sh",
           *sorted((ROOT / "src" / "sigrift" / "bridge" / "scripts").glob("*.sh"))]


def headings() -> list[str]:
    out = []
    for line in (ROOT / "TROUBLESHOOTING.md").read_text().splitlines():
        if line.startswith("#"):
            out.append(line.lstrip("#").strip().strip('"').replace("`", ""))
    return out


def test_every_named_troubleshooting_heading_exists():
    named = set()
    for path in SOURCES:
        for m in re.finditer(r'TROUBLESHOOTING\.md,? \\?"([^"\\]+)', path.read_text()):
            named.add(m.group(1).strip())
    assert "Importing an archive" in named
    have = headings()
    missing = sorted(n for n in named if not any(h.startswith(n) for h in have))
    assert missing == [], missing
