"""Regression tests for the installer shell scripts.

    python3 -m pytest scripts/tests -q

Needs bash, python3 and openssl. The docker compose checks skip without
`docker compose`, the git checks without git, the workflow check
without PyYAML.

The functions under test are run for real: quickstart.sh and
install-release.sh share marked blocks (tested once, plus a check that
the copies are identical). Host facts (host name, addresses) and network
calls (curl) come from stub commands put first on PATH.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import stat
import subprocess
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
QUICKSTART = SCRIPTS / "quickstart.sh"
INSTALL_RELEASE = SCRIPTS / "install-release.sh"

VALID_KEY = base64.urlsafe_b64encode(bytes(range(32))).decode()  # 44 chars
LEGACY_KEY = VALID_KEY[:-1]  # 43 chars: what secrets.token_urlsafe(32) looks like
STD_KEY = "TtQXipRlc/PC8mwGViJxxI6CC0tEgRYHZIzYBDg3Dyg="  # standard alphabet
PLUS_SLASH_KEY = "+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/s="


def have_compose() -> bool:
    if not shutil.which("docker"):
        return False
    return (
        subprocess.run(["docker", "compose", "version"], capture_output=True).returncode
        == 0
    )


needs_compose = pytest.mark.skipif(
    not have_compose(), reason="docker compose not available"
)
needs_git = pytest.mark.skipif(not shutil.which("git"), reason="git not available")


# ── helpers ─────────────────────────────────────────────────────────────


def marked_block(path: Path, begin: str, end: str) -> str:
    text = path.read_text()
    m = re.search(rf"^{re.escape(begin)}.*?^{re.escape(end)}\n", text, re.S | re.M)
    assert m, f"{begin!r} block missing in {path.name}"
    return m.group(0)


def shared_block(path: Path, name: str) -> str:
    # The space ends the name: "lifecycle" is not "lifecycle-tool".
    return marked_block(path, f"# >>> shared: {name} ", f"# <<< shared: {name}")


def function_text(path: Path, name: str) -> str:
    m = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", path.read_text(), re.S | re.M)
    assert m, f"{name}() missing in {path.name}"
    return m.group(0)


@pytest.fixture
def stubs(tmp_path):
    """A bin dir first on PATH with a fake `hostname` and `ip`.

    FAKE_SHORT / FAKE_FQDN / FAKE_ADDRS (hostname -I) and FAKE_IP_OUTPUT
    (a file with `ip -o addr show` output) control what they print.
    """
    bin_dir = tmp_path / "stub-bin"
    bin_dir.mkdir()

    def add(name: str, body: str) -> None:
        p = bin_dir / name
        p.write_text(body)
        p.chmod(0o755)

    add(
        "hostname",
        textwrap.dedent("""\
            #!/bin/sh
            case "$1" in
                -f) printf '%s\\n' "${FAKE_FQDN-sensor.lab.example}" ;;
                -I) printf '%s\\n' "${FAKE_ADDRS-}" ;;
                *)  printf '%s\\n' "${FAKE_SHORT-sensor}" ;;
            esac
            """),
    )
    add("ip", '#!/bin/sh\n[ -n "$FAKE_IP_OUTPUT" ] && cat "$FAKE_IP_OUTPUT"\nexit 0\n')

    class Stubs:
        dir = bin_dir
        path = f"{bin_dir}:{os.environ['PATH']}"

        @staticmethod
        def add_command(name: str, body: str) -> None:
            add(name, body)

    return Stubs


BASH = shutil.which("bash") or "/bin/bash"


def bash(script: str, *, env: dict | None = None, cwd: Path | None = None):
    """Run *script* with bash in a minimal environment."""
    full = {
        "PATH": os.environ["PATH"],
        "LC_ALL": "C",
        "HOME": os.environ.get("HOME", "/tmp"),
    }
    full.update(env or {})
    return subprocess.run(
        [BASH, "-c", script], capture_output=True, text=True, env=full, cwd=cwd
    )


def source_blocks(tmp_path: Path, *blocks: str) -> Path:
    lib = tmp_path / "blocks.sh"
    lib.write_text("".join(blocks))
    return lib


# ── the shared blocks really are shared ─────────────────────────────────


def test_mfa_key_block_identical_in_both_installers():
    assert shared_block(QUICKSTART, "mfa-key") == shared_block(
        INSTALL_RELEASE, "mfa-key"
    )


def test_tls_cert_block_identical_in_both_installers():
    assert shared_block(QUICKSTART, "tls-cert") == shared_block(
        INSTALL_RELEASE, "tls-cert"
    )


def test_warn_missing_audit_key_identical_in_both_installers():
    assert function_text(QUICKSTART, "warn_missing_audit_key") == function_text(
        INSTALL_RELEASE, "warn_missing_audit_key"
    )


# ── repair_mfa_key (R15, R18) ───────────────────────────────────────────


def run_repair(tmp_path: Path, content: str, *, env: dict | None = None):
    lib = source_blocks(tmp_path, shared_block(QUICKSTART, "mfa-key"))
    env_file = tmp_path / ".env"
    env_file.write_bytes(content.encode())
    env_file.chmod(0o600)
    r = bash(f'source "{lib}"; repair_mfa_key "{env_file}"', env=env, cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    backups = sorted(tmp_path.glob(".env.bak.*"))
    return env_file.read_bytes().decode(), r, backups


def effective_key(text: str) -> str:
    """BRIDGE_MFA_KEY as docker compose would read it (simple cases)."""
    value = None
    for line in text.splitlines():
        m = re.match(r"\s*(?:export\s+)?BRIDGE_MFA_KEY\s*[=:]\s*(.*)$", line)
        if m:
            v = m.group(1)
            if v[:1] in "'\"":
                v = v[1 : v.index(v[0], 1)]
            else:
                v = v.split(" #", 1)[0].rstrip()
            value = v
    assert value is not None
    return value


def is_valid(key: str) -> bool:
    key = key.strip()
    if not re.fullmatch(r"[A-Za-z0-9_+/-]{43}=", key):
        return False
    return (
        len(base64.b64decode(key.replace("-", "+").replace("_", "/"), validate=True))
        == 32
    )


@pytest.mark.parametrize(
    "content",
    [
        f"BRIDGE_MFA_KEY={VALID_KEY}\n",
        f"BRIDGE_MFA_KEY={STD_KEY}\n",
        f"BRIDGE_MFA_KEY={PLUS_SLASH_KEY}\n",
        # R15: the value compose uses is valid; the whole rest of the line is not
        f"BRIDGE_MFA_KEY={VALID_KEY} # rotated 2026\n",
        # R15: `export` prefix — must not append a second assignment
        f"export BRIDGE_MFA_KEY={VALID_KEY}\n",
        f'BRIDGE_MFA_KEY="{VALID_KEY}"\n',
        f"BRIDGE_MFA_KEY='{VALID_KEY}'  # quoted\n",
        f"BRIDGE_MFA_KEY : {VALID_KEY}\n",
        # last assignment wins: the earlier junk line is not the one compose uses
        f"BRIDGE_MFA_KEY=junk\nOTHER=1\nBRIDGE_MFA_KEY={VALID_KEY}\n",
    ],
)
def test_repair_leaves_a_valid_key_alone(tmp_path, content):
    after, r, backups = run_repair(tmp_path, content)
    assert after == content
    assert backups == []
    assert r.stdout == ""


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (f"BRIDGE_MFA_KEY={LEGACY_KEY}\n", f"BRIDGE_MFA_KEY={LEGACY_KEY}=\n"),
        (
            f"A=1\nexport BRIDGE_MFA_KEY={LEGACY_KEY}  # from token_urlsafe\nB=2\n",
            f"A=1\nexport BRIDGE_MFA_KEY={LEGACY_KEY}=  # from token_urlsafe\nB=2\n",
        ),
        (f'BRIDGE_MFA_KEY="{LEGACY_KEY}"\n', f'BRIDGE_MFA_KEY="{LEGACY_KEY}="\n'),
        (
            f"BRIDGE_MFA_KEY={LEGACY_KEY}\r\nX=1\r\n",
            f"BRIDGE_MFA_KEY={LEGACY_KEY}=\r\nX=1\r\n",
        ),
        # only the effective (last) assignment is rewritten
        (
            f"BRIDGE_MFA_KEY={VALID_KEY}\nBRIDGE_MFA_KEY={LEGACY_KEY}\n",
            f"BRIDGE_MFA_KEY={VALID_KEY}\nBRIDGE_MFA_KEY={LEGACY_KEY}=\n",
        ),
    ],
)
def test_repair_pads_a_43_char_key_losslessly(tmp_path, content, expected):
    """R18: the old key bytes are kept (append '='), never replaced."""
    after, r, backups = run_repair(tmp_path, content)
    assert after == expected
    assert "appended '='" in r.stdout
    assert base64.urlsafe_b64decode(effective_key(after)) == bytes(range(32))
    assert len(backups) == 1
    assert backups[0].read_bytes().decode() == content
    assert stat.S_IMODE(backups[0].stat().st_mode) == 0o600
    assert backups[0].name.endswith("~")  # covered by .gitignore's *~


def test_repair_rewrites_an_old_bridge_key_to_the_same_bytes(tmp_path):
    # The old bridge's Fernet(key) used a lenient decoder that skipped the
    # space, so it encrypted with these bytes; keep them.
    spaced = VALID_KEY[:20] + " " + VALID_KEY[20:]
    after, r, _ = run_repair(tmp_path, f'BRIDGE_MFA_KEY="{spaced}"\n')
    new = effective_key(after)
    assert is_valid(new)
    assert base64.urlsafe_b64decode(new) == bytes(range(32))
    assert "same 32 bytes" in r.stdout


@pytest.mark.parametrize(
    "content",
    [
        "",
        "OTHER=1",
        "OTHER=1\n",
        "BRIDGE_MFA_KEY=\n",
        'BRIDGE_MFA_KEY=""\n',
        "BRIDGE_MFA_KEY=changeme\n",
    ],
)
def test_repair_sets_a_new_key_when_nothing_was_encrypted(tmp_path, content):
    after, r, backups = run_repair(tmp_path, content)
    assert is_valid(effective_key(after))
    assert after.count("BRIDGE_MFA_KEY") == max(1, content.count("BRIDGE_MFA_KEY"))
    if content.startswith("OTHER=1"):
        assert after.startswith("OTHER=1\nBRIDGE_MFA_KEY=")
    assert len(backups) == 1
    assert "==>" in r.stdout


@pytest.mark.parametrize(
    "content",
    [
        f'BRIDGE_MFA_KEY="{VALID_KEY[:20]}\n{VALID_KEY[20:]}"\n',  # spans lines
        f"BRIDGE_MFA_KEY=$OTHER{LEGACY_KEY}\n",  # compose would expand it
        f'X="unterminated\nBRIDGE_MFA_KEY={LEGACY_KEY}\n',  # compose cannot read the file
    ],
)
def test_repair_only_warns_when_unsure(tmp_path, content):
    after, r, backups = run_repair(tmp_path, content)
    assert after == content
    assert backups == []
    assert "WARNING" in r.stderr and "left as it is" in r.stderr


@pytest.mark.parametrize(
    ("content", "warns"),
    [
        ("BRIDGE_AUDIT_KEY=abc123\n", False),
        ("export BRIDGE_AUDIT_KEY='abc123'\n", False),
        ("BRIDGE_AUDIT_KEY=\n", True),
        ("BRIDGE_AUDIT_KEY= # todo\n", True),
        ("OTHER=1\n", True),
    ],
)
def test_existing_env_without_audit_key_is_flagged(tmp_path, content, warns):
    """C4: every install needs BRIDGE_AUDIT_KEY; old .env files may lack it."""
    env_file = tmp_path / ".env"
    env_file.write_text(content)
    r = bash(
        function_text(QUICKSTART, "warn_missing_audit_key")
        + f'warn_missing_audit_key "{env_file}"'
    )
    assert ("has no BRIDGE_AUDIT_KEY" in r.stderr) is warns
    assert env_file.read_text() == content  # never added automatically


def test_new_env_files_always_get_an_audit_key():
    for script in (QUICKSTART, INSTALL_RELEASE):
        text = script.read_text()
        assert "AUDIT_KEY=$(randstr)" in text
        assert re.search(r"^BRIDGE_AUDIT_KEY=\$\{AUDIT_KEY\}$", text, re.M), script.name


def test_repair_warns_about_a_shell_override(tmp_path):
    _, r, _ = run_repair(
        tmp_path, f"BRIDGE_MFA_KEY={VALID_KEY}\n", env={"BRIDGE_MFA_KEY": "x"}
    )
    assert "also set in this shell's environment" in r.stderr


@needs_compose
@pytest.mark.parametrize(
    "content",
    [
        f"export BRIDGE_MFA_KEY={LEGACY_KEY}  # c\n",
        f"BRIDGE_MFA_KEY={VALID_KEY} # rotated\n",
        f"BRIDGE_MFA_KEY='{LEGACY_KEY}'\n",
        "BRIDGE_MFA_KEY=\n",
    ],
)
def test_compose_reads_the_repaired_key(tmp_path, content):
    after, _, _ = run_repair(tmp_path, content)
    (tmp_path / "compose.yml").write_text(
        "services:\n  t:\n    image: alpine\n    environment:\n"
        "      - BRIDGE_MFA_KEY=${BRIDGE_MFA_KEY:-}\n"
    )
    out = subprocess.run(
        ["docker", "compose", "-f", "compose.yml", "config", "--format", "json"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
        env={"PATH": os.environ["PATH"], "HOME": str(tmp_path)},
    ).stdout
    value = json.loads(out)["services"]["t"]["environment"]["BRIDGE_MFA_KEY"]
    assert is_valid(value)
    assert value == effective_key(after).strip()


# ── self-signed cert SANs (R19, contract C5) ────────────────────────────

IP_OUTPUT = textwrap.dedent("""\
    1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
    1: lo    inet6 ::1/128 scope host noprefixroute \\       valid_lft forever preferred_lft forever
    2: eth0    inet 192.168.1.50/24 brd 192.168.1.255 scope global dynamic eth0\\       valid_lft 86000sec
    2: eth0    inet6 2001:db8::50/64 scope global dynamic mngtmpaddr \\       valid_lft 86000sec
    2: eth0    inet6 2001:db8::dead:beef/64 scope global temporary dynamic \\       valid_lft 600sec
    2: eth0    inet6 fe80::1/64 scope link \\       valid_lft forever preferred_lft forever
    3: wlan0    inet 10.20.30.40/24 scope global wlan0\\       valid_lft forever
    4: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\\       valid_lft forever
    5: br-0123abcd    inet 172.18.0.1/16 scope global br-0123abcd\\       valid_lft forever
    6: veth12ab@if5    inet6 fe80::2/64 scope link \\       valid_lft forever
    7: tailscale0    inet 100.64.0.7/32 scope global tailscale0\\       valid_lft forever
    """)


def tls_env(stubs, tmp_path, **extra):
    ip_file = tmp_path / "ip-output"
    ip_file.write_text(IP_OUTPUT)
    env = {"PATH": stubs.path, "FAKE_IP_OUTPUT": str(ip_file)}
    env.update(extra)
    return env


def test_host_addresses_skip_loopback_link_local_temporary_and_docker(stubs, tmp_path):
    lib = source_blocks(tmp_path, shared_block(INSTALL_RELEASE, "tls-cert"))
    r = bash(f'source "{lib}"; tls_host_addrs', env=tls_env(stubs, tmp_path))
    assert r.stdout.split() == [
        "192.168.1.50",
        "2001:db8::50",
        "10.20.30.40",
        "100.64.0.7",
    ]


def test_host_addresses_fall_back_to_hostname_I(stubs, tmp_path):
    (stubs.dir / "ip").unlink()
    lib = source_blocks(tmp_path, shared_block(INSTALL_RELEASE, "tls-cert"))
    # Only the stub dir on PATH, so no real `ip` can be found.
    r = bash(
        f'source "{lib}"; tls_host_addrs',
        env={"PATH": str(stubs.dir), "FAKE_ADDRS": "192.168.7.7 fd00::7 "},
    )
    assert r.stdout.split() == ["192.168.7.7", "fd00::7"]


def required_sans(stubs, tmp_path, extra="", **env):
    lib = source_blocks(tmp_path, shared_block(INSTALL_RELEASE, "tls-cert"))
    return bash(
        f'source "{lib}"; tls_san_tool required "$EXTRA" "$(tls_host_names)" "$(tls_host_addrs)"',
        env=tls_env(stubs, tmp_path, EXTRA=extra, **env),
    )


def test_required_sans(stubs, tmp_path):
    r = required_sans(
        stubs,
        tmp_path,
        " sigrift.example.org, 203.0.113.7 ,2001:db8::7,*.lab.example,DNS:alias.lan",
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip().split(",") == [
        "DNS:localhost",
        "DNS:gateway",
        "DNS:bridge",
        "IP:127.0.0.1",
        "IP:::1",
        "DNS:sensor",
        "DNS:sensor.lab.example",
        "IP:192.168.1.50",
        "IP:2001:db8::50",
        "IP:10.20.30.40",
        "IP:100.64.0.7",
        "DNS:sigrift.example.org",
        "IP:203.0.113.7",
        "IP:2001:db8::7",
        "DNS:*.lab.example",
        "DNS:alias.lan",
    ]


def test_required_sans_rejects_bad_operator_entries(stubs, tmp_path):
    r = required_sans(stubs, tmp_path, "ok.example,bad name,DNS:also/bad,IP:not-an-ip")
    assert r.returncode != 0
    assert "SIGRIFT_TLS_SANS" in r.stderr
    for bad in ("bad name", "DNS:also/bad", "IP:not-an-ip"):
        assert bad in r.stderr


def test_required_sans_skip_an_invalid_host_name(stubs, tmp_path):
    r = required_sans(stubs, tmp_path, FAKE_SHORT="bad_name;x", FAKE_FQDN="")
    assert r.returncode == 0
    assert "bad_name" not in r.stdout
    assert "not a valid DNS name" in r.stderr


def cert_sans(cert: Path) -> set[str]:
    out = subprocess.run(
        ["openssl", "x509", "-in", str(cert), "-noout", "-text"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    line = out.split("X509v3 Subject Alternative Name:")[1].splitlines()[1]
    return {p.strip().replace("IP Address:", "IP:") for p in line.split(",")}


def ensure_cert(stubs, tmp_path, extra="", **env):
    lib = source_blocks(tmp_path, shared_block(INSTALL_RELEASE, "tls-cert"))
    (tmp_path / "tls").mkdir(exist_ok=True)
    r = bash(
        f'source "{lib}"; tls_ensure_cert tls/cert.pem tls/key.pem localhost "$EXTRA"; '
        'echo "CHANGED=$TLS_CERT_CHANGED"',
        env=tls_env(stubs, tmp_path, EXTRA=extra, **env),
        cwd=tmp_path,
    )
    return r


def openssl_cert(
    tmp_path: Path,
    subj: str,
    san: str,
    *,
    ca: tuple[Path, Path] | None = None,
    days: int = 30,
):
    """A cert like the old installers made, or (with *ca*) a CA-issued one."""
    tls = tmp_path / "tls"
    tls.mkdir(exist_ok=True)
    cert, key = tls / "cert.pem", tls / "key.pem"
    if ca is None:
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                str(days),
                "-subj",
                subj,
                "-addext",
                f"subjectAltName={san}",
                "-keyout",
                str(key),
                "-out",
                str(cert),
            ],
            check=True,
            capture_output=True,
        )
    else:
        csr = tmp_path / "leaf.csr"
        subprocess.run(
            [
                "openssl",
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                subj,
                "-keyout",
                str(key),
                "-out",
                str(csr),
            ],
            check=True,
            capture_output=True,
        )
        ext = tmp_path / "ext.cnf"
        ext.write_text(f"subjectAltName={san}\n")
        subprocess.run(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                str(csr),
                "-CA",
                str(ca[0]),
                "-CAkey",
                str(ca[1]),
                "-CAcreateserial",
                "-days",
                str(days),
                "-extfile",
                str(ext),
                "-out",
                str(cert),
            ],
            check=True,
            capture_output=True,
        )
    return cert


def make_ca(tmp_path: Path, name: str = "ca"):
    crt, key = tmp_path / f"{name}.crt", tmp_path / f"{name}.key"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "30",
            "-subj",
            f"/CN=Test {name}",
            "-keyout",
            str(key),
            "-out",
            str(crt),
        ],
        check=True,
        capture_output=True,
    )
    return crt, key


def test_cert_is_created_with_every_required_name(stubs, tmp_path):
    r = ensure_cert(stubs, tmp_path, "sigrift.example.org")
    assert r.returncode == 0, r.stderr
    assert "CHANGED=1" in r.stdout
    sans = cert_sans(tmp_path / "tls" / "cert.pem")
    for want in (
        "DNS:localhost",
        "DNS:gateway",
        "DNS:bridge",
        "IP:127.0.0.1",
        "DNS:sensor",
        "DNS:sensor.lab.example",
        "IP:192.168.1.50",
        "IP:10.20.30.40",
        "DNS:sigrift.example.org",
    ):
        assert want in sans
    assert "IP:0:0:0:0:0:0:0:1" in sans or "IP:::1" in sans
    assert "IP:172.17.0.1" not in sans
    key = tmp_path / "tls" / "key.pem"
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert not list((tmp_path / "tls").glob("*.new"))


def test_cert_is_kept_when_nothing_is_missing(stubs, tmp_path):
    assert "CHANGED=1" in ensure_cert(stubs, tmp_path, "sigrift.example.org").stdout
    before = (tmp_path / "tls" / "cert.pem").read_bytes()
    # The operator name need not be repeated: it is not dropped either.
    r = ensure_cert(stubs, tmp_path)
    assert r.returncode == 0, r.stderr
    assert "CHANGED=0" in r.stdout
    assert (tmp_path / "tls" / "cert.pem").read_bytes() == before


def test_cert_is_regenerated_when_a_name_is_missing_keeping_old_names(stubs, tmp_path):
    ensure_cert(stubs, tmp_path, "sigrift.example.org")
    r = ensure_cert(stubs, tmp_path, "203.0.113.9", FAKE_SHORT="sensor2")
    assert r.returncode == 0, r.stderr
    assert "CHANGED=1" in r.stdout and "lacks subjectAltName" in r.stdout
    sans = cert_sans(tmp_path / "tls" / "cert.pem")
    assert {
        "DNS:sensor2",
        "IP:203.0.113.9",
        "DNS:sensor",
        "DNS:sigrift.example.org",
    } <= sans


@pytest.mark.parametrize(
    ("subj", "san"),
    [
        ("/CN=localhost", "DNS:localhost,IP:127.0.0.1"),  # old install-release.sh
        (
            "/CN=localhost",
            "DNS:localhost,DNS:gateway,DNS:bridge,IP:127.0.0.1",
        ),  # old quickstart
    ],
)
def test_old_installer_certs_are_upgraded(stubs, tmp_path, subj, san):
    openssl_cert(tmp_path, subj, san)
    r = ensure_cert(stubs, tmp_path)
    assert "CHANGED=1" in r.stdout
    assert {"IP:192.168.1.50", "DNS:sensor", "DNS:gateway"} <= cert_sans(
        tmp_path / "tls" / "cert.pem"
    )


def test_an_operator_supplied_cert_is_never_replaced(stubs, tmp_path):
    ca = make_ca(tmp_path)
    cert = openssl_cert(
        tmp_path, "/CN=sigrift.example.org", "DNS:sigrift.example.org", ca=ca
    )
    before = cert.read_bytes()
    r = ensure_cert(stubs, tmp_path)
    assert r.returncode == 0
    assert "CHANGED=0" in r.stdout
    assert "is not self-signed" in r.stderr and "DNS:gateway" in r.stderr
    assert cert.read_bytes() == before


def test_bad_operator_sans_leave_the_cert_alone(stubs, tmp_path):
    ensure_cert(stubs, tmp_path)
    before = (tmp_path / "tls" / "cert.pem").read_bytes()
    r = ensure_cert(stubs, tmp_path, "not a name")
    assert r.returncode == 0  # the function returned 1; `echo` ran after it
    assert "CHANGED=0" in r.stdout and "SIGRIFT_TLS_SANS" in r.stderr
    assert (tmp_path / "tls" / "cert.pem").read_bytes() == before


# ── install-release.sh compose handling (R22) ───────────────────────────


def install_release_compose(tmp_path: Path) -> Path:
    text = INSTALL_RELEASE.read_text()
    body = re.search(
        r"cat > docker-compose\.yml <<EOF\n(.*?)\nEOF\n", text, re.S
    ).group(1)
    r = bash(f"VERSION=v9.9.9 OWNER=sigrift PORT=8444\ncat <<EOF\n{body}\nEOF\n")
    assert r.returncode == 0, r.stderr
    out = tmp_path / "docker-compose.yml"
    out.write_text(r.stdout)
    return out


def check_gateway_env(tmp_path: Path, compose: Path):
    fn = function_text(INSTALL_RELEASE, "check_compose_gateway_env")
    return bash(fn + f'check_compose_gateway_env "{compose}"')


def test_generated_compose_passes_no_master_key_to_the_gateway(tmp_path):
    compose = install_release_compose(tmp_path)
    r = check_gateway_env(tmp_path, compose)
    assert r.returncode == 0 and r.stderr == ""


def test_old_compose_files_get_warnings(tmp_path):
    compose = install_release_compose(tmp_path)
    text = compose.read_text()
    old = text.replace(
        "      - BRIDGE_AUDIT_KEY=${BRIDGE_AUDIT_KEY:-}\n      - BRIDGE_MFA_KEY=${BRIDGE_MFA_KEY:-}\n      - UC_TLS_CERT",
        "      - BRIDGE_MASTER_KEY=${BRIDGE_MASTER_KEY:-}\n      - UC_TLS_CERT",
    )
    assert old != text
    compose.write_text(old)
    r = check_gateway_env(tmp_path, compose)
    assert "- BRIDGE_AUDIT_KEY=${BRIDGE_AUDIT_KEY:-}" in r.stderr
    assert "- BRIDGE_MFA_KEY=${BRIDGE_MFA_KEY:-}" in r.stderr
    assert "passes BRIDGE_MASTER_KEY" in r.stderr


def compose_json(files: list[Path], project_dir: Path) -> dict:
    cmd = ["docker", "compose", "--project-directory", str(project_dir)]
    for f in files:
        cmd += ["-f", str(f)]
    env = {
        "PATH": os.environ["PATH"],
        "HOME": str(project_dir),
        "BRIDGE_MASTER_KEY": "master-123456",
        "BRIDGE_AUDIT_KEY": "audit-123456",
        "BRIDGE_MFA_KEY": VALID_KEY,
        "UC_PROXY_SECRET": "proxy-123456",
    }
    subprocess.run(cmd + ["config", "-q"], check=True, capture_output=True, env=env)
    out = subprocess.run(
        cmd + ["config", "--format", "json"],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    ).stdout
    return json.loads(out)


def quickstart_override(tmp_path: Path) -> Path:
    text = QUICKSTART.read_text()
    body = re.search(
        r"cat > docker-compose\.override\.yml <<EOF\n(.*?)\nEOF\n", text, re.S
    ).group(1)
    r = bash(
        f"OV_HEADER='# Generated by scripts/quickstart.sh'\ncat <<EOF\n{body}\nEOF\n"
    )
    out = tmp_path / "docker-compose.override.yml"
    out.write_text(r.stdout)
    return out


@needs_compose
@pytest.mark.parametrize(
    "overlays",
    [
        [],
        ["docker-compose.pki.yml"],
        ["quickstart-override"],
    ],
)
def test_compose_files_keep_the_master_key_off_the_gateway(tmp_path, overlays):
    files = [ROOT / "docker-compose.yml"]
    for o in overlays:
        files.append(
            quickstart_override(tmp_path) if o == "quickstart-override" else ROOT / o
        )
    cfg = compose_json(files, ROOT)
    gw = cfg["services"]["gateway"]["environment"]
    assert "BRIDGE_MASTER_KEY" not in gw
    assert (
        gw["BRIDGE_AUDIT_KEY"] == "audit-123456" and gw["BRIDGE_MFA_KEY"] == VALID_KEY
    )
    assert (
        cfg["services"]["bridge"]["environment"]["BRIDGE_MASTER_KEY"] == "master-123456"
    )


@needs_compose
def test_install_release_compose_is_valid_and_keeps_the_master_key_off_the_gateway(
    tmp_path,
):
    compose = install_release_compose(tmp_path)
    cfg = compose_json([compose], tmp_path)
    assert "BRIDGE_MASTER_KEY" not in cfg["services"]["gateway"]["environment"]


# ── docs and workflows ──────────────────────────────────────────────────


def test_cert_swap_recreate_commands_include_wifi_scan():
    """R23: wifi-scan verifies TLS too and must pick up a new cert."""
    for doc in ROOT.glob("*.md"):
        for n, line in enumerate(doc.read_text().splitlines(), 1):
            if "--force-recreate" in line and "bt-scan" in line:
                assert "wifi-scan" in line, f"{doc.name}:{n}"


def test_workflows_parse():
    yaml = pytest.importorskip("yaml")
    for wf in (ROOT / ".github" / "workflows").glob("*.yml"):
        assert isinstance(yaml.safe_load(wf.read_text()), dict), wf.name


# ── round 3: shared blocks, certificate renewal, key permissions ────────


@pytest.mark.parametrize(
    "name",
    [
        "tls-key-perms",
        "exposure",
        "volumes",
        "lifecycle-tool",
        "lifecycle-engine",
        "identity",
        "preflight",
        "lifecycle",
        "state-tool",
        "state-engine",
        "restore",
        "archive-engine",
        "move",
    ],
)
def test_new_shared_blocks_identical_in_both_installers(name):
    assert shared_block(QUICKSTART, name) == shared_block(INSTALL_RELEASE, name)


def test_lifecycle_blocks_follow_the_backend_subnet_block_in_order():
    for path in (QUICKSTART, INSTALL_RELEASE):
        text = path.read_text()
        starts = [
            text.index(f"# >>> shared: {n} ")
            for n in (
                "backend-subnet",
                "lifecycle-tool",
                "lifecycle-engine",
                "identity",
                "preflight",
                "lifecycle",
                "state-tool",
                "state-engine",
                "restore",
                "archive-engine",
                "move",
            )
        ]
        assert starts == sorted(starts), path.name


def test_lifecycle_state_is_ignored_by_git_and_docker(tmp_path):
    """Restore points hold .env and TLS key copies: never commit or build them."""
    ignore = (ROOT / ".gitignore").read_text().splitlines()
    assert ".sigrift/" in ignore and ".sigrift-state" in ignore
    docker = (ROOT / ".dockerignore").read_text().splitlines()
    assert "**/.sigrift/" in docker and "**/.sigrift-state" in docker
    if shutil.which("git") and (ROOT / ".git").exists():
        for path in (".sigrift/journal.json", ".sigrift-state"):
            r = subprocess.run(["git", "check-ignore", "-q", path], cwd=ROOT)
            assert r.returncode == 0, path


def test_tls_cert_block_calls_the_snapshot_hook_before_the_swap(stubs, tmp_path):
    """A caller that keeps restore points copies the old pair first."""
    assert "CHANGED=1" in ensure_cert(stubs, tmp_path).stdout
    cert, key = tmp_path / "tls" / "cert.pem", tmp_path / "tls" / "key.pem"
    (tmp_path / "tls" / ".recreate-pending").unlink()  # as after a recreate
    old = (cert.read_bytes(), key.read_bytes())
    lib = source_blocks(tmp_path, shared_block(INSTALL_RELEASE, "tls-cert"))
    # The hook sees the old files (and no recreate marker yet), and its
    # failure does not stop the renewal.
    hook = (
        'tls_before_swap() { cp "$1" saved-cert; cp "$2" saved-key; '
        '[ ! -e tls/.recreate-pending ] && echo NO-MARKER; return 7; }; '
    )
    r = bash(
        f'source "{lib}"; {hook}TLS_RENEW_DAYS=900; '
        'tls_ensure_cert tls/cert.pem tls/key.pem localhost ""; '
        'echo "CHANGED=$TLS_CERT_CHANGED"',
        env=tls_env(stubs, tmp_path),
        cwd=tmp_path,
    )
    assert r.returncode == 0, r.stderr
    assert "NO-MARKER" in r.stdout and "CHANGED=1" in r.stdout
    assert ((tmp_path / "saved-cert").read_bytes(), (tmp_path / "saved-key").read_bytes()) == old
    assert cert.read_bytes() != old[0]
    block = shared_block(INSTALL_RELEASE, "tls-cert")
    assert block.index("tls_before_swap \"$cert\" \"$key\" || true") < block.index(
        ': > "$(tls_recreate_marker "$cert")"'
    )
    # Without a hook (quickstart keeps no restore points yet) the renewal
    # runs as before.
    r = bash(
        f'source "{lib}"; TLS_RENEW_DAYS=900; '
        'tls_ensure_cert tls/cert.pem tls/key.pem localhost ""; '
        'echo "CHANGED=$TLS_CERT_CHANGED"',
        env=tls_env(stubs, tmp_path),
        cwd=tmp_path,
    )
    assert r.returncode == 0 and "CHANGED=1" in r.stdout, r.stderr


def full_sans_cert(stubs, tmp_path, days: int) -> Path:
    """A self-signed cert with every required name, valid for *days* days."""
    assert "CHANGED=1" in ensure_cert(stubs, tmp_path).stdout
    cert = tmp_path / "tls" / "cert.pem"
    sans = ",".join(sorted(cert_sans(cert))).replace("IP:", "IP:")
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            str(days),
            "-subj",
            "/CN=localhost",
            "-addext",
            f"subjectAltName={sans}",
            "-keyout",
            str(tmp_path / "tls" / "key.pem"),
            "-out",
            str(cert),
        ],
        check=True,
        capture_output=True,
    )
    return cert


def valid_for_days(cert: Path, days: int) -> bool:
    return (
        subprocess.run(
            [
                "openssl",
                "x509",
                "-in",
                str(cert),
                "-noout",
                "-checkend",
                str(days * 86400),
            ],
            capture_output=True,
        ).returncode
        == 0
    )


def test_an_expiring_self_signed_cert_is_renewed_with_the_same_names(stubs, tmp_path):
    cert = full_sans_cert(stubs, tmp_path, days=10)
    names = cert_sans(cert)
    r = ensure_cert(stubs, tmp_path)
    assert r.returncode == 0, r.stderr
    assert "CHANGED=1" in r.stdout and "expires within 30 days" in r.stdout
    assert cert_sans(cert) == names
    assert valid_for_days(cert, 800)  # new certs: 825 days


def test_an_expired_self_signed_cert_is_renewed(stubs, tmp_path):
    cert = full_sans_cert(stubs, tmp_path, days=1)
    # openssl cannot backdate here; -checkend past the end covers "expired".
    assert not valid_for_days(cert, 2)
    r = ensure_cert(stubs, tmp_path)
    assert "CHANGED=1" in r.stdout
    assert valid_for_days(cert, 800)


def test_a_cert_with_more_than_30_days_left_is_kept(stubs, tmp_path):
    cert = full_sans_cert(stubs, tmp_path, days=60)
    before = cert.read_bytes()
    r = ensure_cert(stubs, tmp_path)
    assert "CHANGED=0" in r.stdout
    assert cert.read_bytes() == before


def test_an_expiring_operator_cert_is_kept_with_a_warning(stubs, tmp_path):
    ca = make_ca(tmp_path)
    assert "CHANGED=1" in ensure_cert(stubs, tmp_path).stdout
    sans = ",".join(sorted(cert_sans(tmp_path / "tls" / "cert.pem")))
    # Stay well inside the warning window; exactly 30 days can still be
    # outside it when certificate creation and checking share one second.
    cert = openssl_cert(tmp_path, "/CN=sigrift.example.org", sans, ca=ca, days=1)
    before = cert.read_bytes()
    r = ensure_cert(stubs, tmp_path)
    assert "CHANGED=0" in r.stdout
    assert "expires within 30 days" in r.stderr and "lacks" not in r.stderr
    assert cert.read_bytes() == before


def key_perms(tmp_path: Path, stubs, *, env: dict | None = None):
    lib = source_blocks(tmp_path, shared_block(QUICKSTART, "tls-key-perms"))
    tls = tmp_path / "tls"
    tls.mkdir(exist_ok=True)
    (tls / "cert.pem").write_text("cert")
    key = tls / "key.pem"
    key.write_text("key")
    key.chmod(0o600)
    full = {"PATH": stubs.path}
    full.update(env or {})
    r = bash(
        f'source "{lib}"; secure_tls_files tls/cert.pem tls/key.pem; echo "rc=$?"',
        env=full,
        cwd=tmp_path,
    )
    st = key.stat()
    return r, st.st_gid, stat.S_IMODE(st.st_mode)


@pytest.mark.skipif(os.geteuid() != 0, reason="needs root to chown to gid 1500")
def test_tls_key_gets_group_1500_and_0640_as_root(stubs, tmp_path):
    r, gid, mode = key_perms(tmp_path, stubs)
    assert r.returncode == 0 and "WARNING" not in r.stderr, r.stderr
    assert (gid, mode) == (1500, 0o640)
    assert stat.S_IMODE((tmp_path / "tls" / "cert.pem").stat().st_mode) == 0o644


def non_root_stubs(stubs, docker_body: str) -> None:
    stubs.add_command(
        "id", '#!/bin/sh\n[ "$1" = "-u" ] && echo 1000 && exit 0\nexit 1\n'
    )
    stubs.add_command("chgrp", "#!/bin/sh\nexit 1\n")
    stubs.add_command("docker", docker_body)


def test_tls_key_uses_a_pinned_throwaway_container_when_not_root(stubs, tmp_path):
    log = tmp_path / "docker.log"
    non_root_stubs(stubs, f'#!/bin/sh\nprintf "%s\\n" "$*" >> "{log}"\nexit 0\n')
    r, _gid, mode = key_perms(tmp_path, stubs)
    call = log.read_text()
    assert "run --rm --network none -v" in call
    assert f"{tmp_path / 'tls'}:/tls" in call
    assert re.search(r"alpine:[0-9.]+@sha256:[0-9a-f]{64}", call)
    assert call.rstrip().endswith("key.pem")
    # The stub changed nothing, so the key is left readable, loudly.
    assert mode == 0o644 and "WARNING" in r.stderr and "0640" in r.stderr


@pytest.mark.skipif(os.geteuid() != 0, reason="the stub container chowns as root")
def test_tls_key_container_fallback_restricts_the_key(stubs, tmp_path):
    # A stand-in for `docker run ... sh -c '<chown/chmod>' sh key.pem` that
    # runs the same shell snippet against the bind-mounted directory.
    docker = textwrap.dedent("""\
        #!/bin/bash
        while [ "$1" != "-v" ]; do shift; done
        dir=${2%%:/tls}
        shift 3  # -v, mount, image
        snippet=$3
        sh -c "${snippet//\\/tls/$dir}" sh "$5"
        """)
    non_root_stubs(stubs, docker)
    r, gid, mode = key_perms(tmp_path, stubs)
    assert "WARNING" not in r.stderr, r.stderr
    assert (gid, mode) == (1500, 0o640)


def test_installers_no_longer_make_the_tls_key_world_readable():
    for script in (QUICKSTART, INSTALL_RELEASE):
        text = script.read_text()
        assert "chmod 0644 tls/cert.pem tls/key.pem" not in text, script.name
        assert "secure_tls_files tls/cert.pem tls/key.pem" in text, script.name


# ── SIGRIFT_BIND (I1) ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("value", "ok"),
    [
        ("127.0.0.1", True),
        ("0.0.0.0", True),
        ("192.168.1.5", True),
        ("[::1]", True),
        ("[fd00::5]", True),
        # docker publishes an IPv6 host address on IPv6 only: [::] would
        # cut off IPv4 clients and the scanners on https://127.0.0.1.
        ("[::]", False),
        ("[::0]", False),
        ("[0:0:0:0:0:0:0:0]", False),
        ("::", False),
        ("[127.0.0.1]", False),
        ("localhost", False),
        ("0.0.0.0:8444", False),
        ("1.2.3.4\nBRIDGE_ENV=development", False),
        ("", False),
    ],
)
def test_bind_setting_validation(tmp_path, value, ok):
    lib = source_blocks(tmp_path, shared_block(QUICKSTART, "exposure"))
    r = bash(f'source "{lib}"; bind_setting_valid "$V"', env={"V": value})
    assert (r.returncode == 0) == ok


def persist(tmp_path: Path, content: str, bind: str | None):
    lib = source_blocks(tmp_path, shared_block(QUICKSTART, "exposure"))
    env_file = tmp_path / ".env"
    env_file.write_text(content)
    env = {} if bind is None else {"SIGRIFT_BIND": bind}
    r = bash(f'source "{lib}"; persist_bind_setting "{env_file}"', env=env)
    return r, env_file.read_text()


def test_persist_bind_setting(tmp_path):
    r, text = persist(tmp_path, "A=1\n", None)
    assert r.returncode == 0 and text == "A=1\n"
    r, text = persist(tmp_path, "A=1\n", "0.0.0.0")
    assert r.returncode == 0 and text == "A=1\nSIGRIFT_BIND=0.0.0.0\n"
    r, text = persist(tmp_path, "SIGRIFT_BIND=0.0.0.0\n", "0.0.0.0")
    assert r.returncode == 0 and text == "SIGRIFT_BIND=0.0.0.0\n" and not r.stderr
    r, text = persist(tmp_path, "SIGRIFT_BIND='127.0.0.1'\n", "0.0.0.0")
    assert r.returncode == 0 and text == "SIGRIFT_BIND='127.0.0.1'\n"
    assert "NOTE" in r.stderr
    r, text = persist(tmp_path, "A=1\n", "0.0.0.0\nX=1")
    assert r.returncode == 1 and text == "A=1\n"


def test_ipv6_wildcard_bind_is_refused_with_the_reason(tmp_path):
    r, text = persist(tmp_path, "A=1\n", "[::]")
    assert r.returncode == 1 and text == "A=1\n"
    assert "IPv6 only" in r.stderr and "127.0.0.1" in r.stderr
    assert "0.0.0.0" in r.stderr


DOCKER_FACTS_STUB = textwrap.dedent("""\
    #!/bin/sh
    case "$*" in
        "compose port gateway 8444") [ -n "$FAKE_PORT" ] && echo "$FAKE_PORT" ;;
        "compose config --format json")
            printf '{"name": "proj", "services": {"bridge": {"environment": {"BRIDGE_ENV": "%s"}}}}\\n' "$FAKE_MODE" ;;
        *) exit 1 ;;
    esac
    """)


@pytest.mark.parametrize(
    ("port", "mode", "where", "how"),
    [
        ("127.0.0.1:8444", "production", "only: this machine", "production mode"),
        ("0.0.0.0:8444", "development", "other machines", "DEVELOPMENT mode"),
        ("0.0.0.0:8444 [::]:8444", "production", "other machines", "production mode"),
        ("192.168.1.5:8444", "production", "other machines", "production mode"),
        # IPv6 host addresses are published on IPv6 only.
        ("[::]:8444", "production", "IPv6 only", "production mode"),
        ("[fd00::5]:8444", "production", "IPv6 only", "production mode"),
        ("[::1]:8444", "production", "IPv6 only", "production mode"),
    ],
)
def test_closing_message_states_the_real_bind_and_mode(
    stubs, tmp_path, port, mode, where, how
):
    stubs.add_command("docker", DOCKER_FACTS_STUB)
    lib = source_blocks(tmp_path, shared_block(QUICKSTART, "exposure"))
    r = bash(
        f'source "{lib}"; describe_stack',
        env={"PATH": stubs.path, "FAKE_PORT": port, "FAKE_MODE": mode},
    )
    assert r.returncode == 0, r.stderr
    assert port in r.stdout and where in r.stdout and how in r.stdout


def test_closing_messages_use_the_real_bind_and_mode():
    for script in (QUICKSTART, INSTALL_RELEASE):
        summary = script.read_text().split("# ── Summary")[-1]
        assert "$(describe_stack)" in summary, script.name
        assert "all of this" not in summary and "development mode;" not in summary


def test_volume_fix_touches_only_this_projects_volumes(stubs, tmp_path):
    log = tmp_path / "docker.log"
    stubs.add_command(
        "docker",
        textwrap.dedent(f"""\
            #!/bin/sh
            printf '%s\\n' "$*" >> "{log}"
            case "$*" in
                "compose config --format json") echo '{{"name": "proj"}}' ;;
                *"label=com.docker.compose.volume=bridge_data"*) echo proj_bridge_data ;;
                *"label=com.docker.compose.volume=bridge_secrets"*) echo proj_bridge_secrets ;;
            esac
            """),
    )
    lib = source_blocks(
        tmp_path,
        shared_block(QUICKSTART, "tls-key-perms"),
        shared_block(QUICKSTART, "volumes"),
    )
    r = bash(f'source "{lib}"; fix_volume_ownership', env={"PATH": stubs.path})
    assert r.returncode == 0, r.stderr
    calls = log.read_text().splitlines()
    lists = [c for c in calls if c.startswith("volume ls")]
    assert all("label=com.docker.compose.project=proj" in c for c in lists)
    runs = [c for c in calls if c.startswith("run ")]
    assert len(runs) == 2
    assert all("--network none" in c and "@sha256:" in c for c in runs)
    data = next(c for c in runs if "proj_bridge_data:/data" in c)
    secrets = next(c for c in runs if "proj_bridge_secrets:/data" in c)
    assert "chown -R 1500:1500 /data" in data and "chmod" not in data
    assert "chown -R 1500:1500 /data && chmod 0700 /data" in secrets


# ── install-release.sh: production by default (I1) ───────────────────────


def install_release_env_template() -> str:
    text = INSTALL_RELEASE.read_text()
    return re.search(r'cat > "\$tmp_env" <<EOF\n(.*?)\nEOF\n', text, re.S).group(1)


def test_install_release_writes_a_production_env_with_every_key_it_needs():
    body = install_release_env_template()
    lines = dict(
        line.split("=", 1)
        for line in body.splitlines()
        if "=" in line and line[0] != "#"
    )
    assert lines["BRIDGE_ENV"] == "production"
    assert lines["SIGRIFT_BIND"] == "${BIND}"
    # What the bridge's and gateway's production start-up checks require.
    for key in (
        "BRIDGE_MFA_KEY",
        "BRIDGE_KEYSTORE_KEY",
        "BRIDGE_AUDIT_KEY",
        "BRIDGE_MASTER_KEY",
        "UC_PROXY_SECRET",
        "BRIDGE_ADMIN_PASSWORD",
        "UC_TLS_CERT",
        "UC_TLS_KEY",
    ):
        assert lines.get(key), key
    assert "BRIDGE_MFA_KEY=${MFA_KEY}" in body  # fernet_key, not randstr
    assert "BRIDGE_KEYSTORE_KEY=${KEYSTORE_KEY}" in body
    assert re.search(
        r"^    MFA_KEY=\$\(fernet_key\)$", INSTALL_RELEASE.read_text(), re.M
    )
    assert re.search(
        r"^    KEYSTORE_KEY=\$\(fernet_key\)$", INSTALL_RELEASE.read_text(), re.M
    )


def test_install_release_no_longer_recommends_curl_pipe_bash():
    text = INSTALL_RELEASE.read_text()
    assert not re.search(r"\|\s*(SIGRIFT_VERSION=\S+\s+)?(ba)?sh\b", text)
    assert "cosign verify-blob" in text
    assert (
        '--certificate-identity "https://github.com/SigRift/SigRift/.github/workflows/release.yml@refs/tags/$V"'
        in text
    )
    assert "sha256sum --check --ignore-missing SHA256SUMS" in text


def test_old_compose_files_get_k2_k6_warnings(tmp_path):
    compose = install_release_compose(tmp_path)
    text = compose.read_text()
    old = text.replace("      - bridge_secrets:/app/secrets\n", "").replace(
        "      - BRIDGE_REQUIRE_PROXY=true\n", ""
    )
    assert old != text
    compose.write_text(old)
    r = check_gateway_env(tmp_path, compose)
    assert "no `bridge_secrets` volume" in r.stderr
    assert "BRIDGE_REQUIRE_PROXY=true" in r.stderr


# ── compose: loopback, proxy-only bridge, secrets volume (I1, K2, K6) ─────


def compose_cfg(files: list[Path], project_dir: Path, **extra_env) -> dict:
    cmd = ["docker", "compose", "--project-directory", str(project_dir)]
    for f in files:
        cmd += ["-f", str(f)]
    env = {
        "PATH": os.environ["PATH"],
        "HOME": str(project_dir),
        "BRIDGE_MASTER_KEY": "master-123456",
        "BRIDGE_AUDIT_KEY": "audit-123456",
        "BRIDGE_MFA_KEY": VALID_KEY,
        "UC_PROXY_SECRET": "proxy-123456",
        **extra_env,
    }
    out = subprocess.run(
        cmd + ["config", "--format", "json"],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    ).stdout
    return json.loads(out)


STACKS = [
    [],
    ["docker-compose.pki.yml"],
    ["quickstart-override"],
    ["install-release"],
]


def stack_files(tmp_path: Path, overlays: list[str]) -> tuple[list[Path], Path]:
    if overlays == ["install-release"]:
        return [install_release_compose(tmp_path)], tmp_path
    files = [ROOT / "docker-compose.yml"]
    for o in overlays:
        files.append(
            quickstart_override(tmp_path) if o == "quickstart-override" else ROOT / o
        )
    return files, ROOT


def volume_sources(svc: dict) -> set[str]:
    return {v.get("source", "") for v in svc.get("volumes", [])}


@needs_compose
@pytest.mark.parametrize("overlays", STACKS)
def test_gateway_is_published_on_loopback_unless_opted_in(tmp_path, overlays):
    files, project = stack_files(tmp_path, overlays)
    ports = compose_cfg(files, project)["services"]["gateway"]["ports"]
    assert [p["host_ip"] for p in ports] == ["127.0.0.1"]
    ports = compose_cfg(files, project, SIGRIFT_BIND="0.0.0.0")["services"]["gateway"][
        "ports"
    ]
    assert [p["host_ip"] for p in ports] == ["0.0.0.0"]


@needs_compose
@pytest.mark.parametrize("overlays", STACKS)
def test_bridge_only_serves_the_gateway(tmp_path, overlays):
    files, project = stack_files(tmp_path, overlays)
    cfg = compose_cfg(files, project)
    bridge, gateway = cfg["services"]["bridge"], cfg["services"]["gateway"]
    env = bridge["environment"]
    assert env["BRIDGE_REQUIRE_PROXY"] == "true"
    gw_ip = gateway["networks"]["backend"]["ipv4_address"]
    assert env["BRIDGE_TRUSTED_PROXIES"] == gw_ip
    subnet = cfg["networks"]["backend"]["ipam"]["config"][0]["subnet"]
    import ipaddress

    assert ipaddress.ip_address(gw_ip) in ipaddress.ip_network(subnet)
    # Only the gateway shares a network with the bridge.
    assert set(bridge["networks"]) == {"backend"}
    for name, svc in cfg["services"].items():
        if name not in ("bridge", "gateway"):
            assert "backend" not in (svc.get("networks") or {}), name
    # In-stack agents reach the bridge only through the gateway.
    for name, svc in cfg["services"].items():
        for key, value in (svc.get("environment") or {}).items():
            if key.startswith("MLRF_") and key.endswith("_URL"):
                assert value in (
                    "https://gateway:8444",
                    "https://127.0.0.1:8444",
                ), (name, key, value)
                assert "bridge" not in value and "8001" not in value


CUSTOM_BACKEND = {
    "SIGRIFT_BACKEND_SUBNET": "10.77.0.0/24",
    "SIGRIFT_BACKEND_IP_RANGE": "10.77.0.128/25",
    "SIGRIFT_GATEWAY_BACKEND_IP": "10.77.0.2",
}


def backend_addresses(cfg: dict):
    import ipaddress

    gw_ip = ipaddress.ip_address(
        cfg["services"]["gateway"]["networks"]["backend"]["ipv4_address"]
    )
    (pool,) = cfg["networks"]["backend"]["ipam"]["config"]
    assert "ip_range" in pool, (
        "backend has no ip_range: docker may give the bridge the gateway's address"
    )
    return (
        gw_ip,
        ipaddress.ip_network(pool["subnet"]),
        ipaddress.ip_network(pool["ip_range"]),
    )


@needs_compose
@pytest.mark.parametrize("overlays", STACKS)
def test_gateway_backend_address_is_outside_the_dynamic_range(tmp_path, overlays):
    # The bridge starts first (the gateway depends on it) and docker gives
    # it the lowest free address of ip_range — or, without an ip_range, of
    # the whole subnet: the gateway's fixed address, which then fails to
    # start with "Address already in use".
    files, project = stack_files(tmp_path, overlays)
    for env in ({}, CUSTOM_BACKEND):
        cfg = compose_cfg(files, project, **env)
        gw_ip, subnet, ip_range = backend_addresses(cfg)
        assert ip_range.subnet_of(subnet)
        assert gw_ip in subnet and gw_ip not in ip_range
        assert gw_ip not in (subnet.network_address, subnet.broadcast_address)
        assert cfg["services"]["bridge"]["environment"][
            "BRIDGE_TRUSTED_PROXIES"
        ] == str(gw_ip)
        # Only the gateway has a fixed address; the bridge's comes from the range.
        assert "ipv4_address" not in (
            cfg["services"]["bridge"]["networks"]["backend"] or {}
        )
    assert (str(subnet), str(ip_range), str(gw_ip)) == tuple(CUSTOM_BACKEND.values())


def test_env_example_backend_defaults_match_the_compose_file():
    import ipaddress

    text = (ROOT / ".env.example").read_text()
    documented = dict(
        re.findall(
            r"^# (SIGRIFT_(?:BACKEND_\w+|GATEWAY_BACKEND_IP))=(\S+)$", text, re.M
        )
    )
    compose = (ROOT / "docker-compose.yml").read_text()
    defaults = dict(
        re.findall(
            r"\$\{(SIGRIFT_(?:BACKEND_\w+|GATEWAY_BACKEND_IP)):-([^}]+)\}", compose
        )
    )
    assert set(defaults) == set(CUSTOM_BACKEND)
    assert documented == defaults
    gw_ip = ipaddress.ip_address(defaults["SIGRIFT_GATEWAY_BACKEND_IP"])
    ip_range = ipaddress.ip_network(defaults["SIGRIFT_BACKEND_IP_RANGE"])
    assert gw_ip in ipaddress.ip_network(defaults["SIGRIFT_BACKEND_SUBNET"])
    assert gw_ip not in ip_range


@needs_compose
@pytest.mark.parametrize("overlays", STACKS)
def test_ca_key_volume_is_mounted_on_the_bridge_only(tmp_path, overlays):
    files, project = stack_files(tmp_path, overlays)
    cfg = compose_cfg(files, project)
    bridge = cfg["services"]["bridge"]
    assert any(
        v.get("source") == "bridge_secrets" and v["target"] == "/app/secrets"
        for v in bridge["volumes"]
    )
    assert bridge["environment"]["BRIDGE_SECRETS_DIR"] == "/app/secrets"
    for name, svc in cfg["services"].items():
        if name != "bridge":
            assert "bridge_secrets" not in volume_sources(svc), name
    # The gateway keeps the data volume: detections.db, keys.json, ca.crt.
    assert "bridge_data" in volume_sources(cfg["services"]["gateway"])
    if "docker-compose.pki.yml" in overlays:
        gw_env = cfg["services"]["gateway"]["environment"]
        assert gw_env["UC_TLS_CLIENT_CA"] == "/app/data/ca/ca.crt"


@needs_compose
def test_install_release_compose_defaults_to_production(tmp_path):
    cfg = compose_cfg([install_release_compose(tmp_path)], tmp_path)
    for svc in ("bridge", "gateway"):
        assert cfg["services"][svc]["environment"]["BRIDGE_ENV"] == "production"


# ── quickstart.sh smoke: no password in argv (I10) ────────────────────────


@needs_compose
def test_quickstart_login_body_escapes_the_password(tmp_path):
    fn = function_text(QUICKSTART, "login_body")
    tricky = 'p"a\\s$(id)`x`\'s #1 \\"'
    env_file = tmp_path / ".env"
    encoded = json.dumps(tricky.replace("$", "$$"))
    env_file.write_text(f"BRIDGE_ADMIN_USER=admin\nBRIDGE_ADMIN_PASSWORD={encoded}\n")
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  bridge:\n    image: busybox\n    environment:\n"
        "      BRIDGE_ADMIN_USER: ${BRIDGE_ADMIN_USER:-admin}\n"
        "      BRIDGE_ADMIN_PASSWORD: ${BRIDGE_ADMIN_PASSWORD}\n"
    )
    r = bash(fn + f'login_body "{env_file}"', cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout) == {"username": "admin", "password": tricky}
    env_file.write_text('BRIDGE_ADMIN_PASSWORD="quoted pw"\nX=1\n')
    assert json.loads(bash(fn + f'login_body "{env_file}"', cwd=tmp_path).stdout)[
        "password"
    ] == ("quoted pw")


def test_quickstart_smoke_avoids_shared_tmp_and_argv_password_copy():
    text = QUICKSTART.read_text()
    assert "/tmp/sigrift-smoke-cookies" not in text
    assert not re.search(r"\bADMIN_PASS\b", text)  # the old argv-bound copy
    # A private body file permits one cooldown retry without putting the secret
    # in curl argv. Real TLS tests verify stdin/file modes and signal cleanup;
    # a particular shell pipeline is not the privacy contract.
    assert "--data-binary @-" in function_text(QUICKSTART, "smoke_login")
    assert re.search(r"SMOKE_TMP=\$\(mktemp -d ", text)


# ── staging-smoke.sh: a scoped admin session fails the smoke (I7) ─────────


SMOKE = SCRIPTS / "staging-smoke.sh"
SMOKE_SESSION = "tok-123"
# What the gateway sets on login (every release since 0.1.0): the session
# only in an HttpOnly cookie, beside the JS-readable CSRF cookie and an
# expired legacy bridge_token.
SMOKE_LOGIN_COOKIES = [
    f"session_token={SMOKE_SESSION}; Path=/; SameSite=Lax; HttpOnly",
    "csrf_token=csrf-123; Path=/; SameSite=Lax",
    "bridge_token=; Path=/; Max-Age=0; SameSite=Lax",
]


def run_smoke(tmp_path: Path, scenario: dict):
    import http.server
    import threading

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, code: int, body, cookies=()) -> None:
            data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            for cookie in cookies:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(data)

        def has_session(self) -> bool:
            # Authenticated only by the jar's session cookie: the smoke
            # must replay it, and needs no Bearer copy of the token.
            pairs = [p.strip() for p in self.headers.get("Cookie", "").split(";")]
            return f"session_token={SMOKE_SESSION}" in pairs and not self.headers.get(
                "Authorization"
            )

        def do_GET(self):
            path = self.path.split("?")[0]
            if path == "/health":
                self.reply(200, "ok")
            elif path == "/api/version":
                self.reply(200, {"server_version": "4.0.0"})
            elif path == "/api/ready":
                self.reply(200, {"status": "ready"})
            elif path in ("/api/auth/me", "/api/detections/recent") and not (
                self.has_session()
            ):
                self.reply(401, {"detail": "Not authenticated"})
            elif path == "/api/auth/me":
                self.reply(*scenario.get("me", (200, {"username": "admin"})))
            elif path == "/api/detections/recent":
                self.reply(*scenario.get("recent", (200, [])))
            else:
                self.reply(404, {"detail": "not found"})

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(length)
            if self.path == "/api/auth/login":
                self.reply(
                    200,
                    {"csrf_token": "csrf-123", **scenario.get("login", {})},
                    scenario.get("login_cookies", SMOKE_LOGIN_COOKIES),
                )
            else:
                self.reply(404, {"detail": "not found"})

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        return subprocess.run(
            [BASH, str(SMOKE)],
            capture_output=True,
            text=True,
            env={
                "PATH": os.environ["PATH"],
                "BASE_URL": f"http://127.0.0.1:{server.server_address[1]}",
                "BRIDGE_ADMIN_PASSWORD": "correct-horse-battery",
                "LOG_DIR": str(tmp_path),
                "TMPDIR": str(tmp_path),
            },
            timeout=60,
        )
    finally:
        server.shutdown()


needs_smoke_tools = pytest.mark.skipif(
    not (shutil.which("curl") and shutil.which("jq")), reason="needs curl and jq"
)
PW_403 = (403, {"detail": "Password change required"})


@needs_smoke_tools
@pytest.mark.parametrize(
    "login",
    [
        {},
        # Today's gateways also return the token in the body; the smoke
        # ignores it, so it passes with either contract.
        {"session_token": SMOKE_SESSION},
    ],
)
def test_smoke_passes_a_full_admin_session(tmp_path, login):
    r = run_smoke(tmp_path, {"login": login})
    assert r.returncode == 0, r.stderr
    assert "ALL 7 smoke steps passed" in r.stderr


@needs_smoke_tools
@pytest.mark.parametrize(
    "cookies",
    [
        [],  # no session cookie at all
        # Not HttpOnly: a JS-readable session cookie is not a pass.
        [f"session_token={SMOKE_SESSION}; Path=/", "csrf_token=c; Path=/"],
        ["session_token=; Path=/; Max-Age=0; HttpOnly", "csrf_token=c; Path=/"],
    ],
)
def test_smoke_fails_without_an_httponly_session_cookie(tmp_path, cookies):
    r = run_smoke(
        tmp_path, {"login": {"session_token": SMOKE_SESSION}, "login_cookies": cookies}
    )
    assert r.returncode == 1, r.stderr
    assert "ALL" not in r.stderr
    assert "step 5: login set no HttpOnly session_token cookie" in r.stderr


def test_smoke_reads_no_session_token_from_the_login_body():
    text = SMOKE.read_text()
    assert ".session_token" not in text
    assert "Authorization: Bearer" not in text
    assert "AUTH_HEADERS" not in text


@needs_smoke_tools
@pytest.mark.parametrize(
    "scenario",
    [
        {"me": PW_403},  # older bridges: /me itself refused
        {"recent": (403, {"detail": "password change required"})},  # contract K3
        {"login": {"password_change_required": True}},
        {"login": {"mfa_setup_required": True}},
        {"me": (403, {"detail": "MFA setup required"})},
    ],
)
def test_smoke_fails_on_a_scoped_admin_session(tmp_path, scenario):
    r = run_smoke(tmp_path, scenario)
    assert r.returncode == 1, r.stderr
    assert "ALL" not in r.stderr and "FAIL" in r.stderr


# ── round 4: renewal keeps names, recreate is retried, backend subnet ───
# (Q17 renewal never adds names, Q18 recreate marker, Q19 backend subnet,
# Q20 proxy secret required, Q21 set-aside keys ignored, contract K7)


def renew_only(stubs, tmp_path, **env):
    """tls_ensure_cert the way the --renew-tls / renew-tls modes call it."""
    lib = source_blocks(tmp_path, shared_block(INSTALL_RELEASE, "tls-cert"))
    (tmp_path / "tls").mkdir(exist_ok=True)
    return bash(
        f'source "{lib}"; TLS_RENEW_ONLY=1; '
        'tls_ensure_cert tls/cert.pem tls/key.pem localhost ""; '
        'echo "CHANGED=$TLS_CERT_CHANGED"',
        env=tls_env(stubs, tmp_path, **env),
        cwd=tmp_path,
    )


def moved_host(tmp_path: Path) -> dict:
    """The host got a new name and address (a DHCP lease, a VPN interface)."""
    ip_file = tmp_path / "ip-output-moved"
    ip_file.write_text(
        IP_OUTPUT
        + "8: wg0    inet 10.99.0.7/24 scope global wg0\\       valid_lft forever\n"
    )
    return {"FAKE_IP_OUTPUT": str(ip_file), "FAKE_SHORT": "sensor-new"}


def test_renewal_never_regenerates_the_cert_for_a_new_address(stubs, tmp_path):
    assert "CHANGED=1" in ensure_cert(stubs, tmp_path).stdout
    tls = tmp_path / "tls"
    (tls / ".recreate-pending").unlink()
    before = ((tls / "cert.pem").read_bytes(), (tls / "key.pem").read_bytes())
    r = renew_only(stubs, tmp_path, **moved_host(tmp_path))
    assert r.returncode == 0, r.stderr
    assert "CHANGED=0" in r.stdout
    assert "lacks subjectAltName" in r.stderr
    assert "DNS:sensor-new" in r.stderr and "IP:10.99.0.7" in r.stderr
    assert "re-run the installer" in r.stderr
    assert ((tls / "cert.pem").read_bytes(), (tls / "key.pem").read_bytes()) == before
    assert not (tls / ".recreate-pending").exists()
    # A run of the installer itself still adds the names.
    r = ensure_cert(stubs, tmp_path, **moved_host(tmp_path))
    assert "CHANGED=1" in r.stdout
    assert {"IP:10.99.0.7", "DNS:sensor-new", "DNS:sensor"} <= cert_sans(
        tls / "cert.pem"
    )


def test_renewal_of_an_expiring_cert_keeps_exactly_its_names(stubs, tmp_path):
    cert = full_sans_cert(stubs, tmp_path, days=10)
    names = cert_sans(cert)
    r = renew_only(stubs, tmp_path, **moved_host(tmp_path))
    assert r.returncode == 0, r.stderr
    assert "CHANGED=1" in r.stdout and "renewing it (same names)" in r.stdout
    assert "lacks subjectAltName" in r.stderr
    assert cert_sans(cert) == names  # the new address was not added
    assert valid_for_days(cert, 800)


def test_a_new_cert_leaves_a_recreate_marker_until_the_caller_clears_it(
    stubs, tmp_path
):
    marker = tmp_path / "tls" / ".recreate-pending"
    assert "CHANGED=1" in ensure_cert(stubs, tmp_path).stdout
    assert marker.exists()
    # A later run — the recreate failed in between: the cert is current,
    # but the containers still have to be recreated.
    lib = source_blocks(tmp_path, shared_block(INSTALL_RELEASE, "tls-cert"))
    r = bash(
        f'source "{lib}"; tls_ensure_cert tls/cert.pem tls/key.pem localhost ""; '
        'echo "CHANGED=$TLS_CERT_CHANGED"; '
        "tls_recreate_pending tls/cert.pem && echo PENDING; "
        "tls_recreate_done tls/cert.pem; "
        "tls_recreate_pending tls/cert.pem || echo CLEARED",
        env=tls_env(stubs, tmp_path),
        cwd=tmp_path,
    )
    assert r.stdout.split() == ["CHANGED=0", "PENDING", "CLEARED"], r.stderr
    assert not marker.exists()


def fake_docker(stubs, tmp_path: Path) -> Path:
    """A `docker` that logs its arguments and plays a healthy stack.

    FAKE_PULL_RC / FAKE_UP_RC are the exit status of `docker pull` and
    `compose pull` / `compose up`; FAKE_HEALTH and FAKE_BRIDGE_HEALTH
    (default healthy) what `compose ps` says about the gateway and the
    bridge.
    The stack runs bridge, gateway and edge (`compose ps -q` lists one
    container each, plus, without service names, an orphan `oldsvc` from
    a service no longer in the compose file); `inspect` says each started
    now, except the orphan and the services in FAKE_STALE, which still
    run from 2020 (an `up` that died before it reached them). Services
    in FAKE_DOWN have no running container.
    `date +%s` moves 100 s on per call and `sleep` returns at once, so a
    health wait that never succeeds ends at once too.
    """
    log = tmp_path / "docker.log"
    log.write_text("")
    real_date = shutil.which("date")
    stubs.add_command(
        "docker",
        textwrap.dedent(f"""\
            #!/bin/sh
            printf '%s\\n' "$*" >> "{log}"
            if [ "$1" = inspect ]; then
                for a in "$@"; do
                    case "$a" in
                        id-*) svc=${{a#id-}}
                            case " $FAKE_STALE oldsvc " in
                                *" $svc "*) t=2020-01-01T00:00:00.5Z ;;
                                *) t=$("{real_date}" -u +%Y-%m-%dT%H:%M:%S.%NZ) ;;
                            esac
                            echo "$svc $t" ;;
                    esac
                done
                exit 0
            fi
            # The installers pull the images themselves, before any change.
            [ "$1" = pull ] && exit "${{FAKE_PULL_RC:-0}}"
            [ "$1" = compose ] || exit 0
            for a in "$@"; do
                case "$a" in
                    version) exit 0 ;;
                    pull) exit "${{FAKE_PULL_RC:-0}}" ;;
                    up) exit "${{FAKE_UP_RC:-0}}" ;;
                    ps) case " $* " in
                            *" -q "*)
                                q=; names=
                                for s in "$@"; do
                                    [ -n "$q" ] && names="$names $s"
                                    [ "$s" = -q ] && q=1
                                done
                                for s in ${{names:-bridge gateway edge oldsvc}}; do
                                    case " $FAKE_DOWN " in
                                        *" $s "*) ;;
                                        *) echo "id-$s" ;;
                                    esac
                                done ;;
                            *) printf '{{"Service":"bridge","State":"running","Health":"%s"}}\\n' \\
                                "${{FAKE_BRIDGE_HEALTH:-healthy}}"
                                printf '{{"Service":"gateway","State":"running","Health":"%s"}}\\n' \\
                                "${{FAKE_HEALTH:-healthy}}" ;;
                        esac
                        exit 0 ;;
                    port) echo 127.0.0.1:8444; exit 0 ;;
                    config) case " $* " in
                            *" --services "*) printf '%s\\n' bridge gateway edge ;;
                            *".sigrift-compose-"*) echo '{{"services":{{"bridge":{{"image":"ghcr.io/sigrift/sigrift-bridge:v9.9.9"}},"gateway":{{"image":"ghcr.io/sigrift/sigrift-gateway:v9.9.9"}}}}}}' ;;
                            *" --format json "*)
                                # The project: --env-file, the shell, .env, the folder.
                                n= prev=
                                for e in "$@"; do
                                    [ "$prev" = --env-file ] && n=$(sed -n 's/^COMPOSE_PROJECT_NAME=//p' "$e" | tail -1)
                                    prev=$e
                                done
                                [ -n "$n" ] || n=${{COMPOSE_PROJECT_NAME:-}}
                                [ -n "$n" ] || n=$(sed -n 's/^COMPOSE_PROJECT_NAME=//p' .env 2>/dev/null | tail -1)
                                [ -n "$n" ] || n=$(basename "$PWD" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9_-')
                                printf '{{"name":"%s"}}\\n' "$n" ;;
                            *) echo '{{}}' ;;
                        esac
                        exit 0 ;;
                esac
            done
            exit 0
            """),
    )
    clock = tmp_path / "clock"
    stubs.add_command(
        "date",
        textwrap.dedent(f"""\
            #!/bin/sh
            if [ "$1" = +%s ]; then
                n=$(( $(cat "{clock}" 2>/dev/null || echo 1700000000) + 100 ))
                echo "$n" > "{clock}"
                echo "$n"
            else
                exec "{real_date}" "$@"
            fi
            """),
    )
    stubs.add_command("sleep", "#!/bin/sh\nexit 0\n")
    return log


def compose_ups(log: Path) -> list[str]:
    return [
        line for line in log.read_text().splitlines() if line.startswith("compose up")
    ]


INSTALLED_ENV = (
    f"BRIDGE_ENV=production\nBRIDGE_MFA_KEY={VALID_KEY}\n"
    "BRIDGE_AUDIT_KEY=audit-123456\nBRIDGE_MASTER_KEY=master-123456\n"
    "UC_PROXY_SECRET=proxy-123456\nBRIDGE_ADMIN_PASSWORD=correct-horse-battery\n"
)


def release_dir(tmp_path: Path) -> Path:
    """An install-release.sh install: the script, its compose file, .env."""
    d = tmp_path / "release"
    d.mkdir()
    shutil.copy(INSTALL_RELEASE, d / "install-release.sh")
    shutil.move(install_release_compose(tmp_path), d / "docker-compose.yml")
    (d / ".env").write_text(INSTALLED_ENV)
    return d


def quickstart_dir(tmp_path: Path) -> Path:
    d = tmp_path / "checkout"
    (d / "scripts").mkdir(parents=True)
    shutil.copy(QUICKSTART, d / "scripts" / "quickstart.sh")
    (d / ".env").write_text(INSTALLED_ENV + "SIGRIFT_QUICKSTART_MODE=dashboard-only\n")
    return d


def run_script(stubs, tmp_path: Path, script: Path, *args: str, **env):
    full = tls_env(stubs, tmp_path, **env)
    full.update({"HOME": str(tmp_path), "LC_ALL": "C", "SIGRIFT_VERSION": "v9.9.9"})
    return subprocess.run(
        [BASH, str(script), *args],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env=full,
        timeout=300,
    )


def test_release_renewal_retries_a_recreate_that_failed(stubs, tmp_path):
    d = release_dir(tmp_path)
    log = fake_docker(stubs, tmp_path)
    script, marker = d / "install-release.sh", d / "tls" / ".recreate-pending"
    recreate = "compose up -d --pull never --force-recreate gateway"
    r = run_script(stubs, tmp_path, script, "--renew-tls", FAKE_UP_RC="1")
    assert r.returncode != 0  # the cert was written, the recreate failed
    assert compose_ups(log) == [recreate] and marker.exists()
    log.write_text("")
    r = run_script(stubs, tmp_path, script, "--renew-tls")
    assert r.returncode == 0, r.stderr
    assert "did not finish recreating the gateway" in r.stdout
    assert compose_ups(log) == [recreate] and not marker.exists()
    log.write_text("")
    r = run_script(stubs, tmp_path, script, "--renew-tls")
    assert r.returncode == 0 and "nothing to do" in r.stdout
    assert compose_ups(log) == []


def test_release_rerun_changes_nothing_when_the_pull_fails_then_recreates(
    stubs, tmp_path
):
    d = release_dir(tmp_path)
    log = fake_docker(stubs, tmp_path)
    script, marker = d / "install-release.sh", d / "tls" / ".recreate-pending"
    before = {p.name: p.read_bytes() for p in d.iterdir() if p.is_file()}
    r = run_script(stubs, tmp_path, script, FAKE_PULL_RC="1")
    # The images are pulled before any file changes: nothing was written.
    assert r.returncode == 3, r.stderr
    assert r.stderr.rstrip().endswith("Nothing was changed.")
    assert compose_ups(log) == [] and not (d / "tls").exists() and not marker.exists()
    assert {p.name: p.read_bytes() for p in d.iterdir() if p.is_file()} == before
    log.write_text("")
    r = run_script(stubs, tmp_path, script)
    assert r.returncode == 0, r.stderr
    # The bridge first; then the gateway, recreated for its new certificate.
    assert compose_ups(log) == [
        "compose up -d --pull never --remove-orphans bridge",
        "compose up -d --pull never --remove-orphans --force-recreate gateway",
    ]
    assert not marker.exists()
    log.write_text("")
    r = run_script(stubs, tmp_path, script)
    assert r.returncode == 0, r.stderr
    assert compose_ups(log) == [
        "compose up -d --pull never --remove-orphans bridge",
        "compose up -d --pull never --remove-orphans",
    ]


def test_release_renewal_leaves_the_cert_alone_when_the_host_gains_an_address(
    stubs, tmp_path
):
    d = release_dir(tmp_path)
    log = fake_docker(stubs, tmp_path)
    script = d / "install-release.sh"
    assert run_script(stubs, tmp_path, script, "--renew-tls").returncode == 0
    tls = d / "tls"
    before = ((tls / "cert.pem").read_bytes(), (tls / "key.pem").read_bytes())
    log.write_text("")
    r = run_script(stubs, tmp_path, script, "--renew-tls", **moved_host(tmp_path))
    assert r.returncode == 0, r.stderr
    assert "nothing to do" in r.stdout
    assert "lacks subjectAltName" in r.stderr and "IP:10.99.0.7" in r.stderr
    assert ((tls / "cert.pem").read_bytes(), (tls / "key.pem").read_bytes()) == before
    assert compose_ups(log) == []


def test_quickstart_renewal_retries_until_the_gateway_is_back(stubs, tmp_path):
    d = quickstart_dir(tmp_path)
    log = fake_docker(stubs, tmp_path)
    script, marker = d / "scripts" / "quickstart.sh", d / "tls" / ".recreate-pending"
    recreate = "compose up -d --no-build --force-recreate"
    # New cert; the gateway does not come back.
    r = run_script(stubs, tmp_path, script, "--renew-tls", FAKE_HEALTH="starting")
    assert r.returncode != 0 and "did not become healthy" in r.stderr
    assert compose_ups(log) == [recreate] and marker.exists()
    log.write_text("")
    # `up` fails (an SDR service without its hardware), the gateway is fine.
    r = run_script(stubs, tmp_path, script, "--renew-tls", FAKE_UP_RC="1")
    assert r.returncode == 0, r.stderr
    assert "did not finish recreating the services" in r.stdout
    assert compose_ups(log) == [recreate] and not marker.exists()
    log.write_text("")
    r = run_script(stubs, tmp_path, script, "--renew-tls", **moved_host(tmp_path))
    assert r.returncode == 0 and "nothing to do" in r.stdout
    assert "lacks subjectAltName" in r.stderr
    assert compose_ups(log) == []


def test_a_healthy_gateway_from_before_the_new_cert_keeps_the_marker(stubs, tmp_path):
    """tls_recreate_confirm: the marker goes only when all of it is new."""
    fake_docker(stubs, tmp_path)
    lib = source_blocks(tmp_path, shared_block(INSTALL_RELEASE, "tls-cert"))
    marker = tmp_path / "tls" / ".recreate-pending"
    marker.parent.mkdir()

    def confirm(**env):
        marker.touch()
        return bash(
            f'source "{lib}"; tls_recreate_confirm tls/cert.pem docker compose',
            env=tls_env(stubs, tmp_path, **env),
            cwd=tmp_path,
        )

    # `up` died before compose reached the gateway: the old one still
    # runs (and is healthy), so does the edge agent behind it.
    r = confirm(FAKE_STALE="gateway edge")
    assert r.returncode == 1 and marker.exists()
    assert "did not reach: edge gateway" in r.stderr
    r = confirm(FAKE_STALE="edge")  # the gateway is new, an agent is not
    assert r.returncode == 1 and marker.exists()
    assert "did not reach: edge\n" in r.stderr
    r = confirm(FAKE_DOWN="gateway")  # no gateway runs: nothing proven
    assert r.returncode == 1 and marker.exists()
    assert "did not reach: gateway(not-running)" in r.stderr
    # An SDR service without its hardware is not running: that is fine.
    r = confirm(FAKE_DOWN="edge", FAKE_STALE="edge")
    assert r.returncode == 0, r.stderr
    assert not marker.exists()
    # Everything the compose file declares is new; the orphan of a
    # service that left the compose file is not looked at.
    r = confirm()
    assert r.returncode == 0, r.stderr
    assert not marker.exists()
    # No marker: nothing pending, nothing to check.
    log = tmp_path / "docker.log"
    log.write_text("")
    r = bash(
        f'source "{lib}"; tls_recreate_confirm tls/cert.pem docker compose',
        env=tls_env(stubs, tmp_path),
        cwd=tmp_path,
    )
    assert r.returncode == 0 and log.read_text() == ""


def test_quickstart_renewal_keeps_the_marker_while_the_old_gateway_runs(
    stubs, tmp_path
):
    d = quickstart_dir(tmp_path)
    log = fake_docker(stubs, tmp_path)
    script, marker = d / "scripts" / "quickstart.sh", d / "tls" / ".recreate-pending"
    # New cert; recreating the bridge failed (a full disk), so compose
    # never got to the gateway: `ps` still says healthy — the old one.
    r = run_script(
        stubs,
        tmp_path,
        script,
        "--renew-tls",
        FAKE_UP_RC="1",
        FAKE_STALE="gateway edge",
    )
    assert r.returncode != 0
    assert "did not reach: edge gateway" in r.stderr
    assert "Copy" not in r.stdout
    assert marker.exists()
    log.write_text("")
    # Next run: recreated for real this time.
    r = run_script(stubs, tmp_path, script, "--renew-tls", FAKE_UP_RC="1")
    assert r.returncode == 0, r.stderr
    assert "did not finish recreating the services" in r.stdout
    assert compose_ups(log) == ["compose up -d --no-build --force-recreate"]
    assert not marker.exists()


def test_installers_recreate_while_a_recreate_is_pending():
    """The full runs honour the marker too and clear it only after success."""
    qs = QUICKSTART.read_text()
    assert (
        "if tls_recreate_pending tls/cert.pem; then\n    up_args+=(--force-recreate)"
        in qs
    )
    # `up` runs with `|| true` there: a healthy gateway is not enough, the
    # marker goes only once every running container is new (Q18).
    wait = qs.index('if ! wait_gateway_healthy 240; then\n    echo "" >&2')
    confirm = "if ! tls_recreate_confirm tls/cert.pem docker compose; then\n"
    assert qs.index(confirm, wait) > wait
    assert qs.count(confirm) == 2  # the --renew-tls branch too
    # The shared lifecycle block's two-stage start (release installs; its
    # `up` fails hard, so its exit status proves the recreate) is not
    # quickstart's own flow.
    assert "tls_recreate_done tls/cert.pem" not in qs.replace(
        shared_block(QUICKSTART, "lifecycle"), ""
    )
    # The release start: the gateway is recreated while a recreate is
    # pending, and the marker goes only after it turned healthy.
    start = function_text(INSTALL_RELEASE, "lc_start_rest")
    assert (
        "    if tls_recreate_pending tls/cert.pem; then\n"
        "        # The certificate is new: recreate the gateway (only it mounts\n"
        "        # tls/; the bridge just became healthy).\n"
        "        docker compose up -d --pull never --remove-orphans --force-recreate gateway\n"
    ) in start
    assert start.index("lc_wait_service_healthy gateway") < start.index(
        "tls_recreate_done tls/cert.pem"
    )


# ── backend subnet (Q19) ──────────────────────────────────────────────────

DOCKER_DEFAULT_POOLS = [f"172.{n}.0.0/16" for n in range(17, 32)] + ["192.168.0.0/16"]


def compose_backend_defaults(text: str) -> dict:
    return dict(
        re.findall(r"\$\{(SIGRIFT_(?:BACKEND_\w+|GATEWAY_BACKEND_IP)):-([^}]+)\}", text)
    )


def test_the_default_backend_subnet_is_outside_dockers_default_pools():
    import ipaddress

    main = compose_backend_defaults((ROOT / "docker-compose.yml").read_text())
    assert compose_backend_defaults(INSTALL_RELEASE.read_text()) == main
    subnet = ipaddress.ip_network(main["SIGRIFT_BACKEND_SUBNET"])
    for pool in DOCKER_DEFAULT_POOLS:
        assert not subnet.overlaps(ipaddress.ip_network(pool)), pool


def test_backend_subnet_block_identical_in_both_installers():
    assert shared_block(QUICKSTART, "backend-subnet") == shared_block(
        INSTALL_RELEASE, "backend-subnet"
    )


def test_every_installer_checks_the_backend_subnet_before_starting():
    qs = QUICKSTART.read_text()
    assert qs.index("\nensure_backend_subnet .env\n") < qs.index(
        '\ndocker compose "${SCANNER_COMPOSE_ARGS[@]}" build "${QUICKSTART_SERVICES[@]}"\n'
    )
    rel = INSTALL_RELEASE.read_text()
    # A new install: before its start. A re-run and an upgrade: the switch
    # (release_switch, the "switch" step) runs it before the start steps.
    fresh = rel.index("    fresh)\n")
    assert (
        fresh
        < rel.index("\n        ensure_backend_subnet .env\n", fresh)
        < rel.index("\n        lc_start_two_stage\n", fresh)
    )
    assert "\n    ensure_backend_subnet .env\n}" in function_text(
        INSTALL_RELEASE, "release_switch"
    )
    rerun = rel.index("    rerun)\n")
    assert rel.index("        release_switch\n", rerun) < rel.index(
        "        lc_start_two_stage\n", rerun
    )
    steps = re.search(r'^LC_UPGRADE_STEPS="([^"]+)"', rel, re.M).group(1).split()
    assert steps.index("switch") < steps.index("start-bridge")


def subnet_env(stubs, tmp_path: Path, networks: list[str], routes: str = "") -> dict:
    """`docker network` plays NETWORKS ("NAME ID SUBNET..." lines, as the
    inspect format prints them); `ip -4 route` prints ROUTES. Everything
    else goes to the real docker (compose config)."""
    nets = tmp_path / "networks"
    nets.write_text("".join(n + "\n" for n in networks))
    rts = tmp_path / "routes"
    rts.write_text(routes)
    real_docker = shutil.which("docker")
    stubs.add_command(
        "docker",
        textwrap.dedent(f"""\
            #!/bin/sh
            if [ "$1" = network ]; then
                case "$2" in
                    ls) awk '{{print $2}}' "{nets}" ;;
                    inspect) cat "{nets}" ;;
                esac
                exit 0
            fi
            exec "{real_docker}" "$@"
            """),
    )
    stubs.add_command(
        "ip", f'#!/bin/sh\n[ "$1 $2" = "-4 route" ] && cat "{rts}"\nexit 0\n'
    )
    return {"PATH": stubs.path, "HOME": str(tmp_path)}


def ensure_subnet(tmp_path: Path, env: dict, env_text: str | None = None, compose=None):
    stack = tmp_path / "stack"  # compose project "stack": its network is stack_backend
    stack.mkdir(exist_ok=True)
    env_file = stack / ".env"
    if env_text is not None:
        env_file.write_text(env_text)
    lib = source_blocks(tmp_path, shared_block(INSTALL_RELEASE, "backend-subnet"))
    compose = compose or ROOT / "docker-compose.yml"
    r = bash(
        f'source "{lib}"; ensure_backend_subnet "{env_file}" '
        f'-f "{compose}" --project-directory "{stack}"',
        env=env,
        cwd=stack,
    )
    return r, env_file


OTHER_STACK = [
    "bridge 1111aaaa2222bbbb 172.17.0.0/16",
    "sigrift_default 3333cccc4444dddd 172.18.0.0/16",
    "sigrift_backend 5555eeee6666ffff 10.203.84.0/28",
]


@needs_compose
def test_a_second_stack_gets_a_free_backend_subnet(stubs, tmp_path):
    env = subnet_env(stubs, tmp_path, OTHER_STACK)
    r, env_file = ensure_subnet(tmp_path, env, "UC_PROXY_SECRET=x")  # no final newline
    assert r.returncode == 0, r.stderr
    assert "overlaps docker network sigrift_backend (10.203.84.0/28)" in r.stdout
    text = env_file.read_text()
    assert text.startswith("UC_PROXY_SECRET=x\n#")
    assert text.endswith(
        "SIGRIFT_BACKEND_SUBNET=10.203.84.16/28\n"
        "SIGRIFT_BACKEND_IP_RANGE=10.203.84.24/29\n"
        "SIGRIFT_GATEWAY_BACKEND_IP=10.203.84.18\n"
    )
    cfg = compose_cfg([ROOT / "docker-compose.yml"], tmp_path / "stack")
    gw_ip, subnet, ip_range = backend_addresses(cfg)
    assert (str(subnet), str(ip_range), str(gw_ip)) == (
        "10.203.84.16/28",
        "10.203.84.24/29",
        "10.203.84.18",
    )
    assert cfg["services"]["bridge"]["environment"]["BRIDGE_TRUSTED_PROXIES"] == str(
        gw_ip
    )
    # Next run: this stack's own network is on that subnet now — nothing to do.
    env = subnet_env(
        stubs,
        tmp_path,
        OTHER_STACK + ["stack_backend 7777aaaa8888bbbb 10.203.84.16/28"],
    )
    r, _ = ensure_subnet(tmp_path, env)
    assert (r.returncode, r.stdout, r.stderr) == (0, "", "")
    assert env_file.read_text() == text


@needs_compose
def test_the_stacks_own_backend_network_is_no_clash(stubs, tmp_path):
    routes = (
        "10.203.84.0/28 dev br-7777aaaa8888 proto kernel scope link src 10.203.84.1\n"
        "local 10.203.84.1 dev br-7777aaaa8888 table local proto kernel scope host\n"
    )
    env = subnet_env(
        stubs, tmp_path, ["stack_backend 7777aaaa8888bbbb 10.203.84.0/28"], routes
    )
    r, env_file = ensure_subnet(tmp_path, env, "X=1\n")
    assert (r.returncode, r.stdout, r.stderr) == (0, "", "")
    assert env_file.read_text() == "X=1\n"


@needs_compose
def test_a_host_network_on_the_default_subnet_is_avoided(stubs, tmp_path):
    routes = textwrap.dedent("""\
        default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.50 metric 100
        0.0.0.0/1 via 10.8.0.1 dev tun0
        128.0.0.0/1 via 10.8.0.1 dev tun0
        10.203.80.0/21 dev eth1 proto kernel scope link src 10.203.80.5
        local 10.203.80.5 dev eth1 table local proto kernel scope host src 10.203.80.5
        broadcast 10.203.87.255 dev eth1 table local proto kernel scope link
        local 127.0.0.0/8 dev lo table local proto kernel scope host src 127.0.0.1
        """)
    env = subnet_env(stubs, tmp_path, ["bridge 1111aaaa2222bbbb 172.17.0.0/16"], routes)
    r, env_file = ensure_subnet(tmp_path, env, "")
    assert r.returncode == 0, r.stderr
    assert "overlaps host route on eth1 (10.203.80.0/21)" in r.stdout
    assert "SIGRIFT_BACKEND_SUBNET=10.203.88.0/28\n" in env_file.read_text()


@needs_compose
def test_an_operator_backend_setting_is_never_rewritten(stubs, tmp_path):
    env = subnet_env(stubs, tmp_path, ["other_backend 9999aaaa0000bbbb 10.77.0.0/24"])
    text = (
        "SIGRIFT_BACKEND_SUBNET=10.77.0.0/24\n"
        "SIGRIFT_BACKEND_IP_RANGE=10.77.0.128/25\n"
        "SIGRIFT_GATEWAY_BACKEND_IP=10.77.0.2\n"
    )
    r, env_file = ensure_subnet(tmp_path, env, text)
    assert r.returncode == 0 and r.stdout == ""
    assert "WARNING" in r.stderr and "other_backend" in r.stderr
    assert "10.203.84.0/28" in r.stderr  # what is free
    assert env_file.read_text() == text
    # Exported in the shell counts as the operator's setting too.
    r, env_file = ensure_subnet(
        tmp_path, {**env, "SIGRIFT_BACKEND_SUBNET": "10.77.0.0/24"}, ""
    )
    assert "WARNING" in r.stderr and env_file.read_text() == ""


@needs_compose
def test_a_compose_file_that_fixes_the_subnet_only_gets_a_warning(stubs, tmp_path):
    compose = tmp_path / "fixed.yml"
    compose.write_text(
        textwrap.dedent("""\
            services:
              bridge:
                image: busybox
                networks: [backend]
                environment:
                  - BRIDGE_TRUSTED_PROXIES=10.203.84.2
              gateway:
                image: busybox
                networks:
                  backend:
                    ipv4_address: 10.203.84.2
            networks:
              backend:
                ipam:
                  config:
                    - subnet: 10.203.84.0/28
                      ip_range: 10.203.84.8/29
            """)
    )
    env = subnet_env(stubs, tmp_path, OTHER_STACK)
    r, env_file = ensure_subnet(tmp_path, env, "X=1\n", compose=compose)
    assert r.returncode == 0 and r.stdout == ""
    assert "does not take SIGRIFT_BACKEND_SUBNET" in r.stderr
    assert env_file.read_text() == "X=1\n"


# ── compose: proxy secret required (Q20), unbound node keys (K7) ─────────


@needs_compose
@pytest.mark.parametrize("overlays", STACKS)
def test_unbound_node_key_setting_reaches_bridge_and_gateway(tmp_path, overlays):
    files, project = stack_files(tmp_path, overlays)
    for extra in ({}, {"BRIDGE_ALLOW_UNBOUND_NODE_KEYS": "1"}):
        cfg = compose_cfg(files, project, **extra)
        for svc in ("bridge", "gateway"):
            env = cfg["services"][svc]["environment"]
            value = env["BRIDGE_ALLOW_UNBOUND_NODE_KEYS"]
            assert (value or "") == extra.get("BRIDGE_ALLOW_UNBOUND_NODE_KEYS", ""), svc


@needs_compose
@pytest.mark.parametrize("overlays", STACKS)
def test_csp_mode_setting_reaches_the_gateway(tmp_path, overlays):
    """UC_CSP_MODE, the documented diagnosis switch, comes from .env; unset
    or empty it is strict (never an empty value, which clap refuses)."""
    files, project = stack_files(tmp_path, overlays)
    for extra, expected in (
        ({}, "strict"),
        ({"UC_CSP_MODE": ""}, "strict"),
        ({"UC_CSP_MODE": "report-only"}, "report-only"),
    ):
        cfg = compose_cfg(files, project, **extra)
        assert cfg["services"]["gateway"]["environment"]["UC_CSP_MODE"] == expected
        assert "UC_CSP_MODE" not in cfg["services"]["bridge"]["environment"]


@needs_compose
@pytest.mark.parametrize("overlays", STACKS)
def test_the_bridge_is_unhealthy_without_a_proxy_secret(tmp_path, overlays):
    import http.server
    import sys
    import threading

    files, project = stack_files(tmp_path, overlays)
    test = compose_cfg(files, project)["services"]["bridge"]["healthcheck"]["test"]
    assert test[:3] == ["CMD", "python3", "-c"]

    class Ok(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(200 if self.path == "/api/healthz" else 404)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Ok)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        code = test[3].replace(
            "http://localhost:8001", f"http://127.0.0.1:{server.server_port}"
        )
        assert code != test[3]
        for secret, healthy in (
            (None, False),
            ("", False),
            ("uppercrust-internal", False),
            ("proxy-123456", True),
        ):
            env = {"PATH": os.environ["PATH"]}
            if secret is not None:
                env["UC_PROXY_SECRET"] = secret
            r = subprocess.run(
                [sys.executable, "-c", code], capture_output=True, text=True, env=env
            )
            assert (r.returncode == 0) == healthy, (secret, r.stderr)
            if not healthy:
                assert "UC_PROXY_SECRET is empty" in r.stderr
    finally:
        server.shutdown()


def test_docs_say_the_proxy_secret_is_required_in_every_mode():
    env_example = (ROOT / ".env.example").read_text()
    assert "UC_PROXY_SECRET is required in EVERY mode" in env_example
    assert "Required in production" not in env_example
    security = (ROOT / "SECURITY.md").read_text()
    assert "`UC_PROXY_SECRET`: optional" not in security
    assert "`UC_PROXY_SECRET`: **required with the shipped" in security
    # Neither service makes one up: the gateway only warns (builder.rs
    # check_startup_secrets) and sends the configured value, the bridge
    # only warns. The docs must not promise a generated secret.
    for text in (security, env_example):
        assert not re.search(
            r"(?<!Neither )(gateway|bridge|service)s?( then)? generates?"
            r"|auto-generated per",
            text,
        )
    assert "Neither service generates a\n  value" in security


def flat(text: str) -> str:
    """*text* with every run of whitespace (line wraps) made one space."""
    return " ".join(text.split())


def test_upgrade_notes_cover_node_certificates_binding_and_hooks():
    """What an upgrade changes for node credentials and hooks (V8, W4).

    A node client certificate acts only for the node its identity names,
    and agents send no API key while one is loaded, so per-agent
    certificates from the old PKI docs lose all ingest. The binding rules
    (node keys only, first key wins), the hook hand-over (asynchronous,
    spooled across a graceful gateway stop, disabled without
    UC_PROXY_SECRET) and the stop grace period must be in the notes.
    """
    install = (ROOT / "INSTALL.md").read_text()
    upgrading = flat(install.split("\n## Upgrading\n", 1)[1].split("\n## ", 1)[0])
    for needle in (
        "Node client certificates act only for the node their identity names",
        "the agents send no API key while a certificate is loaded",
        '`{"identity": "<MLRF_NODE_ID>", "role": "node"}`',
        "The first key to claim a node keeps it",
        "Node endpoints require a node API key",
        "An unbound `analyst` key is operator tooling",
        "`post_ingest_hooks.enabled: false`",
        "`gateway-post-ingest-hooks.spool`",
        "`stop_grace_period: 30s`",
    ):
        assert needle in upgrading, needle
    changelog = flat((ROOT / "CHANGELOG.md").read_text().split("\n## [0.1.0]")[0])
    assert (
        "Node client certificates act only for the node their identity names"
        in changelog
    )
    pki = (ROOT / "PKI_ARCHITECTURE.md").read_text()
    assert "(per agent)" not in pki and "gives each agent its own" not in pki
    assert "**Upgrading from per-agent certificates.**" in pki


def install_upgrading_section() -> str:
    install = (ROOT / "INSTALL.md").read_text()
    return flat(install.split("\n## Upgrading\n", 1)[1].split("\n## ", 1)[0])


def test_docs_say_hand_overs_are_dropped_while_the_bridge_is_down():
    """Only a gateway stop spools post-ingest hooks (K8b; IN5-R1).

    While the gateway runs, a hook the bridge does not take is retried
    `ATTEMPTS` times (`RetryTiming` backoff), then dropped and counted in
    `failed_*`. A bridge restart, or an upgrade that recreates the bridge
    while the old gateway still serves, therefore loses the alerts,
    webhooks and decode jobs of the batches ingested meanwhile. The
    upgrade notes and TROUBLESHOOTING must say so, with the gateway's
    numbers and log line, and not imply that every hand-over is kept.
    """
    hooks = (
        ROOT / "src/gateway/crates/sigrift-gateway-core/src/ingest/hooks.rs"
    ).read_text()
    attempts = re.search(r"pub const ATTEMPTS: usize = (\d+);", hooks)
    backoff = re.search(
        r"backoff: \[Duration::from_millis\((\d+)\), Duration::from_secs\((\d+)\)\]",
        hooks,
    )
    assert attempts and backoff
    # What the docs below say: 3 attempts, 0.5 s then 1 s apart.
    assert (attempts[1], backoff[1], backoff[2]) == ("3", "500", "1")
    drop_log = "Post-ingest hook failed after retries — dropped"
    assert f'"{drop_log}"' in hooks

    upgrading = install_upgrading_section()
    for needle in (
        "Only a gateway stop spools",
        "`docker compose restart bridge`",
        "an upgrade, which recreates the bridge while the old gateway is still serving",
        "tries each hand-over 3 times (0.5 s, then 1 s apart), then drops it",
        "`post_ingest_hooks.failed_batches` / `failed_detections`",
        f"`{drop_log}`",
    ):
        assert needle in upgrading, needle
    trouble = flat((ROOT / "TROUBLESHOOTING.md").read_text())
    assert "did not take it in 3 attempts (0.5 s, then 1 s apart)" in trouble
    assert "**dropped, not spooled** (only a gateway stop spools)" in trouble
    security = flat((ROOT / "SECURITY.md").read_text())
    assert "Only a gateway stop spools" in security
    changelog = flat((ROOT / "CHANGELOG.md").read_text().split("\n## [0.1.0]")[0])
    assert "are dropped after 3 attempts" in changelog


def test_docs_say_who_binds_without_the_proxy_secret_and_what_the_flag_keeps():
    """K10 and K7b as the services implement them (IN5-R2, IN5-R3).

    Without a usable UC_PROXY_SECRET only the gateway's detection ingest
    skips the binding: the bridge's own node routes bind a node key on
    first use without the secret (`enforce_node_binding` writes keys.json
    itself), and the gateway enforces that binding from then on. So the
    docs must not say that unbound node keys may act for any node in that
    mode. BRIDGE_ALLOW_UNBOUND_NODE_KEYS keeps node keys unbound; it does
    not make an unbound viewer key a node credential.
    """
    security = flat((ROOT / "SECURITY.md").read_text())
    upgrading = install_upgrading_section()
    bridge_binds = (
        "the bridge's own node routes (heartbeats, WiFi / BT ingest, node "
        "commands, IQ uploads) still bind such a key on first use"
    )
    for name, text in (("SECURITY.md", security), ("INSTALL.md", upgrading)):
        assert "unbound node keys may act for any node" not in text, name
        assert "unbound node keys may submit for any node" not in text, name
        assert bridge_binds in text, name
    assert (
        "(403 `Node endpoints require a node API key` on node routes, also "
        "with `BRIDGE_ALLOW_UNBOUND_NODE_KEYS=1`)"
    ) in security
    assert (
        "the key is never bound to a node; `BRIDGE_ALLOW_UNBOUND_NODE_KEYS=1` "
        "does not change that"
    ) in upgrading
    trouble = flat((ROOT / "TROUBLESHOOTING.md").read_text())
    assert "and a `viewer` key is still refused" in trouble
    changelog = flat((ROOT / "CHANGELOG.md").read_text().split("\n## [0.1.0]")[0])
    assert "it does not let `viewer` keys act for a node" in changelog


def test_an_old_release_compose_that_drops_the_unbound_setting_is_flagged(tmp_path):
    compose = install_release_compose(tmp_path)
    text = compose.read_text()
    old = re.sub(r"\n *- BRIDGE_ALLOW_UNBOUND_NODE_KEYS=[^\n]*", "", text)
    assert old != text
    compose.write_text(old)
    fn = function_text(INSTALL_RELEASE, "check_compose_gateway_env")
    (tmp_path / ".env").write_text("BRIDGE_ALLOW_UNBOUND_NODE_KEYS=1\n")
    r = bash(fn + f'check_compose_gateway_env "{compose}"', cwd=tmp_path)
    assert "BRIDGE_ALLOW_UNBOUND_NODE_KEYS is set" in r.stderr
    # Unset: nothing to say. The current file passes it to both.
    (tmp_path / ".env").write_text("X=1\n")
    assert (
        bash(fn + f'check_compose_gateway_env "{compose}"', cwd=tmp_path).stderr == ""
    )
    compose.write_text(text)
    (tmp_path / ".env").write_text("BRIDGE_ALLOW_UNBOUND_NODE_KEYS=1\n")
    assert (
        bash(fn + f'check_compose_gateway_env "{compose}"', cwd=tmp_path).stderr == ""
    )


# ── time to shut down (W3) ────────────────────────────────────────────────


def go_duration_seconds(text: str) -> float:
    """Seconds in a duration as `docker compose config` prints it ("30s", "1m30s")."""
    units = {"h": 3600, "m": 60, "s": 1, "ms": 1e-3, "us": 1e-6, "ns": 1e-9}
    parts = re.findall(r"(\d+(?:\.\d+)?)(ms|us|ns|h|m|s)", text)
    assert parts and "".join(n + u for n, u in parts) == text, text
    return sum(float(n) * units[u] for n, u in parts)


@needs_compose
@pytest.mark.parametrize("overlays", STACKS)
def test_bridge_and_gateway_get_time_to_shut_down(tmp_path, overlays):
    """Docker kills a container 10 s after SIGTERM unless told otherwise.

    The bridge's shutdown waits, bounded, for analysis jobs (5 s), the
    write queue (up to 10 s) and worker threads (5 s) and only then saves
    what changed and closes the database; the gateway spends up to 3 + 5 s
    on requests and queued hooks before it spools the rest. DEPLOYMENT.md
    asks for 30 s; every shipped stack must give it.
    """
    files, project = stack_files(tmp_path, overlays)
    services = compose_cfg(files, project)["services"]
    for svc in ("bridge", "gateway"):
        grace = services[svc].get("stop_grace_period")
        assert grace, f"{svc}: no stop_grace_period (Docker's default is 10 s)"
        assert go_duration_seconds(grace) >= 30, (svc, grace)


def test_an_old_release_compose_without_stop_grace_period_gets_a_note(tmp_path):
    compose = install_release_compose(tmp_path)
    text = compose.read_text()
    line = "    stop_grace_period: 30s\n"
    assert text.count(line) == 2  # bridge and gateway
    head, sep, tail = text.partition("\n  gateway:\n")
    fn = function_text(INSTALL_RELEASE, "check_compose_gateway_env")

    def note(content: str) -> str:
        compose.write_text(content)
        r = bash(fn + f'check_compose_gateway_env "{compose}"', cwd=tmp_path)
        assert r.returncode == 0
        return r.stderr

    assert "stop_grace_period for: bridge gateway." in note(text.replace(line, ""))
    # A commented-out setting is no setting.
    assert "for: bridge gateway." in note(text.replace(line, "    # " + line[4:]))
    only_gateway = note(head + sep + tail.replace(line, ""))
    assert "stop_grace_period for: gateway." in only_gateway
    assert "stop_grace_period: 30s" in only_gateway  # says what to add
    assert note(text) == ""


# ── set-aside CA keys are not committed (Q21) ─────────────────────────────


@needs_git
def test_set_aside_ca_keys_are_git_ignored():
    inside = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "--is-inside-work-tree"],
        capture_output=True,
        text=True,
    )
    if inside.stdout.strip() != "true":
        pytest.skip("not a git work tree")
    names = [
        # The from-source default secrets dir: everything in it.
        "src/sigrift/bridge/secrets/ca/ca.key",
        "src/sigrift/bridge/secrets/ca/ca.replaced.20261105T120000Z.key",
        "src/sigrift/bridge/secrets/ca/ca.legacy.20261105T120000Z.1.key",
        "src/sigrift/bridge/secrets/ca/ca.key.tmp",
        "src/sigrift/bridge/secrets/ca/ca.key.legacy.20261105T120000Z",
        "src/sigrift/bridge/secrets/other.txt",
        # A BRIDGE_SECRETS_DIR somewhere else in a checkout.
        "secrets/ca/ca.replaced.20261105T120000Z.key",
        "secrets/ca/ca.key.replaced.20261105T120000Z",  # older bridges' names
        "secrets/ca/ca.key.tmp",
    ]
    r = subprocess.run(
        ["git", "-C", str(ROOT), "check-ignore", "--no-index", *names],
        capture_output=True,
        text=True,
    )
    assert sorted(r.stdout.split()) == sorted(names), r.stderr
