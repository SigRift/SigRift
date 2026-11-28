"""Test helpers for the installers' lifecycle blocks (not collected).

FakeDockerHost puts a `docker` on PATH that plays a whole Docker host from
a JSON state file: Compose-labelled volumes and containers, local images,
and the engine (it answers the engine's requests from a small model of
each project's data, so the secrets checks see realistic verdicts). Every
call is logged with its argv, working directory and the names (never the
values) of the variables it saw, so tests can prove that no secret
reached argv and that a refusal started nothing.

READONLY_DOCKER_PY / READONLY_DOCKER_SH are lines for the strict fakes of
other tests: they answer the read-only queries of lc_identity with an
empty host.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INSTALL_RELEASE = ROOT / "scripts" / "install-release.sh"
QUICKSTART = ROOT / "scripts" / "quickstart.sh"
BASH = shutil.which("bash") or "/bin/bash"

# For a strict fake in Python whose argv list is `args`.
READONLY_DOCKER_PY = (
    "if args[:2] == ['volume', 'ls'] or (args[:1] == ['ps'] and "
    "any(a in ('-a', '-q') for a in args)):\n"
    "    sys.exit(0)  # lc_identity's read-only queries: an empty host\n"
)
# For a strict fake in sh.
READONLY_DOCKER_SH = (
    'case "$1 $2" in "volume ls"|"ps -a"|"ps -q") exit 0 ;; esac'
    "  # lc_identity's read-only queries: an empty host\n"
)

KEY_A = base64.urlsafe_b64encode(bytes(range(32))).decode()
KEY_B = base64.urlsafe_b64encode(bytes(range(32, 64))).decode()
KEY_C = base64.urlsafe_b64encode(bytes(range(64, 96))).decode()

INSTALLED_ENV = (
    f"BRIDGE_ENV=production\nBRIDGE_MFA_KEY={KEY_A}\n"
    "BRIDGE_AUDIT_KEY=audit-123456\nBRIDGE_MASTER_KEY=master-123456\n"
    "UC_PROXY_SECRET=proxy-123456\nBRIDGE_ADMIN_USER=admin\n"
    "BRIDGE_ADMIN_PASSWORD=correct-horse-battery\n"
    "UC_TLS_CERT=/app/tls/cert.pem\nUC_TLS_KEY=/app/tls/key.pem\n"
)
SECRET_VALUES = ("audit-123456", "master-123456", "proxy-123456",
                 "correct-horse-battery", KEY_A)


def shared_block(path: Path, name: str) -> str:
    text = path.read_text()
    m = re.search(rf"^# >>> shared: {re.escape(name)} .*?^# <<< shared: {re.escape(name)}\n",
                  text, re.S | re.M)
    assert m, f"shared block {name} missing in {path.name}"
    return m.group(0)


def lifecycle_tool_source(path: Path = INSTALL_RELEASE) -> str:
    block = shared_block(path, "lifecycle-tool")
    return re.search(r"LC_TOOL_SRC <<'PY' \|\| true\n(.*?)\nPY\n", block, re.S).group(1) + "\n"


def engine_source(path: Path = INSTALL_RELEASE) -> str:
    block = shared_block(path, "lifecycle-engine")
    return re.search(r"cat <<'PY'\n(.*?)\nPY\n", block, re.S).group(1) + "\n"


def load_lifecycle_tool(path: Path = INSTALL_RELEASE):
    """The lifecycle-tool heredoc of an installer, imported as a module."""
    import types

    module = types.ModuleType("lc_tool_under_test")
    module.__file__ = str(path)
    exec(compile(lifecycle_tool_source(path), "<lc_tool>", "exec"), module.__dict__)
    return module


def derive(name: str) -> str:
    return "".join(re.findall(r"[a-z0-9_-]", name.lower())).lstrip("_-")


def release_compose(version="v0.1.0", owner="sigrift", port="8444", keystore=False) -> str:
    """docker-compose.yml as install-release.sh's template writes it."""
    text = INSTALL_RELEASE.read_text()
    body = re.search(r"cat > docker-compose\.yml <<EOF\n(.*?)\nEOF\n", text, re.S).group(1)
    r = subprocess.run(
        [BASH, "-c", f"VERSION={version} OWNER={owner} PORT={port}\ncat <<EOF\n{body}\nEOF\n"],
        capture_output=True, text=True, check=True)
    out = r.stdout
    if not keystore:
        # The template of v0.1.x installs: without BRIDGE_KEYSTORE_KEY.
        out = re.sub(r"      # Key for the protocol decryption keys.*?\n.*?\n"
                     r"      - BRIDGE_KEYSTORE_KEY=\$\{BRIDGE_KEYSTORE_KEY:-\}\n", "", out, flags=re.S)
    return out


# ── the fake docker ───────────────────────────────────────────────────

FAKE_DOCKER = r'''
import base64, hashlib, hmac, json, os, re, sys, time
STATE = os.environ.get("FAKE_DOCKER_STATE") or __STATE__
LOG = os.path.join(os.path.dirname(STATE), "docker-log.jsonl")
args = sys.argv[1:]

def load():
    with open(STATE) as f:
        return json.load(f)

def save(st):
    tmp = STATE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(st, f, indent=1, sort_keys=True)
    os.replace(tmp, STATE)

st = load()
head = ""
try:
    with open("docker-compose.yml") as f:
        head = f.readline().rstrip("\n")
except OSError:
    pass
entry = {"argv": args, "cwd": os.getcwd(),
         "env_keys": sorted(k for k in os.environ if k.startswith(("BRIDGE_", "UC_", "COMPOSE_", "SIGRIFT_"))),
         "compose_file_head": head}
if st.get("watch_dir"):
    # The files of a folder at the time of this call (for "nothing changed
    # before the pull").
    h = hashlib.sha256()
    for root, dirs, files in sorted(os.walk(st["watch_dir"])):
        dirs.sort()
        for name in sorted(files):
            p = os.path.join(root, name)
            h.update(os.path.relpath(p, st["watch_dir"]).encode() + b"\0")
            try:
                h.update(open(p, "rb").read())
            except OSError:
                h.update(b"<unreadable>")
    entry["watch"] = h.hexdigest()
stdin_bytes = b""
if args[:1] == ["run"] and "-i" in args:
    stdin_bytes = sys.stdin.buffer.read()
    n = len([x for x in os.listdir(os.path.dirname(STATE)) if x.startswith("engine-stdin.")])
    with open(os.path.join(os.path.dirname(STATE), "engine-stdin.%d" % n), "wb") as f:
        f.write(stdin_bytes)
with open(LOG, "a") as f:
    f.write(json.dumps(entry) + "\n")

def fail_at():
    """fail_at: {argv regex: rc}, {argv regex: [rc, n]} (fail after the
    first n matching calls) or {argv regex: {"rc": rc, "skip": n,
    "env_has": text}} (only while ./.env contains text)."""
    joined = " ".join(args)
    for pat, rule in (st.get("fail_at") or {}).items():
        if not re.search(pat, joined):
            continue
        if isinstance(rule, list):
            rule = {"rc": rule[0], "skip": rule[1]}
        elif not isinstance(rule, dict):
            rule = {"rc": rule}
        if rule.get("env_has"):
            try:
                if rule["env_has"] not in open(".env").read():
                    continue
            except OSError:
                continue
        seen = st.setdefault("fail_counts", {}).get(pat, 0)
        st["fail_counts"][pat] = seen + 1
        save(st)
        if seen >= int(rule.get("skip", 0)):
            sys.exit(int(rule["rc"]))
fail_at()

def on_call():
    """on_call: [{"match": regex, "write": {path: text}, "spawn": container,
    "data": {volume: {key: value}}}], each applied once, before the first
    call that matches: something else changing the host mid-run."""
    joined = " ".join(args)
    changed = False
    for rule in st.get("on_call") or []:
        if rule.get("done") or not re.search(rule["match"], joined):
            continue
        rule["done"] = changed = True
        for path, text in (rule.get("write") or {}).items():
            with open(path, "w") as f:
                f.write(text)
        if rule.get("spawn"):
            st["containers"].append(rule["spawn"])
        for vol, kv in (rule.get("data") or {}).items():
            st.setdefault("data", {}).setdefault(vol, {}).update(kv)
    if changed:
        save(st)
on_call()

def out(text):
    sys.stdout.write(text)

def derive(name):
    return "".join(re.findall(r"[a-z0-9_-]", name.lower())).lstrip("_-")

def dotenv(path):
    vals = {}
    try:
        text = open(path, errors="replace").read()
    except OSError:
        return vals
    for line in text.splitlines():
        m = re.match(r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", line)
        if m:
            v = m.group(2).strip()
            if v[:1] in "'\"" and v[-1:] == v[:1]:
                v = v[1:-1]
            else:
                v = v.split(" #", 1)[0].strip()
            vals[m.group(1)] = v
    return vals

def compose_project(cwd, env_file=None):
    if env_file is not None:
        if st.get("compose_honours_env_file", True):
            p = dotenv(env_file).get("COMPOSE_PROJECT_NAME")
            if p:
                return p
    if os.environ.get("COMPOSE_PROJECT_NAME"):
        return os.environ["COMPOSE_PROJECT_NAME"]
    if env_file is None and st.get("compose_honours_env_file", True):
        p = dotenv(os.path.join(cwd, ".env")).get("COMPOSE_PROJECT_NAME")
        if p:
            return p
    return derive(os.path.basename(cwd))

def images_of(path):
    imgs = {}
    try:
        text = open(path).read()
    except OSError:
        return imgs
    svc = None
    for line in text.splitlines():
        m = re.match(r"^  ([a-z][a-z0-9_-]*):\s*$", line)
        if m:
            svc = m.group(1)
        m = re.match(r"^    image:\s*(\S+)", line)
        if m and svc:
            imgs[svc] = m.group(1)
    return imgs

def opt(name):
    if name in args:
        i = args.index(name)
        return args[i + 1] if i + 1 < len(args) else None
    for a in args:
        if a.startswith(name + "="):
            return a.split("=", 1)[1]
    return None

def containers_of(project):
    return [c for c in st["containers"] if c["project"] == project]

def container(ident):
    for c in st["containers"]:
        if ident in (c["id"], c["name"]) or c["id"].startswith(ident):
            return c
    return None

def label_filters():
    return [args[i + 1][len("label="):] for i, a in enumerate(args)
            if a == "--filter" and i + 1 < len(args) and args[i + 1].startswith("label=")]

def render(fmt, obj):
    def sub(m):
        expr = m.group(1).strip()
        lm = re.fullmatch(r'\.Label "([^"]+)"', expr)
        if lm:
            return obj.get("labels", {}).get(lm.group(1), "")
        if expr.startswith("json "):
            return json.dumps(obj.get(expr[5:].strip().lstrip(".")))
        return str(obj.get(expr.lstrip("."), ""))
    return re.sub(r"\{\{(.*?)\}\}", sub, fmt)

def vol_obj(v):
    return {"Name": v["name"], "labels": {"com.docker.compose.project": v["project"],
                                          "com.docker.compose.volume": v["volume"]}}

def cont_obj(c):
    status = ("Up 2 minutes (%s)" % ((st.get("health") or {}).get(c["service"], "healthy"))
              if c["state"] == "running" else "Exited (0) 1 minute ago")
    labels = {"com.docker.compose.project": c["project"],
              "com.docker.compose.service": c["service"],
              "com.docker.compose.project.working_dir": c.get("working_dir", "")}
    labels.update(c.get("labels") or {})
    return {"ID": c["id"], "Names": c["name"], "State": c["state"], "Image": c["image"],
            "Status": status,
            "Mounts": ",".join(c.get("mounts") or []), "Ports": c.get("ports", ""),
            "labels": labels}

def matches(labels, filters):
    for f in filters:
        k, sep, v = f.partition("=")
        if k not in labels or (sep and labels[k] != v):
            return False
    return True

# ── engine ──
def fp(secret, name):
    return hmac.new(secret, b"sigrift-key-fingerprint-v1:" + name.encode(), hashlib.sha256).hexdigest()[:32]

def keyb(k):
    try:
        raw = base64.b64decode(k.strip().replace("-", "+").replace("_", "/"), validate=True)
        return raw if len(raw) == 32 and len(k.strip()) == 44 else None
    except Exception:
        return None

def audit_eff(vals, data=None):
    for name, src in (("BRIDGE_AUDIT_KEY", "env-key"), ("BRIDGE_AUDIT_SECRET", "legacy-secret")):
        if (vals.get(name) or "").strip():
            return src, hashlib.sha256(vals[name].strip().encode()).digest()
    if (vals.get("BRIDGE_MASTER_KEY") or "").strip():
        return "master", hashlib.sha256(b"bridge-audit-hmac:" + vals["BRIDGE_MASTER_KEY"].strip().encode()).digest()
    if data and data.get("audit_file"):
        # The volume's own audit.key (a development install).
        return "file", hashlib.sha256(data["audit_file"].encode()).digest()
    return "none", None

def evaluate(vals, data):
    unknown = bool(data.get("encrypted") or data.get("db_error"))
    mfa = vals.get("BRIDGE_MFA_KEY") or ""
    if not mfa:
        m = "missing"
    elif keyb(mfa) is None:
        m = "invalid-key"
    elif unknown:
        m = "unchecked"
    elif not data.get("totp_fernet"):
        m = "n/a"
    else:
        m = "ok" if keyb(mfa) == keyb(data.get("mfa_key") or "") else "fail"
    src, sec = audit_eff(vals, data)
    a = {"result": "n/a", "source": src, "valid": None, "checked": 0, "mismatches": 0}
    rows = data.get("audit_rows", 0)
    if unknown:
        a["result"] = "unchecked"
    elif sec is None:
        a["result"] = "no-key" if rows else "n/a"
    elif rows:
        _, want = audit_eff(data.get("audit_values") or {}, data)
        good = sec == want
        a.update(result="ok" if good else "fail", valid=good, checked=rows,
                 mismatches=0 if good else rows)
    ks = vals.get("BRIDGE_KEYSTORE_KEY") or ""
    return {"mfa": m, "audit": a, "keystore": {"present": bool(ks), "valid": keyb(ks) is not None if ks else None},
            "fingerprints": {"audit": fp(sec, "audit") if sec else None,
                             "mfa": fp(keyb(mfa), "mfa") if keyb(mfa) else None,
                             "keystore": fp(keyb(ks), "keystore") if keyb(ks) else None}}

def image_info(image):
    """A local image by reference or by id (sha256:...)."""
    imgs = st.get("images") or {}
    if image in imgs:
        return imgs[image]
    for ref, info in imgs.items():
        if image in (info.get("id"), "sha256:" + hashlib.sha256(ref.encode()).hexdigest()):
            return info
    return {}

def engine(image):
    r = stdin_bytes
    def rec(buf):
        nl = buf.index(b"\n")
        n = int(buf[:nl])
        return buf[nl + 1: nl + 1 + n], buf[nl + 1 + n:]
    src, rest = rec(r)
    reqb, rest = rec(rest)
    req = json.loads(reqb)
    vol = None
    for i, a in enumerate(args):
        if a == "-v" and args[i + 1].endswith(":" + req["data_dir"]):
            vol = args[i + 1].split(":", 1)[0]
    data = (st.get("data") or {}).get(vol or "", {})
    op = req["op"]
    replies = st.get("engine_replies") or {}
    if op in replies:
        out(json.dumps(replies[op]))
        sys.exit(0 if replies[op].get("ok") else 1)
    if op == "image-info":
        info = image_info(image)
        out(json.dumps({"format": 1, "ok": True, "op": "image-info",
                        "newest_migration": info.get("newest_migration", 56), "python": "3.11.9"}))
        return
    if op == "write-record":
        rec_ = dict(req.get("record") or {})
        secrets = req.get("secrets") or {}
        src_, sec = audit_eff(secrets)
        rec_["fingerprints"] = {"audit": {"source": src_, "fp": fp(sec, "audit") if sec else None},
                                "mfa": fp(keyb(secrets.get("BRIDGE_MFA_KEY") or ""), "mfa") if keyb(secrets.get("BRIDGE_MFA_KEY") or "") else None,
                                "keystore": None}
        rec_.setdefault("schema", data.get("schema"))
        st.setdefault("records", {})[vol] = rec_
        save(st)
        out(json.dumps({"format": 1, "ok": True, "op": "write-record"}))
        return
    if not data.get("readable", True):
        out(json.dumps({"format": 1, "ok": False, "error": "OperationalError: unable to open database file"}))
        sys.exit(1)
    counts = {"users": data.get("users", 1), "totp_fernet": data.get("totp_fernet", 0),
              "audit_rows": data.get("audit_rows", 0),
              "audit_head_id": data.get("audit_head_id", data.get("audit_rows") or None),
              "crypto_keys": data.get("crypto_keys", 0), "detections_max_id": data.get("detections_max_id")}
    if data.get("encrypted") or data.get("db_error"):
        # The engine could not read the database: every count unknown.
        counts = dict((k, None) for k in counts)
    markers = [m for m in ("bridge_data", "bridge_secrets") if m in (
        data.get("restore_markers") or (["bridge_data"] if data.get("restore_marker") else []))]
    facts = {"format": 1, "ok": True, "op": "facts", "data_dir_exists": True,
             "db": {"present": True, "encrypted": bool(data.get("encrypted")),
                    "bytes": data.get("db_bytes", 4096), "wal_bytes": 0,
                    "schema": None if data.get("encrypted") or data.get("db_error")
                    else data.get("schema", 56), "error": data.get("db_error")},
             "counts": counts, "restore_marker": bool(markers), "restore_markers": markers,
             "record": (st.get("records") or {}).get(vol), "candidates": {}}
    for source, vals in (req.get("candidates") or {}).items():
        if vals is None:
            facts["candidates"][source] = None
        elif vals.get("same_as"):
            facts["candidates"][source] = {"same_as": vals["same_as"]}
        else:
            facts["candidates"][source] = evaluate(vals, data)
    out(json.dumps(facts))

cmd = args[0] if args else ""
if cmd == "compose":
    rest = args[1:]
    env_file = opt("--env-file")
    pdir = opt("--project-directory") or os.getcwd()
    files = [args[i + 1] for i, a in enumerate(args) if a == "-f"]
    project = compose_project(pdir, env_file)
    with open(LOG + ".projects", "a") as f:
        f.write(json.dumps({"argv": args, "project": project}) + "\n")
    sub = [a for a in rest if not a.startswith("-")]
    # the first word that is a compose subcommand
    verbs = ("version", "config", "ps", "up", "pull", "stop", "start", "logs", "port", "down", "create", "images", "build")
    verb = next((a for a in rest if a in verbs), "")
    if verb == "version":
        out("Docker Compose version v2.29.0\n"); sys.exit(0)
    if verb == "config":
        if "--services" in rest:
            out("bridge\ngateway\n"); sys.exit(0)
        if "--environment" in rest:
            for k, v in dotenv(".env").items():
                out("%s=%s\n" % (k, v))
            sys.exit(0)
        imgs = images_of(files[0] if files else "docker-compose.yml")
        out(json.dumps({"name": project, "services": dict((s, {"image": i}) for s, i in imgs.items())}) + "\n")
        sys.exit(0)
    if verb == "pull":
        sys.exit(int(st.get("compose_pull_rc", 0)))
    if verb == "up":
        rc = int(st.get("compose_up_rc", 0))
        if rc:
            sys.exit(rc)
        imgs = images_of("docker-compose.yml")
        targets = [a for a in rest[rest.index("up") + 1:] if not a.startswith("-") and a not in ("never", "always", "missing")]
        exits = st.get("exit_on_up") or {}
        for svc in (targets or [s for s in imgs]):
            name = "%s-%s-1" % (project, svc)
            c = container(name)
            if c is None:
                c = {"id": hashlib.sha256(name.encode()).hexdigest()[:12], "name": name, "project": project,
                     "service": svc, "state": "running", "image": imgs.get(svc, ""), "env": {}, "mounts": [], "ports": ""}
                st["containers"].append(c)
            if st.get("up_sleep") and svc in targets:
                time.sleep(float(st["up_sleep"]))
            if "--no-recreate" in rest and c.get("env"):
                # An existing container starts as it was (its image and env).
                c.update(state="exited" if exits.get(svc) else "running", started_at=time.time())
                continue
            c.update(state="exited" if exits.get(svc) else "running", working_dir=os.getcwd(),
                     image=imgs.get(svc, c.get("image", "")), env=dotenv(".env"), started_at=time.time())
            c.pop("image_id", None)
            if (st.get("images") or {}).get(c["image"], {}).get("id"):
                c["image_id"] = st["images"][c["image"]]["id"]
            if svc == "bridge" and st.get("migrate_on_up", True):
                # The new bridge applies its migrations at start-up.
                newest = (st.get("images") or {}).get(c["image"], {}).get("newest_migration")
                d = (st.get("data") or {}).get("%s_bridge_data" % project)
                if d is not None and newest:
                    d["schema"] = max(int(d.get("schema", 0) or 0), int(newest))
            if svc == "bridge":
                for v in ("bridge_data", "bridge_secrets"):
                    vname = "%s_%s" % (project, v)
                    if not any(x["name"] == vname for x in st["volumes"]):
                        st["volumes"].append({"name": vname, "project": project, "volume": v})
                c["mounts"] = ["%s_bridge_data" % project, "%s_bridge_secrets" % project]
            if svc == "gateway":
                c["mounts"] = ["%s_bridge_data" % project]
                c["ports"] = "127.0.0.1:%s->8444/tcp" % st.get("published_port", "8444")
        save(st)
        sys.exit(0)
    if verb == "ps":
        cs = [c for c in containers_of(project) if "--all" in rest or "-a" in rest or c["state"] == "running"]
        names = [a for a in rest[rest.index("ps") + 1:] if not a.startswith("-") and a not in ("json",)]
        if names:
            cs = [c for c in cs if c["service"] in names]
        if "-q" in rest:
            out("".join(c["id"] + "\n" for c in cs)); sys.exit(0)
        health = st.get("health") or {}
        seqs = st.get("health_seq") or {}
        for c in cs:
            h = health.get(c["service"], "healthy")
            seq = seqs.get(c["service"])
            if seq:
                # One health reading per poll (a bridge that takes a while).
                h = seq.pop(0)
                save(st)
            out(json.dumps({"Service": c["service"], "State": c["state"],
                            "Health": h if c["state"] == "running" else ""}) + "\n")
        sys.exit(0)
    if verb == "logs":
        seq = st.get("migration_logs") or []
        n = seq.pop(0) if len(seq) > 1 else (seq[0] if seq else 0)
        save(st)
        out("".join("bridge-1  | Migration %d applied: test\n" % (57 + i) for i in range(n)))
        sys.exit(0)
    if verb in ("stop", "start"):
        names = [a for a in rest[rest.index(verb) + 1:] if not a.startswith("-")]
        for c in containers_of(project):
            if not names or c["service"] in names:
                c["state"] = "exited" if verb == "stop" else "running"
        save(st)
        sys.exit(0)
    if verb == "port":
        out("127.0.0.1:%s\n" % st.get("published_port", "8444")); sys.exit(0)
    if verb in ("down", "create", "images", "build"):
        sys.exit(0)
    sys.exit(0)
if cmd == "volume" and args[1:2] == ["ls"]:
    fmt = opt("--format") or "{{.Name}}"
    filt = label_filters()
    for v in st["volumes"]:
        if matches(vol_obj(v)["labels"], filt):
            out((v["name"] if "-q" in args else render(fmt, vol_obj(v))) + "\n")
    sys.exit(0)
if cmd == "ps":
    fmt = opt("--format") or "{{.ID}}"
    filt = label_filters()
    vols = [args[i + 1][len("volume="):] for i, a in enumerate(args) if a == "--filter" and args[i + 1].startswith("volume=")]
    for c in st["containers"]:
        if "-a" not in args and c["state"] != "running":
            continue
        o = cont_obj(c)
        if not matches(o["labels"], filt):
            continue
        if vols and not any(v in (c.get("mounts") or []) for v in vols):
            continue
        out((c["id"] if "-q" in args else render(fmt, o)) + "\n")
    sys.exit(0)
if cmd == "inspect":
    fmt = opt("--format") or opt("-f") or ""
    ident = args[-1]
    c = container(ident)
    if c is None:
        sys.exit(1)
    if "Config.Env" in fmt:
        out(json.dumps(["%s=%s" % kv for kv in sorted((c.get("env") or {}).items())]) + "\n")
    elif ".Image" in fmt:
        out(c.get("image_id") or "sha256:" + hashlib.sha256(c.get("image", "").encode()).hexdigest() + "\n")
    else:
        out("%s %s\n" % (c["service"], time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())))
    sys.exit(0)
if cmd == "image" and args[1:2] == ["inspect"]:
    ref = args[-1]
    imgs = st.get("images") or {}
    fmt = opt("--format") or ""
    if ref in imgs or ref.startswith("sha256:"):
        if "RepoDigests" in fmt:
            out(ref.rsplit(":", 1)[0] + "@sha256:" + hashlib.sha256(("digest:" + ref).encode()).hexdigest() + "\n")
        else:
            out((imgs.get(ref, {}).get("id") or "sha256:" + hashlib.sha256(ref.encode()).hexdigest()) + "\n")
        sys.exit(0)
    sys.exit(1)
if cmd == "pull":
    rc = int((st.get("pull_rc") or {}).get(args[-1], st.get("pull_rc_default", 0)))
    if rc == 0:
        st.setdefault("images", {}).setdefault(args[-1], dict((st.get("registry") or {}).get(args[-1], {})))
        save(st)
    sys.exit(rc)
if cmd == "run":
    if "--entrypoint" in args and "python3" in args:
        image = args[args.index("-c") - 1]
        engine(image)
        sys.exit(0)
    mounts = [args[i + 1] for i, a in enumerate(args) if a == "-v"]
    tls = [m for m in mounts if m.split(":")[1:2] == ["/tls"]]
    if tls and "cat" in args and args[-1].startswith("/tls/"):
        # The helper (root in a container) reads a file this user cannot.
        path = os.path.join(tls[0].split(":")[0], args[-1][len("/tls/"):])
        mode = os.stat(path).st_mode
        os.chmod(path, 0o600)
        try:
            sys.stdout.buffer.write(open(path, "rb").read())
        finally:
            os.chmod(path, mode)
        sys.exit(0)
    if tls and "sh" in args and any("cat >" in a for a in args):
        d = tls[0].split(":")[0]
        path = os.path.join(d, args[-1])
        mode = os.stat(d).st_mode
        os.chmod(d, 0o700)
        try:
            with open(path + ".sigrift-new", "wb") as f:
                f.write(stdin_bytes)
            os.replace(path + ".sigrift-new", path)
        finally:
            os.chmod(d, mode)
        sys.exit(0)
    if "cat" in args or "head" in args:
        target = args[-1]
        for i, a in enumerate(args):
            if a == "-v":
                vol, _, mnt = args[i + 1].partition(":")
                mnt = mnt.split(":")[0]
                if target.startswith(mnt + "/") and target.endswith(".sigrift-install.json"):
                    rec_ = (st.get("records") or {}).get(vol)
                    if rec_ is None:
                        sys.exit(1)
                    out(json.dumps(rec_)); sys.exit(0)
        sys.exit(1)
    sys.exit(0)
if cmd == "info":
    fmt = opt("--format") or ""
    if "DockerRootDir" in fmt:
        out(st.get("docker_root", "/var/lib/docker") + "\n"); sys.exit(0)
    out(st.get("daemon_id", "fakehost:FAKE-DAEMON-ID") + "\n"); sys.exit(0)
if cmd == "network":
    sys.exit(0)
if cmd == "stop":
    idents = []
    skip = False
    for a in args[1:]:
        if skip:
            skip = False
            continue
        if a in ("--time", "-t"):
            skip = True
            continue
        if not a.startswith("-"):
            idents.append(a)
    for ident in idents:
        c = container(ident)
        if c:
            c["state"] = "exited"
    save(st); sys.exit(0)
sys.exit(0)
'''


class FakeDockerHost:
    """A Docker host in a JSON file, with `docker`, `date` and `sleep` on PATH."""

    def __init__(self, tmp_path: Path):
        self.tmp = tmp_path
        self.dir = tmp_path / "fake-docker"
        self.dir.mkdir()
        self.bin = tmp_path / "fake-bin"
        self.bin.mkdir()
        self.state_path = self.dir / "docker-state.json"
        self.log_path = self.dir / "docker-log.jsonl"
        self.state = {"volumes": [], "containers": [], "images": {}, "data": {}, "records": {}}
        self.save()
        docker = self.bin / "docker"
        # -IS: no site-packages to scan on each of the hundreds of calls.
        docker.write_text(f"#!{sys.executable} -IS\n"
                          + FAKE_DOCKER.replace("__STATE__", repr(str(self.state_path))))
        docker.chmod(0o755)
        real_date = shutil.which("date")
        clock = self.dir / "clock"
        (self.bin / "date").write_text(textwrap.dedent(f"""\
            #!/bin/sh
            if [ "$1" = +%s ]; then
                n=$(( $(cat "{clock}" 2>/dev/null || echo 1700000000) + ${{FAKE_CLOCK_STEP:-3}} ))
                echo "$n" > "{clock}"
                echo "$n"
            else
                exec "{real_date}" "$@"
            fi
            """))
        (self.bin / "date").chmod(0o755)
        (self.bin / "sleep").write_text("#!/bin/sh\nexit 0\n")
        (self.bin / "sleep").chmod(0o755)
        (self.bin / "hostname").write_text("#!/bin/sh\necho sensor\n")
        (self.bin / "hostname").chmod(0o755)
        (self.bin / "ip").write_text("#!/bin/sh\nexit 0\n")
        (self.bin / "ip").chmod(0o755)

    # state
    def load(self) -> dict:
        self.state = json.loads(self.state_path.read_text())
        return self.state

    def save(self) -> None:
        self.state_path.write_text(json.dumps(self.state, indent=1, sort_keys=True))

    def update(self, **kw) -> None:
        self.load()
        self.state.update(kw)
        self.save()

    def add_project(self, project, folder=None, *, running=True, containers=True,
                    image="ghcr.io/sigrift/sigrift-bridge:v0.1.0", gateway_image=None,
                    env=None, port="8444", data=None, record=None):
        self.load()
        for v in ("bridge_data", "bridge_secrets"):
            self.state["volumes"].append({"name": f"{project}_{v}", "project": project, "volume": v})
        if containers:
            for svc, img in (("bridge", image),
                             ("gateway", gateway_image or image.replace("sigrift-bridge", "sigrift-gateway"))):
                name = f"{project}-{svc}-1"
                self.state["containers"].append({
                    "id": hashlib.sha256(name.encode()).hexdigest()[:12], "name": name,
                    "project": project, "service": svc, "working_dir": str(folder or ""),
                    "state": "running" if running else "exited", "image": img,
                    "env": dict(env or {}),
                    "mounts": [f"{project}_bridge_data"] + ([f"{project}_bridge_secrets"] if svc == "bridge" else []),
                    "ports": f"127.0.0.1:{port}->8444/tcp" if svc == "gateway" and running else ""})
        self.state["data"][f"{project}_bridge_data"] = dict(data or {})
        if record is not None:
            self.state["records"][f"{project}_bridge_data"] = record
        self.save()

    def add_image(self, ref, newest_migration=56):
        self.load()
        self.state["images"][ref] = {"newest_migration": newest_migration}
        self.save()

    # log
    def calls(self) -> list[dict]:
        if not self.log_path.exists():
            return []
        return [json.loads(line) for line in self.log_path.read_text().splitlines() if line]

    def compose_projects(self) -> list[tuple[str, str]]:
        """(argv, project) of every compose call: the project it resolved."""
        p = Path(str(self.log_path) + ".projects")
        if not p.exists():
            return []
        rows = [json.loads(line) for line in p.read_text().splitlines() if line]
        return [(" ".join(r["argv"]), r["project"]) for r in rows]

    def argvs(self) -> list[str]:
        return [" ".join(c["argv"]) for c in self.calls()]

    def clear_log(self) -> None:
        for p in (self.log_path, Path(str(self.log_path) + ".projects")):
            if p.exists():
                p.unlink()
        for p in self.dir.glob("engine-stdin.*"):
            p.unlink()

    def engine_inputs(self) -> list[bytes]:
        return [p.read_bytes() for p in sorted(self.dir.glob("engine-stdin.*"))]

    def env(self, **extra) -> dict:
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(("COMPOSE_", "BRIDGE_", "SIGRIFT_", "UC_", "DOCKER_"))}
        env.update({"PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}", "LC_ALL": "C",
                    "HOME": str(self.tmp), "FAKE_DOCKER_STATE": str(self.state_path),
                    "SIGRIFT_UPGRADE_PROMPT_SECONDS": "0"})
        env.update({k: str(v) for k, v in extra.items()})
        return env


def release_install(host: FakeDockerHost, tmp_path: Path, name="sigrift-v0.1.0",
                    version="v0.1.0", env=INSTALLED_ENV, running=True, pinned=False,
                    data=None, containers=True, keystore=False, port="8444",
                    parent: Path | None = None) -> Path:
    """A release install folder plus its stack on the fake host."""
    d = (parent or tmp_path) / name
    d.mkdir(parents=True)
    shutil.copy(INSTALL_RELEASE, d / "install-release.sh")
    (d / "VERSION").write_text(version + "\n")
    (d / "docker-compose.yml").write_text(release_compose(version, port=port, keystore=keystore))
    (d / "docker-compose.override.yml").write_text(
        "services:\n  gateway:\n    volumes:\n      - ./tls:/app/tls:ro\n")
    project = derive(name)
    text = env + (f"COMPOSE_PROJECT_NAME={project}\n" if pinned else "")
    (d / ".env").write_text(text)
    (d / ".env").chmod(0o600)
    container_env = {k: v for k, v in (line.split("=", 1) for line in env.splitlines() if "=" in line)}
    model = {"users": 1, "totp_fernet": 2, "mfa_key": KEY_A, "audit_rows": 40,
             "audit_values": {"BRIDGE_AUDIT_KEY": "audit-123456"}, "crypto_keys": 0, "schema": 56}
    model.update(data or {})
    host.add_project(project, d, running=running, containers=containers,
                     image=f"ghcr.io/sigrift/sigrift-bridge:{version}", env=container_env,
                     port=port, data=model)
    host.add_image(f"ghcr.io/sigrift/sigrift-bridge:{version}")
    host.add_image(f"ghcr.io/sigrift/sigrift-gateway:{version}")
    return d


def unpacked_release(tmp_path: Path, version="v0.2.0", name=None) -> Path:
    d = tmp_path / (name or f"sigrift-{version}")
    d.mkdir()
    shutil.copy(INSTALL_RELEASE, d / "install-release.sh")
    (d / "VERSION").write_text(version + "\n")
    for f in ("LICENSE", "NOTICE"):
        shutil.copy(ROOT / f, d / f)
    (d / "THIRD-PARTY-NOTICES.txt").write_text("notices\n")
    (d / "README-INSTALL.txt").write_text("readme\n")
    return d


def source_checkout(tmp_path: Path, name="SigRift", env=None) -> Path:
    d = tmp_path / name
    (d / "scripts").mkdir(parents=True)
    shutil.copy(QUICKSTART, d / "scripts" / "quickstart.sh")
    shutil.copy(ROOT / "docker-compose.yml", d / "docker-compose.yml")
    if env is not None:
        (d / ".env").write_text(env)
        (d / ".env").chmod(0o600)
    return d


def run_installer(folder: Path, *args, host: FakeDockerHost, tty=False, answer=None,
                  env=None, script="install-release.sh", stdin="", timeout=300):
    full = host.env(**(env or {}))
    cmd = [BASH, str(folder / script), *args]
    if not tty:
        return subprocess.run(cmd, capture_output=True, text=True, cwd=folder, env=full,
                              input=stdin, timeout=timeout)
    import pty
    import select

    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(folder)
        os.execve(BASH, cmd, full)
    output = b""
    sent = False
    deadline = __import__("time").time() + timeout
    status = None
    while True:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                chunk = b""
            if not chunk:
                break
            output += chunk
            if answer is not None and not sent and b"Upgrade it now?" in output:
                os.write(fd, (answer + "\n").encode())
                sent = True
        done, st = os.waitpid(pid, os.WNOHANG)
        if done:
            status = st
            try:
                while True:
                    chunk = os.read(fd, 4096)
                    if not chunk:
                        break
                    output += chunk
            except OSError:
                pass
            break
        if __import__("time").time() > deadline:
            os.kill(pid, 9)
            break
    if status is None:
        _, status = os.waitpid(pid, 0)
    os.close(fd)
    text = output.decode("utf-8", "replace").replace("\r\n", "\n")
    return subprocess.CompletedProcess(cmd, os.waitstatus_to_exitcode(status), text, text)


def tree_digest(*folders: Path) -> dict:
    """sha256 and mode of every file under the folders."""
    out = {}
    for folder in folders:
        for p in sorted(Path(folder).rglob("*")):
            if p.is_file() or p.is_symlink():
                data = p.read_bytes() if p.is_file() and os.access(p, os.R_OK) else b"<unreadable>"
                out[str(p)] = (hashlib.sha256(data).hexdigest(), p.lstat().st_mode)
    return out


CHANGING = re.compile(r"^(compose (.* )?(up|stop|start|down|create)\b|stop |volume create|run -d)")


def changing_calls(host: FakeDockerHost) -> list[str]:
    """Logged docker calls that start, stop or change something."""
    return [a for a in host.argvs() if CHANGING.search(a)]
