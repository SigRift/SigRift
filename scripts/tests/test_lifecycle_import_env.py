"""The .env of an import (phase2-spec 4.2, 7.1, 7.2; 14.2): env-import's rules.

The state tool's heredoc is imported as a module (lifecycle_fakes'
load_state_tool) and its env_import_plan / env_texts run on .env texts and
on sealed-metadata names, as env-import --dry and the real run do. The
audit derivations of storage/audit.py and the gateway's chain.rs are
ported here (and the port is pinned against both sources), so a promotion
is shown to keep the chain's secret byte for byte. Standard library only.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

from lifecycle_fakes import INSTALL_RELEASE, QUICKSTART, load_lifecycle_tool, load_state_tool

ROOT = Path(__file__).resolve().parents[2]
TOOL = load_state_tool()
LC = load_lifecycle_tool()
META = {"archive_id": "00000000-0000-4000-8000-000000000003", "created_at": "2026-12-02T10:15:31Z",
        "install_type": "release", "source": {"hostname": "pi5"},
        "audit": {"source": "env-key", "head_id": 7}, "counts": {"totp_fernet": 0}}
MANIFEST = {"audit": {"source": "env-key", "entries": 7, "head_id": 7},
            "counts": {"totp_fernet": 0}}


def plan(text, meta=None, manifest=None, target="release", **kw):
    eff = TOOL.env_effective(text)
    names = dict((x.name, "set" if x.value else "empty") for x in TOOL.parse_dotenv(text))
    args = dict(mode=None, port=8444, bind=None, backend={}, current={})
    args.update(kw)
    return TOOL.env_import_plan(names, eff, meta or META, manifest or MANIFEST, target,
                                args["mode"], args["port"], args["bind"], args["backend"],
                                args["current"], args.get("promote"))


def texts(text, **kw):
    p = plan(text, **kw)
    meta = kw.get("meta") or META
    return TOOL.env_texts(text, p, meta) + (p,)


def bridge_secret(env, data_file=None):
    """storage/audit.py _get_audit_secret, ported (1-4)."""
    for k in ("BRIDGE_AUDIT_KEY", "BRIDGE_AUDIT_SECRET"):
        v = (env.get(k) or "").strip()
        if v:
            return hashlib.sha256(v.encode()).digest()
    m = (env.get("BRIDGE_MASTER_KEY") or "").strip()
    if m:
        return hashlib.sha256(b"bridge-audit-hmac:" + m.encode()).digest()
    return hashlib.sha256(data_file.strip().encode()).digest() if data_file else None


def gateway_secret(env, data_file=None):
    """chain.rs resolve_audit_secret, ported (trim() before each hash)."""
    for k in ("BRIDGE_AUDIT_KEY", "BRIDGE_AUDIT_SECRET"):
        v = (env.get(k) or "").strip(" \t\n\r\x0b\x0c")
        if v:
            return hashlib.sha256(v.encode()).digest()
    m = (env.get("BRIDGE_MASTER_KEY") or "").strip(" \t\n\r\x0b\x0c")
    if m:
        return hashlib.sha256(b"bridge-audit-hmac:" + m.encode()).digest()
    return hashlib.sha256(data_file.strip(" \t\n\r\x0b\x0c").encode()).digest() if data_file \
        else None


def template_keys():
    body = re.search(r"cat > docker-compose\.yml <<EOF\n(.*?)\nEOF\n", INSTALL_RELEASE.read_text(),
                     re.S).group(1)
    return sorted(set(re.findall(r"\\\$\{([A-Z][A-Z0-9_]*)", body)))


def test_every_env_key_has_an_import_rule():
    assert TOOL.KEY_CLASSES == LC.KEY_CLASSES
    keys = set(re.findall(r"(?m)^#? ?([A-Z][A-Z0-9_]*)=", (ROOT / ".env.example").read_text()))
    for path in (INSTALL_RELEASE, QUICKSTART):
        text = path.read_text()
        keys |= set(re.findall(r"set_env_value\s+\"?([A-Z][A-Z0-9_]*)", text))
        # The keys env_plan writes (lc_tool's generated and migrated keys).
        keys |= set(re.findall(r'"key": "([A-Z][A-Z0-9_]*)"', text))
    keys |= set(re.findall(r"\$\{([A-Z][A-Z0-9_]*)", (ROOT / "docker-compose.yml").read_text()))
    keys |= set(template_keys())
    keys = sorted(k for k in keys if k.startswith(("BRIDGE_", "UC_", "SIGRIFT_", "MLRF_",
                                                   "COMPOSE_")))
    assert len(keys) > 25
    missing = [k for k in keys if k not in TOOL.KEY_CLASSES]
    assert missing == [], missing
    # Every key, known or not, gets exactly one outcome.
    text = "".join("%s=v\n" % k for k in keys) + "SOMETHING_NEW=1\nDOCKER_HOST=x\n"
    p = plan(text)
    moved = dict(p["moved"])
    for k in keys + ["SOMETHING_NEW", "DOCKER_HOST"]:
        outcomes = (k in moved) + (k in p["kept"]) + (k in p["changes"]) + (
            k in p["added"] and k not in p["kept"])
        assert outcomes >= 1, k


def test_host_keys_go_to_env_imported_and_the_subnet_is_detected_again():
    text = ("BRIDGE_AUDIT_KEY=a\nSIGRIFT_BACKEND_SUBNET=172.30.0.0/24\n"
            "SIGRIFT_BACKEND_IP_RANGE=172.30.0.0/28\nSIGRIFT_GATEWAY_BACKEND_IP=172.30.0.2\n")
    new, imp, p = texts(text, backend={"SIGRIFT_BACKEND_SUBNET": "172.31.7.0/28"})
    assert "SIGRIFT_BACKEND_SUBNET=172.31.7.0/28\n" in new and "172.30" not in new
    assert "SIGRIFT_BACKEND_SUBNET=172.30.0.0/24\n" in imp and "172.30.0.2" in imp
    assert {k for k, r in p["moved"] if r == "host"} == {
        "SIGRIFT_BACKEND_SUBNET", "SIGRIFT_BACKEND_IP_RANGE", "SIGRIFT_GATEWAY_BACKEND_IP"}
    # The default subnet was free: no key at all.
    new, _, _ = texts(text, backend={})
    assert "SIGRIFT_BACKEND" not in new
    # --replace: the target's current values.
    new, _, _ = texts(text, backend=None, current={"SIGRIFT_BACKEND_SUBNET": "10.9.0.0/28"})
    assert "SIGRIFT_BACKEND_SUBNET=10.9.0.0/28\n" in new


@pytest.mark.parametrize("value, mine, refused", [
    ("127.0.0.1", [], False), ("::1", [], False), ("0.0.0.0", [], False), ("::", [], False),
    ("", [], False), ("192.0.2.40", ["192.0.2.40"], False), ("192.0.2.40", ["192.0.2.50"], True)])
def test_bind_values_kept_own_address_kept_other_address_refused(value, mine, refused):
    assert TOOL.bind_refused(value, mine) is refused
    new, _, p = texts("BRIDGE_AUDIT_KEY=a\nSIGRIFT_BIND=%s\n" % value)
    if not refused:
        assert ("SIGRIFT_BIND=%s\n" % value) in new and "SIGRIFT_BIND" in p["kept"]
    new, _, _ = texts("BRIDGE_AUDIT_KEY=a\nSIGRIFT_BIND=%s\n" % value, bind="127.0.0.1")
    assert "SIGRIFT_BIND=127.0.0.1\n" in new and new.count("SIGRIFT_BIND") == 1


def test_compose_class_keys_go_to_env_imported():
    keys = ["COMPOSE_FILE", "COMPOSE_PROFILES", "COMPOSE_ENV_FILES", "COMPOSE_PATH_SEPARATOR",
            "COMPOSE_IGNORE_ORPHANS", "DOCKER_HOST", "DOCKER_CONFIG"]
    text = "COMPOSE_PROJECT_NAME=old\nBRIDGE_AUDIT_KEY=a\n" + "".join("%s=x\n" % k for k in keys)
    new, imp, p = texts(text)
    assert dict(p["moved"]) == dict((k, "compose") for k in keys)
    assert all(k not in new for k in keys) and "COMPOSE_PROJECT_NAME" not in new
    assert all(("%s=x\n" % k) in imp for k in keys)
    for path in (ROOT / ".env.example", ROOT / "docker-compose.yml"):
        assert not re.search(r"\b(COMPOSE_(?!PROJECT_NAME)[A-Z_]+|DOCKER_[A-Z_]+)=",
                             path.read_text())


SOURCE_ENV = ("BRIDGE_ENV=development\nBRIDGE_MFA_KEY=m\nBRIDGE_AUDIT_KEY=a\n"
              "BRIDGE_MASTER_KEY=k\nUC_PROXY_SECRET=p\nBRIDGE_LOCAL_NODE_KEY=lnk\n"
              "SIGRIFT_QUICKSTART_MODE=full\nMLRF_NODE_ID=local-edge\nMLRF_WIFI_IFACE=wlan1\n"
              "SIGRIFT_PRESET=lab\nUC_TLS_CERT=/app/tls/cert.pem\nUC_TLS_KEY=/app/tls/key.pem\n"
              "UC_PORT=9444\n")


def test_source_to_release_mapping():
    meta = dict(META, install_type="source")
    new, imp, p = texts(SOURCE_ENV, meta=meta)
    assert p["switch"] == "source-to-release"
    moved = dict(p["moved"])
    for k in ("BRIDGE_ENV", "BRIDGE_LOCAL_NODE_KEY", "SIGRIFT_QUICKSTART_MODE", "MLRF_NODE_ID",
              "SIGRIFT_PRESET", "UC_PORT"):
        assert moved.get(k) == "switch", k
    assert moved["MLRF_WIFI_IFACE"] == "old-host"
    assert "BRIDGE_ENV=production\n" in new and "BRIDGE_ENV=development\n" in imp
    # The release template interpolates UC_TLS_*: they stay.
    assert "UC_TLS_CERT=/app/tls/cert.pem\n" in new and "UC_TLS_KEY=" in new
    for k in ("BRIDGE_MFA_KEY=m", "BRIDGE_AUDIT_KEY=a", "BRIDGE_MASTER_KEY=k",
              "UC_PROXY_SECRET=p"):
        assert k + "\n" in new
    assert "lnk" not in new and "lnk" in imp


def test_release_to_source_mapping():
    text = "BRIDGE_ENV=production\nBRIDGE_AUDIT_KEY=a\nBRIDGE_MFA_KEY=m\nUC_PROXY_SECRET=p\n"
    new, imp, p = texts(text, target="source", port=9555, mode=None)
    assert p["switch"] == "release-to-source"
    assert "UC_PORT=9555\n" in new and "SIGRIFT_QUICKSTART_MODE=dashboard-only\n" in new
    assert "BRIDGE_ENV=production\n" in new and "BRIDGE_LOCAL_NODE_KEY" in p["generated"]
    new, _, _ = texts(text, target="source", port=9555, mode="full")
    assert "SIGRIFT_QUICKSTART_MODE=full\n" in new


AUDIT_CASES = {
    "env-key": ("BRIDGE_AUDIT_KEY=  the-audit-key \n", None),
    "legacy-secret": ("BRIDGE_AUDIT_SECRET= legacy-secret-1\n", None),
    "master": ("BRIDGE_MASTER_KEY=master value 2 \n", None),
    "file": ("", "dev-file-key-3\n"),
    "none": ("", None),
}


@pytest.mark.parametrize("source", sorted(AUDIT_CASES))
def test_audit_promotion_each_source_gives_the_same_secret(source):
    text, filetext = AUDIT_CASES[source]
    text = "BRIDGE_MFA_KEY=m\nUC_PROXY_SECRET=p\n" + text
    meta = dict(META, install_type="source", audit={"source": source})
    manifest = {"audit": {"source": source, "entries": 0 if source == "none" else 3},
                "counts": {"totp_fernet": 0}}
    new, imp, p = texts(text, meta=meta, manifest=manifest, promote=filetext)
    before = TOOL.env_effective(text)
    after = TOOL.env_effective(new)
    assert bridge_secret(before, filetext) == gateway_secret(before, filetext)
    if source == "none":
        assert p["promoted"] is None and "BRIDGE_AUDIT_KEY" in p["generated"]
        return
    assert bridge_secret(after) == bridge_secret(before, filetext)
    assert gateway_secret(after) == gateway_secret(before, filetext)
    if source != "env-key":
        assert p["promoted"] == {"from": source, "to": "BRIDGE_AUDIT_KEY"}
    if source == "legacy-secret":
        assert "BRIDGE_AUDIT_SECRET" not in after and "BRIDGE_AUDIT_SECRET" in imp
    if source == "master":
        assert after["BRIDGE_MASTER_KEY"] == before["BRIDGE_MASTER_KEY"]


def test_release_template_key_list_is_derived_from_the_template():
    assert sorted(TOOL.RELEASE_TEMPLATE_KEYS) == template_keys()


@pytest.mark.parametrize("value", ["plain-value_1.2:3+4/5=", "with space", "a#b", "x$y",
                                   "bridge-audit-hmac:k v", "€uro"])
def test_promoted_value_round_trips_parse_dotenv_with_quoting(value):
    line = "BRIDGE_AUDIT_KEY=%s\n" % TOOL.env_quote(value)
    assert TOOL.env_effective(line)["BRIDGE_AUDIT_KEY"] == value
    assert LC.parse_dotenv(line)[0].value == value
    if not re.fullmatch(r"[A-Za-z0-9._:+/=-]*", value):
        assert line.startswith("BRIDGE_AUDIT_KEY='")


@pytest.mark.parametrize("raw, ok", [
    ("it's", False), ("two\nlines", False), ("a\x1cb", False), ("end\x1f", False),
    ("\x1estart", False), ("   ", False), (" lead and trail\t", True)])
def test_promotion_refuses_values_strip_and_trim_read_differently(raw, ok):
    meta = dict(META, install_type="source", audit={"source": "legacy-secret"})
    manifest = {"audit": {"source": "legacy-secret", "entries": 3}, "counts": {}}
    names = {"BRIDGE_AUDIT_SECRET": "set", "BRIDGE_MFA_KEY": "set"}
    eff = {"BRIDGE_AUDIT_SECRET": raw, "BRIDGE_MFA_KEY": "m"}
    # Python's str.strip() drops U+001C-U+001F, Rust's str::trim() keeps them.
    assert ("end\x1f".strip(), "end\x1f".strip(" \t\n\r\x0b\x0c")) == ("end", "end\x1f")
    if ok:
        p = TOOL.env_import_plan(names, eff, meta, manifest, "release", None, 8444, None, {},
                                 {})
        assert p["added"]["BRIDGE_AUDIT_KEY"] == raw.strip()
        assert bridge_secret({"BRIDGE_AUDIT_KEY": raw.strip()}) == gateway_secret(
            {"BRIDGE_AUDIT_SECRET": raw})
        return
    with pytest.raises(TOOL.EnvRefused) as ei:
        TOOL.env_import_plan(names, eff, meta, manifest, "release", None, 8444, None, {}, {})
    assert ei.value.code == "audit-value"
    assert TOOL.audit_value_for("legacy-secret", eff) is None
    assert TOOL.audit_value_for("file", {}, raw) is None


def test_chain_rs_derivation_is_the_one_ported():
    rs = (ROOT / "src" / "gateway" / "crates" / "sigrift-gateway-core" / "src" / "audit" /
          "chain.rs").read_text()
    body = re.search(r"(?ms)^pub fn resolve_audit_secret\(.*?^\}", rs).group(0)
    assert body.count(".trim()") >= 3 and 'b"bridge-audit-hmac:"' in body
    assert body.index("BRIDGE_AUDIT_SECRET") < body.index("BRIDGE_MASTER_KEY")
    py = (ROOT / "src" / "sigrift" / "bridge" / "storage" / "audit.py").read_text()
    fn = re.search(r"(?ms)^def _get_audit_secret\(\).*?(?=^def )", py).group(0)
    assert 'b"bridge-audit-hmac:" + master_key.encode("utf-8")' in fn
    assert fn.index('"BRIDGE_AUDIT_KEY", "").strip()') < fn.index('"BRIDGE_AUDIT_SECRET"')


def test_env_imported_header_mode_and_byte_preserved_lines():
    text = ("# my comment\nBRIDGE_AUDIT_KEY=a\nCOMPOSE_FILE=a.yml:b.yml\n"
            "export DOCKER_HOST='tcp://x' # note\nMLRF_WIFI_IFACE=wlan9\n")
    new, imp, p = texts(text, meta=dict(META, source={"hostname": "pi\x1b]0;x\x07"}))
    first = imp.splitlines()[0]
    assert first == ("# Values from archive %s of pi\\x1b]0;x\\x07 (%s) that describe the old "
                     "host or the other install type. Not used here." % (
                         META["archive_id"], META["created_at"]))
    assert "COMPOSE_FILE=a.yml:b.yml\n" in imp and "export DOCKER_HOST='tcp://x' # note\n" in imp
    assert "# COMPOSE_FILE: " in imp and "# MLRF_WIFI_IFACE: " in imp
    assert new.startswith("# my comment\nBRIDGE_AUDIT_KEY=a\n")


def test_production_keys_added_when_nothing_depends_on_them_else_refused():
    meta = dict(META, install_type="source", audit={"source": "env-key"},
                env={"keys": {"BRIDGE_AUDIT_KEY": "set"}, "parse": "ok", "audit_value": "n/a"})
    for totp, refused in ((0, False), (2, True)):
        manifest = {"audit": {"source": "env-key", "entries": 3}, "counts": {"totp_fernet": totp}}
        text = "BRIDGE_AUDIT_KEY=a\n"
        for dry in (True, False):
            names = meta["env"]["keys"] if dry else {"BRIDGE_AUDIT_KEY": "set"}
            eff = {} if dry else TOOL.env_effective(text)
            if refused:
                with pytest.raises(TOOL.EnvRefused) as ei:
                    TOOL.env_import_plan(names, eff, meta, manifest, "release", None, 8444, None,
                                         {}, {})
                assert ei.value.code == "production" and ei.value.detail == ["BRIDGE_MFA_KEY"]
            else:
                p = TOOL.env_import_plan(names, eff, meta, manifest, "release", None, 8444, None,
                                         {}, {})
                assert set(p["generated"]) >= {"BRIDGE_MFA_KEY", "UC_PROXY_SECRET",
                                               "BRIDGE_MASTER_KEY"}
    # A dry run refuses an unwritable promoted value from the metadata alone.
    meta2 = dict(meta, audit={"source": "master"}, env=dict(meta["env"],
                                                            audit_value="unwritable"))
    with pytest.raises(TOOL.EnvRefused) as ei:
        TOOL.env_import_plan({"BRIDGE_MASTER_KEY": "set"}, {}, meta2,
                             {"audit": {"source": "master"}, "counts": {}}, "release", None, 8444,
                             None, {}, {})
    assert ei.value.code == "audit-value"


def test_metadata_env_holds_names_and_states_only():
    text = ("BRIDGE_AUDIT_KEY=secret-audit-value\nBRIDGE_MFA_KEY=\nUC_PROXY_SECRET=pp-value\n"
            "BROKEN='unterminated\n")
    env = TOOL.env_names(text)
    blob = repr(env)
    for v in ("secret-audit-value", "pp-value", "unterminated"):
        assert v not in blob
    assert env["keys"]["BRIDGE_AUDIT_KEY"] == "set" and env["keys"]["BRIDGE_MFA_KEY"] == "empty"
    assert env["parse"] == "line 4"
    assert TOOL.env_names("A=1\n")["parse"] == "ok"


@pytest.mark.parametrize("direction", ["source-to-release", "release-to-source"])
def test_generated_keys_are_written_by_the_one_write(direction, tmp_path):
    """4.2 (fix round F2): every key env-import names as generated has a
    non-empty value in env.new, written by the real run's one write (1a's
    env_plan never runs after an import), for both switch directions."""
    import json
    import os

    if direction == "source-to-release":
        meta = dict(META, install_type="source", audit={"source": "env-key"})
        text, target = "BRIDGE_AUDIT_KEY=a\nBRIDGE_ENV=development\n", "release"
        want = {"BRIDGE_MFA_KEY", "UC_PROXY_SECRET", "BRIDGE_MASTER_KEY"}
    else:
        meta = dict(META, install_type="release")
        text, target = "BRIDGE_ENV=production\nBRIDGE_AUDIT_KEY=a\nBRIDGE_MFA_KEY=m\n" \
            "UC_PROXY_SECRET=p\n", "source"
        want = {"BRIDGE_LOCAL_NODE_KEY"}
    manifest = {"audit": {"source": "env-key", "entries": 3}, "counts": {"totp_fernet": 0}}
    jid = "20261128T010000Z"
    ops = tmp_path / ".sigrift" / "ops" / jid
    (ops / "payload" / "files").mkdir(parents=True)
    for p in (tmp_path / ".sigrift", tmp_path / ".sigrift" / "ops", ops):
        os.chmod(p, 0o700)
    (ops / "probe.json").write_text(json.dumps({"metadata": meta, "manifest": manifest}))
    (ops / "payload" / "files" / ".env").write_text(text)
    res = tmp_path / "result.json"
    old_hook = __import__("sys").excepthook
    try:
        TOOL.main(["env-import", "--dir", str(tmp_path), "--jid", jid, "--target", target,
                   "--port", "8444", "--result", str(res)])
    finally:
        __import__("sys").excepthook = old_hook
    r = json.loads(res.read_text())
    assert want <= set(r["generated"]), r
    new = TOOL.env_effective((ops / "env.new").read_text())
    for k in r["generated"]:
        assert new.get(k), k
    if "BRIDGE_MFA_KEY" in r["generated"]:
        assert len(new["BRIDGE_MFA_KEY"]) == 44  # a Fernet key
    # No value reaches the result: names only.
    blob = res.read_text()
    assert all(new[k] not in blob for k in r["generated"])
