"""Archive format v1 (phase2-spec 3, 5.1, 14.1, 14.5): the archive engine in process.

The state-engine, archive-engine and lifecycle-engine sources of
scripts/install-release.sh are exec'd as one module, as the bootstrap does
in the bridge image; each ar-* op runs with its frames captured from ST_IO.
The host side (the header checks, the passphrase rules) is the state tool's
heredoc imported as a module. Argon2id runs at 2^16 KiB, 1 pass, 1 lane
except in the vector tests; nothing here sleeps or waits.
"""

from __future__ import annotations

import ast
import base64
import gzip
import hashlib
import importlib.util
import io
import json
import os
import re
import sqlite3
import struct
import subprocess
import sys
import tarfile
import threading
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TEXT = (ROOT / "scripts" / "install-release.sh").read_text()
FIX = Path(__file__).resolve().parent / "fixtures" / "state_archive"
PP = b"correct horse battery staple"
DK = bytes(range(32))
SALT = bytes(range(16))
WS = bytes(range(32, 48))
NP = bytes(range(0xA0, 0xA7))
S64 = 65536
RB = "20261201T000100Z"
AID = "00000000-0000-4000-8000-000000000002"
META = {"tool": "install-release.sh", "installer_release": "v0.2.0",
        "sigrift_version": "v0.2.0-secret-version-tag", "bridge_release": "v0.2.0",
        "install_type": "release", "install_id": "00000000-0000-4000-8000-0000000000bb",
        "project": "archive-test-project", "moved": False,
        "source": {"hostname": "very-secret-hostname", "arch": "arm64", "host_id": "ab" * 16,
                   "working_dir": "/home/pi/x", "addresses": ["192.0.2.9"], "port": 8444,
                   "bind": "0.0.0.0", "tls_names": ["very-secret-hostname"],
                   "tls_cert_sha256": "00" * 32, "host_keys": {}},
        "schema_version": 56, "db_encrypted": False,
        "audit": {"source": "env-key", "result": "ok", "head_id": 1},
        "env": {"keys": {"BRIDGE_AUDIT_KEY": "set"}, "parse": "ok", "audit_value": "n/a"},
        "counts": {}, "summary_nodes": [], "in_stack_node": None, "parts": [],
        "captures": "included", "kept_out": {"backups_bytes": 0, "exports_bytes": 0}}
GOLDEN = {"v1-golden.sigrift-archive": {
    "sha256": "8fe82c3799a76f7ff58d886b3cd0759faeab1bc453fcb07d06674121aeb69f9c",
    "header_checksum": "853f2bb0c044f389537c23d09695dbb093a6a0318be6aa73a191f7cdc1d916d7",
    "segments": 3, "params": (16, 1, 1, 65536),
    "prefix": "534947524946542d4152434849564500000102100101000102030405060708090a0b0c0d0e0f"
              "010000010000a0a1a2a3a4a5a600",
    "wrapped": "628628198f037d11a7e8cc42e73fc0913b8daf726cc37072c6b7ef82bfa0ff161998362248d5"
               "0c02deee99bbe038c64e",
    "wrap_check": "35b83af2a4f6afa0945cad1fa74ce6d4a226d4e05c715fbb64d6232bc13c285b"},
    "v1-golden-max.sigrift-archive": {
    "sha256": "ac21911521259915f893d8f4e78f97aa942a853592f8488d05d7d619b21e2215",
    "header_checksum": "ddc89c686d1454de01193197c30940d045ce404e3bb7e4022e294afb1448906b",
    "segments": 1, "params": (18, 4, 4, 4194304),
    "prefix": "534947524946542d4152434849564500000102120404000102030405060708090a0b0c0d0e0f"
              "010000400000a0a1a2a3a4a5a600",
    "wrapped": "df6cda6cc582d1b346876ea1135e326809f034d82056d6a617c6d14992f634dfc5574c20fe2a"
               "f369dac96150322b4e78",
    "wrap_check": "934ce7b76b4f24c24ea11cd0739574a4d382752477317d2046ac973576b9976c"}}
GOLDEN_MEMBERS = {
    "manifest.json": "2305e48439323577d226aefdde94e871ab77af757c4509d509b63240fd545053",
    "rf_rows.json": "9b2797532f1627d61d12472b8985f75237925b74817b2b0b6d145ad6eba54bdd",
    "volumes/bridge_data.tar.gz": "6d3ce5cda5381203e25527ae19477f12c233a5759f6613d53a218d76"
                                  "7f90a4bc"}


def block(name):
    return re.search(r"(?ms)^# >>> shared: %s .*?^# <<< shared: %s\n" % (name, name),
                     TEXT).group(0)


def heredoc(name):
    return re.search(r"cat <<'PY'\n(.*?)\nPY\n", block(name), re.S).group(1) + "\n"


ENGINE_SRC = heredoc("state-engine") + heredoc("archive-engine") + heredoc("lifecycle-engine")
TOOL_SRC = re.search(r"<<'PY'\n(.*?)\nPY\n", block("state-tool"), re.S).group(1) + "\n"


def b64(b):
    return base64.b64encode(b).decode()


def sha(b):
    return hashlib.sha256(b).hexdigest()


def parse_frames(b):
    out, i = [], 0
    while i < len(b):
        kind, n = b[i:i + 1], struct.unpack(">Q", b[i + 1:i + 9])[0]
        out.append((kind, b[i + 9:i + 9 + n]))
        i += 9 + n
    assert i == len(b)
    return out


def section(data, step=1 << 20):
    return b"".join(b"%d\n" % len(data[i:i + step]) + data[i:i + step]
                    for i in range(0, len(data), step)) + b"0\n"


def lst(members):
    return [{"n": n, "s": len(b), "h": sha(b)} for n, b in members]


def pad(n, seed=b"pad"):
    out, i = [], 0
    while sum(map(len, out)) < n:
        out.append(hashlib.sha256(seed + b":%d" % i).digest())
        i += 1
    return b"".join(out)[:n]


def empty_tgz():
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT):
        pass
    return gzip.compress(raw.getvalue(), compresslevel=1, mtime=0)


EMPTY_TGZ = empty_tgz()


def basic(*files):
    """A grammatical member list: manifest, rf_rows, FILES, two empty parts."""
    out = [("manifest.json", b'{"format": 1}\n'), ("rf_rows.json", b"{}\n")]
    out += [("files/f%02d" % i, b) for i, b in enumerate(files)]
    for v in ("bridge_secrets", "bridge_data"):
        out += [("volumes/%s.members.json" % v, b""), ("volumes/%s.tar.gz" % v, EMPTY_TGZ)]
    return out


@pytest.fixture(scope="module")
def ns():
    space = {"__name__": "sigrift_engine_under_test", "REQUEST": {}}
    exec(compile(ENGINE_SRC, "<sigrift-engine>", "exec"), space)
    return space


@pytest.fixture(scope="module")
def tool():
    mod = types.ModuleType("lc_state_tool_under_test")
    exec(compile(TOOL_SRC, "<lc_state_tool>", "exec"), mod.__dict__)
    return mod


class Eng:
    def __init__(self, ns, tmp):
        self.ns = ns
        self.data, self.secrets = tmp / "vol-data", tmp / "vol-secrets"
        self.data.mkdir()
        self.secrets.mkdir()

    def call(self, op, req, stdin=b"", sink=None):
        out = sink if sink is not None else io.BytesIO()
        self.ns["ST_IO"]["out"] = out
        self.ns["ST_IO"]["in"] = stdin if hasattr(stdin, "read") else \
            io.BufferedReader(io.BytesIO(stdin))
        full = {"format": 1, "op": op, "framed": True, "data_dir": str(self.data),
                "secrets_dir": str(self.secrets)}
        full.update(req)
        hooks = (sys.excepthook, threading.excepthook)
        try:
            try:
                rc = self.ns["run"](full)
            except SystemExit as e:
                rc = e.code
        finally:
            sys.excepthook, threading.excepthook = hooks
        if sink is not None:
            return rc, None, []
        frames = parse_frames(out.getvalue())
        term = [f for f in frames if f[0] in (b"R", b"E")]
        assert len(term) == 1 and frames[-1] is term[0], [f[0] for f in frames]
        return rc, json.loads(term[0][1]), frames

    def ok(self, op, req, stdin=b""):
        rc, r, frames = self.call(op, req, stdin)
        assert rc == 0 and r.get("ok") is True, r
        return r, b"".join(p for k, p in frames if k == b"D")

    def err(self, op, req, stdin=b"", code=None, archive_error=None):
        rc, r, frames = self.call(op, req, stdin)
        assert rc == 1 and r["ok"] is False, r
        if code:
            assert r["code"] == code, r
        if archive_error:
            assert r.get("archive_error") == archive_error, r
        return r, frames

    def wrap(self, pp=PP, dk=DK, seg=S64, kdf=(16, 1, 1)):
        r, _ = self.ok("ar-wrap", {"passphrase_b64": b64(pp), "data_key": b64(dk),
                                   "kdf": {"mem_log2": kdf[0], "t": kdf[1], "lanes": kdf[2]},
                                   "segment_size": seg})
        return {"prefix": r["prefix"], "wrapped": r["wrapped"], "wrap_check": r["wrap_check"],
                "archive_id": AID, "created_at": "2026-12-01T00:01:00Z",
                "crypto": {"cryptography": "test", "openssl": "test"}}

    def write(self, members, wrap=None, dk=DK, meta=None, data=None):
        wrap = wrap or self.wrap(dk=dk)
        req = {"data_key": b64(dk), "wrap": wrap, "metadata": dict(meta or META),
               "members": lst(members)}
        stdin = b"".join(section(b) for _, b in (data or members))
        r, arch = self.ok("ar-write", req, stdin)
        assert len(arch) == r["archive_bytes"] and sha(arch) == r["archive_sha256"]
        return arch, r, wrap

    def probe(self, arch, pp=PP, want_key=True):
        H = 184 + struct.unpack(">I", arch[52:56])[0]
        return self.call("ar-probe", {"passphrase_b64": b64(pp), "header": b64(arch[:H]),
                                      "want_key": want_key, "archive_bytes": len(arch)},
                         section(arch[H:]))

    def verify(self, arch, wrap, members, dk=DK, total=None):
        return self.call("ar-verify", {"data_key": b64(dk), "wrap_check": wrap["wrap_check"],
                                       "header_checksum": hdr_sum(arch),
                                       "archive_bytes": len(arch) if total is None else total,
                                       "members": lst(members)}, section(arch))

    def stage(self, arch, parts, manifest_sha, dk=DK, total=None, **extra):
        req = {"data_key": b64(dk), "header_checksum": hdr_sum(arch),
               "archive_bytes": len(arch) if total is None else total, "rb_id": RB,
               "parts": parts, "reserve_bytes": 0, "manifest_sha256": manifest_sha}
        req.update(extra)
        return self.call("ar-stage", req, section(arch))


def hdr_sum(arch):
    m = struct.unpack(">I", arch[52:56])[0]
    return arch[152 + m:184 + m].hex()


@pytest.fixture
def e(ns, tmp_path, monkeypatch):
    for k in ("KDF", "URANDOM", "AEAD"):
        monkeypatch.setitem(ns, k, ns[k])
    return Eng(ns, tmp_path)


class Out:
    """A StOut stand-in for the stream classes used directly."""

    def step(self, **_kw):
        pass


def read_stream(ns, arch, dk=DK, body=None):
    """(meta, [(name, bytes)]) through ArStream and ArMember; BODY replaces
    the bytes after the header (a stream reader without the length check)."""
    h = ns["ar_parse"](arch, len(arch))
    keys = ns["ar_mac_ok"](h, dk)
    assert keys is not None
    meta = ns["ar_open_metadata"](h, keys)
    src = io.BytesIO(arch[h["H"]:] if body is None else body)
    stream = ns["ArStream"](src, h, keys, meta, Out())
    out = []
    for i, m in enumerate(meta["members"]):
        r = ns["ArMember"](stream, meta["members"], i)
        out.append((m["n"], r.read()))
        r.finish()
    ns["ar_trailing"](src)
    return meta, out


def a_code(ns, fn, *args):
    with pytest.raises(ns["ArError"]) as ei:
        fn(*args)
    return ei.value.code, ei.value.fields


def recheck(arch):
    """ARCH with its header checksum recomputed (a deliberate change)."""
    m = struct.unpack(">I", arch[52:56])[0]
    b = bytearray(arch)
    b[152 + m:184 + m] = hashlib.sha256(bytes(b[:152 + m])).digest()
    return bytes(b)


def seg_bounds(arch, i, seg=S64):
    H = 184 + struct.unpack(">I", arch[52:56])[0]
    a = H + i * (seg + 16)
    return a, min(a + seg + 16, len(arch))


# ── 1-4: vectors ────────────────────────────────────────────────────────


def test_hkdf_matches_rfc5869_case_a1(ns):
    okm = ns["ar_hkdf"](bytes(range(13)), b"\x0b" * 22, bytes(range(0xF0, 0xFA)), 42)
    assert okm.hex() == ("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                         "34007208d5b887185865")


def test_argon2id_vectors_rfc9106_and_the_four_parameter_sets(ns):
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    src = ast.parse(heredoc("archive-engine"))
    fn = next(n for n in src.body if isinstance(n, ast.FunctionDef) and n.name == "ar_kdf")
    assert "Argon2id" in ast.unparse(fn) and "memory_cost=1 << mem_log2" in ast.unparse(fn)
    rfc = Argon2id(salt=b"\x02" * 16, length=32, iterations=3, lanes=4, memory_cost=32,
                   ad=b"\x04" * 12, secret=b"\x03" * 8).derive(b"\x01" * 32)
    assert rfc.hex() == "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
    pw = b"correct horse battery staple"
    for params, want in (((16, 1, 1), "ddb47644b1c7fcedcde4bf9220a884f033e8635be9329cf1c4ee3ad7"
                                      "941e3a62"),
                         ((16, 3, 4), "853b272a44db1421c02962669a55eb0994f3cab385ed1c4c79253eee"
                                      "19bab49e"),
                         ((18, 3, 4), "446539bd5c5b1ecce56f2120d87c64925395b4bb2016d9369e17e67a"
                                      "0a2cd8db"),
                         ((18, 4, 4), "a45342f708de9426cdad16317518e6cc4c0f05b9c57615f5e9eb1d00"
                                      "a8e85357")):
        assert ns["ar_kdf"](pw, SALT, *params).hex() == want, params


def test_hkdf_label_vectors(ns):
    k = ns["ar_subkeys"](SALT, DK, WS)
    assert k["header"].hex() == "cdb4d3eb109fc4df787c8e65117334087337d110b83d13d7fd07fe5b014cb4bb"
    assert k["wrapcheck"].hex() == ("3f08ace4fd3725064400ac8a192868e3332d01d3e7f98ce8258b3294"
                                    "a460b936")
    assert k["metadata"].hex() == ("563896eed8b0c4a8e634b6c0ea62915aab6c5e070060b73c05441290"
                                   "22d433ab")
    assert k["segments"].hex() == ("0e21be055121d8541ad7ba88eca5b11ebf27878a22e956a1c5f4ea28"
                                   "6339bce9")
    for g in GOLDEN.values():
        mem, t, lanes, seg = g["params"]
        prefix = ns["ar_prefix"](mem, t, lanes, SALT, seg, NP)
        assert prefix.hex() == g["prefix"]
        kek = ns["ar_kdf"](PP, SALT, mem, t, lanes)
        wrapped = ns["ar_aead"](kek).encrypt(bytes(12), DK, prefix)
        assert wrapped.hex() == g["wrapped"]
        assert ns["ar_wrap_check"](DK, SALT, prefix, wrapped).hex() == g["wrap_check"]


GCM = [  # McGrew-Viega, "The Galois/Counter Mode of Operation", test cases 13-16
    ("00" * 32, "00" * 12, "", "", "", "530f8afbc74536b9a963b4f1c4cb738b"),
    ("00" * 32, "00" * 12, "00" * 16, "", "cea7403d4d606b6e074ec5d3baf39d18",
     "d0d1c8a799996bf0265b98b5d48ab919"),
    ("feffe9928665731c6d6a8f9467308308" * 2, "cafebabefacedbaddecaf888",
     "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449"
     "a6b525b16aedf5aa0de657ba637b391aafd255", "",
     "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b10568"
     "28838c5f61e6393ba7a0abcc9f662898015ad", "b094dac5d93471bdec1a502270e3cc6c"),
    ("feffe9928665731c6d6a8f9467308308" * 2, "cafebabefacedbaddecaf888",
     "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449"
     "a6b525b16aedf5aa0de657ba637b39", "feedfacedeadbeeffeedfacedeadbeefabaddad2",
     "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b10568"
     "28838c5f61e6393ba7a0abcc9f662", "76fc6ece0f4e1768cddf8853bb2d551b"),
]


def test_aesgcm_binding_matches_gcm_spec_256_bit_cases(ns):
    for k, iv, p, aad, c, t in GCM:
        a = ns["ar_aead"](bytes.fromhex(k))
        out = a.encrypt(bytes.fromhex(iv), bytes.fromhex(p), bytes.fromhex(aad))
        assert out.hex() == c + t
        assert a.decrypt(bytes.fromhex(iv), out, bytes.fromhex(aad)) == bytes.fromhex(p)
        assert a.decrypt(bytes.fromhex(iv), out, b"x" + bytes.fromhex(aad)) is None
    a = ns["ar_aead"](bytes(32))
    for n in (0, 11, 13, 16):
        with pytest.raises(AssertionError):
            a.encrypt(bytes(n), b"x", b"")
        with pytest.raises(AssertionError):
            a.decrypt(bytes(n), bytes(17), b"")


# ── 5-11: layout, payload, fresh subkeys, golden fixtures ─────────────


def test_header_offsets_lengths_and_header_len(e):
    members = basic(pad(1000))
    arch, r, wrap = e.write(members)
    m = struct.unpack(">I", arch[52:56])[0]
    H = 184 + m
    assert arch[0:16] == b"SIGRIFT-ARCHIVE\x00" and struct.unpack(">H", arch[16:18])[0] == 1
    assert list(arch[18:22]) == [2, 16, 1, 1] and arch[38] == 1 and arch[39] == 0
    assert struct.unpack(">I", arch[40:44])[0] == S64 and arch[51] == 0
    assert arch[:52] == base64.b64decode(wrap["prefix"])
    assert arch[56:104] == base64.b64decode(wrap["wrapped"])
    assert 17 <= m <= 65552 and len(arch) == H + r["payload_bytes"] + 16 * r["segments"]
    assert arch[152 + m:H] == hashlib.sha256(arch[:152 + m]).digest()
    assert arch[152 + m:H].hex() == r["header_checksum"]
    keys = e.ns["ar_subkeys"](arch[22:38], DK, arch[104:120])
    import hmac
    assert arch[120 + m:152 + m] == hmac.new(keys["header"], arch[:120 + m],
                                             hashlib.sha256).digest()


@pytest.mark.parametrize("size", [1, S64 - 300, 2 * S64, 2 * S64 + 1])
def test_round_trip_one_segment_exact_multiple_and_one_byte_over(e, size):
    members = basic()
    fixed = sum(len(b) for _, b in members)
    members.insert(2, ("files/blob", pad(size - fixed) if size > fixed else b""))
    arch, r, _ = e.write(members)
    pb = sum(len(b) for _, b in members)
    assert r["segments"] == -(-pb // S64)
    meta, out = read_stream(e.ns, arch)
    assert out == members and meta["payload_bytes"] == pb


def test_payload_is_the_concatenation_and_payload_bytes_the_sum(e):
    sizes = [0, 1, S64 - 1, S64, S64 + 1] + [7] * 20
    members = basic(*[pad(n, b"m%d" % i) for i, n in enumerate(sizes)])
    # A member that ends exactly on a segment boundary.
    head = sum(len(b) for _, b in members[:2])
    members.insert(2, ("files/align", pad(S64 - head)))
    arch, r, _ = e.write(members)
    meta, out = read_stream(e.ns, arch)
    assert meta["payload_bytes"] == sum(len(b) for _, b in members) == r["payload_bytes"]
    assert out == members
    assert [m["n"] for m in meta["members"]] == [n for n, _ in members]


def test_plaintext_reveals_only_magic_format_parameters_and_sizes(e):
    members = basic(b"BRIDGE_AUDIT_KEY=a-very-secret-env-value\n")
    members[2] = ("files/.env", members[2][1])
    arch, r, _ = e.write(members)
    m = struct.unpack(">I", arch[52:56])[0]
    clear = arch[:120] + arch[120 + m:]  # everything outside the sealed metadata
    for needle in (b"very-secret-hostname", b"a-very-secret-env-value", b".env",
                   b"manifest.json", b"bridge_data", b"v0.2.0", b"archive-test-project",
                   b"release"):
        assert needle not in arch, needle
    assert clear[:16] == b"SIGRIFT-ARCHIVE\x00"
    assert len(arch) - (184 + m) == r["payload_bytes"] + 16 * r["segments"]


def test_each_write_attempt_uses_fresh_subkeys(e):
    members = basic(pad(3 * S64, b"x"))
    wrap = e.wrap()
    a1, _, _ = e.write(members, wrap)
    a2, _, _ = e.write(members, wrap)
    changed = [(n, (b[:-1] + b"!") if n == "files/f00" else b) for n, b in members]
    a3, _, _ = e.write(changed, wrap)
    assert a1[:104] == a2[:104] == a3[:104]
    salts = {a[104:120] for a in (a1, a2, a3)}
    assert len(salts) == 3
    keys = [e.ns["ar_subkeys"](SALT_OF(a), DK, a[104:120]) for a in (a1, a2, a3)]
    assert len({k["metadata"] for k in keys}) == 3 and len({k["segments"] for k in keys}) == 3

    def blocks(a):
        m = struct.unpack(">I", a[52:56])[0]
        body = a[120:120 + m] + a[184 + m:]
        return {body[i:i + 16] for i in range(0, len(body) - 15, 16)}
    assert not (blocks(a1) & blocks(a2)) and not (blocks(a1) & blocks(a3))
    for a, mm in ((a1, members), (a2, members), (a3, changed)):
        rc, rep, _ = e.verify(a, wrap, mm)
        assert rc == 0, rep
    # A restore point that no longer matches its checksums: A-TAR.
    bad = [(n, (b[:-1] + b"?") if n == "files/f00" else b) for n, b in members]
    req = {"data_key": b64(DK), "wrap": wrap, "metadata": META, "members": lst(members)}
    r, _ = e.err("ar-write", req, b"".join(section(b) for _, b in bad), code="archive",
                 archive_error="A-TAR")
    assert r["member"] == 2 and r["why"] == "sha256"


def SALT_OF(a):
    return a[22:38]


@pytest.mark.parametrize("name", sorted(GOLDEN))
def test_reads_golden_v1_and_v1_max_fixtures(e, name):
    g = GOLDEN[name]
    arch = (FIX / name).read_bytes()
    assert sha(arch) == g["sha256"] and hdr_sum(arch) == g["header_checksum"]
    assert arch[:52].hex() == g["prefix"] and arch[56:104].hex() == g["wrapped"]
    rc, r, frames = e.probe(arch)
    assert rc == 0, r
    assert r["metadata"]["segments"] == g["segments"] and base64.b64decode(r["data_key"]) == DK
    assert r["manifest_sha256"] == GOLDEN_MEMBERS["manifest.json"]
    manifest = b"".join(p for k, p in frames if k == b"D")
    assert sha(manifest) == GOLDEN_MEMBERS["manifest.json"]
    meta, out = read_stream(e.ns, arch)
    got = dict(out)
    for n, h in GOLDEN_MEMBERS.items():
        assert sha(got[n]) == h, n
    wrap = {"wrap_check": g["wrap_check"]}
    rc, r, _ = e.call("ar-verify", {"data_key": b64(DK), "wrap_check": g["wrap_check"],
                                    "header_checksum": g["header_checksum"],
                                    "archive_bytes": len(arch), "members": meta["members"]},
                      section(arch))
    assert rc == 0 and r["members"] == len(meta["members"]), r
    del wrap


def load_make_v1():
    spec = importlib.util.spec_from_file_location("make_v1_under_test", FIX / "make_v1.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_writer_reproduces_golden_v1_bytes(ns):
    mk = load_make_v1()
    eng = mk.load()
    for name, (mem, t, lanes, seg) in mk.PARAMS.items():
        if mem != 16:
            continue  # the max fixture is read by the test above; one KDF at 2^18 is enough
        arch = (FIX / name).read_bytes()
        _meta, out = read_stream(ns, arch)
        data, _wrap, _r = mk.write_archive(eng, dict(out), mem, t, lanes, seg)
        assert data == arch


# ── 12-17: the header, the KDF, the passphrase ──────────────────────────

FIELDS = {"magic": (0, 16, "A-NOT-ARCHIVE"), "format": (16, 18, "A-FORMAT"),
          "kdf": (18, 22, "A-HEADER-DAMAGED"), "salt": (22, 38, "A-HEADER-DAMAGED"),
          "aead-flags-seg": (38, 44, "A-HEADER-DAMAGED"), "nonce": (44, 52, "A-HEADER-DAMAGED"),
          "meta_len": (52, 56, "A-HEADER-DAMAGED"), "wrapped": (56, 104, "A-HEADER-DAMAGED"),
          "write_salt": (104, 120, "A-HEADER-DAMAGED"), "sealed": (120, -64, "A-HEADER-DAMAGED"),
          "mac-checksum": (-64, 0, "A-HEADER-DAMAGED")}


@pytest.mark.parametrize("field", sorted(FIELDS))
def test_flipping_any_header_byte_gives_header_damaged(ns, tool, field):
    arch = (FIX / "v1-golden.sigrift-archive").read_bytes()
    H = 184 + struct.unpack(">I", arch[52:56])[0]
    a, b, want = FIELDS[field]
    a, b = (a if a >= 0 else H + a), (b if b > 0 else H + b)
    for off in range(a, b):
        for bit in (0x01, 0x80):
            x = bytearray(arch)
            x[off] ^= bit
            got, _ = a_code(ns, ns["ar_parse"], bytes(x), len(x))
            with pytest.raises(tool.ArRefused) as ei:
                tool.ar_host_header(bytes(x), len(x))
            # The magic and the format come first (3.7 steps 1-2): a flip
            # there reads as another file or a newer format.
            assert got == ei.value.code == want, (field, off, bit, got)


def golden_header():
    arch = (FIX / "v1-golden.sigrift-archive").read_bytes()
    return arch, 184 + struct.unpack(">I", arch[52:56])[0]


def with_bytes(arch, off, new):
    x = bytearray(arch)
    x[off:off + len(new)] = new
    return recheck(bytes(x))


HOSTILE = {"mem15": (19, b"\x0f"), "mem19": (19, b"\x13"), "t0": (20, b"\x00"),
           "t5": (20, b"\x05"), "lanes0": (21, b"\x00"), "lanes5": (21, b"\x05"),
           "scrypt": (18, b"\x01"), "kdf3": (18, b"\x03"), "seg0": (40, struct.pack(">I", 0)),
           "seg4096": (40, struct.pack(">I", 4096)), "seg2^23": (40, struct.pack(">I", 1 << 23)),
           "seg-not-pow2": (40, struct.pack(">I", 3 * 65536)), "flags": (39, b"\x01"),
           "reserved": (51, b"\x01"), "aead": (38, b"\x02")}


def test_changed_field_with_recomputed_checksum_gives_the_field_error(e, tool):
    arch, H = golden_header()
    for key in ("seg2^23", "t5", "aead"):
        off, new = HOSTILE[key]
        x = with_bytes(arch, off, new)
        assert a_code(e.ns, e.ns["ar_parse"], x, len(x))[0] == "A-PARAMS"
    # Within bounds, before the wrap's end: the unwrap fails.
    for off, new in ((22, b"\xff"), (19, b"\x11"), (20, b"\x02"), (21, b"\x02"), (44, b"\x00"),
                     (60, b"\x00")):
        x = with_bytes(arch, off, bytes([arch[off] ^ 0x5A]) if new == b"\x00" else new)
        rc, r, _ = e.probe(x)
        assert r.get("archive_error") == "A-PASSPHRASE", (off, r)
    # After the wrap: the header MAC fails.
    for off in (104, 130, H - 64 - 5, H - 40):
        x = with_bytes(arch, off, bytes([arch[off] ^ 0x01]))
        rc, r, _ = e.probe(x)
        assert r.get("archive_error") in ("A-HEADER-AUTH", "A-METADATA"), (off, r)
    m = struct.unpack(">I", arch[52:56])[0]
    x = bytearray(arch[:120 + m - 1] + arch[120 + m:])
    x[52:56] = struct.pack(">I", m - 1)
    x = recheck(bytes(x))
    rc, r, _ = e.probe(x)
    assert r.get("archive_error") in ("A-HEADER-AUTH", "A-LENGTH"), r


@pytest.mark.parametrize("case", sorted(HOSTILE))
def test_hostile_parameters_refused_before_the_kdf(e, tool, case):
    arch, H = golden_header()
    off, new = HOSTILE[case]
    x = with_bytes(arch, off, new)
    with pytest.raises(tool.ArRefused) as ei:
        tool.ar_host_header(x, len(x))
    assert ei.value.code == "A-PARAMS"
    calls = []
    e.ns["KDF"] = lambda *a: calls.append(a) or bytes(32)
    # The engine, given a header that differs from the one ar-header checked.
    rc, r, _ = e.probe(x)
    assert r["archive_error"] == "A-PARAMS" and calls == []


def test_kdf_exception_gives_a_params(e):
    arch, H = golden_header()

    def boom(*_a):
        raise ValueError("kdf secret text correct horse")
    e.ns["KDF"] = boom
    rc, r, frames = e.probe(arch)
    assert rc == 1 and r["archive_error"] == "A-PARAMS"
    assert b"secret text" not in b"".join(p for _, p in frames)
    for mem in range(16, 19):
        for lanes in range(1, 5):
            assert (1 << mem) >= 8 * lanes


def test_wrong_passphrase_gives_a_passphrase(e):
    arch, _ = golden_header()
    rc, r, frames = e.probe(arch, pp=b"correct horse battery stapler")
    assert rc == 1 and r["archive_error"] == "A-PASSPHRASE"
    assert not any(k == b"D" for k, _ in frames)


def canon_line(tool, raw, export=False):
    r, w = os.pipe()
    os.write(w, raw)
    os.close(w)
    try:
        line = tool.pp_read_line(r)
    finally:
        os.close(r)
    return tool.pp_canonical(line, export)


def test_passphrase_canonical_form(e, tool):
    # 3.9's vectors.
    assert canon_line(tool, b"\xef\xbb\xbfcorrect\xc2\xa0horse battery staple\r\n") == \
        "correct horse battery staple"
    assert canon_line(tool, "Café au lait 2026".encode()).encode().hex() == \
        "436166c3a9206175206c6169742032303236"
    assert canon_line(tool, b"k7qm 3xva-PL2R wn5d-jh6t BYCE\n") == "k7qm-3xva-pl2r-wn5d-jh6t-byce"
    # NFC and NFD spellings open the same archive.
    key = canon_line(tool, "Café au lait 2026\n".encode()).encode()
    arch, _, _ = e.write(basic(), e.wrap(pp=key))
    rc, r, _ = e.probe(arch, pp=canon_line(tool, "Café au lait 2026".encode()).encode())
    assert rc == 0, r
    # CRLF, a BOM and no final newline: the plain line's key.
    for raw in (b"correct horse battery staple\n", b"correct horse battery staple",
                b"\xef\xbb\xbfcorrect horse battery staple\r\n"):
        assert canon_line(tool, raw) == "correct horse battery staple"
    for sp in (" ", "　", "​"):
        assert canon_line(tool, ("correct%shorse battery staple" % sp).encode()) == \
            "correct horse battery staple"
    gen = "k7qm-3xva-pl2r-wn5d-jh6t-byce"
    for typed in ("K7QM-3XVA-PL2R-WN5D-JH6T-BYCE", "k7qm 3xva pl2r wn5d jh6t byce",
                  "k7qm3xvapl2rwn5djh6tbyce"):
        assert canon_line(tool, typed.encode()) == gen
    for raw in (b"correct horse \xff battery", "correct horse \ud800 x".encode(
            "utf-8", "surrogatepass")):
        with pytest.raises(tool.PassRefused) as ei:
            canon_line(tool, raw)
        assert ei.value.code == "ENCODING"
    # The refusal names no byte and no offset.
    r = subprocess.run([sys.executable, "-I", "-c", TOOL_RUNNER, "ENCODING"],
                       capture_output=True, env={"LC_ALL": "C", "PATH": os.environ["PATH"]})
    assert r.returncode == 3 and b"not valid UTF-8." in r.stderr
    assert b"0x" not in r.stderr and b"position" not in r.stderr and b"\\x" not in r.stderr
    for odd in ("\U0001f600", "\t", "\x1b", "‍"):
        raw = ("correct horse%sbattery staple" % odd).encode()
        with pytest.raises(tool.PassRefused) as ei:
            canon_line(tool, raw, export=True)
        assert ei.value.code == "CHARS", repr(odd)
        assert canon_line(tool, raw) == "correct horse%sbattery staple" % odd
    for short in (b"elevenchars", b"x" * 1025):
        with pytest.raises(tool.PassRefused) as ei:
            canon_line(tool, short)
        assert ei.value.code == "SHORT"
    with pytest.raises(tool.PassRefused) as ei:
        canon_line(tool, b"a" * 4098)
    assert ei.value.code == "SHORT"


TOOL_RUNNER = """import sys, types
src = open(%r).read()
import re
src = re.search(r"<<'PY'\\n(.*?)\\nPY\\n", re.search(r"(?ms)^# >>> shared: state-tool .*?^# <<< shared: state-tool\\n", src).group(0), re.S).group(1)
m = types.ModuleType("t"); exec(compile(src, "<t>", "exec"), m.__dict__)
m.pp_refuse(m.PassRefused(sys.argv[1]), {}, True)
""" % str(ROOT / "scripts" / "install-release.sh")


WEAK = ["aaaaabbbbbccccc", "qwertyuiop[]", "abcdefghijkl", "lkjihgfedcba",
        "1 2 3 4 5 6 7 8 9 0 - =", "sigrift-sigrift", "my-project-my-project-x"]


def test_weak_passphrases_refused_at_export_only(e, tool):
    for w in WEAK:
        with pytest.raises(tool.PassRefused) as ei:
            tool.pp_canonical(w.encode(), True, names=("my-project", "myhost"))
        assert ei.value.code == "WEAK", w
        assert tool.pp_canonical(w.encode(), False) == w
    assert tool.pp_canonical(b"my sigrift archive of 2026", True, names=("p", "h"))
    # An archive made with such a passphrase through the op itself imports.
    arch, _, _ = e.write(basic(), e.wrap(pp=b"qwertyuiop[]"))
    assert e.probe(arch, pp=b"qwertyuiop[]")[0] == 0
    gen = tool.pp_generate()
    assert re.fullmatch(r"[a-z2-7]{4}(-[a-z2-7]{4}){5}", gen)
    assert tool.pp_canonical(gen.encode(), True, generated=True) == gen


# ── 18-26: segments ─────────────────────────────────────────────────────


def four_segments(e):
    members = basic()
    fixed = sum(len(b) for _, b in members)
    members.insert(2, ("files/blob", pad(4 * S64 - fixed)))
    arch, r, wrap = e.write(members)
    assert r["segments"] == 4 and r["payload_bytes"] == 4 * S64
    return arch, members, wrap


@pytest.mark.parametrize("i", [0, 1, 3])
def test_bit_flip_in_first_middle_last_segment_gives_a_segment(e, i):
    arch, members, wrap = four_segments(e)
    a, b = seg_bounds(arch, i)
    x = bytearray(arch)
    x[(a + b) // 2] ^= 0x04
    rc, r, _ = e.verify(bytes(x), wrap, members)
    assert r["archive_error"] == "A-SEGMENT" and r["segment"] == i and r["of"] == 4


def drop(arch, i):
    a, b = seg_bounds(arch, i)
    return arch[:a] + arch[b:]


@pytest.mark.parametrize("i", [0, 1, 3])
def test_dropped_first_middle_last_segment(e, tool, i):
    arch, members, wrap = four_segments(e)
    x = drop(arch, i)
    rc, r, _ = e.probe(x)
    assert r["archive_error"] == "A-LENGTH"
    H = 184 + struct.unpack(">I", x[52:56])[0]
    code, f = a_code(e.ns, read_stream, e.ns, arch, DK, x[H:])
    if i == 3:
        assert code == "A-TRUNCATED"
    else:
        assert code == "A-ORDER" and f["segment"] == i and f["held"] == i + 1


def test_bounded_memory_20mb_against_200mb(tmp_path):
    """Each size in its own process (ar-write, then ar-verify of what it
    wrote, the payload made on the fly): the peak resident sets differ by
    less than 8 MiB."""
    got = {}
    # Under a loaded test run the allocator's peak can move by a few MiB from
    # one process to the next: a second pair of runs (the lower peak of each
    # size counts) tells noise from growth, which would show in both.
    for attempt in range(2):
        for mb in (20, 200):
            r = subprocess.run([sys.executable, "-I", "-c", MEMORY_RUNNER, str(mb),
                                str(tmp_path)], capture_output=True, text=True, timeout=120)
            assert r.returncode == 0, r.stderr[-2000:]
            got[mb] = min(got.get(mb, 1 << 62), int(r.stdout.split()[-1]))
        if abs(got[200] - got[20]) < 8 << 20:
            break
    assert abs(got[200] - got[20]) < 8 << 20, got


MEMORY_RUNNER = r"""import base64, hashlib, io, json, os, re, resource, struct, sys
mb, tmp = int(sys.argv[1]), sys.argv[2]
TEXT = open(%r).read()
def block(n): return re.search(r"(?ms)^# >>> shared: %%s .*?^# <<< shared: %%s\n" %% (n, n), TEXT).group(0)
def doc(n): return re.search(r"cat <<'PY'\n(.*?)\nPY\n", block(n), re.S).group(1) + "\n"
ns = {"__name__": "mem", "REQUEST": {}}
exec(compile(doc("state-engine") + doc("archive-engine") + doc("lifecycle-engine"), "<e>", "exec"), ns)
CH = 1 << 20
def chunk(i): return hashlib.sha256(b"%%d" %% i).digest() * (CH // 32)
total = mb * CH
h = hashlib.sha256()
for i in range(mb): h.update(chunk(i))
import gzip, tarfile
raw_t = io.BytesIO()
with tarfile.open(fileobj=raw_t, mode="w", format=tarfile.PAX_FORMAT): pass
tgz = gzip.compress(raw_t.getvalue(), mtime=0)
names = [("manifest.json", b"{}\n"), ("rf_rows.json", b"{}\n")]
small = [(n, tgz if n.endswith(".tar.gz") else b"") for n in ("volumes/bridge_secrets.members.json", "volumes/bridge_secrets.tar.gz", "volumes/bridge_data.members.json", "volumes/bridge_data.tar.gz")]
members = [{"n": n, "s": len(b), "h": hashlib.sha256(b).hexdigest()} for n, b in names] + [{"n": "files/blob", "s": total, "h": h.hexdigest()}] + [{"n": n, "s": len(b), "h": hashlib.sha256(b).hexdigest()} for n, b in small]
class Gen(io.RawIOBase):
    def __init__(self, parts): self.parts, self.buf = parts, b""
    def readable(self): return True
    def readinto(self, b):
        while not self.buf:
            try: self.buf = next(self.parts)
            except StopIteration: return 0
        n = min(len(b), len(self.buf)); b[:n] = self.buf[:n]; self.buf = self.buf[n:]; return n
def sec_parts():
    for _, b in names: yield b"%%d\n" %% len(b) + b + b"0\n"
    for i in range(mb): yield b"%%d\n" %% CH + chunk(i)
    yield b"0\n"
    for _, b in small: yield (b"%%d\n" %% len(b) + b if b else b"") + b"0\n"
def run(op, req, stdin, sink):
    ns["ST_IO"]["out"] = sink; ns["ST_IO"]["in"] = io.BufferedReader(stdin)
    full = {"format": 1, "op": op, "framed": True, "data_dir": tmp, "secrets_dir": tmp}; full.update(req)
    try: ns["run"](full)
    except SystemExit: pass
class DeFrame:
    def __init__(self, f): self.f, self.buf, self.last = f, b"", None
    def write(self, b):
        self.buf += b
        while len(self.buf) >= 9:
            n = struct.unpack(">Q", self.buf[1:9])[0]
            if len(self.buf) < 9 + n: break
            k, p = self.buf[:1], self.buf[9:9 + n]; self.buf = self.buf[9 + n:]
            if k == b"D": self.f.write(p)
            elif k in (b"R", b"E"): self.last = (k, p)
    def flush(self): pass
ns["URANDOM"] = os.urandom
dk = bytes(range(32))
ws = io.BytesIO()
run("ar-wrap", {"passphrase_b64": base64.b64encode(b"correct horse battery staple").decode(), "data_key": base64.b64encode(dk).decode(), "kdf": {"mem_log2": 16, "t": 1, "lanes": 1}, "segment_size": 65536}, Gen(iter([])), ws)
raw = ws.getvalue()
i = 0; frames = []
while i < len(raw):
    k, n = raw[i:i+1], struct.unpack(">Q", raw[i+1:i+9])[0]; frames.append((k, raw[i+9:i+9+n])); i += 9 + n
w = json.loads(frames[-1][1])
wrap = {"prefix": w["prefix"], "wrapped": w["wrapped"], "wrap_check": w["wrap_check"], "archive_id": "x", "created_at": "x", "crypto": {}}
arch = os.path.join(tmp, "a%%d.arch" %% mb)
with open(arch, "wb") as o:
    sink = DeFrame(o)
    run("ar-write", {"data_key": base64.b64encode(dk).decode(), "wrap": wrap, "metadata": {}, "members": members}, Gen(sec_parts()), sink)
last = sink.last
assert last[0] == b"R", last
r = json.loads(last[1])
size = os.path.getsize(arch)
def arch_parts():
    with open(arch, "rb") as f:
        while True:
            b = f.read(CH)
            if not b: break
            yield b"%%d\n" %% len(b) + b
    yield b"0\n"
class Null:
    def __init__(self): self.last = b""
    def write(self, b): self.last = (self.last + b)[-4096:]
    def flush(self): pass
sink = Null()
run("ar-verify", {"data_key": base64.b64encode(dk).decode(), "wrap_check": w["wrap_check"], "header_checksum": r["header_checksum"], "archive_bytes": size, "members": members}, Gen(arch_parts()), sink)
assert b'"ok": true' in sink.last, sink.last[-300:]
rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
print(rss if sys.platform == "darwin" else rss * 1024)
""" % str(ROOT / "scripts" / "install-release.sh")


def test_swapped_and_duplicated_segments_give_a_order(e):
    arch, members, wrap = four_segments(e)
    s1, s2 = seg_bounds(arch, 1), seg_bounds(arch, 2)
    swapped = arch[:s1[0]] + arch[s2[0]:s2[1]] + arch[s1[0]:s1[1]] + arch[s2[1]:]
    rc, r, _ = e.verify(swapped, wrap, members)
    assert (r["archive_error"], r["segment"], r["held"]) == ("A-ORDER", 1, 2)
    dup = arch[:s2[0]] + arch[s1[0]:s1[1]] + arch[s2[1]:]
    rc, r, _ = e.verify(dup, wrap, members)
    assert (r["archive_error"], r["segment"], r["held"]) == ("A-ORDER", 2, 1)


def test_truncated_mid_segment_at_a_boundary_and_inside_the_header(e, tool):
    arch, members, wrap = four_segments(e)
    H = 184 + struct.unpack(">I", arch[52:56])[0]
    for cut in (seg_bounds(arch, 2)[0], seg_bounds(arch, 2)[0] + 100):
        x = arch[:cut]
        rc, r, _ = e.probe(x)
        assert r["archive_error"] == "A-LENGTH"
        code, _f = a_code(e.ns, read_stream, e.ns, arch, DK, x[H:])
        assert code == "A-TRUNCATED"
    for cut, want in ((100, "A-HEADER-DAMAGED"), (55, "A-NOT-ARCHIVE"), (H - 1,
                                                                        "A-HEADER-DAMAGED")):
        with pytest.raises(tool.ArRefused) as ei:
            tool.ar_host_header(arch[:cut], cut)
        assert ei.value.code == want, cut


def test_trailing_bytes_give_a_trailing(e):
    arch, members, wrap = four_segments(e)
    x = arch + b"appended"
    rc, r, _ = e.probe(x)
    assert r["archive_error"] == "A-LENGTH"
    rc, r, _ = e.verify(x, wrap, members, total=len(arch))
    assert r["archive_error"] == "A-TRAILING"
    H = 184 + struct.unpack(">I", arch[52:56])[0]
    assert a_code(e.ns, read_stream, e.ns, arch, DK, arch[H:] + b"x")[0] == "A-TRAILING"


def test_segment_and_tail_spliced_from_another_archive(e):
    a, members, wrap = four_segments(e)
    b, _, wrap_b = e.write(members, wrap)  # same passphrase, same key, another write_salt
    s1 = seg_bounds(a, 1)
    x = a[:s1[0]] + b[s1[0]:s1[1]] + a[s1[1]:]
    rc, r, _ = e.verify(x, wrap, members)
    assert (r["archive_error"], r["segment"]) == ("A-SEGMENT", 1)
    y = a[:s1[0]] + b[s1[0]:]
    rc, r, _ = e.verify(y, wrap, members)
    assert (r["archive_error"], r["segment"]) == ("A-SEGMENT", 1)


def test_header_of_one_archive_with_the_body_of_another(e):
    a, members, wrap = four_segments(e)
    other = e.wrap()
    b, _, _ = e.write(members, other)
    H = 184 + struct.unpack(">I", a[52:56])[0]
    x = a[:H] + b[H:]
    rc, r, _ = e.verify(x, wrap, members)
    assert (r["archive_error"], r["segment"]) == ("A-SEGMENT", 0)


def test_early_last_flag_forged_with_a_known_key_is_detected(e, ns):
    arch, members, wrap = four_segments(e)
    h = ns["ar_parse"](arch, len(arch))
    keys = ns["ar_subkeys"](h["salt"], DK, h["write_salt"])
    meta, out = read_stream(ns, arch)
    plain = b"".join(b for _, b in out)
    a = ns["ar_aead"](keys["segments"])
    nonce = h["nonce_prefix"] + struct.pack(">I", 1) + b"\x01"
    forged = a.encrypt(nonce, plain[S64:2 * S64], h["checksum"])
    s1 = seg_bounds(arch, 1)
    body = arch[h["H"]:s1[0]] + forged
    code, f = a_code(ns, read_stream, ns, arch, DK, body)
    assert code == "A-TRUNCATED" and f["segment"] == 1
    rc, r, _ = e.probe(arch[:s1[0]] + forged)
    assert r["archive_error"] == "A-LENGTH"


# ── 27, 14.5: the payload and tar-safety matrix ─────────────────────────


def tar_of(entries):
    """(tar.gz bytes, members file bytes) of ENTRIES [(TarInfo kw, data, line)]."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for kw, data, _ in entries:
            kw = dict(kw)
            ti = tarfile.TarInfo(kw.pop("name"))
            for k, val in kw.items():
                setattr(ti, k, val)
            if data is not None:
                ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data) if data is not None else None)
    arch = gzip.compress(raw.getvalue(), compresslevel=1, mtime=0)
    mem = b"".join((json.dumps(line, sort_keys=True, separators=(",", ":")) + "\n").encode()
                   for _, _, line in entries if line is not None)
    return arch, mem


def fline(p, data, m="0600", **extra):
    d = {"p": p, "t": "f", "m": m, "s": len(data), "h": sha(data), "mt": 1}
    d.update(extra)
    return d


def point(parts):
    """A restore-point payload: the members (3.6 order) and the manifest of
    PARTS {name: (tar.gz, members file)}."""
    vols = []
    files = [("files/.env", b"BRIDGE_AUDIT_KEY=x\n")]
    for name in ("bridge_secrets", "bridge_data", "edge_data", "opt-sigrift-pki"):
        if name not in parts:
            continue
        arch, mem = parts[name]
        vols.append({"name": name, "archive": "volumes/%s.tar.gz" % name,
                     "archive_sha256": sha(arch), "archive_bytes": len(arch),
                     "members_file_sha256": sha(mem), "excludes": [],
                     "keep_back": ["backups", "exports"] if name == "bridge_data" else []})
    manifest = {"format": 1, "kind": "full", "id": "20261201T000000Z-v0.2.0-full",
                "reason": "export", "files": [{"path": ".env", "sha256": sha(files[0][1])}],
                "volumes": vols}
    mbytes = (json.dumps(manifest, indent=1, sort_keys=True) + "\n").encode()
    out = [("manifest.json", mbytes), ("rf_rows.json", b"{}\n")] + files
    for v in vols:
        arch, mem = parts[v["name"]]
        out += [("volumes/%s.members.json" % v["name"], mem), ("volumes/%s.tar.gz" % v["name"],
                                                               arch)]
    return out, mbytes


OK_SECRETS = tar_of([({"name": "ca", "mode": 0o700, "type": tarfile.DIRTYPE}, None,
                      {"p": "ca", "t": "d", "m": "0700", "mt": 1}),
                     ({"name": "ca/ca.key", "mode": 0o600}, b"placeholder-not-a-key\n",
                      fline("ca/ca.key", b"placeholder-not-a-key\n"))])
INNER = {
    "absolute": [({"name": "/etc/x", "mode": 0o600}, b"x", fline("/etc/x", b"x"))],
    "dotdot": [({"name": "../x", "mode": 0o600}, b"x", fline("../x", b"x"))],
    "hardlink": [({"name": "a", "mode": 0o600}, b"x", fline("a", b"x")),
                 ({"name": "b", "mode": 0o600, "type": tarfile.LNKTYPE, "linkname": "a"}, None,
                  fline("b", b""))],
    "chardev": [({"name": "dev", "mode": 0o600, "type": tarfile.CHRTYPE}, None, fline("dev", b""))],
    "blockdev": [({"name": "dev", "mode": 0o600, "type": tarfile.BLKTYPE}, None,
                  fline("dev", b""))],
    "fifo": [({"name": "f", "mode": 0o600, "type": tarfile.FIFOTYPE}, None, fline("f", b""))],
    "sparse": [({"name": "s", "mode": 0o600, "type": tarfile.GNUTYPE_SPARSE}, b"x",
                fline("s", b"x"))],
    "under-a-link": [({"name": "l", "mode": 0o777, "type": tarfile.SYMTYPE, "linkname": "/tmp"},
                      None, {"p": "l", "t": "l", "m": "0777", "mt": 1, "l": "/tmp"}),
                     ({"name": "l/x", "mode": 0o600}, b"x", fline("l/x", b"x"))],
    "lifecycle": [({"name": ".sigrift-restore-incomplete", "mode": 0o600}, b"x",
                   fline(".sigrift-restore-incomplete", b"x"))],
    "keepback": [({"name": "backups", "mode": 0o700, "type": tarfile.DIRTYPE}, None,
                  {"p": "backups", "t": "d", "m": "0700", "mt": 1})],
    "differs": [({"name": "a", "mode": 0o600}, b"x", fline("a", b"y"))],
    "retargeted-link": [({"name": "l", "mode": 0o777, "type": tarfile.SYMTYPE,
                          "linkname": "keys.json"}, None,
                         {"p": "l", "t": "l", "m": "0777", "mt": 1, "l": "../../etc/passwd"})],
}
PKI_BAD = {
    "pki-symlink": [({"name": "l", "mode": 0o777, "type": tarfile.SYMTYPE, "linkname": "x"},
                     None, {"p": "l", "t": "l", "m": "0777", "mt": 1, "l": "x", "o": "0:0"})],
    "pki-hardlink": [({"name": "a", "mode": 0o600}, b"x", fline("a", b"x", o="0:0")),
                     ({"name": "b", "mode": 0o600, "type": tarfile.LNKTYPE, "linkname": "a"},
                      None, fline("b", b"", o="0:0"))],
    "pki-owner": [({"name": "a", "mode": 0o600}, b"x", fline("a", b"x", o="1000:1000"))],
}


def staged_dirs(e):
    return [p for root in (e.data, e.secrets) for p in root.glob(".sigrift-restore-*")]


@pytest.mark.parametrize("case", sorted(INNER) + sorted(PKI_BAD) + ["setuid"])
def test_tar_safety_matrix(e, tmp_path, case):
    if case in PKI_BAD:
        parts = {"bridge_secrets": OK_SECRETS, "bridge_data": tar_of([]),
                 "opt-sigrift-pki": tar_of(PKI_BAD[case])}
        stage_parts = [{"name": "bridge_secrets", "action": "stage"},
                       {"name": "bridge_data", "action": "stage"},
                       {"name": "opt-sigrift-pki", "action": "stage"}]
        pki = tmp_path / "pki"
        pki.mkdir()
        extra = {"pki_dir": str(pki)}
    else:
        entries = [({"name": "x", "mode": 0o4755}, b"run", fline("x", b"run", m="4755"))] \
            if case == "setuid" else INNER[case]
        parts = {"bridge_secrets": OK_SECRETS, "bridge_data": tar_of(entries)}
        stage_parts = [{"name": "bridge_secrets", "action": "stage"},
                       {"name": "bridge_data", "action": "stage"}]
        extra = {}
    members, mbytes = point(parts)
    arch, _, _ = e.write(members)
    rc, r, _ = e.stage(arch, stage_parts, sha(mbytes), **extra)
    if case == "setuid":
        assert rc == 0, r
        staged = e.data / (".sigrift-restore-" + RB) / "x"
        assert staged.read_bytes() == b"run" and (staged.stat().st_mode & 0o7777) == 0o755
        return
    assert rc == 1 and r["archive_error"] == "A-TAR", r
    assert r["why"] in ("inner-unsafe", "inner-integrity", "inner-tar"), r
    if case.startswith("pki-"):
        assert r["why"] == "inner-unsafe"
    assert staged_dirs(e) == []
    if extra:
        assert list((tmp_path / "pki").iterdir()) == []
    assert not Path("/tmp/x").exists() or Path("/tmp/x").read_bytes() != b"x"


def craft(ns, members_meta, payload, meta_text=None, seg=S64):
    """An archive sealed by a test key (it passes 3.7 steps 6-11) whose
    metadata is MEMBERS_META or the raw META_TEXT, payload PAYLOAD."""
    salt, ws = SALT, WS
    prefix = ns["ar_prefix"](16, 1, 1, salt, seg, NP)
    kek = ns["ar_kdf"](PP, salt, 16, 1, 1)
    wrapped = ns["ar_aead"](kek).encrypt(bytes(12), DK, prefix)
    keys = ns["ar_subkeys"](salt, DK, ws)
    n = -(-len(payload) // seg)
    if meta_text is None:
        meta = dict(META, format=1, archive_id=AID, created_at="x", crypto={},
                    payload_bytes=len(payload), segments=n, members=members_meta)
        meta_text = json.dumps(meta, sort_keys=True, separators=(",", ":")).encode()
    m = len(meta_text) + 16
    fixed = prefix + struct.pack(">I", m) + wrapped + ws
    sealed = ns["ar_aead"](keys["metadata"]).encrypt(bytes(12), meta_text, fixed)
    import hmac
    mac = hmac.new(keys["header"], fixed + sealed, hashlib.sha256).digest()
    checksum = hashlib.sha256(fixed + sealed + mac).digest()
    a = ns["ar_aead"](keys["segments"])
    body = b"".join(a.encrypt(NP + struct.pack(">I", i) + (b"\x01" if i == n - 1 else b"\x00"),
                              payload[i * seg:(i + 1) * seg], checksum) for i in range(n))
    return fixed + sealed + mac + checksum + body


def payload_case(case):
    members, mbytes = point({"bridge_secrets": OK_SECRETS, "bridge_data": tar_of([])})
    meta = lst(members)
    payload = b"".join(b for _, b in members)
    raw = None
    if case in ("outside-grammar", "absolute", "dotdot", "dot", "long", "newline"):
        meta[2]["n"] = {"outside-grammar": "files/a b", "absolute": "/etc/passwd",
                        "dotdot": "files/../x", "dot": "files/./x", "long": "files/" + "a" * 251,
                        "newline": "files/.env\n"}[case]
    elif case == "duplicate":
        meta.insert(3, dict(meta[2]))
        payload = payload[:sum(m["s"] for m in meta[:3])] + members[2][1] + \
            payload[sum(m["s"] for m in meta[:3]):]
    elif case in ("size-true", "size-float"):
        meta[2]["s"] = True if case == "size-true" else float(meta[2]["s"])
    elif case == "order":
        meta[0], meta[1] = meta[1], meta[0]
        payload = members[1][1] + members[0][1] + payload[len(members[0][1]) +
                                                          len(members[1][1]):]
    elif case == "missing":
        del meta[2]
    elif case == "extra":
        meta.insert(3, {"n": "files/extra", "s": 5, "h": sha(b"extra")})
    elif case == "sum":
        meta[2]["s"] += 1
    elif case == "sha":
        meta[2]["h"] = sha(b"not it")
    elif case in ("dup-key", "nan"):
        good = dict(META, format=1, archive_id=AID, created_at="x", crypto={},
                    payload_bytes=len(payload), segments=-(-len(payload) // S64), members=meta)
        text = json.dumps(good, sort_keys=True, separators=(",", ":"))
        raw = (text[:-1] + (',"format":1}' if case == "dup-key" else ',"x":NaN}')).encode()
    return meta, payload, raw, mbytes


PAYLOAD_CASES = ["outside-grammar", "absolute", "dotdot", "dot", "long", "newline", "duplicate",
                 "size-true", "size-float", "order", "missing", "extra", "sum", "sha", "dup-key",
                 "nan"]


@pytest.mark.parametrize("case", PAYLOAD_CASES)
def test_tar_safety_matrix_payload(e, case):
    meta, payload, raw, mbytes = payload_case(case)
    arch = craft(e.ns, meta, payload, raw)
    rc, r, _ = e.stage(arch, [{"name": "bridge_secrets", "action": "stage"},
                              {"name": "bridge_data", "action": "stage"}], sha(mbytes))
    want = "A-TAR" if case == "sha" else "A-METADATA"
    assert rc == 1 and r["archive_error"] == want, (case, r)
    assert staged_dirs(e) == []


# ── 28-42: the ops' own rules ───────────────────────────────────────────


def test_ar_probe_reads_only_up_to_rf_rows(e, ns):
    members = basic(pad(5 * S64))
    arch, r, wrap = e.write(members)
    seen = []
    real = ns["AEAD"]

    def spy(key):
        a = real(key)

        class Spy:
            def encrypt(self, *x):
                return a.encrypt(*x)

            def decrypt(self, nonce, data, aad):
                seen.append(nonce)
                return a.decrypt(nonce, data, aad)
        return Spy()
    ns["AEAD"] = spy
    rc, res, frames = e.probe(arch)
    assert rc == 0 and res["segments_read"] == 1
    segs = [x for x in seen if x[:7] == arch[44:51]]
    assert len(segs) == 1 and res["metadata"]["segments"] == r["segments"] > 1
    assert b"".join(p for k, p in frames if k == b"D") == members[0][1]
    ns["AEAD"] = real
    rc, res, _ = e.probe(arch, want_key=False)
    assert rc == 0 and "data_key" not in res
    # A manifest or rf_rows.json whose sha256 differs from the sealed list.
    for i in (0, 1):
        meta = lst(members)
        meta[i]["h"] = sha(b"other")
        x = craft(ns, meta, b"".join(b for _, b in members))
        rc, res, _ = e.probe(x)
        assert res["archive_error"] == "A-TAR" and res["member"] == i, res
    # A manifest over 16 MiB: A-METADATA (before any segment).
    huge = [("manifest.json", bytes((16 << 20) + 1))] + members[1:]
    x = craft(ns, lst(huge), b"".join(b for _, b in huge))
    rc, res, _ = e.probe(x)
    assert res["archive_error"] == "A-METADATA"


def bridge_point(tmp_path, e, big=0):
    """A payload of real snapshot-volume archives of a small bridge tree."""
    src_d, src_s = tmp_path / "src-data", tmp_path / "src-secrets"
    (src_s / "ca").mkdir(parents=True)
    (src_s / "ca" / "ca.key").write_bytes(b"placeholder-not-a-key\n")
    src_d.mkdir()
    conn = sqlite3.connect(src_d / "detections.db")
    conn.executescript("CREATE TABLE schema_version (version INTEGER PRIMARY KEY);"
                       "INSERT INTO schema_version VALUES (56);"
                       "CREATE TABLE sessions (id INTEGER PRIMARY KEY, t TEXT);"
                       "INSERT INTO sessions (t) VALUES ('tok');"
                       "CREATE TABLE nodes (node_id TEXT PRIMARY KEY, last_seen TEXT);"
                       "INSERT INTO nodes VALUES ('local-edge', NULL);")
    conn.commit()
    conn.close()
    (src_d / "keys.json").write_text(json.dumps({"keys": {
        "local-edge": {"hash": "h", "salt": "s", "role": "node"},
        "ops": {"hash": "h2", "salt": "s2", "role": "analyst"}}}))
    (src_d / "audit.key").write_text("dummy-audit-file-value\n")
    if big:
        (src_d / "iq_captures").mkdir()
        (src_d / "iq_captures" / "c.iq").write_bytes(pad(big, b"iq"))
    parts = {}
    for vol, root in (("bridge_secrets", src_s), ("bridge_data", src_d)):
        rc, r, frames = e.call("snapshot-volume", {"volume": vol, "excludes": [],
                                                   "data_dir": str(src_d),
                                                   "secrets_dir": str(src_s)})
        assert rc == 0, r
        parts[vol] = (b"".join(p for k, p in frames if k == b"D"),
                      b"".join(p for k, p in frames if k == b"M"))
    return point(parts)


STAGE_BOTH = [{"name": "bridge_secrets", "action": "stage"},
              {"name": "bridge_data", "action": "stage"}]


def test_ar_stage_authenticates_the_whole_archive_when_parts_are_already_staged(e, tmp_path):
    members, mbytes = bridge_point(tmp_path, e)
    arch, _, _ = e.write(members)
    rc, r, frames = e.stage(arch, STAGE_BOTH, sha(mbytes))
    assert rc == 0 and [x["already"] for x in r["staged"]] == [False, False], r
    host = b"".join(p for k, p in frames if k == b"D")
    assert host.startswith(mbytes) and r["host_part"]["sha256"] == sha(host)
    rc, r, _ = e.stage(arch, STAGE_BOTH, sha(mbytes))
    assert rc == 0 and [x["already"] for x in r["staged"]] == [True, True]
    # Already staged, but the last segment is damaged: the run still fails.
    x = bytearray(arch)
    x[-5] ^= 1
    rc, r, _ = e.stage(bytes(x), STAGE_BOTH, sha(mbytes))
    assert rc == 1 and r["archive_error"] == "A-SEGMENT"


def test_ar_stage_failure_removes_every_staging_it_made(e, tmp_path):
    members, mbytes = bridge_point(tmp_path, e, big=3 * S64)
    arch, _, _ = e.write(members)
    x = bytearray(arch)
    x[-5] ^= 1  # inside bridge_data's archive, after bridge_secrets was staged
    rc, r, _ = e.stage(bytes(x), STAGE_BOTH, sha(mbytes))
    assert rc == 1 and r["archive_error"] == "A-SEGMENT" and staged_dirs(e) == []


def test_ar_verify_detects_a_member_that_differs_from_the_restore_point(e, tmp_path):
    members, _ = bridge_point(tmp_path, e)
    arch, _, wrap = e.write(members)
    rc, r, _ = e.verify(arch, wrap, members)
    assert rc == 0, r
    changed = [(n, b + b"\n" if n == "files/.env" else b) for n, b in members]
    rc, r, _ = e.verify(arch, wrap, changed)
    assert r["archive_error"] == "A-TAR" and r["why"] == "list"
    # A tar.gz whose content differs from its members file (sealed as such).
    bad = list(members)
    i = next(k for k, (n, _) in enumerate(bad) if n == "volumes/bridge_data.members.json")
    lines = bad[i][1].decode().splitlines()
    lines[-1] = lines[-1].replace('"m":"06', '"m":"07')
    bad[i] = (bad[i][0], ("\n".join(lines) + "\n").encode())
    arch2, _, wrap2 = e.write(bad)
    rc, r, _ = e.verify(arch2, wrap2, bad)
    assert r["archive_error"] == "A-TAR" and r["why"].startswith("inner-"), r


ZERO_8G1 = "b47800cd5a0c0bd2a7d6c2ac9402cc117bbe89363299bdc51f8a72aef8543693"


@pytest.mark.slow
@pytest.mark.performance
@pytest.mark.timeout(300)
def test_member_larger_than_8_gib(e, ns, monkeypatch):
    """A 2^33 + 1-byte member generated on the fly through ar-write with a
    null cipher: no member size cap, and the sizes, the segment count and
    the archive length come out right (its sha256 is pinned: ZERO_8G1)."""
    big = (1 << 33) + 1
    seg = 1 << 22

    class Null:
        def encrypt(self, nonce, data, aad):
            return data + bytes(16)

        def decrypt(self, nonce, data, aad):
            return data[:-16]
    empty = sha(b"")
    members = [{"n": "manifest.json", "s": 3, "h": sha(b"{}\n")},
               {"n": "rf_rows.json", "s": 3, "h": sha(b"{}\n")},
               {"n": "files/big", "s": big, "h": ZERO_8G1}] + [
        {"n": n, "s": 0, "h": empty} for n in (
            "volumes/bridge_secrets.members.json", "volumes/bridge_secrets.tar.gz",
            "volumes/bridge_data.members.json", "volumes/bridge_data.tar.gz")]
    wrap = e.wrap(seg=seg)
    zero = bytes(1 << 20)

    class Sections(io.RawIOBase):
        def __init__(self):
            self.parts = iter(self.gen())
            self.buf = b""

        def gen(self):
            yield b"3\n{}\n0\n3\n{}\n0\n"
            left = big
            while left:
                n = min(left, len(zero))
                yield b"%d\n" % n
                yield zero[:n] if n < len(zero) else zero
                left -= n
            yield b"0\n" + b"0\n" * 4

        def readable(self):
            return True

        def readinto(self, b):
            while not self.buf:
                try:
                    self.buf = next(self.parts)
                except StopIteration:
                    return 0
            n = min(len(b), len(self.buf))
            b[:n] = self.buf[:n]
            self.buf = self.buf[n:]
            return n

    class Count:
        def __init__(self):
            self.n, self.first, self.tail = 0, None, b""

        def write(self, b):
            if self.first is None:
                self.first = bytes(b[:9 + 120])
            self.n += len(b)
            self.tail = (self.tail + bytes(b[-4096:]))[-4096:]

        def flush(self):
            pass
    sink = Count()
    monkeypatch.setitem(ns, "AEAD", lambda key: Null())
    e.call("ar-write", {"data_key": b64(DK), "wrap": wrap, "metadata": {}, "members": members},
           io.BufferedReader(Sections(), 1 << 20), sink=sink)
    reply = json.loads(sink.tail[sink.tail.rindex(b"{"):])
    assert reply.get("ok") is True, reply
    pb = big + 6
    n = -(-pb // seg)
    assert reply["payload_bytes"] == pb and reply["segments"] == n
    hl = 184 + struct.unpack(">I", sink.first[9 + 52:9 + 56])[0]
    assert reply["archive_bytes"] == hl + pb + 16 * n


def test_archive_engine_module_level_imports_are_stdlib_only():
    src = heredoc("archive-engine")
    tree = ast.parse(src)
    stdlib = set(sys.stdlib_module_names)
    for node in tree.body:
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in stdlib, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in stdlib, node.module
    inner = [n for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
             and n not in tree.body]
    crypto = [n.module for n in inner if isinstance(n, ast.ImportFrom)
              and (n.module or "").startswith("cryptography")]
    assert sorted(crypto) == ["cryptography.exceptions",
                              "cryptography.hazmat.backends.openssl.backend",
                              "cryptography.hazmat.primitives.ciphers.aead",
                              "cryptography.hazmat.primitives.kdf.argon2"]
    assert "modes.GCM" not in src and "Cipher(" not in src and "import os.environ" not in src
    assert "os.environ" not in src and "getenv" not in src


def test_no_crypto_and_no_kdf_give_their_errors(e, ns, monkeypatch):
    import builtins
    real = builtins.__import__

    def block_(prefix):
        def imp(name, *a, **kw):
            if name.startswith(prefix):
                raise ImportError(name)
            return real(name, *a, **kw)
        return imp
    monkeypatch.setattr(builtins, "__import__", block_("cryptography.hazmat.primitives.kdf"))
    rc, r, _ = e.call("ar-wrap", {"passphrase_b64": b64(PP), "data_key": b64(DK),
                                  "kdf": {"mem_log2": 16, "t": 1, "lanes": 1},
                                  "segment_size": S64})
    assert rc == 1 and r["code"] == "no-kdf"
    monkeypatch.setattr(builtins, "__import__", block_("cryptography.hazmat.primitives.ciphers"))
    rc, r, _ = e.call("ar-wrap", {"passphrase_b64": b64(PP), "data_key": b64(DK),
                                  "kdf": {"mem_log2": 16, "t": 1, "lanes": 1},
                                  "segment_size": S64})
    assert rc == 1 and r["code"] == "no-crypto"


def test_every_mac_comparison_uses_compare_digest_and_errors_echo_no_request_field(
        e, ns, tool, tmp_path, monkeypatch):
    import hmac
    calls = []
    real = hmac.compare_digest

    def spy(a, b):
        calls.append(1)
        return real(a, b)
    monkeypatch.setattr(hmac, "compare_digest", spy)
    members, mbytes = bridge_point(tmp_path, e)
    secret_pp = b"a-passphrase-nobody-guesses"
    wrap = e.wrap(pp=secret_pp)
    arch, _, _ = e.write(members, wrap)
    n0 = len(calls)
    assert e.verify(arch, wrap, members)[0] == 0 and len(calls) >= n0 + 2  # wrap_check, MAC
    n1 = len(calls)
    assert e.probe(arch, pp=secret_pp)[0] == 0 and len(calls) > n1
    n2 = len(calls)
    assert e.stage(arch, STAGE_BOTH, sha(mbytes))[0] == 0 and len(calls) > n2
    point_src = re.search(r"(?ms)^class Point\(object\):\n.*?(?=^def )", TOOL_SRC).group(0)
    assert "hmac.compare_digest(" in point_src  # 1b's COMPLETE re-check
    # Errors and replies hold no passphrase, no key and no request value.
    needles = [secret_pp, base64.b64encode(secret_pp), DK.hex().encode(),
               base64.b64encode(DK), b"very-secret-hostname", b"archive-test-project"]
    outputs = []
    bad = bytearray(arch)
    bad[-3] ^= 1
    for op, req, stdin in (
            ("ar-probe", {"passphrase_b64": b64(b"wrong " + secret_pp), "header": b64(arch[:2000]),
                          "want_key": False, "archive_bytes": len(arch)}, b"0\n"),
            ("ar-verify", {"data_key": b64(DK), "wrap_check": "00", "header_checksum": "x",
                           "archive_bytes": len(arch), "members": []}, section(arch)),
            ("ar-stage", {"data_key": b64(bytes(32)), "header_checksum": hdr_sum(arch),
                          "archive_bytes": len(arch), "rb_id": RB, "parts": STAGE_BOTH},
             section(arch)),
            ("ar-stage", {"data_key": b64(DK), "header_checksum": hdr_sum(arch),
                          "archive_bytes": len(arch), "rb_id": RB, "parts": STAGE_BOTH,
                          "manifest_sha256": sha(mbytes)}, section(bytes(bad))),
            ("ar-write", {"data_key": b64(DK), "wrap": wrap, "metadata": META,
                          "members": lst(members)}, b"0\n"),
            ("ar-wrap", {"passphrase_b64": b64(secret_pp), "data_key": b64(DK[:31]),
                         "kdf": {}, "segment_size": S64}, b"")):
        rc, r, frames = e.call(op, req, stdin)
        assert rc == 1, (op, r)
        outputs.append(b"".join(p for k, p in frames if k != b"D"))
    rc, r, frames = e.probe(arch, pp=secret_pp, want_key=False)
    outputs.append(json.dumps({k: v for k, v in r.items() if k != "metadata"}).encode())
    blob = b"\n".join(outputs)
    for x in needles:
        assert x not in blob, x


def test_wrap_check_binds_the_key_file_to_the_wrap(e, ns):
    members = basic(pad(100))
    wrap = e.wrap()
    arch, _, _ = e.write(members, wrap)
    stdin = b"".join(section(b) for _, b in members)
    bad_wraps = []
    p = bytearray(base64.b64decode(wrap["prefix"]))
    p[40:44] = struct.pack(">I", 2 * S64)
    bad_wraps.append(dict(wrap, prefix=b64(bytes(p))))
    p = bytearray(base64.b64decode(wrap["prefix"]))
    p[30] ^= 1
    bad_wraps.append(dict(wrap, prefix=b64(bytes(p))))
    w = bytearray(base64.b64decode(wrap["wrapped"]))
    w[5] ^= 1
    bad_wraps.append(dict(wrap, wrapped=b64(bytes(w))))
    bad_wraps.append(dict(wrap, wrap_check=("1" if wrap["wrap_check"][0] != "1" else "2")
                          + wrap["wrap_check"][1:]))
    # A non-ASCII wrap_check (a damaged wrap.json) is E integrity too, not
    # E io from compare_digest's TypeError (fix round, review nit).
    bad_wraps.append(dict(wrap, wrap_check="\u00e9" + wrap["wrap_check"][1:]))
    for bw in bad_wraps:
        rc, r, frames = e.call("ar-write", {"data_key": b64(DK), "wrap": bw, "metadata": META,
                                            "members": lst(members)}, stdin)
        assert r["code"] == "integrity" and not any(k == b"D" for k, _ in frames), bw
        rc, r, frames = e.call("ar-verify", {"data_key": b64(DK), "wrap_check": bw["wrap_check"],
                                             "header_checksum": hdr_sum(arch),
                                             "archive_bytes": len(arch),
                                             "members": lst(members)}, section(arch))
        if bw["wrap_check"] != wrap["wrap_check"]:
            assert r["code"] == "integrity"
    for dk in (b"", DK[:31], os.urandom(32)):
        rc, r, frames = e.call("ar-write", {"data_key": b64(dk), "wrap": wrap, "metadata": META,
                                            "members": lst(members)}, stdin)
        assert r["code"] == "integrity" and not any(k == b"D" for k, _ in frames)
        rc, r, _ = e.verify(arch, wrap, members, dk=dk)
        assert r["code"] == "integrity"
    # ar-wrap's self-check: a wrap that does not open to DK is refused.
    real = ns["AEAD"]

    def liar(key):
        a = real(key)
        return types.SimpleNamespace(encrypt=a.encrypt,
                                     decrypt=lambda n, d, aad: b"\0" * 32)
    ns["AEAD"] = liar
    rc, r, _ = e.call("ar-wrap", {"passphrase_b64": b64(PP), "data_key": b64(DK),
                                  "kdf": {"mem_log2": 16, "t": 1, "lanes": 1},
                                  "segment_size": S64})
    assert r["code"] == "integrity"


def test_ar_stage_checks_the_header_mac_before_any_segment(e, ns, tmp_path):
    members, mbytes = bridge_point(tmp_path, e)
    arch, _, _ = e.write(members)
    seen = []
    real = ns["AEAD"]
    ns["AEAD"] = lambda key: seen.append(key) or real(key)
    rc, r, frames = e.stage(arch, STAGE_BOTH, sha(mbytes), dk=os.urandom(32))
    assert rc == 1 and r["code"] == "integrity" and seen == []
    assert staged_dirs(e) == [] and not any(k == b"D" for k, _ in frames)


def test_every_op_holding_dk_checks_the_mac_before_decrypting(e, ns, tmp_path, monkeypatch):
    members, mbytes = bridge_point(tmp_path, e)
    wrap = e.wrap()
    arch, _, _ = e.write(members, wrap)
    import hmac
    events = []
    real_cd, real_aead = hmac.compare_digest, ns["AEAD"]

    def cd(a, b):
        events.append("mac")
        return real_cd(a, b)

    def aead(key):
        a = real_aead(key)
        return types.SimpleNamespace(encrypt=a.encrypt, decrypt=lambda *x: (
            events.append("decrypt"), a.decrypt(*x))[1])
    monkeypatch.setattr(hmac, "compare_digest", cd)
    ns["AEAD"] = aead
    for fn in (lambda: e.probe(arch), lambda: e.verify(arch, wrap, members),
               lambda: e.stage(arch, STAGE_BOTH, sha(mbytes))):
        events.clear()
        rc, r, _ = fn()
        assert rc == 0, r
        # ar-probe unwraps DK first (that decrypt opens the wrap, not the
        # metadata or a segment); every other decrypt follows a MAC check.
        ev = events[1:] if events[0] == "decrypt" else events
        assert ev[0] == "mac" and "decrypt" in ev, events


def test_strict_parsing_of_authenticated_inputs(e, ns, tool, tmp_path):
    for case in ("newline", "size-true", "size-float", "dup-key", "nan"):
        meta, payload, raw, mbytes = payload_case(case)
        rc, r, _ = e.probe(craft(ns, meta, payload, raw))
        assert r["archive_error"] == "A-METADATA", case
    # The manifest and probe.json: duplicate keys and NaN refused.
    for text in ('{"a": 1, "a": 2}', '{"a": NaN}', '{"a": Infinity}'):
        with pytest.raises(ValueError):
            tool.strict_json(text.encode())
        with pytest.raises(ValueError):
            ns["ar_strict_json"](text.encode())
    members, _ = point({"bridge_secrets": OK_SECRETS, "bridge_data": tar_of([])})
    bad_manifest = b'{"format": 1, "format": 1}\n'
    members[0] = ("manifest.json", bad_manifest)
    arch, _, _ = e.write(members)
    rc, r, _ = e.stage(arch, STAGE_BOTH, sha(bad_manifest))
    assert r["archive_error"] == "A-METADATA"
    # A symlink whose target differs from its members line: E integrity in
    # 1b's stage; through ar-stage, A-TAR (inner-integrity).
    arch_t, mem_t = tar_of(INNER["retargeted-link"])
    rc, r, _ = e.call("stage", {"volume": "bridge_data", "rb_id": RB, "restore_point": "x",
                                "archive_sha256": sha(arch_t), "archive_bytes": len(arch_t),
                                "members_file_sha256": sha(mem_t), "keep_back": [],
                                "excludes": [], "reserve_bytes": 0},
                      section(mem_t) + section(arch_t))
    assert r["code"] == "integrity"
    for case in PKI_BAD:
        arch_p, mem_p = tar_of(PKI_BAD[case])
        pki = tmp_path / ("pki-" + case)
        pki.mkdir()
        rc, r, _ = e.call("stage", {"volume": "opt-sigrift-pki", "pki_dir": str(pki),
                                    "rb_id": RB, "restore_point": "x",
                                    "archive_sha256": sha(arch_p), "archive_bytes": len(arch_p),
                                    "members_file_sha256": sha(mem_p), "keep_back": [],
                                    "excludes": [], "reserve_bytes": 0},
                          section(mem_p) + section(arch_p))
        assert r["code"] == "unsafe", (case, r)
        assert list(pki.iterdir()) == []


def test_secret_hygiene_in_the_ar_ops(e, ns, tool, monkeypatch):
    for op in ("ar-wrap", "ar-write", "ar-verify", "ar-probe", "ar-stage"):
        fn_name = {"ar-wrap": "ar_op_wrap", "ar-write": "ar_op_write",
                   "ar-verify": "ar_op_verify", "ar-probe": "ar_op_probe",
                   "ar-stage": "ar_op_stage"}[op]
        hooks = sys.excepthook

        def boom(req, out):
            raise RuntimeError("leaked-secret-%s" % req.get("passphrase_b64"))
        framed = ns["ar_framed"](boom)
        out = io.BytesIO()
        ns["ST_IO"]["out"] = out
        try:
            with pytest.raises(SystemExit):
                framed({"passphrase_b64": "pp-value"})
            assert sys.excepthook is ns["ar_excepthook"]
        finally:
            sys.excepthook = hooks
        blob = out.getvalue()
        assert b"leaked-secret" not in blob and b"pp-value" not in blob
        assert b'"error": "RuntimeError"' in blob, blob
        assert fn_name in ns and ns["ARCHIVE_OPS"][op].__name__ == "op"
    # The passphrase reader: a non-UTF-8 entry's refusal shows its code only.
    with pytest.raises(tool.PassRefused) as ei:
        tool.pp_canonical(b"\xff" * 20)
    assert str(ei.value) == "ENCODING"
    # RLIMIT_CORE is 0 in the ar-* subcommands; requests never go through
    # --request-file or --result.
    r = subprocess.run([sys.executable, "-I", "-c", RLIMIT_RUNNER], capture_output=True,
                       text=True)
    assert r.stdout.split() == ["0", "0"], r.stderr
    # ar-key-check holds DK and env-import parses the decrypted .env: the
    # same hygiene (fix round).
    for name in ("cmd_ar_wrap", "cmd_ar_write", "cmd_ar_verify", "cmd_ar_probe",
                 "cmd_ar_stage", "cmd_ar_key_check", "cmd_env_import"):
        body = re.search(r"(?ms)^def %s\(a\):\n.*?(?=^def )" % name, TOOL_SRC).group(0)
        assert "ar_tool_setup()" in body and "request_file" not in body, name
        assert "put_result(req" not in body and "put_result(dict(req" not in body, name


RLIMIT_RUNNER = """import re, resource, types
src = open(%r).read()
src = re.search(r"<<'PY'\\n(.*?)\\nPY\\n", re.search(r"(?ms)^# >>> shared: state-tool .*?^# <<< shared: state-tool\\n", src).group(0), re.S).group(1)
m = types.ModuleType("t"); exec(compile(src, "<t>", "exec"), m.__dict__)
m.ar_tool_setup()
print(*resource.getrlimit(resource.RLIMIT_CORE))
""" % str(ROOT / "scripts" / "install-release.sh")


def test_ar_ops_bound_the_segment_size_before_allocating(e, ns):
    arch, H = golden_header()
    x = with_bytes(arch, 40, struct.pack(">I", 1 << 23))
    made = []
    real = ns["ArStream"]
    ns["ArStream"] = lambda *a: made.append(a) or real(*a)
    try:
        rc, r, _ = e.call("ar-verify", {"data_key": b64(DK), "wrap_check": GOLDEN[
            "v1-golden.sigrift-archive"]["wrap_check"], "header_checksum": hdr_sum(x),
            "archive_bytes": len(x), "members": []}, section(x))
        assert r["archive_error"] == "A-PARAMS"
        rc, r, _ = e.stage(x, STAGE_BOTH, "0" * 64)
        assert r["archive_error"] == "A-PARAMS"
    finally:
        ns["ArStream"] = real
    assert made == []


# ── import-rules (5.1) ──────────────────────────────────────────────────


def test_import_rules_revoke_and_drop_local_edge_and_end_sessions(e, tmp_path):
    members, mbytes = bridge_point(tmp_path, e)
    arch, _, _ = e.write(members)
    assert e.stage(arch, STAGE_BOTH, sha(mbytes))[0] == 0
    rc, r, _ = e.call("import-rules", {"rb_id": RB, "rules": {
        "sessions": True, "revoke_key_ids": ["local-edge", "absent"]}})
    assert rc == 0 and r["revoked"] == ["local-edge"] and r["sessions"]["ended"] == 1, r
    S = e.data / (".sigrift-restore-" + RB)
    keys = json.loads((S / "keys.json").read_text())["keys"]
    assert keys["local-edge"]["revoked"] is True and "revoked" not in keys["ops"]
    rc, r, _ = e.call("import-rules", {"rb_id": RB, "rules": {}})
    assert r.get("already") is True
    (S / ".sigrift-carried").unlink()
    rc, r, _ = e.call("import-rules", {"rb_id": RB, "rules": {
        "drop_revoked_key_ids": ["local-edge"]}})
    assert r["dropped"] == ["local-edge"]
    assert "local-edge" not in json.loads((S / "keys.json").read_text())["keys"]
