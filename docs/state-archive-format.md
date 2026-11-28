# SigRift State Archive Format (v1)

A **state archive** (`NAME.sigrift-archive`) is the encrypted, portable form of
a full restore point of one SigRift install: its database and volumes, its
`.env` secrets, its TLS pair and its embedded CA. `install-release.sh --export`
and `scripts/quickstart.sh --export` write one; `--import` on another host (or
into the other install type) reads it. This document is the normative
contract of format 1: a reader can be written from it alone. The reference
implementation is the `archive-engine` block of `scripts/install-release.sh`
(the `ar_*` functions; the same block is in `scripts/quickstart.sh`), with the
host-side checks in its `state-tool` block.

## 1. Purpose and threat model

An archive protects **confidentiality and integrity at rest and in transit**
against someone who:

- gets the file (a lost USB stick, a copied backup),
- may change it and hand it back to an import,
- may see the importer's error messages,
- or is a local unprivileged user on the writing or the importing host.

It does **not** protect:

- the fact that a file is a SigRift archive, its KDF and segment parameters
  and its sizes (section 2);
- against anyone who knows the passphrase (they can read the archive and write
  a new one);
- deniability;
- **freshness**: format 1 proves origin, not freshness. An older authentic
  archive under the same passphrase imports, unless the import names the newer
  one with `--expect HC16` (the first 16 hex digits of its header checksum,
  which the export prints) or each export has its own passphrase (the
  generated one).

## 2. File layout

```
archive = header ‖ segment_0 ‖ … ‖ segment_{n-1}          (no trailer)
length  = H + payload_bytes + 16·n                        (exactly)
```

Integers are big-endian and unsigned. The writer creates the file 0600.

### Header (H = 184 + m bytes)

| Offset | Bytes | Field | v1 writer | Reader accepts |
|---|---|---|---|---|
| 0 | 16 | magic | `SIGRIFT-ARCHIVE\0` (`53 49 47 52 49 46 54 2D 41 52 43 48 49 56 45 00`) | exactly |
| 16 | 2 | format | 1 | 1 |
| 18 | 1 | kdf_id | 2 = Argon2id (RFC 9106, version 0x13) | 2 (1, the scrypt of drafts, is refused) |
| 19 | 1 | memory, log2 of KiB | 18 (256 MiB) | 16..18 |
| 20 | 1 | iterations (passes) | 3 | 1..4 |
| 21 | 1 | lanes | 4 | 1..4 |
| 22 | 16 | salt | random | any |
| 38 | 1 | aead_id | 1 = AES-256-GCM | 1 |
| 39 | 1 | flags | 0 | 0 |
| 40 | 4 | segment_size S | 1048576 | a power of two, 65536..4194304 |
| 44 | 7 | nonce_prefix | random | any |
| 51 | 1 | reserved | 0 | 0 |
| 52 | 4 | m = meta_len | len(sealed metadata) | 17..65552 |
| 56 | 48 | wrapped DK | section 3 | - |
| 104 | 16 | write_salt | random, drawn anew by every write attempt | any |
| 120 | m | sealed metadata | section 3, 5 | - |
| 120+m | 32 | header MAC | HMAC-SHA256(K_header, header[0:120+m]) | - |
| 152+m | 32 | header checksum | SHA-256(header[0:152+m]) | - |

The **prefix** is header[0:52], every field before `meta_len`; it is the
wrap's associated data. `meta_len` and `write_salt` are authenticated by the
metadata's AEAD (its associated data is header[0:120]) and by the header MAC.
H runs from 201 to 65 736 bytes. **HC16**, the first 16 hex digits of the
header checksum, names an archive in `--expect` and in messages.

Nothing in plaintext says more than "a SigRift archive, format 1, these KDF
and segment parameters" and the sizes: `meta_len` gives the metadata's length
and the file length gives `payload_bytes + 16·n`. Versions, host names, the
member list and the install type are in the sealed metadata.

## 3. Key schedule and nonces

```
P           = the canonical passphrase (section 10), as UTF-8
KEK         = Argon2id(P, salt, memory_cost = 2^header[19] KiB, iterations = header[20],
                       lanes = header[21], length = 32, no secret, no associated data)
DK          = 32 random bytes (the archive's data key)
wrapped     = AES-256-GCM(KEK).encrypt(nonce = 0x00·12, DK, aad = header[0:52])    (48 bytes)
PRK         = HMAC-SHA256(key = salt, msg = DK)                         (HKDF-Extract, RFC 5869)
K_header    = HMAC-SHA256(PRK, b"sigrift-archive v1 header"    + 0x01)   (HKDF-Expand, L = 32)
K_wrapcheck = HMAC-SHA256(PRK, b"sigrift-archive v1 wrapcheck" + 0x01)
K_metadata  = HMAC-SHA256(PRK, b"sigrift-archive v1 metadata"  + write_salt + 0x01)
K_segments  = HMAC-SHA256(PRK, b"sigrift-archive v1 segments"  + write_salt + 0x01)
wrap_check  = HMAC-SHA256(K_wrapcheck, header[0:52] ‖ wrapped)    (the writer's own check; never in the file)
sealed      = AES-256-GCM(K_metadata).encrypt(nonce = 0x00·12, metadata_json, aad = header[0:120])
MAC         = HMAC-SHA256(K_header, header[0:120+m])
segment_i   = AES-256-GCM(K_segments).encrypt(nonce_i, C_i, aad = header checksum (32 bytes))
nonce_i     = nonce_prefix (7) ‖ u32(i) ‖ (0x01 if i = n-1 else 0x00)
```

- **KDF bounds.** A reader checks the header's KDF fields against the table
  of section 2 before it runs the KDF: at most 256 MiB, 4 passes and 4 lanes,
  so a hostile header cannot ask a small host for more memory. Every accepted
  (memory, lanes) pair satisfies memory ≥ 8·lanes KiB. Any error from the KDF
  is reported like out-of-range parameters.
- **Unique nonces.** KEK is fresh per salt and encrypts exactly one message.
  K_metadata and K_segments are fresh per write attempt (`write_salt`), so the
  zero metadata nonce and each `(counter, last)` pair are used once per key;
  a resumed export is a fresh write, never a second plaintext under an old
  nonce. K_header and K_wrapcheck only MAC.
- **Key binding.** The writer keeps DK in a 0600 file while it works and
  checks `wrap_check` before it writes anything, so a damaged or empty key
  file can never produce an archive the passphrase does not open (HMAC, HKDF
  and AES-GCM accept an empty key silently).
- **Commitment.** AES-GCM is not key-committing; the header MAC is (an HMAC
  commits to its key). A crafted archive cannot open under two passphrases to
  two plaintexts. Every reader that holds DK checks the MAC before it
  decrypts any metadata or segment, and compares it with a constant-time
  comparison.

## 4. Segments (STREAM)

- The payload (section 6) is cut into C_0 … C_{n-1}: every chunk but the last
  is exactly S bytes, the last is 1..S bytes, `n = ceil(payload_bytes / S)`,
  `1 ≤ n < 2^32`.
- Each segment on the wire is `len(C_i) + 16` bytes (ciphertext, then the tag).
  The reader knows every segment's length from the metadata.
- The last flag in the nonce makes "the stream ends here" part of what the tag
  authenticates: a stream cut at a segment boundary fails at its new last
  segment.
- A segment's plaintext is used only after its tag verified.

## 5. Metadata

Compact JSON (`separators=(",", ":")`), keys sorted, UTF-8, at most 65 536
bytes, no secret value. Stable within format 1: new fields may be added,
never removed or redefined. Readers parse it strictly: duplicate keys,
`NaN` and `Infinity` are errors, and every size is a JSON integer (not
`true`, not `1.0`).

```json
{"format": 1, "archive_id": "<uuid4>", "created_at": "2026-12-02T10:15:31Z",
 "tool": "install-release.sh|quickstart.sh", "installer_release": "v0.2.0|dev",
 "sigrift_version": "v0.2.0|<git commit>", "bridge_release": "v0.2.0|main-<sha7>|dev|unknown",
 "install_type": "release|source", "install_id": "<uuid4>", "project": "sigrift-v020",
 "moved": true,
 "source": {"hostname": "pi5", "arch": "arm64", "host_id": "<32 hex>",
            "working_dir": "/home/pi/sigrift-v0.2.0", "addresses": ["192.168.1.40"],
            "port": 8444, "bind": "0.0.0.0", "tls_names": ["pi5", "192.168.1.40"],
            "tls_cert_sha256": "<64 hex>", "host_keys": {"SIGRIFT_BIND": "0.0.0.0"}},
 "schema_version": 56, "db_encrypted": false,
 "audit": {"source": "env-key|legacy-secret|master|file|none", "result": "ok", "head_id": 18233},
 "env": {"keys": {"BRIDGE_AUDIT_KEY": "set", "BRIDGE_MFA_KEY": "empty"},
         "parse": "ok|line <n>", "audit_value": "ok|unwritable|n/a"},
 "counts": {"users": 3, "keys": 23, "nodes": 2, "webhooks": 2, "crypto_keys": 1,
            "detections": 991, "totp_fernet": 1},
 "summary_nodes": ["pi-edge-2"], "in_stack_node": "local-edge|null",
 "parts": [{"name": "bridge_secrets", "bytes_raw": 0}, {"name": "bridge_data", "bytes_raw": 0}],
 "captures": "included|excluded", "kept_out": {"backups_bytes": 0, "exports_bytes": 0},
 "payload_bytes": 1400000000, "segments": 1336,
 "members": [{"n": "manifest.json", "s": 41233, "h": "<sha256>"}, "..."],
 "crypto": {"cryptography": "50.0.2", "openssl": "OpenSSL 3.0.15 ..."}}
```

- `members`: the payload's members in order (section 6): name, size, SHA-256.
- `env`: names only, each `set` or `empty`; `parse` is the result of the
  installer's `.env` parser; `audit_value` whether an audit key promotion
  (a switch from a source install) can be written.
- `source.addresses` and `source.tls_names` only feed the importer's check for
  a source host that still serves the same certificate.

## 6. Payload

The payload is the plain concatenation of the members' bytes, in the order of
the metadata's `members` list, with no framing: the sealed list is the only
index, so no member has a size limit and there is no outer parser. Members, in
this order and no other:

1. `manifest.json` (at most 16 MiB): the restore point's manifest (Appendix A).
2. `rf_rows.json`: the restore point's RF summary rows.
3. `files/<path>` for each entry of the manifest's `files[]`, in its order.
4. For each `volumes[]` entry, in the order bridge_secrets, bridge_data,
   edge_data, opt-sigrift-pki (the last two only when present):
   `volumes/<name>.members.json`, then `volumes/<name>.tar.gz` (Appendix A).

Names are ASCII, at most 255 bytes, match

```
(manifest\.json|rf_rows\.json|files/[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*|volumes/(bridge_secrets|bridge_data|edge_data|opt-sigrift-pki)\.(members\.json|tar\.gz))
```

as a full match (a trailing newline does not match), are unique and have no
`.` or `..` component. The sizes are integers ≥ 0 and sum to `payload_bytes`
(≥ 1; the manifest is never empty).

## 7. Reader algorithm and errors

| Step | Check | Error |
|---|---|---|
| 1 | file ≥ 56 bytes, the magic | A-NOT-ARCHIVE |
| 2 | format = 1 | A-FORMAT |
| 3 | 17 ≤ m ≤ 65 552, file ≥ H | A-HEADER-DAMAGED |
| 4 | the header checksum | A-HEADER-DAMAGED |
| 5 | kdf_id, aead_id, flags, reserved, S, memory, passes, lanes within section 2 (before the KDF) | A-PARAMS |
| 6 | the KDF (any error: A-PARAMS), the unwrap of DK | A-PASSPHRASE |
| 7 | the header MAC | A-HEADER-AUTH |
| 8 | the metadata decrypts and parses strictly; `segments = ceil(payload_bytes/S)`, `n < 2^32`; the member list's grammar, order, uniqueness and sizes; the manifest ≤ 16 MiB | A-METADATA |
| 9 | file length = H + payload_bytes + 16·n | A-LENGTH |
| 10 | each segment decrypts with nonce_i | A-SEGMENT, A-ORDER, A-TRUNCATED |
| 11 | EOF after segment n-1 | A-TRAILING |
| 12 | each member's SHA-256 equals the list's; every volume member against its members file, the archive SHA-256 against the manifest | A-TAR |

Steps 1-5 run on the importing host before any container starts; a reader
runs them again on the exact header bytes it uses. Steps 1-9 change nothing.

**Segment diagnosis** (after a tag failure at index i; at most 17 extra
decryptions of that segment's bytes): `(i, not last_i)` succeeds →
A-TRUNCATED ("the stream ends after segment i, which is not its last");
`(j, last_j)` for j in [i-8, i+8] ∩ [0, n), j ≠ i succeeds → A-ORDER with j
(j > i: a segment is missing; j < i: repeated or reordered); none →
A-SEGMENT (damaged, or from another archive). A short read before segment
n-1 is complete → A-TRUNCATED.

## 8. Compatibility

- Every later release reads format 1. The golden files
  `tests/bridge/fixtures/state_archive/v1-golden.sigrift-archive` (Argon2id
  2^16 KiB, 1 pass, 1 lane; S = 64 KiB; n = 3) and `v1-golden-max…` (the
  reader's maxima: 2^18 KiB, 4 passes, 4 lanes; S = 4 MiB) are made once by
  `make_v1.py` from fixed inputs; tests read them and require the writer to
  reproduce them byte for byte.
- A change to the layout, the key schedule or the payload framing is a format
  2, which readers add; format 1 never changes.
- A new `aead_id` or `kdf_id` within format 1 derives its subkeys with labels
  that name it (`b"sigrift-archive v1 " + x + b" aead=" + bytes([aead_id])`);
  the v1 labels are never reused for another AEAD.
- Archives are architecture-neutral (SQLite, JSON, PEM, gzip tar) and never
  hold container images.

## 9. Test vectors

With cryptography 50.0.2 and the standard library:

- HKDF-SHA256, RFC 5869 A.1: OKM
  `3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865`.
- Argon2id, RFC 9106 §5.3 (password `01`×32, salt `02`×16, secret `03`×8, ad
  `04`×12, 32 KiB, 3 passes, 4 lanes):
  `0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659`.
- `KDF(b"correct horse battery staple", salt = 00..0f)`, 32 bytes:
  (2^16 KiB, 1, 1) `ddb47644b1c7fcedcde4bf9220a884f033e8635be9329cf1c4ee3ad7941e3a62`;
  (2^16, 3, 4) `853b272a44db1421c02962669a55eb0994f3cab385ed1c4c79253eee19bab49e`;
  (2^18, 3, 4) `446539bd5c5b1ecce56f2120d87c64925395b4bb2016d9369e17e67a0a2cd8db`;
  (2^18, 4, 4) `a45342f708de9426cdad16317518e6cc4c0f05b9c57615f5e9eb1d00a8e85357`.
- Subkeys with salt = `00..0f`, DK = `00..1f`, write_salt = `20..2f`:
  K_header `cdb4d3eb109fc4df787c8e65117334087337d110b83d13d7fd07fe5b014cb4bb`,
  K_wrapcheck `3f08ace4fd3725064400ac8a192868e3332d01d3e7f98ce8258b3294a460b936`,
  K_metadata `563896eed8b0c4a8e634b6c0ea62915aab6c5e070060b73c0544129022d433ab`,
  K_segments `0e21be055121d8541ad7ba88eca5b11ebf27878a22e956a1c5f4ea286339bce9`.
- Golden prefix (nonce prefix `a0..a6`, S = 64 KiB):
  `534947524946542d4152434849564500000102100101000102030405060708090a0b0c0d0e0f010000010000a0a1a2a3a4a5a600`;
  wrapped `628628198f037d11a7e8cc42e73fc0913b8daf726cc37072c6b7ef82bfa0ff161998362248d50c02deee99bbe038c64e`;
  wrap_check `35b83af2a4f6afa0945cad1fa74ce6d4a226d4e05c715fbb64d6232bc13c285b`.
  Golden-max prefix
  `534947524946542d4152434849564500000102120404000102030405060708090a0b0c0d0e0f010000400000a0a1a2a3a4a5a600`;
  wrapped `df6cda6cc582d1b346876ea1135e326809f034d82056d6a617c6d14992f634dfc5574c20fe2af369dac96150322b4e78`;
  wrap_check `934ce7b76b4f24c24ea11cd0739574a4d382752477317d2046ac973576b9976c`.
- Golden nonces (n = 3): nonce_0 `a0a1a2a3a4a5a6 00000000 00`, nonce_2
  `a0a1a2a3a4a5a6 00000002 01`.
- AES-256-GCM: the GCM specification's 256-bit test cases 13-16 (TC16, with
  associated data, tag `76fc6ece0f4e1768cddf8853bb2d551b`).
- Passphrase canonical form (input bytes → KDF input): `ef bb bf` `correct`
  `c2 a0` `horse battery staple` `0d 0a` → `correct horse battery staple`;
  `Cafe` U+0301 ` au lait 2026` → `436166c3a9206175206c6169742032303236`;
  `k7qm 3xva-PL2R wn5d-jh6t BYCE` → `k7qm-3xva-pl2r-wn5d-jh6t-byce`.

## 10. Security notes

- **The passphrase.** Whoever has the file can guess offline without limit;
  each guess costs one Argon2id run of 256 MiB and 3 passes (about 0.27 s of
  one core on the review host). A generated passphrase (press Enter at the
  export prompt: 120 random bits, six groups of four base-32 characters) is
  out of reach; a typed one is as strong as its choice. ASCII passphrases are
  the most portable. The canonical form: strict UTF-8, one leading BOM
  removed, every Unicode 3.2 space separator as U+0020, the generated form
  normalised (case, spaces and dashes), NFC, 12 to 1024 code points, no NUL;
  at export also no control, format, private-use or unassigned character by
  the frozen Unicode 3.2 table, and not a guessable one.
- **What a found archive reveals**: section 2 (the format, the parameters, the
  sizes).
- **Impersonation.** Anyone with the file and the passphrase holds the
  gateway's TLS key, its embedded CA and every API key hash: they can
  impersonate this gateway to its edge nodes. After a lost archive, rotate
  what SECURITY.md lists.
- **Freshness**: section 1 and `--expect`.
- **Commitment** comes from the header MAC, not from GCM. The separate
  A-HEADER-AUTH error is a deliberate diagnostic; as a partitioning oracle it
  is worth at most 3 candidate passphrases per crafted import (the zero wrap
  nonce and the 48-byte wrap leave a crafted wrap at most 3 KEKs that open
  it, and only one DK passes the MAC), which adds nothing to offline guessing.
- **Verification on the writer** reads past the page cache
  (`POSIX_FADV_DONTNEED`), but a drive's own cache, or a kernel that ignores
  the hint, can still serve cached bytes: only an import on the new host is a
  full check. `--import FILE --dry-run` proves the passphrase and the length;
  the import authenticates every segment. Wipe or reuse the old host only
  after it.
- **The state directory** (`.sigrift/` of a release install, or quickstart's
  state directory) holds the archive's data key during an export or an
  import (`ops/<id>/archive.key`, 0600, removed as soon as it is unused and on
  every final path). It belongs in the same backup class as the secrets.

## Appendix A: the restore-point layout the payload carries

A full restore point (the source of every archive) is a directory:

```
manifest.json                    the manifest (below)
COMPLETE                         hmac-sha256 of manifest.json under the install's rp.key (not carried)
rf_rows.json                     {"format": 1, "tables": bool, "streams": [...], "fences": [...], "summary_hours": {...}}
files/<path>                     the install's files (.env, compose, tls/cert.pem, tls/key.pem, ...)
volumes/<name>.members.json      one JSON line per member of the volume, in walk order
volumes/<name>.tar.gz            the volume as a gzip'd PAX tar, in the same order
```

**Members file.** One compact JSON object per line, sorted keys, in walk order
(the tuple of path components compared as bytes, a directory's subtree before
its next sibling): `p` (the relative path), `t` (`f` file, `d` directory, `l`
symlink), `m` (the mode, four octal digits), `mt` (mtime in ns), and for a
file `s` (size) and `h` (SHA-256), for a symlink `l` (its target text). The
pki part (`opt-sigrift-pki`) adds `o` (`uid:gid`), restored only from
`0:0` and `1500:1500`; it may hold no symlink and no hard link.

**Volume archive.** Members in the members file's order, names equal to `p`,
modes equal to `m`; regular files, directories and symlinks only (no hard
link, device, FIFO or sparse member), no absolute path and no `..`, no
member under a symlink. A restore strips setuid, setgid and sticky bits and
never writes outside its staging directory.

**Manifest** (`kind: "full"`, compact or indented JSON, sorted keys): `format`
(1), `id`, `reason` (`upgrade`, `manual`, `export`, `pre-import`),
`created_at`, `from_version`, `to_version`, `install_id`, `project`,
`installer_release`, `schema_version`, `db`, `audit` (`source`, `result`,
`entries`, `head_id`, and `head_tag`: the first 32 hex digits of the
sha256 of `sigrift-audit-chain-v1:` and the head entry's `hmac_chain`, which
an import `--replace` compares with the current data's chain; `""` for an
entry without a chain value; absent from older manifests, which such an
import refuses to relate), `counts`, `security` (a projection of hashes and tags,
never a secret; its `created` names when each API key, client certificate
and protocol key was made, which an import `--replace` dates against the
last common audit entry), `rf_summary` (`tables`, `rows`, `digest`,
`rows_file_sha256`, and `exempt_nodes` when the point holds edge_data),
`captures`, `nodes`, `kept_out`, `files[]` (`path`, `sha256`, `bytes`,
`mode`, `via_helper`, `restore_on_rollback`), `volumes[]` (`name`,
`docker_volume`, `archive`, `archive_sha256`, `archive_bytes`, `bytes_raw`,
`members`, `members_file_sha256`, `excludes`, `keep_back`; the pki part also
`host_path` and `owners: true`), and for a source install `install_type:
"source"` and `git_commit`.
