# SigRift Learned-State Bundle Format (v1)

A **bundle** is a portable, versioned container for the anomaly-detection state
SigRift learns after install. It has two forms:

- **export** — a lossless, same-site backup (restore after `docker compose down -v`
  or a hardware migration). May contain MAC/BSSID-keyed WiFi/BT baselines.
- **preset** — a site-transferable, **fully synthetic** starting point that lets a
  fresh install skip the ~300-detections-per-bin cold start. Contains only
  site-agnostic RF state; never MAC-keyed data or anything site-identifying.

This document is the authoritative contract: a third party can produce and
validate a bundle from this file alone. The reference implementation is
`src/sigrift/bridge/bundles.py`.

## Container

A bundle is a gzip-compressed tar archive named
`sigrift_export_<UTC-timestamp>.sigrift.tar.gz` (exports) or
`preset_<profile>_v<N>.sigrift.tar.gz` (presets). Members are a **flat, exact
allowlist** — `manifest.json` (always the first member) plus any of:

| Member | Component type | Serialization |
|---|---|---|
| `rf_baselines.json` | `rf_baselines` | `BaselineManager.save` format |
| `signal_whitelist.json` | `signal_whitelist` | `SignalWhitelist.save` format |
| `detection_config.json` | `detection_config` | `{"config": {...}}` |
| `wifi_baselines.json` | `wifi_baselines` | `WifiBaselineManager.save` (export only) |
| `bt_baselines.json` | `bt_baselines` | `BtBaselineManager.save` (export only) |

The component JSON is byte-for-byte what the corresponding SigRift serializer
emits — a bundle is a manifest plus those files, nothing re-nested.

## `manifest.json`

```json
{
  "schema_version": 1,
  "kind": "preset",
  "profile": "urban-dense",
  "name": "Urban dense RF preset",
  "description": "High-occupancy city-center environment. Fully synthetic.",
  "created_at": "2026-07-01T00:00:00+00:00",
  "generator": {
    "tool": "training/generate_preset_bundles.py",
    "git_sha": "abc1234",
    "sigrift_version": "0.1.0",
    "seed": 41001,
    "profile_config_sha256": "…",
    "numpy_version": "1.26.4"
  },
  "compatibility": {
    "baseline_schema": 1,
    "freq_bin_strategy": "adaptive_v1",
    "taxonomy": "open_default_16",
    "class_set": ["noise", "tone", "…"],
    "class_set_sha256": "…",
    "bands": ["sub_1ghz", "…"],
    "bands_sha256": "…",
    "min_learning_detections": 300,
    "hourly_counts": "neutral_prior"
  },
  "components": [
    {"file": "rf_baselines.json", "type": "rf_baselines", "sha256": "…", "bytes": 412345, "optional": false}
  ],
  "extensions": {}
}
```

All manifest objects reject unknown keys (`extra="forbid"`). Additive growth is
possible without a schema bump via two escape hatches: a component with
`"optional": true` and an unknown `type` is skipped (with a warning) by a v1
importer, and the free-form `extensions` object (≤ 8 KB, ignored by v1) carries
additive metadata.

- `schema_version` — integer. An importer rejects a bundle whose version is
  greater than it supports; a lower version runs registered migrations.
- `kind` — `preset` selects the stricter validation profile and forbids
  `wifi_baselines`/`bt_baselines`.
- `compatibility.freq_bin_strategy` — must equal the importer's binning scheme
  (`adaptive_v1` = 25 kHz below 1 GHz, 500 kHz at/above), else frequency keys
  would not align → hard reject.
- `compatibility.class_set` / `class_set_sha256` — SHA-256 of the sorted JSON
  class list. On import, if fewer than 50 % of the bundle's classes exist in the
  running model, the bundle is rejected unless `force=true`.
- `components[].sha256` / `bytes` — integrity + a hard per-member byte ceiling
  enforced *during* the streamed read (defeats decompression bombs).

## Preset sanitation (kind = preset)

RF baselines shipped in a preset MUST be sanitized. The importer re-derives the
idempotent parts and rejects a preset that does not already satisfy them:

1. **Transients zeroed** — `cusum_pos`, `cusum_neg`, `cusum_changepoints`,
   `cusum_last_changepoint`, `last_detection_time`, `last_inter_arrival` = 0.
2. **Neutral hourly prior** — `hourly_counts` is replaced by, for every hour
   0–23 and every class in `class_counts`, `max(1, class_counts[cls] // 24)`.
   (Dropping `hourly_counts` entirely is a bug: an empty histogram makes the
   timing dimension score 1.0 on every detection until the bin relearns.)
3. **Buffers truncated** to the last 120 power/SNR/bandwidth samples.
4. **Variance widened** (power/SNR) by the profile factor (default ×1.5) so a
   different receiver's absolute levels do not trip false z-scores.
5. **Floats rounded** to 4 significant figures.
6. **No MAC-shaped strings**, non-null `node_ids`, or lat/lon keys anywhere.

`detection_config` in a preset is restricted to the transferable key subset
(dimension weights, thresholds, learning/snooze scalars); `bt_dimension_weights`
is reserved and rejected in v1. Protocol toggles and hardware-specific keys are
omitted so an operator's site choices survive a preset apply.

## Validation pipeline (ordered, fail-fast)

Applied to every untrusted bundle (import, preset apply, CLI — presets get no
trust shortcut):

1. Transport size ≤ 64 MiB.
2. Archive safety: regular files only; no absolute paths, `..`, path
   separators, symlinks/hardlinks/devices; ≤ 16 members; no duplicates;
   `manifest.json` first.
3. Manifest ≤ 64 KiB; parsed with NaN/Infinity literals banned; `extra="forbid"`;
   members and manifest components map 1:1.
4. Each member: SHA-256 and byte size match the manifest, enforced during a
   chunked read.
5. Structural checks: all floats finite and ≤ 1e9; freq keys in
   [10 kHz, 10 GHz]; ≤ 50 000 bins; ≤ 500 samples/buffer; ≤ 128 classes/bin;
   `alpha ∈ (0, 1]`; whitelist entries round-trip `WhitelistEntry`;
   `detection_config` values follow the rules of `PUT
   /api/admin/detection-config` (`sigrift.bridge.detection_config`): weight
   keys valid, each ∈ [0, 1], ≤ 64 per object, summing ≤ 2.0. The API
   (import, dry run included, and preset apply) checks the weight and
   protocol-toggle bounds again on the objects as merged into the
   configuration in force (`detection_config merge`); a bundle that breaks
   them there is refused (422) before any component is applied.
6. Kind = preset: forbidden members rejected; `node_ids` null; MAC scan; the
   sanitizer idempotence check above.
7. Compatibility: bin strategy, taxonomy overlap, band hash.

Every failure is reported as a structured check naming the member, the failed
check, and the fix — never a bare 500.

## CLI

```
python -m sigrift.bridge.bundles export     --data-dir DIR [-o OUT] [--components rf whitelist detection_config]
python -m sigrift.bridge.bundles validate   BUNDLE                       # spec-only; non-zero exit on failure
python -m sigrift.bridge.bundles import     BUNDLE --data-dir DIR [--dry-run] [--force]
python -m sigrift.bridge.bundles extract    BUNDLE --component rf -o baselines.json
python -m sigrift.bridge.bundles list-presets
```

`import` (and `extract` into a data dir) refuses to write when a bridge appears
to be running (a `detections.db-wal` modified in the last 60 s) unless `--force`;
prefer the admin API on a live system. `extract` is the supported path for
seeding an edge node — drop the extracted `rf_baselines.json` as `baselines.json`
into the node's `MLRF_DATA_DIR`.

## Versioning

`schema_version` starts at 1. Presets are regenerated from committed profile
configs each release and never migrate; exports keep N-1 loader support. A
component's internal `baseline_schema` (from the manager's `SCHEMA_VERSION`)
versions the per-file layout independently of the container.

`wifi_baselines.json` is at schema 2: its SSIDs (`expected_ssids` and the
`ssid_to_bssids` keys) are the text the access point sent. A schema 1 file, or
one without `schema_version`, holds them HTML-escaped once, as the Wi-Fi
ingest routes stored them before; loading it (from disk or a bundle) decodes
that one layer (only `&amp;`, `&lt;`, `&gt;`, `&quot;` and `&#x27;`), and the
next save writes schema 2. `bt_baselines.json` names are stored as heard as
well, without a schema change. A loader from before schema 2 does not check
`schema_version` and reads these SSIDs and names as escaped text, so an
export that will be imported by an older bridge should leave out the `wifi`
and `bt` components (see "Baseline Files (Radio Text as Heard)" in
`src/sigrift/bridge/UPGRADE.md`).
