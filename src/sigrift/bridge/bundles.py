"""Learned-state bundles: versioned tar.gz export/import + preset packaging.

A *bundle* is a gzip-compressed tar archive of the exact JSON files the
existing serializers already emit (RF/WiFi/BT baselines, the RF signal
whitelist, the detection-config subset) plus a ``manifest.json`` describing
schema version, provenance, per-file SHA-256, and compatibility keys.

Two kinds:

* ``kind="export"`` — a lossless same-site backup. May include the MAC-keyed
  WiFi/BT baselines. Restores learned state after ``docker compose down -v`` or
  a hardware migration.
* ``kind="preset"`` — a site-transferable, fully synthetic starting point.
  Contains only RF baselines (sanitized of transients + real hourly patterns),
  the whitelist band entries, and the transferable detection-config subset.
  Never contains MAC-keyed data or anything site-identifying.

The format is deliberately built on the primitives that already exist so the
diff stays small and a third party can produce/validate a bundle from
``docs/bundle-format.md`` alone. This module owns the format, the untrusted
validation pipeline, and the apply primitives; the HTTP surface lives in
``routers/maintenance.py`` and the generator in ``training/``.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import logging
import math
import re
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Literal

from pydantic import BaseModel, Field, ValidationError

from sigrift.bridge.anomaly import bands
from sigrift.bridge.anomaly.baseline import (
    BaselineManager,
    FrequencyBaseline,
    json_snapshot,
)
from sigrift.bridge.anomaly.whitelist import WhitelistEntry
from sigrift.bridge.detection_config import DetectionConfigError, check_detection_config
from sigrift.lib import taxonomy_open

logger = logging.getLogger(__name__)

# --- Format constants -------------------------------------------------------

BUNDLE_SCHEMA_VERSION = 1
FREQ_BIN_STRATEGY = "adaptive_v1"  # matches BaselineManager adaptive binning

# Hard limits enforced during untrusted-bundle validation.
MAX_BUNDLE_BYTES = 64 * 1024 * 1024  # 64 MiB compressed transport cap
MAX_MANIFEST_BYTES = 64 * 1024  # manifest member ceiling
MAX_EXTENSIONS_BYTES = 8 * 1024
MAX_MEMBERS = 16
MAX_FREQ_BINS = 50_000
MAX_SAMPLES_PER_BUFFER = 500
MAX_CLASSES_PER_BIN = 128
MAX_WHITELIST_ENTRIES = 1_000
MAX_STRING_KEY_LEN = 128
MAX_ABS_FLOAT = 1e9
FREQ_MIN_HZ = 10_000.0
FREQ_MAX_HZ = 10_000_000_000.0

# Preset generation defaults (also the validated invariants).
PRESET_BUFFER_CAP = 120
PRESET_VARIANCE_WIDENING = 1.5
PRESET_FLOAT_SIGFIGS = 4

# Component file → logical type. The archive member allowlist is exactly
# {"manifest.json"} ∪ these filenames.
COMPONENT_FILES: dict[str, str] = {
    "rf_baselines.json": "rf_baselines",
    "signal_whitelist.json": "signal_whitelist",
    "detection_config.json": "detection_config",
    "wifi_baselines.json": "wifi_baselines",
    "bt_baselines.json": "bt_baselines",
}
# Short component selector → filename (API/CLI ?components= values).
COMPONENT_SELECTORS: dict[str, str] = {
    "rf": "rf_baselines.json",
    "whitelist": "signal_whitelist.json",
    "detection_config": "detection_config.json",
    "wifi": "wifi_baselines.json",
    "bt": "bt_baselines.json",
}
# Members forbidden in kind="preset" (MAC/BSSID-keyed).
PRESET_FORBIDDEN_TYPES = {"wifi_baselines", "bt_baselines"}

# detection_config keys that are site-transferable (shipped in presets). BT
# dimension weights are reserved-and-rejected in v1 (no update path exists yet).
PRESET_DETECTION_CONFIG_KEYS = {
    "rf_dimension_weights",
    "wifi_dimension_weights",
    "rf_anomaly_insert_threshold",
    "rf_anomaly_alert_threshold",
    "rf_anomaly_critical_threshold",
    "wifi_anomaly_insert_threshold",
    "wifi_anomaly_alert_threshold",
    "wifi_anomaly_critical_threshold",
    "wifi_anomaly_cooldown_seconds",
    "rf_min_learning_detections",
    "rf_min_confidence_floor",
    "rf_auto_snooze_seen_count",
    "rf_auto_snooze_max_score",
    "rf_auto_snooze_hours",
    "wifi_auto_snooze_seen_count",
    "wifi_auto_snooze_max_score",
    "wifi_auto_snooze_hours",
}
_RESERVED_REJECTED_CONFIG_KEYS = {"bt_dimension_weights"}

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")


class BundleError(Exception):
    """Raised when a bundle cannot be built, parsed, validated, or applied."""


# --- Manifest models --------------------------------------------------------


class GeneratorInfo(BaseModel):
    model_config = {"extra": "forbid"}

    tool: str
    git_sha: str | None = None
    sigrift_version: str | None = None
    seed: int | None = None
    profile_config_sha256: str | None = None
    numpy_version: str | None = None


class Compatibility(BaseModel):
    model_config = {"extra": "forbid"}

    baseline_schema: int
    freq_bin_strategy: str
    taxonomy: str
    class_set: list[str] = Field(default_factory=list)
    class_set_sha256: str | None = None
    bands: list[str] = Field(default_factory=list)
    bands_sha256: str | None = None
    min_learning_detections: int | None = None
    hourly_counts: Literal["neutral_prior", "utc"] = "utc"


class ComponentEntry(BaseModel):
    model_config = {"extra": "forbid"}

    file: str
    type: str
    sha256: str
    bytes: int
    optional: bool = False


class BundleManifest(BaseModel):
    model_config = {"extra": "forbid"}

    schema_version: int
    kind: Literal["preset", "export"]
    profile: str | None = None
    name: str = ""
    description: str = ""
    created_at: str
    generator: GeneratorInfo
    compatibility: Compatibility
    components: list[ComponentEntry]
    extensions: dict[str, Any] = Field(default_factory=dict)


# --- Compatibility hashing --------------------------------------------------


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def class_set_sha256(classes: list[str]) -> str:
    """Stable hash of a class set (order-independent)."""
    return _sha256_bytes(json.dumps(sorted(classes)).encode("utf-8"))


def bands_sha256() -> str:
    """Stable hash of the active band definitions."""
    return _sha256_bytes(json.dumps(bands.BAND_RANGES).encode("utf-8"))


def compat_snapshot(class_set: list[str] | None = None) -> Compatibility:
    """Compatibility block describing the running environment.

    ``class_set`` defaults to the open-default 16-class model taxonomy.
    """
    classes = list(class_set) if class_set else list(taxonomy_open.OPEN_DEFAULT_CLASSES)
    return Compatibility(
        baseline_schema=BaselineManager.SCHEMA_VERSION,
        freq_bin_strategy=FREQ_BIN_STRATEGY,
        taxonomy="open_default_16",
        class_set=classes,
        class_set_sha256=class_set_sha256(classes),
        bands=[b[0] for b in bands.BAND_RANGES],
        bands_sha256=bands_sha256(),
    )


# --- Sanitation (generation-time) -------------------------------------------


def _round_sig(x: float, sig: int) -> float:
    if x == 0 or not math.isfinite(x):
        return 0.0 if x == 0 else x
    return round(x, sig - 1 - int(math.floor(math.log10(abs(x)))))


def sanitize_rf_baseline(
    fb: FrequencyBaseline,
    *,
    variance_widening: float = PRESET_VARIANCE_WIDENING,
    buffer_cap: int = PRESET_BUFFER_CAP,
    sigfigs: int = PRESET_FLOAT_SIGFIGS,
) -> FrequencyBaseline:
    """Make one learned baseline safe + compact to ship as a preset.

    Mutates ``fb`` in place and returns it. Order matters: the two idempotent
    steps (transients, hourly prior) are what the import validator re-checks
    for a fixpoint; widening/truncation/rounding are generation-only.
    """
    fb.strip_site_transients()
    fb.neutral_hourly_prior()
    fb.power_samples = fb.power_samples[-buffer_cap:]
    fb.snr_samples = fb.snr_samples[-buffer_cap:]
    fb.bandwidth_samples = fb.bandwidth_samples[-buffer_cap:]
    # Power/SNR EWMAs embed antenna/gain absolutes; widen variance so a
    # different receiver's levels do not trip false z-scores before the
    # alpha=0.01 EWMA re-adapts on real data.
    fb.power_var *= variance_widening
    fb.snr_var *= variance_widening
    _round_baseline_floats(fb, sigfigs)
    _assert_no_leak(fb)
    return fb


def _round_baseline_floats(fb: FrequencyBaseline, sig: int) -> None:
    fb.power_ewma = _round_sig(fb.power_ewma, sig)
    fb.power_var = _round_sig(fb.power_var, sig)
    fb.snr_ewma = _round_sig(fb.snr_ewma, sig)
    fb.snr_var = _round_sig(fb.snr_var, sig)
    fb.class_ewma = {k: _round_sig(v, sig) for k, v in fb.class_ewma.items()}
    fb.power_samples = [_round_sig(v, sig) for v in fb.power_samples]
    fb.snr_samples = [_round_sig(v, sig) for v in fb.snr_samples]
    fb.bandwidth_samples = [_round_sig(v, sig) for v in fb.bandwidth_samples]


def _assert_no_leak(fb: FrequencyBaseline) -> None:
    """Raise if any MAC-shaped string survives in a preset baseline."""
    for key in fb.class_counts:
        if _MAC_RE.match(str(key)):
            raise BundleError(f"MAC-shaped class key in preset baseline: {key!r}")


def expected_neutral_hourly(class_counts: dict[str, int]) -> dict[int, dict[str, int]]:
    """The hourly_counts a sanitized baseline must have (validator reference)."""
    return {
        h: {cls: max(1, c // 24) for cls, c in class_counts.items()} for h in range(24)
    }


# --- Bundle building --------------------------------------------------------


def build_bundle(
    out_path: str | Path,
    *,
    kind: Literal["preset", "export"],
    component_bytes: dict[str, bytes],
    manifest_extra: dict[str, Any] | None = None,
    profile: str | None = None,
    name: str = "",
    description: str = "",
    generator: GeneratorInfo | None = None,
    compatibility: Compatibility | None = None,
    created_at: str | None = None,
    mtime: int = 0,
) -> Path:
    """Assemble a bundle from already-serialized component JSON blobs.

    ``component_bytes`` maps component filename → JSON bytes. Callers are
    responsible for having produced sanitized bytes for presets.
    """
    for fname in component_bytes:
        if fname not in COMPONENT_FILES:
            raise BundleError(f"unknown component file: {fname!r}")
    if kind == "preset":
        forbidden = {
            f for f in component_bytes if COMPONENT_FILES[f] in PRESET_FORBIDDEN_TYPES
        }
        if forbidden:
            raise BundleError(f"preset bundles may not contain {sorted(forbidden)}")

    compat = compatibility or compat_snapshot()
    gen = generator or GeneratorInfo(tool="bridge-export")
    components = [
        ComponentEntry(
            file=fname,
            type=COMPONENT_FILES[fname],
            sha256=_sha256_bytes(data),
            bytes=len(data),
        )
        for fname, data in sorted(component_bytes.items())
    ]
    manifest = BundleManifest(
        schema_version=BUNDLE_SCHEMA_VERSION,
        kind=kind,
        profile=profile,
        name=name,
        description=description,
        created_at=created_at or datetime.now(timezone.utc).isoformat(),
        generator=gen,
        compatibility=compat,
        components=components,
        extensions=manifest_extra or {},
    )
    manifest_bytes = json.dumps(manifest.model_dump(), indent=2).encode("utf-8")

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.with_suffix(out_path.suffix + ".tmp")
    with tarfile.open(tmp, "w:gz", compresslevel=9) as tar:
        # manifest MUST be the first member.
        _member_info(tar, "manifest.json", manifest_bytes, mtime)
        for fname, data in sorted(component_bytes.items()):
            _member_info(tar, fname, data, mtime)
    tmp.replace(out_path)
    logger.info(
        "Bundle written: %s (kind=%s, %d components)", out_path, kind, len(components)
    )
    return out_path


def _member_info(tar: tarfile.TarFile, name: str, data: bytes, mtime: int) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    info.mtime = mtime
    info.mode = 0o644
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    tar.addfile(info, io.BytesIO(data))


def _manager_lock(mgr: Any) -> Any:
    """The manager's state lock (``nullcontext`` for lock-less stand-ins)."""
    lock = getattr(mgr, "lock", None)
    return lock if lock is not None else contextlib.nullcontext()


def serialize_rf_manager(mgr: BaselineManager) -> bytes:
    """Serialize a BaselineManager to export bytes.

    The state is snapshotted under the manager lock (ingest updates the
    baselines from worker threads) and serialised after releasing it.
    """
    with _manager_lock(mgr):
        data = {
            "schema_version": mgr.SCHEMA_VERSION,
            "alpha": mgr.alpha,
            "baselines": {
                str(f): json_snapshot(bl.to_dict()) for f, bl in mgr.baselines.items()
            },
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }
    return json.dumps(data, indent=2).encode("utf-8")


def serialize_wifi_manager(mgr: Any) -> bytes:
    """Serialize a WifiBaselineManager to export bytes WITHOUT touching its
    dirty counter (unlike mgr.save(), which would clear it and silently defeat
    the crash-durability autosave for the canonical wifi_baselines.json).
    Snapshotted under the manager lock, like serialize_rf_manager."""
    with _manager_lock(mgr):
        data = {
            "schema_version": mgr.SCHEMA_VERSION,
            "alpha": mgr.alpha,
            "baselines": {
                b: json_snapshot(bl.to_dict()) for b, bl in mgr.baselines.items()
            },
            "ssid_to_bssids": {
                ssid: sorted(bssids) for ssid, bssids in mgr._ssid_to_bssids.items()
            },
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }
    return json.dumps(data, indent=2).encode("utf-8")


def serialize_bt_manager(mgr: Any) -> bytes:
    """Serialize a BtBaselineManager to export bytes WITHOUT touching its dirty
    counter (see serialize_wifi_manager).  Snapshotted under the manager lock."""
    with _manager_lock(mgr):
        data = {
            "schema_version": mgr.SCHEMA_VERSION,
            "alpha": mgr.alpha,
            "baselines": {
                a: json_snapshot(bl.to_dict()) for a, bl in mgr.baselines.items()
            },
            "batch_device_counts": list(mgr._batch_device_counts),
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }
    return json.dumps(data, indent=2).encode("utf-8")


# --- Validation report ------------------------------------------------------


class Check(BaseModel):
    check: str
    result: Literal["pass", "warn", "fail"]
    detail: str = ""
    fix: str = ""


class ValidationReport(BaseModel):
    valid: bool
    kind: str | None = None
    schema_version: int | None = None
    checks: list[Check] = Field(default_factory=list)
    components: list[dict[str, Any]] = Field(default_factory=list)
    would_apply: list[str] = Field(default_factory=list)

    def add(self, check: str, result: str, detail: str = "", fix: str = "") -> None:
        self.checks.append(Check(check=check, result=result, detail=detail, fix=fix))
        if result == "fail":
            self.valid = False


# --- Untrusted-bundle validation pipeline -----------------------------------


def _read_member(tar: tarfile.TarFile, info: tarfile.TarInfo, max_bytes: int) -> bytes:
    """Stream a member with a hard byte ceiling (defeats gzip bombs)."""
    f = tar.extractfile(info)
    if f is None:
        raise BundleError(f"member {info.name!r} is not a regular file")
    buf = io.BytesIO()
    remaining = max_bytes
    while True:
        chunk = f.read(min(1 << 20, remaining + 1))
        if not chunk:
            break
        remaining -= len(chunk)
        if remaining < 0:
            raise BundleError(
                f"member {info.name!r} exceeds declared size {max_bytes} bytes"
            )
        buf.write(chunk)
    return buf.getvalue()


def _reject_constant(_: str) -> Any:
    raise BundleError("NaN/Infinity literal not allowed in bundle JSON")


def validate_bundle(
    path: str | Path,
    *,
    running_compat: Compatibility | None = None,
    expect_kind: str | None = None,
) -> tuple[ValidationReport, BundleManifest | None, dict[str, bytes]]:
    """Validate an untrusted bundle. Returns (report, manifest, member_bytes).

    Never raises on a *bad bundle* — every problem is a failed check in the
    report (report.valid is False). Only genuinely unreadable input raises.
    """
    report = ValidationReport(valid=True)
    path = Path(path)
    total = path.stat().st_size
    if total > MAX_BUNDLE_BYTES:
        report.add(
            "transport_size",
            "fail",
            f"{total} bytes > {MAX_BUNDLE_BYTES} cap",
            "bundle too large; re-export fewer components",
        )
        return report, None, {}

    running_compat = running_compat or compat_snapshot()
    member_bytes: dict[str, bytes] = {}

    try:
        tar = tarfile.open(path, "r:gz", errorlevel=2)
    except (tarfile.TarError, OSError) as exc:
        report.add("archive_open", "fail", f"cannot open archive: {exc}", "re-download")
        return report, None, {}

    with tar:
        # Collect members by iterating the archive lazily rather than
        # tar.getmembers(): in streaming r:gz mode, advancing past a member
        # decompresses its (skipped) payload to reach the next header. A member
        # declaring a huge size would therefore be decompressed here — a
        # gzip-bomb amplification that runs BEFORE the per-member read ceiling.
        # Checking each header's declared size as it is yielded lets us abort
        # before the oversized payload is ever skipped/decompressed.
        members: list[tarfile.TarInfo] = []
        total_declared = 0
        try:
            for m in tar:
                total_declared += max(0, m.size)
                if m.size > MAX_BUNDLE_BYTES or total_declared > MAX_BUNDLE_BYTES:
                    report.add(
                        "member_size",
                        "fail",
                        f"declared uncompressed size exceeds {MAX_BUNDLE_BYTES} bytes "
                        f"at member {m.name!r}",
                        "bundle too large (possible decompression bomb)",
                    )
                    return report, None, {}
                members.append(m)
                if len(members) > MAX_MEMBERS:
                    report.add("member_count", "fail", f"> {MAX_MEMBERS} members", "")
                    return report, None, {}
        except (tarfile.TarError, OSError) as exc:
            report.add("archive_read", "fail", f"corrupt archive: {exc}", "re-download")
            return report, None, {}
        # -- Archive safety (no extractall; regular files only) --
        seen: set[str] = set()
        for m in members:
            name = m.name
            if (
                m.isdir()
                or m.issym()
                or m.islnk()
                or m.isdev()
                or not m.isfile()
                or name != Path(name).name  # any path component / traversal
                or name.startswith((".", "/"))
                or ".." in name
            ):
                report.add("archive_safety", "fail", f"unsafe member {name!r}", "")
                return report, None, {}
            if name in seen:
                report.add("archive_safety", "fail", f"duplicate member {name!r}", "")
                return report, None, {}
            seen.add(name)
        if not members or members[0].name != "manifest.json":
            report.add(
                "manifest_first", "fail", "manifest.json must be the first member", ""
            )
            return report, None, {}

        # -- Manifest --
        minfo = members[0]
        if minfo.size > MAX_MANIFEST_BYTES:
            report.add("manifest_size", "fail", "manifest too large", "")
            return report, None, {}
        try:
            raw = _read_member(tar, minfo, MAX_MANIFEST_BYTES)
            manifest_dict = json.loads(raw, parse_constant=_reject_constant)
            manifest = BundleManifest(**manifest_dict)
        except (json.JSONDecodeError, ValidationError, BundleError) as exc:
            report.add("manifest_parse", "fail", f"invalid manifest: {exc}", "")
            return report, None, {}

        report.kind = manifest.kind
        report.schema_version = manifest.schema_version

        # -- schema_version gate --
        if manifest.schema_version > BUNDLE_SCHEMA_VERSION:
            report.add(
                "schema_version",
                "fail",
                f"bundle schema {manifest.schema_version} > supported {BUNDLE_SCHEMA_VERSION}",
                "upgrade SigRift to import this bundle",
            )
            return report, manifest, {}
        report.add("schema_version", "pass")

        if expect_kind and manifest.kind != expect_kind:
            report.add(
                "kind",
                "fail",
                f"expected kind={expect_kind}, got {manifest.kind}",
                "use the matching endpoint",
            )

        if len(json.dumps(manifest.extensions)) > MAX_EXTENSIONS_BYTES:
            report.add("extensions_size", "fail", "extensions object too large", "")

        # -- manifest ↔ members 1:1 --
        declared = {c.file: c for c in manifest.components}
        member_names = {m.name for m in members if m.name != "manifest.json"}
        for orphan in member_names - declared.keys():
            report.add(
                "orphan_member", "fail", f"member {orphan!r} not in manifest", ""
            )
        for missing in declared.keys() - member_names:
            report.add("missing_member", "fail", f"{missing!r} declared but absent", "")

        # -- per-component: type allowlist, checksum, size ceiling --
        for m in members:
            if m.name == "manifest.json":
                continue
            comp = declared.get(m.name)
            if comp is None:
                continue  # already reported as orphan
            if comp.type not in COMPONENT_FILES.values():
                if comp.optional:
                    report.add(
                        "optional_skipped",
                        "warn",
                        f"unknown optional component {comp.type!r} skipped",
                    )
                    continue
                report.add(
                    "unknown_component",
                    "fail",
                    f"unknown component type {comp.type!r}",
                    "",
                )
                continue
            try:
                data = _read_member(tar, m, comp.bytes)
            except BundleError as exc:
                report.add(f"{m.name} size", "fail", str(exc), "re-export")
                continue
            digest = _sha256_bytes(data)
            if digest != comp.sha256:
                report.add(
                    f"{m.name} sha256",
                    "fail",
                    "sha256 mismatch vs manifest",
                    "bundle corrupted in transit — re-download or re-export",
                )
                continue
            report.add(f"{m.name} sha256", "pass")
            member_bytes[m.name] = data

    # -- Structural validation of parsed content --
    _validate_components(report, manifest, member_bytes)

    # -- Compatibility --
    _validate_compat(report, manifest, running_compat)

    if report.valid:
        report.would_apply = [
            COMPONENT_FILES[f] for f in member_bytes if f in COMPONENT_FILES
        ]
        report.components = [
            {"type": COMPONENT_FILES[f], "sha256_ok": True} for f in member_bytes
        ]
    return report, manifest, member_bytes


def _validate_components(
    report: ValidationReport,
    manifest: BundleManifest,
    member_bytes: dict[str, bytes],
) -> None:
    is_preset = manifest.kind == "preset"
    for fname, data in member_bytes.items():
        ctype = COMPONENT_FILES[fname]
        if is_preset and ctype in PRESET_FORBIDDEN_TYPES:
            report.add(
                f"{fname} preset_forbidden",
                "fail",
                f"{ctype} is MAC-keyed and forbidden in presets",
                "export from the source site instead of shipping a preset",
            )
            continue
        try:
            obj = json.loads(data, parse_constant=_reject_constant)
        except (json.JSONDecodeError, BundleError) as exc:
            report.add(f"{fname} json", "fail", str(exc), "")
            continue
        # parse_constant only fires for the NaN/Infinity *tokens*; a numeric
        # literal like 1e400 is parsed by the number scanner and becomes inf
        # silently. Walk EVERY float in the component (not just the handful the
        # per-type checks cover). RF-domain components carry legitimately huge-
        # but-finite values (frequencies up to ~10 GHz, bandwidth variance in
        # Hz²), so bound magnitude only for the small-valued components; the
        # per-type validators bound the RF fields that actually matter.
        _rf_domain = ctype in ("rf_baselines", "signal_whitelist")
        _scan_finite(report, fname, obj, max_abs=None if _rf_domain else MAX_ABS_FLOAT)
        if ctype == "rf_baselines":
            _validate_rf(report, fname, obj, is_preset)
        elif ctype == "signal_whitelist":
            _validate_whitelist(report, fname, obj, is_preset)
        elif ctype == "detection_config":
            _validate_detection_config(report, fname, obj, is_preset)
        elif ctype == "wifi_baselines":
            _validate_device_baselines(
                report, fname, obj, _WIFI_TOP_FIELDS, _WIFI_BASELINE_FIELDS
            )
        elif ctype == "bt_baselines":
            _validate_device_baselines(
                report, fname, obj, _BT_TOP_FIELDS, _BT_BASELINE_FIELDS
            )


def _scan_finite(
    report: ValidationReport,
    fname: str,
    obj: Any,
    max_abs: float | None = MAX_ABS_FLOAT,
) -> None:
    """Reject non-finite floats (inf/nan) and over-long keys anywhere in a
    parsed component. ``max_abs`` also bounds magnitude when set; pass None for
    components (RF baselines) that legitimately carry huge-but-finite values
    such as bandwidth variance in Hz². The primary goal is catching the
    ``1e400`` -> inf bypass that parse_constant does not stop.
    """

    def walk(x: Any) -> bool:
        if isinstance(x, float):
            if not math.isfinite(x):
                return False
            return max_abs is None or abs(x) <= max_abs
        if isinstance(x, dict):
            return all(
                len(str(k)) <= MAX_STRING_KEY_LEN and walk(v) for k, v in x.items()
            )
        if isinstance(x, list):
            return all(walk(v) for v in x)
        return True

    if not walk(obj):
        report.add(
            f"{fname} finite", "fail", "non-finite/oversize float or long key", ""
        )


def _validate_rf(
    report: ValidationReport, fname: str, obj: dict, is_preset: bool
) -> None:
    if not isinstance(obj, dict):
        report.add(f"{fname} structure", "fail", "not a JSON object", "")
        return
    baselines = obj.get("baselines", {})
    if not isinstance(baselines, dict):
        report.add(f"{fname} structure", "fail", "baselines is not an object", "")
        return
    if len(baselines) > MAX_FREQ_BINS:
        report.add(
            f"{fname} bin_count", "fail", f"{len(baselines)} > {MAX_FREQ_BINS}", ""
        )
        return
    alpha = obj.get("alpha", 0.01)
    if not (isinstance(alpha, (int, float)) and 0.0 < alpha <= 1.0):
        report.add(f"{fname} alpha", "fail", f"alpha {alpha} not in (0, 1]", "")
    for freq_str, bl in baselines.items():
        try:
            freq = float(freq_str)
        except (TypeError, ValueError):
            report.add(
                f"{fname} freq_key", "fail", f"non-numeric freq {freq_str!r}", ""
            )
            return
        if not (FREQ_MIN_HZ <= freq <= FREQ_MAX_HZ):
            report.add(f"{fname} freq_range", "fail", f"freq {freq} out of range", "")
            return
        if not isinstance(bl, dict):
            report.add(
                f"{fname} structure", "fail", f"bin {freq_str} is not an object", ""
            )
            return
        if not _scan_finite_ok(bl):
            report.add(f"{fname} finite", "fail", f"bad float in bin {freq_str}", "")
            return
        for buf in ("power_samples", "snr_samples", "bandwidth_samples"):
            if len(bl.get(buf, [])) > MAX_SAMPLES_PER_BUFFER:
                report.add(f"{fname} {buf}", "fail", "sample buffer too large", "")
                return
        if len(bl.get("class_counts", {})) > MAX_CLASSES_PER_BIN:
            report.add(f"{fname} class_count", "fail", "too many classes in bin", "")
            return
    if is_preset:
        _validate_preset_rf_sanitized(report, fname, baselines)


def _scan_finite_ok(bl: dict) -> bool:
    for v in (
        bl.get("power_ewma", 0.0),
        bl.get("power_var", 0.0),
        bl.get("snr_ewma", 0.0),
        bl.get("snr_var", 0.0),
    ):
        if not (
            isinstance(v, (int, float)) and math.isfinite(v) and abs(v) <= MAX_ABS_FLOAT
        ):
            return False
    return True


def _validate_preset_rf_sanitized(
    report: ValidationReport, fname: str, baselines: dict
) -> None:
    """Idempotence check: a preset's RF baselines must already be sanitized."""
    for freq_str, bl in baselines.items():
        # Transients must be zero.
        for k in (
            "cusum_pos",
            "cusum_neg",
            "cusum_changepoints",
            "cusum_last_changepoint",
            "last_detection_time",
            "last_inter_arrival",
        ):
            if bl.get(k, 0):
                report.add(
                    f"{fname} sanitized",
                    "fail",
                    f"transient {k} not zeroed in bin {freq_str}",
                    "regenerate the preset with the current sanitizer",
                )
                return
        # hourly_counts must equal the neutral prior of class_counts.
        expected = expected_neutral_hourly(
            {k: int(v) for k, v in bl.get("class_counts", {}).items()}
        )
        actual = {int(h): d for h, d in bl.get("hourly_counts", {}).items()}
        if actual != expected:
            report.add(
                f"{fname} hourly_prior",
                "fail",
                f"hourly_counts is not the neutral prior in bin {freq_str}",
                "regenerate the preset with the current sanitizer",
            )
            return
        # No MAC-shaped keys.
        for key in bl.get("class_counts", {}):
            if _MAC_RE.match(str(key)):
                report.add(f"{fname} mac_leak", "fail", f"MAC-shaped key {key!r}", "")
                return
    report.add(f"{fname} sanitized", "pass")


def _validate_whitelist(
    report: ValidationReport, fname: str, obj: dict, is_preset: bool
) -> None:
    if not isinstance(obj, dict):
        report.add(f"{fname} structure", "fail", "not a JSON object", "")
        return
    entries = obj.get("entries", [])
    if not isinstance(entries, list):
        report.add(f"{fname} structure", "fail", "entries is not a list", "")
        return
    if len(entries) > MAX_WHITELIST_ENTRIES:
        report.add(f"{fname} count", "fail", "too many whitelist entries", "")
        return
    for e in entries:
        try:
            # model_validate: an entry that is not an object is a
            # ValidationError too (WhitelistEntry(**e) raised TypeError).
            entry = WhitelistEntry.model_validate(e)
        except ValidationError as exc:
            report.add(f"{fname} entry", "fail", f"invalid whitelist entry: {exc}", "")
            return
        if is_preset and entry.node_ids is not None:
            report.add(
                f"{fname} node_ids",
                "fail",
                "preset whitelist entries must have node_ids=null",
                "regenerate the preset",
            )
            return
    report.add(f"{fname} whitelist", "pass")


def _validate_detection_config(
    report: ValidationReport, fname: str, obj: dict, is_preset: bool
) -> None:
    config = obj.get("config", obj) if isinstance(obj, dict) else obj
    if not isinstance(config, dict):
        report.add(f"{fname} detection_config", "fail", "config must be an object", "")
        return
    for reserved in _RESERVED_REJECTED_CONFIG_KEYS:
        if reserved in config:
            report.add(
                f"{fname} reserved",
                "fail",
                f"{reserved} is reserved and not accepted in v1",
                "remove it from the bundle",
            )
            return
    if is_preset:
        extra = set(config) - PRESET_DETECTION_CONFIG_KEYS
        if extra:
            report.add(
                f"{fname} preset_subset",
                "fail",
                f"non-transferable keys in preset config: {sorted(extra)}",
                "presets may only carry the transferable config subset",
            )
            return
    # The same rules as PUT /api/admin/detection-config, weight sums and
    # entry counts included (a bundle may carry keys of another version,
    # which stay inert).
    try:
        check_detection_config(config, allow_unknown=True)
    except DetectionConfigError as exc:
        report.add(
            f"{fname} detection_config",
            "fail",
            str(exc),
            "fix or remove these values in the bundle",
        )
        return
    report.add(f"{fname} detection_config", "pass")


# WiFi / BT baselines (export only): checked as serialize_wifi_manager /
# serialize_bt_manager emit them and as the apply path loads and saves them
# (load_*_baselines_from_bytes, replace_state, save), so a member that passes
# is applied without error.  Each key a loader reads is optional (it has a
# default) except "baselines": without it the live baselines would be
# replaced by none.  Other keys are inert.


def _is_number(v: Any) -> bool:
    # Not a bool; abs() also refuses inf/nan and integers float() overflows.
    return (
        isinstance(v, (int, float))
        and not isinstance(v, bool)
        and abs(v) <= MAX_ABS_FLOAT
    )


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _is_count(v: Any) -> bool:
    return _is_int(v) and _is_number(v) and v >= 0


def _is_str(v: Any) -> bool:
    return isinstance(v, str)


def _list_of(ok: Callable[[Any], bool]) -> Callable[[Any], bool]:
    return lambda v: isinstance(v, list) and all(ok(x) for x in v)


_is_strings = _list_of(_is_str)

_FieldRules = dict[str, tuple[Callable[[Any], bool], str]]

_ALPHA = (lambda v: _is_number(v) and 0.0 < v <= 1.0, "a number in (0, 1]")
_NUMBER = (_is_number, f"a number in [-{MAX_ABS_FLOAT:g}, {MAX_ABS_FLOAT:g}]")
_VARIANCE = (lambda v: _is_number(v) and v >= 0, f"a number in [0, {MAX_ABS_FLOAT:g}]")
_COUNT = (_is_count, f"an integer in [0, {MAX_ABS_FLOAT:g}]")
_STRING = (_is_str, "a string")
_STRINGS = (_is_strings, "a list of strings")
_SCHEMA = (lambda v: _is_int(v) and v >= 1, "a positive integer")

_WIFI_TOP_FIELDS: _FieldRules = {
    "schema_version": _SCHEMA,
    "alpha": _ALPHA,
    "ssid_to_bssids": (
        lambda v: isinstance(v, dict) and all(_is_strings(b) for b in v.values()),
        "an object of BSSID lists",
    ),
}
_WIFI_BASELINE_FIELDS: _FieldRules = {
    "alpha": _ALPHA,
    "expected_ssids": _STRINGS,
    "expected_channel": (lambda v: v is None or _is_int(v), "an integer or null"),
    "expected_security": _STRING,
    "expected_vendor": _STRING,
    "seen_channels": (_list_of(_is_int), "a list of integers"),
    "signal_ewma": _NUMBER,
    "signal_var": _VARIANCE,
    "client_count_ewma": _NUMBER,
    "retry_rate_ewma": _NUMBER,
    "total_observations": _COUNT,
}
_BT_TOP_FIELDS: _FieldRules = {
    "schema_version": _SCHEMA,
    "alpha": _ALPHA,
    "batch_device_counts": (_list_of(_is_count), "a list of non-negative integers"),
}
_BT_BASELINE_FIELDS: _FieldRules = {
    "alpha": _ALPHA,
    "expected_name": _STRING,
    "expected_device_class": (_is_int, "an integer"),
    "expected_manufacturer": _STRING,
    "expected_service_uuids": _STRINGS,
    "rssi_ewma": _NUMBER,
    "rssi_m2": _VARIANCE,
    "total_observations": _COUNT,
    "first_seen": _STRING,
    "last_seen": _STRING,
}


def _validate_device_baselines(
    report: ValidationReport,
    fname: str,
    obj: Any,
    top_fields: _FieldRules,
    baseline_fields: _FieldRules,
) -> None:
    """Structure of wifi_baselines.json / bt_baselines.json (see above)."""
    if not isinstance(obj, dict):
        report.add(f"{fname} structure", "fail", "not a JSON object", "re-export")
        return
    if not isinstance(obj.get("baselines"), dict):
        report.add(
            f"{fname} structure",
            "fail",
            "baselines is missing or not an object",
            "re-export",
        )
        return
    for key, (ok, expected) in top_fields.items():
        if key in obj and not ok(obj[key]):
            report.add(f"{fname} {key}", "fail", f"{key} must be {expected}", "")
            return
    for addr, bl in obj["baselines"].items():
        if not isinstance(bl, dict):
            report.add(
                f"{fname} baseline", "fail", f"baseline {addr!r} is not an object", ""
            )
            return
        for key, (ok, expected) in baseline_fields.items():
            if key in bl and not ok(bl[key]):
                report.add(
                    f"{fname} baseline",
                    "fail",
                    f"baseline {addr!r}: {key} must be {expected}",
                    "",
                )
                return
    report.add(f"{fname} structure", "pass")


def _validate_compat(
    report: ValidationReport, manifest: BundleManifest, running: Compatibility
) -> None:
    c = manifest.compatibility
    if c.freq_bin_strategy != running.freq_bin_strategy:
        report.add(
            "freq_bin_strategy",
            "fail",
            f"bundle {c.freq_bin_strategy} != running {running.freq_bin_strategy}",
            "frequency bins would not align; cannot import",
        )
        return
    # Taxonomy overlap.
    bundle_classes = set(c.class_set)
    running_classes = set(running.class_set)
    if bundle_classes:
        overlap = len(bundle_classes & running_classes) / len(bundle_classes)
        if overlap < 0.5:
            report.add(
                "taxonomy_overlap",
                "fail",
                f"overlap {overlap:.2f} < 0.50",
                "disjoint taxonomy; pass force=true to import anyway",
            )
        elif bundle_classes - running_classes:
            report.add(
                "taxonomy_overlap",
                "warn",
                f"overlap {overlap:.2f}; unknown classes: {sorted(bundle_classes - running_classes)}",
                "unknown classes are inert; re-export after a model upgrade to clear",
            )
        else:
            report.add("taxonomy_overlap", "pass")
    if c.bands_sha256 and c.bands_sha256 != running.bands_sha256:
        report.add(
            "bands",
            "warn",
            "band definitions differ from running config",
            "no band-keyed state ships in v1; informational only",
        )
    if (
        c.min_learning_detections is not None
        and running.min_learning_detections is not None
        and c.min_learning_detections != running.min_learning_detections
    ):
        report.add(
            "min_learning_detections",
            "warn",
            "differs from running rf_min_learning_detections; some bins may re-enter learning",
        )


# --- Apply primitives (manager-level; router wires app_state) ---------------


def load_rf_baselines_from_bytes(
    data: bytes,
) -> tuple[dict[float, FrequencyBaseline], float]:
    obj = json.loads(data)
    alpha = float(obj.get("alpha", 0.01))
    out: dict[float, FrequencyBaseline] = {}
    for freq_str, bl in obj.get("baselines", {}).items():
        out[float(freq_str)] = FrequencyBaseline.from_dict(bl)
    return out, alpha


def load_wifi_baselines_from_bytes(data: bytes) -> tuple[dict, dict, float]:
    from sigrift.bridge.anomaly.wifi_scorer import (
        WifiBaseline,
        decode_escaped_ssids,
        stores_escaped_ssids,
    )

    obj = json.loads(data)
    alpha = float(obj.get("alpha", 0.02))
    baselines = {
        bssid: WifiBaseline.from_dict(bl)
        for bssid, bl in obj.get("baselines", {}).items()
    }
    ssid_to_bssids = {
        ssid: set(bssids) for ssid, bssids in obj.get("ssid_to_bssids", {}).items()
    }
    if stores_escaped_ssids(obj):
        # A bundle exported before SSIDs were stored as heard.
        ssid_to_bssids = decode_escaped_ssids(baselines, ssid_to_bssids)
    return baselines, ssid_to_bssids, alpha


def load_bt_baselines_from_bytes(data: bytes) -> tuple[dict, list, float]:
    from sigrift.bridge.anomaly.bt_scorer import BtBaseline

    obj = json.loads(data)
    alpha = float(obj.get("alpha", 0.02))
    baselines = {
        addr: BtBaseline.from_dict(bl) for addr, bl in obj.get("baselines", {}).items()
    }
    batch_counts = list(obj.get("batch_device_counts", []))
    return baselines, batch_counts, alpha


def load_whitelist_entries_from_bytes(data: bytes) -> list[WhitelistEntry]:
    obj = json.loads(data)
    return [WhitelistEntry(**e) for e in obj.get("entries", [])]


def apply_detection_config_to_scorers(
    rf_scorer: Any, wifi_scorer: Any, config: dict[str, Any]
) -> None:
    """Propagate a detection-config dict into the live scorers.

    Extracted from routers/system_config.py so the bundle-apply path and the
    PUT /detection-config path share one implementation. Note wifi_scorer's
    update_weights mutates a module-global at the by-design single worker.
    """
    if wifi_scorer is not None and "wifi_dimension_weights" in config:
        wifi_scorer.update_weights(config["wifi_dimension_weights"])
    if rf_scorer is not None:
        if "rf_dimension_weights" in config:
            rf_scorer.update_weights(config["rf_dimension_weights"])
        if "rf_min_learning_detections" in config:
            rf_scorer.config.min_learning_detections = int(
                config["rf_min_learning_detections"]
            )


def plan_detection_config(
    current: dict[str, Any], bundle_config: dict[str, Any], subset_only: bool
) -> dict[str, Any]:
    """Return the detection_config to persist after applying a bundle's config.

    ``subset_only`` (presets) restricts to the transferable key allowlist.
    Deep-merges weight/threshold dicts over the current config.  The values
    merged are the checked ones (:func:`check_detection_config`, as
    validation checked them, with the weights' sums and entry counts
    checked as merged into *current*); raises :class:`BundleError` for a
    value that check refuses.
    """
    incoming = bundle_config.get("config", bundle_config)
    if isinstance(incoming, dict):
        incoming = {
            key: val
            for key, val in incoming.items()
            if not (subset_only and key not in PRESET_DETECTION_CONFIG_KEYS)
            and key not in _RESERVED_REJECTED_CONFIG_KEYS
        }
    try:
        incoming = check_detection_config(incoming, current, allow_unknown=True)
    except DetectionConfigError as exc:
        raise BundleError(f"detection_config: {exc}") from None
    merged = dict(current)
    for key, val in incoming.items():
        if isinstance(val, dict) and isinstance(merged.get(key), dict):
            merged[key] = {**merged[key], **val}
        else:
            merged[key] = val
    return merged


# --- Packaged preset discovery ----------------------------------------------


def _presets_dir() -> Path:
    return Path(__file__).resolve().parent / "presets"


def list_packaged_presets() -> list[dict[str, Any]]:
    """Enumerate bundles shipped under bridge/presets/ (manifest summaries)."""
    out: list[dict[str, Any]] = []
    pdir = _presets_dir()
    if not pdir.is_dir():
        return out
    for path in sorted(pdir.glob("*.sigrift.tar.gz")):
        try:
            manifest = read_manifest(path)
        except BundleError as exc:
            logger.warning("Skipping unreadable preset %s: %s", path.name, exc)
            continue
        out.append(
            {
                "profile": manifest.profile,
                "name": manifest.name,
                "description": manifest.description,
                "created_at": manifest.created_at,
                "git_sha": manifest.generator.git_sha,
                "size_bytes": path.stat().st_size,
                "sha256": _sha256_bytes(path.read_bytes()),
                "file": path.name,
            }
        )
    return out


def resolve_preset(profile: str) -> Path | None:
    for path in _presets_dir().glob("*.sigrift.tar.gz"):
        try:
            if read_manifest(path).profile == profile:
                return path
        except BundleError:
            continue
    return None


def read_manifest(path: str | Path) -> BundleManifest:
    """Read just the manifest from a bundle (first member)."""
    try:
        with tarfile.open(path, "r:gz", errorlevel=2) as tar:
            members = tar.getmembers()
            if not members or members[0].name != "manifest.json":
                raise BundleError("manifest.json is not the first member")
            data = _read_member(tar, members[0], MAX_MANIFEST_BYTES)
            return BundleManifest(**json.loads(data, parse_constant=_reject_constant))
    except (tarfile.TarError, OSError, json.JSONDecodeError, ValidationError) as exc:
        raise BundleError(f"cannot read manifest from {path}: {exc}") from exc


# --- CLI --------------------------------------------------------------------


def _cli_export(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir)
    selectors = args.components or ["rf", "whitelist", "detection_config"]
    component_bytes: dict[str, bytes] = {}
    for sel in selectors:
        fname = COMPONENT_SELECTORS.get(sel)
        if fname is None:
            logger.error("Unknown component selector: %s", sel)
            return 2
        src = data_dir / _data_file_for(fname)
        if src.exists():
            component_bytes[fname] = src.read_bytes()
        else:
            logger.warning("Skipping %s: %s not found", sel, src)
    if not component_bytes:
        logger.error("No components to export")
        return 1
    out = args.out or (
        Path.cwd()
        / f"sigrift_export_{datetime.now(timezone.utc):%Y%m%d_%H%M%S}.sigrift.tar.gz"
    )
    build_bundle(out, kind="export", component_bytes=component_bytes)
    print(out)
    return 0


def _data_file_for(component_file: str) -> str:
    # RF baselines live as baselines.json in the data dir, not rf_baselines.json.
    return "baselines.json" if component_file == "rf_baselines.json" else component_file


def _cli_validate(args: argparse.Namespace) -> int:
    report, _, _ = validate_bundle(args.bundle)
    print(json.dumps(report.model_dump(), indent=2))
    return 0 if report.valid else 1


def _cli_extract(args: argparse.Namespace) -> int:
    report, _, members = validate_bundle(args.bundle)
    if not report.valid:
        logger.error("Bundle failed validation; refusing to extract")
        return 1
    fname = COMPONENT_SELECTORS.get(args.component) or args.component
    if fname not in members:
        logger.error("Component %s not in bundle", args.component)
        return 1
    if args.out == "-":
        sys.stdout.buffer.write(members[fname])
    else:
        Path(args.out).write_bytes(members[fname])
        print(args.out)
    return 0


def _live_bridge_guard(data_dir: Path, force: bool) -> bool:
    """Return True if it is safe to write into data_dir from the CLI."""
    if force:
        return True
    wal = data_dir / "detections.db-wal"
    if wal.exists():
        import time

        if time.time() - wal.stat().st_mtime < 60:
            logger.error(
                "A bridge appears to be running (recent %s). Use the API, or --force.",
                wal.name,
            )
            return False
    return True


def _cli_import(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir)
    report, manifest, members = validate_bundle(args.bundle, expect_kind=None)
    if args.dry_run or not report.valid:
        print(json.dumps(report.model_dump(), indent=2))
        return 0 if report.valid else 1
    if not _live_bridge_guard(data_dir, args.force):
        return 1
    data_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for fname, data in members.items():
        target = data_dir / _data_file_for(fname)
        tmp = target.with_suffix(target.suffix + ".tmp")
        tmp.write_bytes(data)
        tmp.replace(target)
        written.append(target.name)
    logger.info("Imported %s into %s", ", ".join(written), data_dir)
    print(json.dumps({"applied": written}, indent=2))
    return 0


def _cli_list_presets(_: argparse.Namespace) -> int:
    print(json.dumps(list_packaged_presets(), indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m sigrift.bridge.bundles")
    sub = p.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("export", help="export current data-dir state to a bundle")
    e.add_argument("--data-dir", required=True)
    e.add_argument("-o", "--out")
    e.add_argument("--components", nargs="*")
    e.set_defaults(func=_cli_export)

    v = sub.add_parser("validate", help="validate a bundle (spec only)")
    v.add_argument("bundle")
    v.set_defaults(func=_cli_validate)

    i = sub.add_parser("import", help="import a bundle into a data dir")
    i.add_argument("bundle")
    i.add_argument("--data-dir", required=True)
    i.add_argument("--dry-run", action="store_true")
    i.add_argument("--components", nargs="*")
    i.add_argument("--force", action="store_true")
    i.set_defaults(func=_cli_import)

    x = sub.add_parser("extract", help="extract one component file from a bundle")
    x.add_argument("bundle")
    x.add_argument("--component", required=True)
    x.add_argument("-o", "--out", default="-")
    x.set_defaults(func=_cli_extract)

    lp = sub.add_parser("list-presets", help="list packaged presets")
    lp.set_defaults(func=_cli_list_presets)
    return p


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    args = build_parser().parse_args(argv)
    func: Callable[[argparse.Namespace], int] = args.func
    return func(args)


if __name__ == "__main__":
    raise SystemExit(main())
