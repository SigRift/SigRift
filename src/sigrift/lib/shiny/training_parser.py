"""Training log parser for SigRift hierarchical metrics.

Parses training log files into TrainingStatus- and EpochData-compatible
dicts.  Supports four log formats:

1. Gen3 hierarchical: per-level losses (cls/mt/fam/sf/cons) and accuracy
2. DDP format: ``Epoch X/Y: Loss X/Y | Class X%/Y% | Balanced Z% | LR X``
3. Knowledge distillation: alpha, temperature, KL divergences
4. Gen2 standard: ``Epoch X/Y - Train Loss: ..., Train Acc: ..., Val Acc: ...``
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Gen3 hierarchical: "Epoch 5/200 | Total 1.234 | cls 0.82 mt 0.14 ..."
_RE_HIER_EPOCH = re.compile(
    r"Epoch\s+(\d+)/(\d+)\s*\|"
    r"\s*Total\s+([\d.]+)\s*\|"
    r"\s*cls\s+([\d.]+)\s+mt\s+([\d.]+)\s+fam\s+([\d.]+)"
    r"\s+sf\s+([\d.]+)\s+cons\s+([\d.]+)"
)

# Gen3 accuracy: "Acc cls 78.3% mt 91.2% fam 94.7% sf 97.1%"
_RE_HIER_ACC = re.compile(
    r"Acc\s+cls\s+([\d.]+)%\s+mt\s+([\d.]+)%\s+fam\s+([\d.]+)%\s+sf\s+([\d.]+)%"
)

# Gen3 validation: "Val Loss 0.98 | Acc cls 80.1% mt 92.0% fam 95.3% sf 97.8%"
_RE_HIER_VAL = re.compile(
    r"Val\s+Loss\s+([\d.]+)\s*\|\s*Acc\s+cls\s+([\d.]+)%"
    r"\s+mt\s+([\d.]+)%\s+fam\s+([\d.]+)%\s+sf\s+([\d.]+)%"
)

# KD metrics: "KD alpha=0.4 T=2.0 | KL cls 0.12 mt 0.05 fam 0.03 sf 0.01"
_RE_KD = re.compile(
    r"KD\s+alpha=([\d.]+)\s+T=([\d.]+)\s*\|"
    r"\s*KL\s+cls\s+([\d.]+)\s+mt\s+([\d.]+)\s+fam\s+([\d.]+)\s+sf\s+([\d.]+)"
)

# DDP: "Epoch  1/100: Loss 2.3/1.8 | Class 45.2%/52.1% | Balanced 40.3% | LR 1e-3"
_RE_DDP = re.compile(
    r"Epoch\s+(\d+)/(\d+):\s*Loss\s+([\d.]+)/([\d.]+)"
    r"\s*\|\s*Class\s+([\d.]+)%/([\d.]+)%"
    r"\s*\|\s*Balanced\s+([\d.]+)%"
    r"\s*\|\s*LR\s+([\d.eE+-]+)"
)

# Gen2 standard: "Epoch 1/40 - Train Loss: 3.36, Train Acc: 5.6%, Val Loss: 2.91, Val Acc: 14.4%"
_RE_STD = re.compile(
    r"Epoch\s+(\d+)/(\d+)\s*-\s*Train Loss:\s*([\d.]+)"
    r",\s*Train Acc:\s*([\d.]+)%"
    r",\s*Val Loss:\s*([\d.]+)"
    r",\s*Val Acc:\s*([\d.]+)%"
)

# LR line: "LR: 3.2e-4" or "LR 0.00032"
_RE_LR = re.compile(r"LR[:\s]+([\d.eE+-]+)")

# Completion markers
_RE_BEST_BAL = re.compile(r"Best balanced accuracy:\s*([\d.]+)%")
_RE_BEST_VAL = re.compile(r"Best validation accuracy:\s*([\d.]+)%")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def parse_training_log(log_path: str | Path) -> dict[str, Any]:
    """Parse a training log for current progress.

    Returns a dict compatible with ``TrainingStatus`` fields.
    """
    path = Path(log_path)
    if not path.exists():
        return {"running": False, "run_id": "", "current_epoch": 0, "total_epochs": 0}

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {"running": False, "run_id": "", "current_epoch": 0, "total_epochs": 0}

    lines = content.strip().splitlines()
    run_id = path.stem

    result: dict[str, Any] = {
        "run_id": run_id,
        "running": True,
        "current_epoch": 0,
        "total_epochs": 0,
        "best_epoch": 0,
        "best_val_acc": 0.0,
        "latest_epoch": None,
    }

    # Scan from end for latest epoch
    for index in range(len(lines) - 1, -1, -1):
        line = lines[index]
        # Gen3 hierarchical
        m = _RE_HIER_EPOCH.search(line)
        if m:
            epoch_data = _parse_hier_epoch(m, _epoch_context(lines, index))
            result["current_epoch"] = int(m.group(1))
            result["total_epochs"] = int(m.group(2))
            result["latest_epoch"] = epoch_data
            break

        # DDP format
        m = _RE_DDP.search(line)
        if m:
            epoch_data = _parse_ddp_epoch(m)
            result["current_epoch"] = int(m.group(1))
            result["total_epochs"] = int(m.group(2))
            result["latest_epoch"] = epoch_data
            break

        # Gen2 standard
        m = _RE_STD.search(line)
        if m:
            epoch_data = _parse_std_epoch(m)
            result["current_epoch"] = int(m.group(1))
            result["total_epochs"] = int(m.group(2))
            result["latest_epoch"] = epoch_data
            break

    # Check completion
    best_bal = _RE_BEST_BAL.search(content)
    best_val = _RE_BEST_VAL.search(content)
    if best_bal:
        result["running"] = False
        result["best_val_acc"] = float(best_bal.group(1))
    elif best_val:
        result["running"] = False
        result["best_val_acc"] = float(best_val.group(1))
    elif "COMPARISON RESULTS" in content:
        result["running"] = False

    return result


def parse_training_history(log_path: str | Path) -> list[dict[str, Any]]:
    """Parse full epoch history from a training log.

    Returns a list of dicts compatible with ``EpochData`` fields.
    """
    path = Path(log_path)
    if not path.exists():
        return []

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    lines = content.strip().splitlines()
    epochs: list[dict[str, Any]] = []

    i = 0
    while i < len(lines):
        line = lines[i]

        # Gen3 hierarchical
        m = _RE_HIER_EPOCH.search(line)
        if m:
            epochs.append(_parse_hier_epoch(m, _epoch_context(lines, i)))
            i += 1
            continue

        # DDP format
        m = _RE_DDP.search(line)
        if m:
            epochs.append(_parse_ddp_epoch(m))
            i += 1
            continue

        # Gen2 standard
        m = _RE_STD.search(line)
        if m:
            epochs.append(_parse_std_epoch(m))
            i += 1
            continue

        i += 1

    return epochs


# ---------------------------------------------------------------------------
# Internal parsers
# ---------------------------------------------------------------------------


def _epoch_context(lines: list[str], start: int) -> list[str]:
    """Keep metrics within one epoch, regardless of progress-line count."""
    end = start + 1
    while end < len(lines):
        if any(
            pattern.search(lines[end]) for pattern in (_RE_HIER_EPOCH, _RE_DDP, _RE_STD)
        ):
            break
        end += 1
    return lines[start:end]


def _parse_hier_epoch(
    m: re.Match[str],
    context_lines: list[str],
) -> dict[str, Any]:
    """Build an EpochData-compatible dict from a hierarchical epoch match."""
    ed: dict[str, Any] = {
        "epoch": int(m.group(1)),
        "loss_total": float(m.group(3)),
        "loss_cls": float(m.group(4)),
        "loss_mt": float(m.group(5)),
        "loss_fam": float(m.group(6)),
        "loss_sf": float(m.group(7)),
        "loss_cons": float(m.group(8)),
        "learning_rate": 0.0,
        "acc_cls": 0.0,
        "acc_mt": 0.0,
        "acc_fam": 0.0,
        "acc_sf": 0.0,
    }

    # Scan nearby lines for accuracy, validation, KD, LR
    for ctx in context_lines:
        vm = _RE_HIER_VAL.search(ctx)
        if vm:
            ed["val_loss"] = float(vm.group(1))
            ed["val_acc_cls"] = float(vm.group(2))
            ed["val_acc_mt"] = float(vm.group(3))
            ed["val_acc_fam"] = float(vm.group(4))
            ed["val_acc_sf"] = float(vm.group(5))
        # Validation also contains "Acc cls". Remove only validation metrics
        # before finding training accuracy; both may share one logger line.
        am = _RE_HIER_ACC.search(_RE_HIER_VAL.sub(" ", ctx))
        if am:
            ed["acc_cls"] = float(am.group(1))
            ed["acc_mt"] = float(am.group(2))
            ed["acc_fam"] = float(am.group(3))
            ed["acc_sf"] = float(am.group(4))

        km = _RE_KD.search(ctx)
        if km:
            ed["kd_alpha"] = float(km.group(1))
            ed["kd_temperature"] = float(km.group(2))
            ed["kl_cls"] = float(km.group(3))
            ed["kl_mt"] = float(km.group(4))
            ed["kl_fam"] = float(km.group(5))
            ed["kl_sf"] = float(km.group(6))

        lm = _RE_LR.search(ctx)
        if lm:
            ed["learning_rate"] = float(lm.group(1))

    return ed


def _parse_ddp_epoch(m: re.Match[str]) -> dict[str, Any]:
    """Build an EpochData-compatible dict from a DDP epoch match."""
    return {
        "epoch": int(m.group(1)),
        "loss_total": float(m.group(3)),
        "val_loss": float(m.group(4)),
        "acc_cls": float(m.group(5)),
        "val_acc_cls": float(m.group(6)),
        "learning_rate": float(m.group(8)),
        "loss_cls": 0.0,
        "loss_mt": 0.0,
        "loss_fam": 0.0,
        "loss_sf": 0.0,
        "loss_cons": 0.0,
        "acc_mt": 0.0,
        "acc_fam": 0.0,
        "acc_sf": 0.0,
    }


def _parse_std_epoch(m: re.Match[str]) -> dict[str, Any]:
    """Build an EpochData-compatible dict from a gen2 standard epoch match."""
    return {
        "epoch": int(m.group(1)),
        "loss_total": float(m.group(3)),
        "acc_cls": float(m.group(4)),
        "val_loss": float(m.group(5)),
        "val_acc_cls": float(m.group(6)),
        "learning_rate": 0.0,
        "loss_cls": 0.0,
        "loss_mt": 0.0,
        "loss_fam": 0.0,
        "loss_sf": 0.0,
        "loss_cons": 0.0,
        "acc_mt": 0.0,
        "acc_fam": 0.0,
        "acc_sf": 0.0,
    }
