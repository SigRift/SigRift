"""Model checkpoints must be loaded with the safe (weights-only) unpickler.

Review finding D13: ``training/train_open_default.py`` resumed with
``torch.load(args.resume)`` and no ``weights_only=True``. On torch < 2.6
(where the default was ``False``) that unpickles arbitrary objects, so a
tampered checkpoint runs code when loaded. Every ``torch.load`` in the
repository now passes ``weights_only=True`` explicitly, and nothing uses
``pickle`` loads directly.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_SCANNED = ("src", "training", "scripts", "tools")
_SKIP_PARTS = {".git", "node_modules", "venv", ".venv", "__pycache__", "target"}


def _python_files() -> list[Path]:
    files: list[Path] = []
    for top in _SCANNED:
        root = _REPO / top
        if not root.is_dir():
            continue
        for path in root.rglob("*.py"):
            rel = path.relative_to(_REPO)
            if _SKIP_PARTS.intersection(rel.parts) or "tests" in rel.parts:
                continue
            files.append(path)
    return files


def _dotted(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _calls(name: str) -> list[tuple[Path, ast.Call]]:
    found = []
    for path in _python_files():
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError:  # pragma: no cover - not our code to judge
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _dotted(node.func) == name:
                found.append((path, node))
    return found


def test_scan_covers_the_training_script() -> None:
    assert _REPO / "training" / "train_open_default.py" in _python_files()


def test_every_torch_load_is_weights_only() -> None:
    calls = _calls("torch.load")
    assert calls, "expected to find torch.load calls to check"
    offenders = []
    for path, call in calls:
        kw = {k.arg: k.value for k in call.keywords if k.arg}
        value = kw.get("weights_only")
        if not (isinstance(value, ast.Constant) and value.value is True):
            offenders.append(f"{path.relative_to(_REPO)}:{call.lineno}")
    assert not offenders, "torch.load without weights_only=True: " + ", ".join(
        offenders
    )


@pytest.mark.parametrize("name", ["pickle.load", "pickle.loads", "pickle.Unpickler"])
def test_no_direct_pickle_loads(name: str) -> None:
    hits = [f"{p.relative_to(_REPO)}:{c.lineno}" for p, c in _calls(name)]
    assert not hits, f"{name} used: {hits}"


def test_resume_checkpoint_shapes_load_with_weights_only(tmp_path: Path) -> None:
    """Both checkpoint shapes the training script resumes from stay loadable.

    The final checkpoint embeds ``TrainingConfig.__dict__`` (tuples, floats,
    bools) and the history dict; the Trainer's periodic checkpoint adds
    optimizer/scheduler/scaler state and provenance strings.
    """
    torch = pytest.importorskip("torch")
    from sigrift.lib.config import TrainingConfig

    model = torch.nn.Linear(4, 2)
    opt = torch.optim.AdamW(model.parameters(), lr=1e-3)
    sched = torch.optim.lr_scheduler.CosineAnnealingWarmRestarts(opt, T_0=5)
    final = {
        "model_state_dict": model.state_dict(),
        "classes": ["a", "b"],
        "input_samples": 4096,
        "git_sha": "deadbeef",
        "config": TrainingConfig().__dict__,
        "history": {"train_loss": [0.5, 0.25], "val_acc": [0.1, 0.2]},
    }
    periodic = {
        "epoch": 5,
        "model_state_dict": model.state_dict(),
        "optimizer_state_dict": opt.state_dict(),
        "scheduler_state_dict": sched.state_dict(),
        "metrics": {"loss": 0.1, "per_class_accuracy": {"a": 1.0}},
        "best_val_acc": 0.9,
        "classes": ["a", "b"],
        "config": {"snr_range_db": [-5.0, 25.0]},
        "provenance": {"git_hash": "unknown", "timestamp": "now"},
    }
    for name, ckpt in (("final.pth", final), ("periodic.pth", periodic)):
        path = tmp_path / name
        torch.save(ckpt, path)
        loaded = torch.load(path, map_location="cpu", weights_only=True)
        assert loaded["model_state_dict"].keys() == model.state_dict().keys()


def test_weights_only_refuses_code_objects(tmp_path: Path) -> None:
    """The safe loader rejects a checkpoint that smuggles a callable."""
    torch = pytest.importorskip("torch")
    path = tmp_path / "evil.pth"
    torch.save({"model_state_dict": {}, "hook": print}, path)
    with pytest.raises(Exception):
        torch.load(path, map_location="cpu", weights_only=True)
