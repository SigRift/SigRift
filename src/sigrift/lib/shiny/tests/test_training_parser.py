"""Training status and history must keep each epoch's metrics separate."""

import pytest

from sigrift.lib.shiny.training_parser import (
    parse_training_history,
    parse_training_log,
)


def epoch(number):
    return f"Epoch {number}/200 | Total 2.5 | cls 1.0 mt 0.5 fam 0.4 sf 0.3 cons 0.2"


def training(accuracy):
    return f"Acc cls {accuracy}% mt 60.0% fam 70.0% sf 80.0%"


VALIDATION = "Val Loss 2.1 | Acc cls 50.0% mt 65.0% fam 75.0% sf 85.0%"


@pytest.mark.parametrize("validation_first", [False, True])
def test_training_and_validation_can_share_a_log_line(tmp_path, validation_first):
    path = tmp_path / "training.log"
    metrics = [training(45.0), VALIDATION]
    if validation_first:
        metrics.reverse()
    path.write_text(epoch(1) + "\nINFO " + " | ".join(metrics))

    latest = parse_training_log(path)["latest_epoch"]
    assert parse_training_history(path) == [latest]
    assert latest["acc_cls"] == 45.0
    assert latest["val_acc_cls"] == 50.0


@pytest.mark.parametrize("prefix", ["", "2026-11-06 09:00:00 INFO "])
def test_training_and_validation_accuracy_are_distinct(tmp_path, prefix):
    path = tmp_path / "training.log"
    path.write_text(
        "\n".join(prefix + line for line in [epoch(1), training(45.0), VALIDATION])
    )

    latest = parse_training_log(path)["latest_epoch"]
    history = parse_training_history(path)
    assert latest == history[0]
    assert [latest[f"acc_{level}"] for level in ("cls", "mt", "fam", "sf")] == [
        45.0,
        60.0,
        70.0,
        80.0,
    ]
    assert [latest[f"val_acc_{level}"] for level in ("cls", "mt", "fam", "sf")] == [
        50.0,
        65.0,
        75.0,
        85.0,
    ]


def test_compact_epochs_do_not_share_accuracy(tmp_path):
    path = tmp_path / "training.log"
    path.write_text("\n".join([epoch(1), training(45.0), epoch(2), training(55.0)]))

    history = parse_training_history(path)
    assert [item["epoch"] for item in history] == [1, 2]
    assert [item["acc_cls"] for item in history] == [45.0, 55.0]
    assert parse_training_log(path)["latest_epoch"] == history[-1]


def test_partial_epoch_does_not_inherit_older_metrics(tmp_path):
    path = tmp_path / "training.log"
    path.write_text(
        "\n".join(
            [
                epoch(1),
                training(45.0),
                VALIDATION,
                "KD alpha=0.4 T=2.0 | KL cls 0.12 mt 0.05 fam 0.03 sf 0.01",
                "LR: 3.2e-4",
                epoch(2),
            ]
        )
    )

    latest = parse_training_log(path)["latest_epoch"]
    assert latest == parse_training_history(path)[-1]
    assert latest["epoch"] == 2
    assert latest["acc_cls"] == latest["learning_rate"] == 0.0
    assert "val_loss" not in latest
    assert "kd_alpha" not in latest


def test_epoch_metrics_survive_interleaved_progress_lines(tmp_path):
    path = tmp_path / "training.log"
    path.write_text(
        "\n".join(
            [
                epoch(1),
                *[f"validation batch {i}" for i in range(6)],
                training(45.0),
                VALIDATION,
                "LR: 3.2e-4",
            ]
        )
    )

    latest = parse_training_log(path)["latest_epoch"]
    assert parse_training_history(path) == [latest]
    assert latest["acc_cls"] == 45.0
    assert latest["val_acc_cls"] == 50.0
    assert latest["learning_rate"] == 3.2e-4


def test_format_transition_stops_hierarchical_context(tmp_path):
    path = tmp_path / "training.log"
    path.write_text(
        "\n".join(
            [
                epoch(1),
                training(45.0),
                "Epoch 2/200 - Train Loss: 1.2, Train Acc: 60.0%, Val Loss: 1.1, Val Acc: 65.0%",
                "LR: 1e-4",
            ]
        )
    )

    history = parse_training_history(path)
    assert len(history) == 2
    assert history[0]["learning_rate"] == 0.0
    assert history[1]["acc_cls"] == 60.0
    assert parse_training_log(path)["latest_epoch"] == history[-1]
