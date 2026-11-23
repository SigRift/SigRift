"""Lightweight family classifier for edge deployment.

Groups 76 modulation classes into 16 signal families for fast
classification on edge nodes (Raspberry Pi + ONNX Runtime).

Architecture: 54 -> 32 -> n_families (softmax)
~1,700 parameters -- fits in L1 cache, <0.1ms inference.
"""

from __future__ import annotations

import logging
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

from sigrift.lib.dsp.spectral_features import compute_dsp_features

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Signal family definitions
# ---------------------------------------------------------------------------

SIGNAL_FAMILIES: dict[str, list[str]] = {
    "ASK": ["ook", "4ask", "8ask", "16ask", "ism433", "uhf-rfid"],
    "PAM": ["4pam", "8pam", "16pam"],
    "PSK": ["bpsk", "qpsk", "8psk", "16psk", "32psk"],
    "QAM": ["16qam", "32qam", "64qam", "128qam", "256qam"],
    "APSK": ["16apsk", "32apsk", "64apsk", "128apsk"],
    "FSK": [
        "2fsk",
        "4fsk",
        "2gfsk",
        "4gfsk",
        "2msk",
        "4msk",
        "2gmsk",
        "4gmsk",
        "dect",
        "zwave",
        "wisun",
        "scada-fsk",
        "pocsag",
        "nrf24",
        "ais",
        "dstar",
        "gsm",
    ],
    "OFDM": [
        "ofdm-64",
        "ofdm-128",
        "ofdm-256",
        "ofdm-512",
        "ofdm-1024",
        "ofdm-2048",
        "dji-ofdm",
        "nbiot",
        "halow",
    ],
    "ANALOG": ["am-dsb", "am-ssb", "fm", "tone", "fpv-analog", "analog-video-24"],
    "SPREAD_SPECTRUM": [
        "lora-css",
        "elrs",
        "sigfox",
        "sidewalk",
        "lora-meshtastic",
        "lora-meshcore",
        "lora-lorawan",
    ],
    "NOISE": ["noise"],
    "PULSED": ["adsb", "uat", "tpms"],
    "802154": ["oqpsk-dsss", "wireless-hart", "isa100"],
    "SATELLITE": ["iridium"],
    "INTERFERENCE": ["gps-jammer"],
    "TRUNKED": ["p25", "dmr", "tetra"],
    "NARROWBAND_FM": ["pmr446", "wireless-mic"],
}

# Build reverse mapping: class_name -> family
_CLASS_TO_FAMILY: dict[str, str] = {}
for _family, _classes in SIGNAL_FAMILIES.items():
    for _cls in _classes:
        _CLASS_TO_FAMILY[_cls] = _family

# Ordered family names (stable ordering for model output indices)
_FAMILY_NAMES: list[str] = sorted(SIGNAL_FAMILIES.keys())
_FAMILY_TO_INDEX: dict[str, int] = {name: i for i, name in enumerate(_FAMILY_NAMES)}


def get_family(class_name: str) -> str:
    """Map a modulation class name to its signal family.

    Parameters
    ----------
    class_name : str
        One of the 41 modulation class names.

    Returns
    -------
    str
        Family name (e.g. "psk", "qam", "ofdm").

    Raises
    ------
    KeyError
        If the class name is not recognized.
    """
    try:
        return _CLASS_TO_FAMILY[class_name]
    except KeyError:
        raise KeyError(
            f"Unknown modulation class: {class_name!r}. "
            f"Valid classes: {sorted(_CLASS_TO_FAMILY.keys())}"
        )


def get_family_index(family: str) -> int:
    """Return the integer index for a family name."""
    return _FAMILY_TO_INDEX[family]


def get_family_names() -> list[str]:
    """Return the ordered list of family names."""
    return list(_FAMILY_NAMES)


# ---------------------------------------------------------------------------
# LightweightClassifier
# ---------------------------------------------------------------------------


class LightweightClassifier(nn.Module):
    """Tiny MLP for edge family classification.

    Architecture: 54 -> 32 -> n_families (softmax)
    ~2,300 parameters -- fits in L1 cache, <0.1ms inference.

    Parameters
    ----------
    input_dim : int
        Input feature dimensionality (default 54).
    hidden_dim : int
        Hidden layer dimensionality (default 32).
    n_families : int
        Number of output classes (default 16).
    """

    def __init__(
        self,
        input_dim: int = 54,
        hidden_dim: int = 32,
        n_families: int = 16,
    ) -> None:
        super().__init__()
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.n_families = n_families

        self.fc1 = nn.Linear(input_dim, hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, n_families)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Forward pass returning logits.

        Parameters
        ----------
        x : torch.Tensor
            Input features ``[B, input_dim]``.

        Returns
        -------
        torch.Tensor
            Logits ``[B, n_families]``.
        """
        h = F.relu(self.fc1(x))
        return self.fc2(h)

    def predict(self, x: torch.Tensor) -> tuple[str, float]:
        """Return (family_name, confidence) for a single input.

        Parameters
        ----------
        x : torch.Tensor
            Feature vector ``[1, input_dim]`` or ``[input_dim]``.

        Returns
        -------
        tuple[str, float]
            (family_name, confidence)
        """
        self.eval()
        with torch.no_grad():
            if x.dim() == 1:
                x = x.unsqueeze(0)
            logits = self.forward(x)
            probs = F.softmax(logits, dim=-1)
            confidence, idx = probs.max(dim=-1)
            family_name = _FAMILY_NAMES[idx.item()]
            return family_name, confidence.item()

    def predict_batch(self, x: torch.Tensor) -> list[tuple[str, float]]:
        """Batch prediction.

        Parameters
        ----------
        x : torch.Tensor
            Feature vectors ``[B, input_dim]``.

        Returns
        -------
        list[tuple[str, float]]
            List of (family_name, confidence) tuples.
        """
        self.eval()
        with torch.no_grad():
            logits = self.forward(x)
            probs = F.softmax(logits, dim=-1)
            confidences, indices = probs.max(dim=-1)
            results = []
            for i in range(x.shape[0]):
                family_name = _FAMILY_NAMES[indices[i].item()]
                results.append((family_name, confidences[i].item()))
            return results


# ---------------------------------------------------------------------------
# FamilyTrainer
# ---------------------------------------------------------------------------


class FamilyTrainer:
    """Train LightweightClassifier on signal_factory data.

    Parameters
    ----------
    epochs : int
        Number of training epochs (default 30).
    batch_size : int
        Batch size (default 256).
    lr : float
        Learning rate (default 1e-2).
    """

    def __init__(
        self,
        epochs: int = 30,
        batch_size: int = 256,
        lr: float = 1e-2,
    ) -> None:
        self.epochs = epochs
        self.batch_size = batch_size
        self.lr = lr
        self.model = LightweightClassifier()
        self._features: torch.Tensor | None = None
        self._labels: torch.Tensor | None = None

    def prepare_data(
        self,
        samples_per_class: int = 500,
        input_samples: int = 1024,
        snr_range: tuple[float, float] = (-5.0, 25.0),
    ) -> int:
        """Generate training data, map classes to families.

        Parameters
        ----------
        samples_per_class : int
            Number of IQ samples to generate per modulation class.
        input_samples : int
            Number of IQ samples per signal.
        snr_range : tuple[float, float]
            Range of SNR values to sample from.

        Returns
        -------
        int
            Total number of training samples generated.
        """
        from sigrift.lib.training.signal_factory import generate_signal, list_classes

        all_classes = list_classes()
        features_list = []
        labels_list = []
        rng = np.random.RandomState(42)

        for cls_name in all_classes:
            family = get_family(cls_name)
            family_idx = get_family_index(family)

            for _ in range(samples_per_class):
                snr = rng.uniform(snr_range[0], snr_range[1])
                try:
                    iq = generate_signal(
                        cls_name,
                        n_samples=input_samples,
                        snr_db=snr,
                        rng=rng,
                    )
                    # Convert to [1, 2, N] tensor
                    i_vals = torch.tensor(iq.real, dtype=torch.float32).unsqueeze(0)
                    q_vals = torch.tensor(iq.imag, dtype=torch.float32).unsqueeze(0)
                    x = torch.stack([i_vals, q_vals], dim=1)
                    feat = compute_dsp_features(x)  # [1, 49]
                    features_list.append(feat.squeeze(0))
                    labels_list.append(family_idx)
                except Exception as exc:
                    logger.warning("Failed to generate %s: %s", cls_name, exc)

        self._features = torch.stack(features_list)
        self._labels = torch.tensor(labels_list, dtype=torch.long)
        total = len(labels_list)
        logger.info(
            "Prepared %d training samples across %d families", total, len(_FAMILY_NAMES)
        )
        return total

    def train(self, seed: int = 42, verbose: bool = True) -> list[dict]:
        """Train the classifier.

        Parameters
        ----------
        seed : int
            Random seed for reproducibility.
        verbose : bool
            Whether to print training progress.

        Returns
        -------
        list[dict]
            Training history (loss per epoch).
        """
        if self._features is None or self._labels is None:
            raise RuntimeError("Call prepare_data() before train()")

        torch.manual_seed(seed)
        optimizer = torch.optim.Adam(self.model.parameters(), lr=self.lr)
        criterion = nn.CrossEntropyLoss()

        n = self._features.shape[0]
        history: list[dict] = []

        self.model.train()
        for epoch in range(self.epochs):
            # Shuffle
            perm = torch.randperm(n)
            features = self._features[perm]
            labels = self._labels[perm]

            epoch_loss = 0.0
            n_batches = 0

            for i in range(0, n, self.batch_size):
                batch_x = features[i : i + self.batch_size]
                batch_y = labels[i : i + self.batch_size]

                optimizer.zero_grad()
                logits = self.model(batch_x)
                loss = criterion(logits, batch_y)
                loss.backward()
                optimizer.step()

                epoch_loss += loss.item()
                n_batches += 1

            avg_loss = epoch_loss / max(n_batches, 1)
            history.append({"epoch": epoch + 1, "loss": avg_loss})
            if verbose:
                logger.info("Epoch %d/%d  loss=%.4f", epoch + 1, self.epochs, avg_loss)

        return history

    def evaluate(self, n_test: int = 100) -> dict:
        """Evaluate: per-family accuracy, confusion matrix.

        Parameters
        ----------
        n_test : int
            Number of test samples per class.

        Returns
        -------
        dict
            Evaluation results with per-family accuracy and confusion matrix.
        """
        from sigrift.lib.training.signal_factory import generate_signal, list_classes

        all_classes = list_classes()
        rng = np.random.RandomState(99)
        n_families = len(_FAMILY_NAMES)

        confusion = np.zeros((n_families, n_families), dtype=int)
        family_correct: dict[str, int] = {f: 0 for f in _FAMILY_NAMES}
        family_total: dict[str, int] = {f: 0 for f in _FAMILY_NAMES}

        self.model.eval()
        with torch.no_grad():
            for cls_name in all_classes:
                true_family = get_family(cls_name)
                true_idx = get_family_index(true_family)

                for _ in range(n_test):
                    snr = rng.uniform(0.0, 20.0)
                    try:
                        iq = generate_signal(
                            cls_name, n_samples=1024, snr_db=snr, rng=rng
                        )
                        i_vals = torch.tensor(iq.real, dtype=torch.float32).unsqueeze(0)
                        q_vals = torch.tensor(iq.imag, dtype=torch.float32).unsqueeze(0)
                        x = torch.stack([i_vals, q_vals], dim=1)
                        feat = compute_dsp_features(x)
                        pred_family, _ = self.model.predict(feat)
                        pred_idx = get_family_index(pred_family)

                        confusion[true_idx, pred_idx] += 1
                        family_total[true_family] += 1
                        if pred_family == true_family:
                            family_correct[true_family] += 1
                    except Exception:
                        pass

        per_family_accuracy = {}
        for f in _FAMILY_NAMES:
            if family_total[f] > 0:
                per_family_accuracy[f] = family_correct[f] / family_total[f]
            else:
                per_family_accuracy[f] = 0.0

        total_correct = sum(family_correct.values())
        total_samples = sum(family_total.values())
        overall_accuracy = total_correct / max(total_samples, 1)

        return {
            "overall_accuracy": overall_accuracy,
            "per_family_accuracy": per_family_accuracy,
            "confusion_matrix": confusion.tolist(),
            "family_names": list(_FAMILY_NAMES),
        }

    def save_model(self, path: str | Path) -> Path:
        """Save PyTorch model.

        Parameters
        ----------
        path : str or Path
            Output path for the .pth file.

        Returns
        -------
        Path
            Path to the saved model.
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        torch.save(
            {
                "model_state_dict": self.model.state_dict(),
                "input_dim": self.model.input_dim,
                "hidden_dim": self.model.hidden_dim,
                "n_families": self.model.n_families,
                "family_names": list(_FAMILY_NAMES),
            },
            path,
        )
        logger.info("Model saved to %s", path)
        return path

    def export_onnx(self, path: str | Path, opset_version: int = 11) -> Path:
        """Export to ONNX format for edge deployment.

        Parameters
        ----------
        path : str or Path
            Output path for the .onnx file.
        opset_version : int
            ONNX opset version (default 11).

        Returns
        -------
        Path
            Path to the exported ONNX file.
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.model.eval()
        dummy_input = torch.randn(1, self.model.input_dim)
        torch.onnx.export(
            self.model,
            dummy_input,
            str(path),
            opset_version=opset_version,
            dynamo=False,
            input_names=["features"],
            output_names=["logits"],
            dynamic_axes={
                "features": {0: "batch_size"},
                "logits": {0: "batch_size"},
            },
        )
        logger.info("ONNX model exported to %s", path)
        return path


# ---------------------------------------------------------------------------
# Model loading
# ---------------------------------------------------------------------------


def load_family_classifier(path: str | Path) -> LightweightClassifier:
    """Load a trained LightweightClassifier from a .pth file.

    Parameters
    ----------
    path : str or Path
        Path to the saved model.

    Returns
    -------
    LightweightClassifier
        The loaded model in eval mode.
    """
    checkpoint = torch.load(path, map_location="cpu", weights_only=True)
    model = LightweightClassifier(
        input_dim=checkpoint.get("input_dim", 54),
        hidden_dim=checkpoint.get("hidden_dim", 32),
        n_families=checkpoint.get("n_families", 10),
    )
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()
    return model
