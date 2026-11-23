"""Tier 3 Autoencoder anomaly detector for RF signal detections.

Central-server ML anomaly detection using a PyTorch autoencoder.
Trained on "normal" detection feature vectors; anomalies are detected
by high reconstruction error (MSE).  Gracefully degrades if PyTorch
is not installed.

Architecture:
  Encoder: input_dim → hidden_dim → latent_dim (ReLU activations)
  Decoder: latent_dim → hidden_dim → input_dim (ReLU + Sigmoid)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional torch import
# ---------------------------------------------------------------------------

try:
    import numpy as np
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, TensorDataset

    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False
    np = None  # type: ignore[assignment]
    torch = None  # type: ignore[assignment]
    nn = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# PyTorch model definition
# ---------------------------------------------------------------------------

if HAS_TORCH:

    class _AutoencoderNet(nn.Module):
        """Simple symmetric autoencoder network."""

        def __init__(
            self,
            input_dim: int,
            hidden_dim: int,
            latent_dim: int,
        ) -> None:
            super().__init__()
            self.encoder = nn.Sequential(
                nn.Linear(input_dim, hidden_dim),
                nn.ReLU(),
                nn.Linear(hidden_dim, latent_dim),
                nn.ReLU(),
            )
            self.decoder = nn.Sequential(
                nn.Linear(latent_dim, hidden_dim),
                nn.ReLU(),
                nn.Linear(hidden_dim, input_dim),
                nn.Sigmoid(),
            )

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            encoded = self.encoder(x)
            decoded = self.decoder(encoded)
            return decoded

else:
    _AutoencoderNet = None  # type: ignore[assignment,misc]


# ---------------------------------------------------------------------------
# AnomalyAutoencoder
# ---------------------------------------------------------------------------


class AnomalyAutoencoder:
    """Tier 3 anomaly detection using an autoencoder.

    Trained on normal (non-anomalous) detection feature vectors.
    Anomalies are detected by high reconstruction MSE.

    Parameters
    ----------
    input_dim : int
        Input feature dimension.
    latent_dim : int
        Latent space dimension.
    hidden_dim : int
        Hidden layer dimension.
    """

    def __init__(
        self,
        input_dim: int = 268,
        latent_dim: int = 32,
        hidden_dim: int = 128,
    ) -> None:
        self.input_dim = input_dim
        self.latent_dim = latent_dim
        self.hidden_dim = hidden_dim

        self._model: Any = None
        self._trained = False
        self._threshold: float = 0.0
        self._device: str = "cpu"

    def build_model(self) -> None:
        """Create the autoencoder network.

        Raises
        ------
        RuntimeError
            If PyTorch is not installed.
        """
        if not HAS_TORCH:
            raise RuntimeError("PyTorch is required for Autoencoder")

        self._model = _AutoencoderNet(
            self.input_dim,
            self.hidden_dim,
            self.latent_dim,
        )

        # Use GPU if available
        if torch.cuda.is_available():
            self._device = "cuda"
        else:
            self._device = "cpu"

        self._model = self._model.to(self._device)
        logger.info(
            "Autoencoder built: %d → %d → %d (device=%s)",
            self.input_dim,
            self.hidden_dim,
            self.latent_dim,
            self._device,
        )

    def train_model(
        self,
        normal_data: Any,
        epochs: int = 50,
        lr: float = 1e-3,
        batch_size: int = 256,
    ) -> list[float]:
        """Train the autoencoder on normal (non-anomalous) data.

        Parameters
        ----------
        normal_data : np.ndarray
            Training data with shape ``(n_samples, input_dim)``.
        epochs : int
            Number of training epochs.
        lr : float
            Learning rate.
        batch_size : int
            Batch size.

        Returns
        -------
        list[float]
            Per-epoch training loss.

        Raises
        ------
        RuntimeError
            If PyTorch is not installed or model not built.
        """
        if not HAS_TORCH:
            raise RuntimeError("PyTorch is required for Autoencoder")

        if self._model is None:
            self.build_model()

        # Convert to tensor
        tensor_data = torch.tensor(normal_data, dtype=torch.float32).to(self._device)
        dataset = TensorDataset(tensor_data)
        loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

        optimizer = torch.optim.Adam(self._model.parameters(), lr=lr)
        criterion = nn.MSELoss()

        self._model.train()
        losses: list[float] = []

        for epoch in range(epochs):
            epoch_loss = 0.0
            n_batches = 0
            for (batch,) in loader:
                optimizer.zero_grad()
                output = self._model(batch)
                loss = criterion(output, batch)
                loss.backward()
                optimizer.step()
                epoch_loss += loss.item()
                n_batches += 1

            avg_loss = epoch_loss / max(n_batches, 1)
            losses.append(avg_loss)

            if (epoch + 1) % 10 == 0:
                logger.debug("AE epoch %d/%d, loss: %.6f", epoch + 1, epochs, avg_loss)

        self._trained = True
        logger.info(
            "Autoencoder trained: %d epochs, final loss: %.6f",
            epochs,
            losses[-1] if losses else 0.0,
        )

        # Set threshold from training data
        with torch.no_grad():
            self._model.eval()
            recon = self._model(tensor_data)
            mse_per_sample = torch.mean((recon - tensor_data) ** 2, dim=1)
            self._threshold = float(mse_per_sample.mean() + 3.0 * mse_per_sample.std())

        return losses

    def score(self, features: Any) -> float:
        """Compute anomaly score (reconstruction MSE) for a feature vector.

        Parameters
        ----------
        features : np.ndarray
            Feature vector of shape ``(input_dim,)``.

        Returns
        -------
        float
            Reconstruction MSE.  Higher = more anomalous.
            Returns 0.0 if model is not ready.
        """
        if not self.is_ready():
            return 0.0

        self._model.eval()
        with torch.no_grad():
            x = (
                torch.tensor(features, dtype=torch.float32)
                .unsqueeze(0)
                .to(self._device)
            )
            recon = self._model(x)
            mse = float(torch.mean((recon - x) ** 2).item())

        return mse

    def score_batch(self, features: Any) -> Any:
        """Compute anomaly scores for a batch of feature vectors.

        Parameters
        ----------
        features : np.ndarray
            Feature array of shape ``(n_samples, input_dim)``.

        Returns
        -------
        np.ndarray
            Per-sample reconstruction MSE scores.
        """
        if not self.is_ready():
            return np.zeros(len(features)) if HAS_TORCH else []

        self._model.eval()
        with torch.no_grad():
            x = torch.tensor(features, dtype=torch.float32).to(self._device)
            recon = self._model(x)
            mse = torch.mean((recon - x) ** 2, dim=1)
            return mse.cpu().numpy()

    def update_threshold(self, scores: Any) -> None:
        """Set the anomaly threshold from a distribution of normal scores.

        Parameters
        ----------
        scores : np.ndarray
            MSE scores from normal data.  Threshold is set to
            ``mean + 3 * std``.
        """
        if not HAS_TORCH:
            return
        arr = np.asarray(scores, dtype=np.float32)
        self._threshold = float(arr.mean() + 3.0 * arr.std())
        logger.info("AE threshold updated: %.6f", self._threshold)

    def is_anomaly(self, features: Any) -> bool:
        """Check if a feature vector is anomalous.

        Parameters
        ----------
        features : np.ndarray
            Feature vector.

        Returns
        -------
        bool
            True if reconstruction MSE exceeds the threshold.
        """
        return self.score(features) > self._threshold

    def is_ready(self) -> bool:
        """Return True if the model is trained and ready for scoring."""
        if not HAS_TORCH:
            return False
        return self._trained and self._model is not None

    def save(self, path: str) -> None:
        """Save the trained model to disk.

        Parameters
        ----------
        path : str
            Output file path.
        """
        if not self.is_ready():
            logger.warning("Cannot save: model is not trained")
            return

        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)

        checkpoint = {
            "model_state": self._model.state_dict(),
            "input_dim": self.input_dim,
            "latent_dim": self.latent_dim,
            "hidden_dim": self.hidden_dim,
            "threshold": self._threshold,
        }
        torch.save(checkpoint, p)
        logger.info("Autoencoder saved to %s", path)

    def load(self, path: str) -> None:
        """Load a trained model from disk.

        Parameters
        ----------
        path : str
            Input file path.
        """
        if not HAS_TORCH:
            logger.warning("Cannot load AE model: PyTorch not installed")
            return

        p = Path(path)
        if not p.exists():
            logger.warning("AE model file not found: %s", path)
            return

        try:
            checkpoint = torch.load(p, map_location=self._device, weights_only=True)

            self.input_dim = checkpoint["input_dim"]
            self.latent_dim = checkpoint["latent_dim"]
            self.hidden_dim = checkpoint["hidden_dim"]
            self._threshold = checkpoint.get("threshold", 0.0)

            self.build_model()
            self._model.load_state_dict(checkpoint["model_state"])
            self._trained = True

            logger.info("Autoencoder loaded from %s", path)
        except (RuntimeError, KeyError, OSError) as exc:
            logger.warning("Failed to load AE model from %s: %s", path, exc)
