"""Configuration loading for SigRift.

FIX: gen2 had a config.yaml that was never loaded anywhere.
This module provides proper YAML config loading with defaults and validation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Sentinel for unset values
_UNSET = object()


@dataclass
class TrainingConfig:
    """Training hyperparameters."""

    epochs: int = 200
    batch_size: int = 256
    learning_rate: float = 1e-3
    weight_decay: float = 1e-4
    gamma: float = 1.5
    label_smoothing: float = 0.1
    ofdm_boost: float = 1.5
    # FIX: early stopping was missing in gen2
    early_stopping_patience: int = 30
    early_stopping_min_delta: float = 1e-4
    # FIX: val SNR range now matches training range
    snr_range_db: tuple[float, float] = (-5.0, 25.0)
    val_snr_range_db: tuple[float, float] = (-5.0, 25.0)
    input_samples: int = 4096
    num_workers: int = 4
    pin_memory: bool = True
    mixed_precision: bool = True
    # Scheduler
    scheduler_t0: int = 50
    scheduler_t_mult: int = 2
    # Mixup
    mixup_alpha: float = 0.4
    mixup_qam_alpha: float = 0.2


@dataclass
class ModelConfig:
    """Model architecture parameters."""

    base_channels: int = 64
    num_classes: int = 41
    input_samples: int = 4096
    dropout: float = 0.3


@dataclass
class HardwareConfig:
    """Hardware capture settings."""

    sample_rate: float = 2_048_000.0
    center_freq: float = 433_000_000.0
    gain: float = 40.0
    rtlsdr_host: str = "127.0.0.1"
    rtlsdr_port: int = 1234
    hackrf_host: str = "127.0.0.1"
    hackrf_port: int = 1235


@dataclass
class SecurityConfig:
    """Security settings for network services."""

    require_auth: bool = True
    tls_enabled: bool = True
    cert_path: str = ""
    key_path: str = ""
    api_key_length: int = 32
    max_request_size_mb: int = 10
    rate_limit_per_minute: int = 600


@dataclass
class DistributedConfig:
    """Distributed deployment settings."""

    mqtt_broker: str = "localhost"
    mqtt_port: int = 8883  # TLS port by default, not 1883
    mqtt_use_tls: bool = True
    mqtt_reconnect_delay: float = 5.0
    mqtt_max_reconnect_delay: float = 300.0
    heartbeat_interval: float = 30.0
    coordinator_host: str = "0.0.0.0"
    coordinator_port: int = 8443


@dataclass
class MLRFConfig:
    """Top-level MLRF configuration."""

    training: TrainingConfig = field(default_factory=TrainingConfig)
    model: ModelConfig = field(default_factory=ModelConfig)
    hardware: HardwareConfig = field(default_factory=HardwareConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    distributed: DistributedConfig = field(default_factory=DistributedConfig)


def _apply_dict(dc: Any, d: dict) -> None:
    """Recursively apply dict values to a dataclass instance."""
    for k, v in d.items():
        if not hasattr(dc, k):
            logger.warning("Unknown config key: %s", k)
            continue
        current = getattr(dc, k)
        if isinstance(v, dict) and hasattr(current, "__dataclass_fields__"):
            _apply_dict(current, v)
        else:
            setattr(dc, k, v)


def load_config(path: str | Path | None = None) -> MLRFConfig:
    """Load configuration from a YAML file, falling back to defaults.

    Args:
        path: Path to config YAML. If None, searches for config.yaml
              in the current directory and parent directories.

    Returns:
        Populated MLRFConfig dataclass.
    """
    config = MLRFConfig()

    if path is None:
        # Search for config.yaml in cwd and parents
        cwd = Path.cwd()
        for parent in [cwd, *cwd.parents]:
            candidate = parent / "config.yaml"
            if candidate.exists():
                path = candidate
                break

    if path is not None:
        path = Path(path)
        if path.exists():
            try:
                import yaml

                with open(path) as f:
                    raw = yaml.safe_load(f)
                if isinstance(raw, dict):
                    _apply_dict(config, raw)
                    logger.info("Loaded config from %s", path)
            except ImportError:
                logger.warning("PyYAML not installed; using default config")
            except Exception:
                logger.exception("Failed to load config from %s", path)

    return config
