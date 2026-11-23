#!/usr/bin/env python3
"""
Distributed RF Signal Detection - Edge Node
Raspberry Pi 5 + AI Hat 2 (Hailo-8L) + RTL-SDR

This is the main edge node daemon that:
1. Captures IQ samples from RTL-SDR
2. Classifies signals using Hailo-8L accelerator
3. Reports detections to central server via MQTT
4. Uploads unknown/low-confidence samples for further analysis
"""

import json
import os
import re
import time
import socket
import ssl
import sys
import struct
import hashlib
import logging
import argparse
import threading
import queue
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, asdict, field
from typing import Optional, Dict, Any, List, Tuple
from enum import Enum
import numpy as np

# Optional imports
try:
    import paho.mqtt.client as mqtt

    HAS_MQTT = True
except ImportError:
    HAS_MQTT = False
    print("Warning: paho-mqtt not installed. Run: pip install paho-mqtt")

try:
    import psutil

    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


# =============================================================================
# Data Models
# =============================================================================


class SignalPriority(Enum):
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class NodeConfig:
    """Edge node configuration."""

    node_id: str
    location: str = "unknown"
    latitude: Optional[float] = None
    longitude: Optional[float] = None

    # MQTT settings
    mqtt_broker: str = "localhost"
    mqtt_port: int = 1883
    mqtt_user: Optional[str] = None
    mqtt_password: Optional[str] = None
    mqtt_use_tls: bool = False
    # CA bundle (PEM file or hashed directory) that signed the broker's
    # certificate; falls back to MLRF_CA_CERT / MLRF_CA_BUNDLE, then the
    # system trust store.
    mqtt_ca_cert: Optional[str] = None

    # RTL-SDR settings
    rtl_tcp_host: str = "localhost"
    rtl_tcp_port: int = 1234
    sample_rate: int = 2_400_000

    # Classification settings
    model_path: str = "model.hef"
    metadata_path: str = "model_metadata.json"
    confidence_threshold: float = 0.6
    unknown_upload_threshold: float = 0.5

    # Scan settings
    scan_frequencies_mhz: List[float] = field(
        default_factory=lambda: [
            433.92,  # ISM band
            868.0,  # EU ISM
            915.0,  # US ISM
            462.5625,  # FRS
            146.52,  # 2m calling
        ]
    )
    dwell_time_ms: int = 100
    samples_per_capture: int = 8192


@dataclass
class Detection:
    """A signal detection event."""

    event_id: str
    node_id: str
    timestamp: str
    freq_hz: float
    signal_class: str
    confidence: float
    family: str
    snr_db: float
    power_dbm: float
    priority: int = 2
    sample_ref: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class NodeStatus:
    """Node health status."""

    node_id: str
    timestamp: str
    status: str
    current_freq_hz: float
    detections_count: int
    samples_processed: int
    cpu_percent: float
    memory_percent: float
    temperature_c: float
    uptime_seconds: float
    hailo_status: str
    rtl_status: str


# =============================================================================
# Hailo Classifier
# =============================================================================


class HailoClassifier:
    """
    RF Signal Classifier using Hailo-8L on Pi 5 AI Kit.
    """

    def __init__(self, hef_path: str, metadata_path: Optional[str] = None):
        self.hef_path = hef_path
        self.class_names = []
        self.input_samples = 8192
        self.available = False

        # Load metadata
        if metadata_path and Path(metadata_path).exists():
            with open(metadata_path, "r") as f:
                metadata = json.load(f)
                self.class_names = metadata.get("class_names", [])
                self.input_samples = metadata.get("input_samples", 8192)

        # Try to initialize Hailo
        try:
            from hailo_platform import HEF, VDevice, ConfigureParams
            from hailo_platform import (
                InputVStreamParams,
                OutputVStreamParams,
                FormatType,
            )
            from hailo_platform import HailoStreamInterface

            logger.info(f"Loading HEF: {hef_path}")
            self.hef = HEF(hef_path)
            self.device = VDevice()

            self.configure_params = ConfigureParams.create_from_hef(
                self.hef, interface=HailoStreamInterface.PCIe
            )
            self.network_group = self.device.configure(self.hef, self.configure_params)[
                0
            ]

            # Get vstream info
            input_vstream_info = self.hef.get_input_vstream_infos()
            output_vstream_info = self.hef.get_output_vstream_infos()

            self.input_name = input_vstream_info[0].name
            self.output_name = output_vstream_info[0].name
            self.input_shape = input_vstream_info[0].shape

            # Create params for InferVStreams
            self.input_vstream_params = InputVStreamParams.make_from_network_group(
                self.network_group, quantized=False, format_type=FormatType.FLOAT32
            )
            self.output_vstream_params = OutputVStreamParams.make_from_network_group(
                self.network_group, quantized=False, format_type=FormatType.FLOAT32
            )
            self.network_group_params = self.network_group.create_params()

            self.available = True
            self.use_hailo_hef = True
            logger.info(
                f"Hailo classifier initialized: {len(self.class_names)} classes"
            )

        except ImportError:
            logger.warning("Hailo runtime not available - using CPU fallback")
            self._init_cpu_fallback()
        except Exception as e:
            logger.error(f"Hailo initialization failed: {e}")
            self._init_cpu_fallback()

    def _init_cpu_fallback(self):
        """Initialize CPU-based classifier as fallback (ONNX Runtime preferred)."""
        self.use_cpu = False
        self.use_onnx = False

        # Try ONNX Runtime first (lighter weight than PyTorch)
        try:
            import onnxruntime as ort

            onnx_path = self.hef_path.replace(".hef", ".onnx")
            if Path(onnx_path).exists():
                logger.info(f"Loading ONNX Runtime fallback: {onnx_path}")
                self.onnx_session = ort.InferenceSession(onnx_path)
                self.onnx_input_name = self.onnx_session.get_inputs()[0].name
                self.available = True
                self.use_onnx = True
                logger.info("ONNX Runtime classifier initialized")
                return
        except ImportError:
            logger.debug("ONNX Runtime not available")
        except Exception as e:
            logger.debug(f"ONNX Runtime init failed: {e}")

        # Try PyTorch as secondary fallback
        try:
            import torch

            pth_path = self.hef_path.replace(".hef", ".pth")
            if Path(pth_path).exists():
                logger.info(f"Loading PyTorch fallback: {pth_path}")
                checkpoint = torch.load(pth_path, map_location="cpu", weights_only=True)
                if isinstance(checkpoint, dict) and "model_state_dict" in checkpoint:
                    # Need to reconstruct model - skip for now
                    logger.warning(
                        "PyTorch checkpoint format not supported for fallback"
                    )
                    self.available = False
                else:
                    self.cpu_model = checkpoint
                    self.cpu_model.eval()
                    self.available = True
                    self.use_cpu = True
                    logger.info("PyTorch classifier initialized")
                    return
        except Exception as e:
            logger.debug(f"PyTorch fallback failed: {e}")

        if not self.available:
            logger.warning("No fallback classifier available")

    def preprocess(self, iq_samples: np.ndarray) -> np.ndarray:
        """Preprocess IQ samples for inference."""
        # Ensure correct length
        if len(iq_samples) > self.input_samples:
            start = (len(iq_samples) - self.input_samples) // 2
            iq_samples = iq_samples[start : start + self.input_samples]
        elif len(iq_samples) < self.input_samples:
            iq_samples = np.pad(iq_samples, (0, self.input_samples - len(iq_samples)))

        # Normalize
        power = np.mean(np.abs(iq_samples) ** 2)
        if power > 0:
            iq_samples = iq_samples / np.sqrt(power)

        # Convert to appropriate format based on backend
        if hasattr(self, "use_hailo_hef") and self.use_hailo_hef:
            # For Hailo HEF: NHWC format [batch, height, width, channels]
            tensor = np.stack([iq_samples.real, iq_samples.imag], axis=-1)  # [8192, 2]
            tensor = tensor.astype(np.float32)
            tensor = tensor[np.newaxis, np.newaxis, :, :]  # [1, 1, 8192, 2]
        else:
            # For ONNX/CPU: NCHW format [batch, channels, samples]
            tensor = np.stack([iq_samples.real, iq_samples.imag], axis=0)
            tensor = tensor.astype(np.float32)
            tensor = np.expand_dims(tensor, 0)  # [1, 2, 8192]

        return tensor

    def classify(
        self, iq_samples: np.ndarray
    ) -> Tuple[str, float, str, Dict[str, float]]:
        """
        Classify IQ samples.

        Returns:
            (class_name, confidence, family, all_probabilities)
        """
        if not self.available:
            return "unknown", 0.0, "unknown", {}

        input_data = self.preprocess(iq_samples)

        if hasattr(self, "use_onnx") and self.use_onnx:
            return self._classify_onnx(input_data)
        elif hasattr(self, "use_cpu") and self.use_cpu:
            return self._classify_cpu(input_data)
        else:
            return self._classify_hailo(input_data)

    def _classify_hailo(
        self, input_data: np.ndarray
    ) -> Tuple[str, float, str, Dict[str, float]]:
        """Run inference on Hailo accelerator using InferVStreams API."""
        from hailo_platform import InferVStreams

        with InferVStreams(
            self.network_group, self.input_vstream_params, self.output_vstream_params
        ) as pipeline:
            input_dict = {self.input_name: input_data}
            with self.network_group.activate(self.network_group_params):
                output = pipeline.infer(input_dict)

        # Get output from the output stream
        logits = list(output.values())[0][0]

        # Softmax
        exp_logits = np.exp(logits - np.max(logits))
        probs = exp_logits / np.sum(exp_logits)

        return self._process_output(probs)

    def _classify_onnx(
        self, input_data: np.ndarray
    ) -> Tuple[str, float, str, Dict[str, float]]:
        """Run inference using ONNX Runtime."""
        output = self.onnx_session.run(None, {self.onnx_input_name: input_data})
        logits = output[0][0]

        # Softmax
        exp_logits = np.exp(logits - np.max(logits))
        probs = exp_logits / np.sum(exp_logits)

        return self._process_output(probs)

    def _classify_cpu(
        self, input_data: np.ndarray
    ) -> Tuple[str, float, str, Dict[str, float]]:
        """Run inference on CPU using PyTorch."""
        import torch

        with torch.no_grad():
            tensor = torch.from_numpy(input_data)
            logits = self.cpu_model(tensor)
            probs = torch.softmax(logits, dim=-1).squeeze().numpy()

        return self._process_output(probs)

    def _process_output(
        self, probs: np.ndarray
    ) -> Tuple[str, float, str, Dict[str, float]]:
        """Process model output probabilities."""
        best_idx = np.argmax(probs)
        confidence = float(probs[best_idx])

        if self.class_names and best_idx < len(self.class_names):
            class_name = self.class_names[best_idx]
        else:
            class_name = f"class_{best_idx}"

        # Determine family
        family = self._get_family(class_name)

        # All probabilities
        all_probs = {}
        for i, prob in enumerate(probs):
            name = self.class_names[i] if i < len(self.class_names) else f"class_{i}"
            all_probs[name] = float(prob)

        return class_name, confidence, family, all_probs

    def _get_family(self, class_name: str) -> str:
        """Get modulation family from class name."""
        class_name = class_name.lower()
        if "psk" in class_name or "qpsk" in class_name or "bpsk" in class_name:
            return "psk"
        elif "qam" in class_name:
            return "qam"
        elif "fsk" in class_name or "gfsk" in class_name:
            return "fsk"
        elif "ofdm" in class_name:
            return "ofdm"
        elif "am" in class_name or "fm" in class_name or "wbfm" in class_name:
            return "analog"
        elif "ask" in class_name or "ook" in class_name:
            return "ask"
        else:
            return "unknown"


# =============================================================================
# RTL-SDR Capture
# =============================================================================


class RTLSDRCapture:
    """RTL-SDR IQ sample capture via rtl_tcp."""

    def __init__(
        self, host: str = "localhost", port: int = 1234, sample_rate: int = 2_400_000
    ):
        self.host = host
        self.port = port
        self.sample_rate = sample_rate
        self.available = False

    @staticmethod
    def _recv_exact(sock: socket.socket, size: int) -> bytes:
        """Read a complete protocol field/capture, never accept a truncated frame."""
        data = bytearray()
        while len(data) < size:
            chunk = sock.recv(min(size - len(data), 65536))
            if not chunk:
                raise ConnectionError("rtl_tcp disconnected before capture completed")
            data.extend(chunk)
        return bytes(data)

    @classmethod
    def _read_header(cls, sock: socket.socket) -> None:
        # rtl_tcp starts every connection with magic + tuner type + gain count.
        # These 12 bytes are metadata, not unsigned interleaved I/Q samples.
        if cls._recv_exact(sock, 12)[:4] != b"RTL0":
            raise ValueError("Invalid rtl_tcp dongle header")

    def check_connection(self) -> bool:
        """Check that rtl_tcp is reachable and speaks the expected protocol."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2.0)
                sock.connect((self.host, self.port))
                self._read_header(sock)
            self.available = True
            return True
        except Exception as e:
            logger.warning(f"RTL-SDR not available: {e}")
            self.available = False
            return False

    def capture(self, freq_hz: float, num_samples: int = 8192) -> Optional[np.ndarray]:
        """Capture exactly *num_samples* IQ pairs, or return None on failure."""
        if not self.available:
            return None

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5.0)
                sock.connect((self.host, self.port))
                self._read_header(sock)

                # Commands are one byte followed by a network-order u32.
                sock.sendall(struct.pack(">BI", 0x01, int(freq_hz)))
                sock.sendall(struct.pack(">BI", 0x02, self.sample_rate))
                sock.sendall(struct.pack(">BI", 0x03, 0))
                data = self._recv_exact(sock, num_samples * 2)

            raw = np.frombuffer(data, dtype=np.uint8)
            iq = (raw[0::2].astype(np.float32) - 127.5) / 127.5 + 1j * (
                raw[1::2].astype(np.float32) - 127.5
            ) / 127.5
            return iq.astype(np.complex64)

        except Exception as e:
            logger.error(f"Capture error at {freq_hz / 1e6:.3f} MHz: {e}")
            return None

    def estimate_snr(self, iq_samples: np.ndarray) -> float:
        """Estimate SNR from IQ samples."""
        spectrum = np.abs(np.fft.fft(iq_samples)) ** 2
        sorted_power = np.sort(spectrum)
        noise = np.mean(sorted_power[: len(sorted_power) // 4])
        signal = np.mean(sorted_power[-len(sorted_power) // 4 :])
        if noise > 0:
            return float(10 * np.log10(signal / noise))
        return 0.0

    def estimate_power(self, iq_samples: np.ndarray) -> float:
        """Estimate power in dBm (rough approximation)."""
        power_linear = np.mean(np.abs(iq_samples) ** 2)
        return float(10 * np.log10(power_linear + 1e-10) - 30)


# =============================================================================
# Sample Uploader
# =============================================================================


class SampleUploader:
    """Upload unknown samples to central server for analysis."""

    def __init__(self, central_url: str, api_key: str = "", node_id: str = ""):
        self.central_url = central_url
        self.api_key = api_key
        self.node_id = node_id
        self.upload_queue = queue.Queue(maxsize=100)
        self.upload_thread = None
        self.running = False

    def start(self):
        """Start background upload thread."""
        self.running = True
        self.upload_thread = threading.Thread(target=self._upload_worker, daemon=True)
        self.upload_thread.start()

    def stop(self):
        """Stop upload thread."""
        self.running = False
        if self.upload_thread:
            self.upload_thread.join(timeout=5)

    def queue_sample(
        self,
        iq_samples: np.ndarray,
        freq_hz: float,
        confidence: float,
        predicted_class: str,
    ) -> Optional[str]:
        """Queue a sample for upload."""
        sample_id = hashlib.sha256(
            f"{self.node_id}:{freq_hz}:{time.time()}".encode()
        ).hexdigest()[:16]

        try:
            self.upload_queue.put_nowait(
                {
                    "sample_id": sample_id,
                    "iq_data": iq_samples,
                    "freq_hz": freq_hz,
                    "confidence": confidence,
                    "predicted_class": predicted_class,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
            return sample_id
        except queue.Full:
            logger.warning("Upload queue full, dropping sample")
            return None

    def _upload_worker(self):
        """Background worker for uploading samples."""
        while self.running:
            try:
                sample = self.upload_queue.get(timeout=1)
                self._upload_sample(sample)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Upload error: {e}")

    def _upload_sample(self, sample: Dict):
        """Upload a single sample."""
        try:
            import requests

            # Compress IQ data
            iq_bytes = sample["iq_data"].tobytes()

            files = {
                "iq_data": (
                    f"{sample['sample_id']}.bin",
                    iq_bytes,
                    "application/octet-stream",
                )
            }
            data = {
                "sample_id": sample["sample_id"],
                "node_id": self.node_id,
                "freq_hz": sample["freq_hz"],
                "confidence": sample["confidence"],
                "predicted_class": sample["predicted_class"],
                "timestamp": sample["timestamp"],
            }
            headers = {}
            if self.api_key:
                headers["X-API-Key"] = self.api_key

            response = requests.post(
                f"{self.central_url}/api/samples/upload",
                files=files,
                data=data,
                headers=headers,
                timeout=30,
            )

            if response.status_code == 200:
                logger.debug(f"Uploaded sample {sample['sample_id']}")
            else:
                logger.warning(f"Upload failed: {response.status_code}")

        except Exception as e:
            logger.error(f"Upload failed: {e}")


# =============================================================================
# MQTT client (TLS)
# =============================================================================

_CA_ENV_VARS = ("MLRF_CA_CERT", "MLRF_CA_BUNDLE")
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


class MQTTTLSConfigError(ValueError):
    """mqtt_use_tls is on but the configured CA bundle cannot be loaded."""


def _insecure_tls_requested() -> bool:
    """True only when the operator explicitly set MLRF_INSECURE_TLS=1."""
    return os.environ.get("MLRF_INSECURE_TLS", "").strip() == "1"


def _mqtt_ca_source(config: "NodeConfig") -> Optional[Tuple[str, str]]:
    """(setting name, path) of the CA bundle to trust, or None (system store).

    ``mqtt_ca_cert`` wins over MLRF_CA_CERT / MLRF_CA_BUNDLE. A path that
    does not exist is logged and skipped (verification stays on, against
    the system store). Any path that exists -- even one this user cannot
    stat or read -- is returned, so that loading it fails loudly instead of
    silently trusting something else. Same rule as the other edge agents
    (detection_reporter._ca_bundle_source); inlined because this script
    also runs as a standalone file.
    """
    candidates = [("mqtt_ca_cert", config.mqtt_ca_cert or "")]
    candidates += [(var, os.environ.get(var, "")) for var in _CA_ENV_VARS]
    for name, path in candidates:
        path = path.strip()
        if not path:
            continue
        try:
            os.stat(path)
        except (FileNotFoundError, NotADirectoryError):
            logger.error(
                "%s=%s does not exist, verifying the MQTT broker against the "
                "system trust store",
                name,
                path,
            )
            continue
        except (OSError, ValueError):
            pass  # exists but cannot be inspected (e.g. EACCES): load fails below
        return name, path
    return None


def _load_mqtt_ca_context(name: str, path: str) -> ssl.SSLContext:
    """Verifying context trusting the CA bundle *path* (file or hashed dir).

    OpenSSL reads a CA directory lazily, during each handshake, so building
    a context from one succeeds even when this user cannot read it or it
    holds nothing (e.g. the empty directory Docker creates when a
    bind-mounted host file does not exist) -- and then every connection
    fails with "certificate verify failed". A directory is therefore probed
    here: it must be listable and hold at least one hash-named CA
    certificate (``<8 hex digits>.<n>``, as written by ``openssl rehash``)
    that this user can load. Same probe as the other edge agents
    (detection_reporter._load_ca_context).

    Raises MQTTTLSConfigError when the bundle cannot be loaded.
    """
    try:
        if not os.path.isdir(path):
            return ssl.create_default_context(cafile=path)
        entries = os.listdir(path)
        if not entries:
            raise ValueError(
                "it is an empty directory -- Docker creates one when a "
                "bind-mounted host file does not exist; mount an existing "
                "CA file"
            )
        hashed = sorted(
            entry for entry in entries if re.fullmatch(r"[0-9a-f]{8}\.[0-9]+", entry)
        )
        if not hashed:
            raise ValueError(
                "it is a directory with no hash-named CA certificates "
                "(<8 hex digits>.0); run `openssl rehash` on it, or point "
                f"{name} at the PEM file itself"
            )
        last_error: Optional[Exception] = None
        for entry in hashed:
            try:
                probe = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                probe.load_verify_locations(cafile=os.path.join(path, entry))
            except (ssl.SSLError, OSError) as exc:
                last_error = exc
            else:
                return ssl.create_default_context(capath=path)
        raise ValueError(
            f"none of the {len(hashed)} hash-named CA certificates in this "
            f"directory can be loaded; last error: {last_error}"
        )
    except (ssl.SSLError, OSError, ValueError) as exc:
        uid = os.getuid() if hasattr(os, "getuid") else "?"
        raise MQTTTLSConfigError(
            f"{name}={path} cannot be loaded as a CA bundle ({exc}). It must "
            "be a PEM CA certificate file (or a directory of them indexed by "
            f"`openssl rehash`) readable by uid {uid}; fix it, or unset {name} "
            "to verify against the system trust store. TLS verification stays "
            "on -- refusing to connect to the MQTT broker."
        ) from exc


def build_mqtt_tls_context(config: "NodeConfig") -> ssl.SSLContext:
    """Verifying TLS context for the MQTT broker connection.

    Certificate and hostname verification are on. A configured CA bundle
    always verifies (it wins over MLRF_INSECURE_TLS, which cannot downgrade
    it either); without one, only MLRF_INSECURE_TLS=1 turns verification
    off, with a warning -- the same policy as the other edge agents.
    Raises MQTTTLSConfigError when the configured CA bundle exists but
    cannot be loaded -- trusting something else instead would be wrong.
    """
    source = _mqtt_ca_source(config)
    if source is not None:
        ctx = _load_mqtt_ca_context(*source)
        logger.info("MQTT TLS verification enabled (%s=%s)", *source)
    elif _insecure_tls_requested():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        logger.warning(
            "MQTT TLS verification DISABLED via MLRF_INSECURE_TLS=1 -- the "
            "broker is not authenticated and the MQTT password can be "
            "intercepted. Set mqtt_ca_cert / MLRF_CA_CERT instead."
        )
    else:
        ctx = ssl.create_default_context()
        logger.info("MQTT TLS verification enabled (system trust store)")
    return ctx


def create_mqtt_client(config: "NodeConfig"):
    """paho MQTT client for *config*, with TLS applied when requested.

    Returns None when paho-mqtt is not installed. With ``mqtt_use_tls`` the
    TLS context is installed before any connect(), so the username and
    password never cross the network in clear text.
    """
    if not HAS_MQTT:
        return None
    tls_ctx = build_mqtt_tls_context(config) if config.mqtt_use_tls else None
    client = mqtt.Client(client_id=config.node_id)
    if tls_ctx is not None:
        client.tls_set_context(tls_ctx)
    elif config.mqtt_user and config.mqtt_broker not in _LOOPBACK_HOSTS:
        logger.warning(
            "MQTT credentials for %s will be sent in clear text: set "
            "mqtt_use_tls (and mqtt_port, usually 8883)",
            config.mqtt_broker,
        )
    if config.mqtt_user:
        client.username_pw_set(config.mqtt_user, config.mqtt_password)
    return client


# =============================================================================
# Edge Node
# =============================================================================


class EdgeNode:
    """
    Main edge node daemon.
    """

    def __init__(self, config: NodeConfig):
        self.config = config
        self.running = False
        self.start_time = None
        self.detections_count = 0
        self.samples_processed = 0

        # Initialize components
        self.classifier = HailoClassifier(config.model_path, config.metadata_path)

        self.sdr = RTLSDRCapture(
            config.rtl_tcp_host, config.rtl_tcp_port, config.sample_rate
        )

        # MQTT client (raises MQTTTLSConfigError for an unusable CA bundle)
        self.mqtt_client = create_mqtt_client(config)

        # Sample uploader
        self.uploader = None

    def connect_mqtt(self) -> bool:
        """Connect to MQTT broker."""
        if not self.mqtt_client:
            return False

        try:
            self.mqtt_client.connect(self.config.mqtt_broker, self.config.mqtt_port)
            self.mqtt_client.loop_start()
            logger.info(f"Connected to MQTT broker: {self.config.mqtt_broker}")
            return True
        except Exception as e:
            logger.error(f"MQTT connection failed: {e}")
            return False

    def disconnect_mqtt(self):
        """Disconnect from MQTT broker."""
        if self.mqtt_client:
            try:
                self.mqtt_client.loop_stop()
            finally:
                self.mqtt_client.disconnect()

    def publish_detection(self, detection: Detection):
        """Publish detection event."""
        if self.mqtt_client:
            topic = f"rf/detections/{self.config.node_id}"
            self.mqtt_client.publish(topic, json.dumps(detection.to_dict()), qos=1)

    def publish_status(self):
        """Publish node status."""
        if not self.mqtt_client:
            return

        cpu_percent = 0.0
        memory_percent = 0.0
        temperature = 0.0

        if HAS_PSUTIL:
            cpu_percent = psutil.cpu_percent()
            memory_percent = psutil.virtual_memory().percent
            try:
                temps = psutil.sensors_temperatures()
                if "cpu_thermal" in temps:
                    temperature = temps["cpu_thermal"][0].current
            except:  # noqa: E722
                pass

        status = NodeStatus(
            node_id=self.config.node_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            status="scanning" if self.running else "idle",
            current_freq_hz=0,
            detections_count=self.detections_count,
            samples_processed=self.samples_processed,
            cpu_percent=cpu_percent,
            memory_percent=memory_percent,
            temperature_c=temperature,
            uptime_seconds=time.time() - self.start_time if self.start_time else 0,
            hailo_status="ok" if self.classifier.available else "unavailable",
            rtl_status="ok" if self.sdr.available else "unavailable",
        )

        topic = f"rf/status/{self.config.node_id}"
        self.mqtt_client.publish(topic, json.dumps(asdict(status)), qos=0)

    def scan_frequency(self, freq_hz: float) -> Optional[Detection]:
        """Scan a single frequency and classify."""
        iq_samples = self.sdr.capture(freq_hz, self.config.samples_per_capture)
        if iq_samples is None:
            return None

        self.samples_processed += len(iq_samples)

        # Check if signal present (simple energy detection)
        snr = self.sdr.estimate_snr(iq_samples)
        if snr < 3.0:  # No significant signal
            return None

        # Classify
        signal_class, confidence, family, all_probs = self.classifier.classify(
            iq_samples
        )

        # Determine if we should report this
        if confidence < self.config.confidence_threshold:
            # Low confidence - might upload for analysis
            if confidence < self.config.unknown_upload_threshold and self.uploader:
                sample_ref = self.uploader.queue_sample(
                    iq_samples, freq_hz, confidence, signal_class
                )
            else:
                sample_ref = None

            # Still report as unknown if very uncertain
            if confidence < 0.3:
                signal_class = "unknown"
                family = "unknown"
        else:
            sample_ref = None

        # Create detection event
        event_id = hashlib.sha256(
            f"{self.config.node_id}:{freq_hz}:{time.time()}".encode()
        ).hexdigest()[:16]

        # Determine priority
        priority = SignalPriority.NORMAL.value
        if confidence > 0.9:
            priority = SignalPriority.HIGH.value
        if signal_class == "unknown":
            priority = SignalPriority.HIGH.value

        detection = Detection(
            event_id=event_id,
            node_id=self.config.node_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            freq_hz=freq_hz,
            signal_class=signal_class,
            confidence=confidence,
            family=family,
            snr_db=snr,
            power_dbm=self.sdr.estimate_power(iq_samples),
            priority=priority,
            sample_ref=sample_ref,
            metadata={
                "location": self.config.location,
                "top_3": sorted(all_probs.items(), key=lambda x: -x[1])[:3],
            },
        )

        self.detections_count += 1
        return detection

    def run(self, status_interval: float = 30.0):
        """Run main scanning loop."""
        self.running = True
        self.start_time = time.time()
        last_status_time = 0

        # Check RTL-SDR
        if not self.sdr.check_connection():
            logger.warning("RTL-SDR not available - running in demo mode")

        # Connect MQTT
        self.connect_mqtt()

        logger.info(f"Edge node {self.config.node_id} starting")
        logger.info(f"  Frequencies: {self.config.scan_frequencies_mhz}")
        logger.info(
            f"  Classifier: {'Hailo' if self.classifier.available else 'unavailable'}"
        )
        logger.info(
            f"  RTL-SDR: {'connected' if self.sdr.available else 'unavailable'}"
        )

        try:
            while self.running:
                # Scan all frequencies
                for freq_mhz in self.config.scan_frequencies_mhz:
                    if not self.running:
                        break

                    freq_hz = freq_mhz * 1e6
                    detection = self.scan_frequency(freq_hz)

                    if detection:
                        logger.info(
                            f"Detection: {detection.signal_class} "
                            f"({detection.confidence * 100:.1f}%) at {freq_mhz:.3f} MHz"
                        )
                        self.publish_detection(detection)

                    # Small delay between frequencies
                    time.sleep(self.config.dwell_time_ms / 1000)

                # Status update
                now = time.time()
                if now - last_status_time >= status_interval:
                    self.publish_status()
                    last_status_time = now

        except KeyboardInterrupt:
            logger.info("Shutdown requested")
        finally:
            self.running = False
            try:
                self.disconnect_mqtt()
            finally:
                try:
                    if self.uploader:
                        self.uploader.stop()
                finally:
                    logger.info("Edge node stopped")


# =============================================================================
# CLI
# =============================================================================


def load_config(config_path: str) -> NodeConfig:
    """Load configuration from YAML file."""
    import yaml

    with open(config_path, "r") as f:
        data = yaml.safe_load(f)

    return NodeConfig(
        node_id=data.get("node_id", socket.gethostname()),
        location=data.get("location", "unknown"),
        latitude=data.get("latitude"),
        longitude=data.get("longitude"),
        mqtt_broker=data.get("mqtt_broker", "localhost"),
        mqtt_port=data.get("mqtt_port", 1883),
        mqtt_user=data.get("mqtt_user"),
        mqtt_password=data.get("mqtt_password"),
        mqtt_use_tls=bool(data.get("mqtt_use_tls", False)),
        mqtt_ca_cert=data.get("mqtt_ca_cert"),
        rtl_tcp_host=data.get("rtl_tcp_host", "localhost"),
        rtl_tcp_port=data.get("rtl_tcp_port", 1234),
        sample_rate=data.get("sample_rate", 2_400_000),
        model_path=data.get("model_path", "model.hef"),
        metadata_path=data.get("metadata_path", "model_metadata.json"),
        confidence_threshold=data.get("confidence_threshold", 0.6),
        unknown_upload_threshold=data.get("unknown_upload_threshold", 0.5),
        scan_frequencies_mhz=data.get("scan_frequencies_mhz", [433.92, 868.0, 915.0]),
        dwell_time_ms=data.get("dwell_time_ms", 100),
        samples_per_capture=data.get("samples_per_capture", 8192),
    )


def main():
    parser = argparse.ArgumentParser(description="RF Signal Detection Edge Node")
    parser.add_argument("--config", "-c", help="Configuration YAML file")
    parser.add_argument("--node-id", help="Node ID (default: hostname)")
    parser.add_argument(
        "--mqtt-broker", default="localhost", help="MQTT broker address"
    )
    parser.add_argument(
        "--mqtt-port",
        type=int,
        default=None,
        help="MQTT broker port (default: 8883 with --mqtt-tls, else 1883)",
    )
    parser.add_argument(
        "--mqtt-tls",
        action="store_true",
        help="Connect to the broker over TLS (certificate verified)",
    )
    parser.add_argument(
        "--mqtt-ca-cert",
        default=None,
        help="CA bundle for the broker certificate (default: MLRF_CA_CERT, "
        "then the system trust store)",
    )
    parser.add_argument("--model", default="model.hef", help="Hailo model path")
    parser.add_argument("--rtl-host", default="localhost", help="rtl_tcp host")
    parser.add_argument("--rtl-port", type=int, default=1234, help="rtl_tcp port")
    parser.add_argument(
        "--test", action="store_true", help="Test mode (no RTL-SDR required)"
    )

    args = parser.parse_args()

    if args.config:
        config = load_config(args.config)
    else:
        config = NodeConfig(
            node_id=args.node_id or socket.gethostname(),
            mqtt_broker=args.mqtt_broker,
            mqtt_port=args.mqtt_port or (8883 if args.mqtt_tls else 1883),
            mqtt_use_tls=args.mqtt_tls,
            mqtt_ca_cert=args.mqtt_ca_cert,
            model_path=args.model,
            rtl_tcp_host=args.rtl_host,
            rtl_tcp_port=args.rtl_port,
        )

    try:
        node = EdgeNode(config)
    except MQTTTLSConfigError as exc:
        logger.error("%s", exc)
        return 1
    node.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
