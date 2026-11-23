# Base image pinned by digest (multi-arch index: linux/amd64 + linux/arm64);
# dependabot's docker updater bumps tag and digest together.
FROM python:3.11-slim@sha256:064f01707f2fc8b06bae86bb43875266c6e41bac7994e77ec5dc623c4a4d0545 AS runtime

# Edge agent. Multiple run modes — compose `command:` override picks one:
#   - default:  `python -m sigrift.edge.node_agent`     heartbeat-only
#   - scan:     `python -m sigrift.edge.rf_scan`        ONNX RF classification
#   - wifi:     `python /app/src/sigrift/edge/wifi_scan.py`
#                                                       802.11 monitor-mode capture
#   - bt:       `python -m sigrift.lib.bt_scanner`      BlueZ HCI scan
#   - rtl-tcp:  `python -m sigrift.edge.rtl_tcp_supervisor`
#                                                       USB SDR → TCP relay (runs rtl_tcp,
#                                                       survives a re-plugged receiver)
#
# All run modes share this image to keep the layer cache hot across them.

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        # rtl-sdr path
        rtl-sdr \
        libusb-1.0-0 \
        # wifi_scan: monitor-mode capture, channel hopping
        tcpdump \
        iw \
        iproute2 \
        wireless-tools \
        # bt_scanner: BlueZ stack for hcitool / bluetoothctl
        bluez \
        # setcap below — file capabilities for non-root BLE scanning
        libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# The container runs as uid 1500 (appuser) with no effective
# capabilities, and the host's D-Bus policy only admits root or the
# ``bluetooth`` group to org.bluez — so bluetoothctl is unusable and
# the BLE path falls back to raw HCI via hcitool. ``lescan`` issues
# privileged HCI commands (set-scan-parameters) that need
# CAP_NET_ADMIN on top of CAP_NET_RAW; grant both on the binary so
# the fallback works without running the scanner as root.
RUN setcap 'cap_net_raw,cap_net_admin+eip' /usr/bin/hcitool

# numpy + onnxruntime are only needed for the rf_scan path. The
# heartbeat-only node_agent uses stdlib alone, so on installs that
# never run scan the extra layer is wasted. Trade-off accepted —
# keeps a single edge image instead of two.
#
# Default installs the CPU onnxruntime. Build with
# `--build-arg ACCEL=cuda` on an amd64 GPU host to install
# onnxruntime-gpu instead; ONNXBackend then runs on the
# CUDAExecutionProvider (with CPU fallback). onnxruntime-gpu 1.26
# requires CUDA 12.* + cuDNN 9.* at runtime; without them it logs a
# CUDA-load error and falls back to CPU. arm64 is always CPU. Both
# variants pinned to the same ORT version for reproducible builds, and
# numpy to the version the bridge lock (src/sigrift/bridge/requirements.txt)
# uses — an unpinned numpy would float to whatever is newest at build
# time, including a release onnxruntime was not built against.
ARG TARGETARCH
ARG ACCEL=cpu
ARG NUMPY_VERSION=2.4.6
RUN if [ "$ACCEL" = "cuda" ] && [ "$TARGETARCH" = "amd64" ]; then \
        pip install --no-cache-dir "numpy==${NUMPY_VERSION}" onnxruntime-gpu==1.26.0; \
    else \
        pip install --no-cache-dir "numpy==${NUMPY_VERSION}" onnxruntime==1.26.0; \
    fi

# Copy only the sigrift package — edge code imports nothing else from
# this repo at runtime.
COPY src/sigrift/ src/sigrift/
# COPY preserves checkout modes, including 0600 files from a private umask.
# Public code must be readable by appuser; keep executable files executable.
# Normalize only source, before creating the writable runtime directory below.
RUN chmod -R u=rwX,go=rX /app/src/sigrift
COPY --chmod=0644 LICENSE NOTICE /app/

# Pin uid/gid 1500 — matches bridge + gateway so any shared volume
# semantics stay consistent across the stack. Pre-create the writable
# log dir for rf_scan (MLRF_LOG_DIR points here in compose).
RUN groupadd -r -g 1500 appuser \
    && useradd -r -u 1500 -g appuser -s /bin/false appuser \
    && mkdir -p /app/logs \
    && chown -R appuser:appuser /app/logs

USER appuser

ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python3", "-m", "sigrift.edge.node_agent"]
