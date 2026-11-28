# Base image pinned by digest (multi-arch index: linux/amd64 + linux/arm64),
# so a re-pushed tag cannot change what we build on. Dependabot's docker
# updater bumps tag and digest together.
FROM python:3.11-slim@sha256:064f01707f2fc8b06bae86bb43875266c6e41bac7994e77ec5dc623c4a4d0545 AS runtime

WORKDIR /app

# Runtime tools the bridge shells out to:
#   - openssh-client: bridge.routers.deployment + admin run `ssh` to
#     audit / manage SSH-managed deploy targets. Dashboard "Refresh"
#     on the Deployment tab fails with `[Errno 2] No such file or
#     directory: 'ssh'` without this.
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies, from hashed locks (scripts/lock-requirements.sh):
# pip refuses any file whose sha256 is not in the lock, so a re-uploaded or
# look-alike package cannot slip in. The image gets runtime dependencies
# only — no pytest (requirements-test.txt is for CI and developers).
ARG TARGETARCH
ARG ACCEL=cpu
COPY src/sigrift/bridge/requirements.txt \
     src/sigrift/bridge/requirements-torch-cpu.txt \
     src/sigrift/bridge/requirements-torch-cuda.txt \
     ./
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

# Torch, in its own step. Default is the CPU-only wheel on every arch
# (small image, runs anywhere — the Pi/quickstart path), from the PyTorch
# CPU index ONLY (--index-url, never --extra-index-url: with two indexes
# pip takes a same-named package from whichever has the higher version)
# and with --no-deps (its dependencies are already in requirements.txt).
# Build with `--build-arg ACCEL=cuda` on an amd64 GPU host for the CUDA
# build from PyPI (with its nvidia-* packages, also hash-locked); the
# anomaly autoencoder picks up the GPU automatically
# (torch.cuda.is_available()). arm64 is always CPU — no CUDA torch wheel
# exists for linux/aarch64.
RUN if [ "$ACCEL" = "cuda" ] && [ "$TARGETARCH" = "amd64" ]; then \
           pip install --no-cache-dir --require-hashes \
               --index-url https://pypi.org/simple \
               -r requirements-torch-cuda.txt; \
       else \
           pip install --no-cache-dir --require-hashes --no-deps \
               --index-url https://download.pytorch.org/whl/cpu \
               -r requirements-torch-cpu.txt; \
       fi \
    && rm -f requirements.txt requirements-torch-cpu.txt requirements-torch-cuda.txt

# Copy source into src/sigrift layout (matches PYTHONPATH=src)
COPY src/sigrift/ src/sigrift/
# COPY preserves checkout modes, including 0600 files from a private umask.
# Public code must be readable by appuser; keep executable files executable.
# Normalize only source, before creating the private runtime directories below.
RUN chmod -R u=rwX,go=rX /app/src/sigrift
COPY --chmod=0644 LICENSE NOTICE /app/

# Non-root user. Pin uid/gid 1500 to match the gateway image, so the
# shared `bridge_data` named volume (mounted on both containers) is
# accessible by both. Without matching uids, gateway as uid 1500 hits
# `unable to open database file` on the bridge-owned SQLite store.
# Create the writable directories the bridge expects (data store +
# access logs — both resolved relative to the source tree at runtime
# via Path(__file__).resolve().parent…) and chown them so appuser can
# write at startup.
#
# /app/secrets (BRIDGE_SECRETS_DIR) holds the CA private key. Compose
# mounts the `bridge_secrets` volume there — on the bridge only, never on
# the gateway — and a new named volume copies this directory's owner and
# 0700 mode.
RUN groupadd -r -g 1500 appuser \
    && useradd -r -u 1500 -g appuser -s /bin/false appuser \
    && mkdir -p src/sigrift/bridge/data src/sigrift/logs/access /app/secrets \
    && chown -R appuser:appuser src/sigrift/bridge/data src/sigrift/logs /app/secrets \
    && chmod 0700 /app/secrets

USER appuser

ENV PYTHONPATH=/app/src
ENV BRIDGE_ENV=production
ENV BRIDGE_SECRETS_DIR=/app/secrets

# The release this image was built for: release.yml passes the tag,
# build-and-push.yml main-<sha12>; any other build is "dev". /api/version
# and /api/health report it next to server_version, and the served edge
# installer checks out that tag. After every RUN, so no cached layer
# depends on it.
ARG SIGRIFT_RELEASE=dev
ENV SIGRIFT_RELEASE=${SIGRIFT_RELEASE}
LABEL org.opencontainers.image.version=${SIGRIFT_RELEASE}

EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8001/api/healthz')" || exit 1

# First move a CA private key that an older version left in the data
# volume (which the gateway mounts too) into BRIDGE_SECRETS_DIR — before
# the gateway, which waits for this container to be healthy, starts. It
# leaves the key where it is when BRIDGE_SECRETS_DIR is not on a volume
# (an older compose file), and never stops the bridge from starting.
#
# Then a single uvicorn worker. With 2 worker processes, the WAL never
# resets: `wal_checkpoint(TRUNCATE)` needs an exclusive moment to truncate
# the file, and across two processes + their threadpools under continuous
# traffic there's nearly always a connection mid-read/write, so TRUNCATE
# perpetually returns busy=1 and the WAL creeps ~1.4 GB/day. One process
# lets the periodic checkpoint reliably get its window (and also removes
# the startup journal_mode=WAL race the busy_timeout fix guards against).
# The bridge is async + uses a threadpool for blocking DB calls, so a
# single worker still serves concurrent requests; staging load is modest.
#
# --timeout-keep-alive (uvicorn's default, stated): an idle connection is
# closed after 5 s. The gateway retires its pooled connections well before
# (BACKEND_POOL_IDLE_TIMEOUT in its proxy/handler.rs), so it never sends a
# request on one the bridge is closing (a 502). Keep the two apart:
# tests/bridge/test_gateway_backend_keepalive.py.
CMD ["sh", "-c", "python3 -m sigrift.bridge.ca migrate-key || echo 'WARNING: CA key migration failed (see above); starting anyway' >&2; exec python3 -m uvicorn sigrift.bridge.app:app --host 0.0.0.0 --port 8001 --workers 1 --timeout-keep-alive 5"]
