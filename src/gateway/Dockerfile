# Pin the builder to a bookworm base so the produced binary's glibc
# requirement matches the bookworm-slim runtime below. The default
# `rust:1.95-slim` tracks Debian 13 (trixie, glibc 2.41) which would
# emit a binary requiring GLIBC_2.38+ — bookworm has 2.36 and the
# loader fails: "version `GLIBC_2.38' not found".
# Both base images are pinned by digest (multi-arch index: linux/amd64 +
# linux/arm64), so a re-pushed tag cannot change what we build on.
# Dependabot's docker updater bumps tag and digest together.
FROM rust:1.96-slim-bookworm@sha256:e18a79fc84dfcfc3ab5ba72290398a644c135c97eaa881447fddc354ee4701a3 AS builder

WORKDIR /build
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock LICENSE ./
COPY src/ src/
COPY licenses/gateway/ licenses/gateway/
COPY scripts/gateway-notices.py scripts/gateway-notices.py
# Reject stale dependency notices using the same locked inputs as CI.
RUN sha256sum --check licenses/gateway/SHA256SUMS

# Cache cargo registry + git + target across BuildKit invocations.
# With docker/build-push-action's `cache-from/cache-to: type=gha` we
# get layer-level caching for "stable" layers, but the cargo build
# layer is invalidated by every src/ change. The cache mounts let
# cargo's own incremental work persist across those rebuilds. arm64
# leg on the Pi runner sees the biggest win.
# The target mount is shared by every build on this BuildKit, whatever
# checkout or commit it builds, and cargo takes a workspace crate as fresh
# when none of its source files is newer than its cached build. COPY keeps
# the context's mtimes, so a checkout made before another checkout's build
# reused that build's binary ("Finished", nothing compiled). Touching the
# gateway sources makes cargo compile the workspace crates from these
# sources; the dependencies stay cached.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    find src/gateway -type f -exec touch {} + \
    && cargo build --release -p sigrift-gateway \
    && strip target/release/sigrift-gateway \
    && cp target/release/sigrift-gateway /tmp/sigrift-gateway-release
# Move the binary out of the cache mount so it's available to the
# next stage (cache mounts aren't copied to the final image).

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS runtime

RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*
# Pin uid/gid to 1500 so the host bootstrap can chown the bind-mounted
# TLS dir to a known group. Without a fixed gid, `useradd -r` picks a
# system uid that varies across base-image versions and the bind-mount
# perms break.
RUN groupadd -r -g 1500 appuser \
    && useradd -r -u 1500 -g appuser -s /bin/false appuser

WORKDIR /app
COPY --chmod=0644 LICENSE NOTICE /app/
COPY --chmod=0644 licenses/gateway/THIRD-PARTY-NOTICES.txt /app/THIRD-PARTY-NOTICES.txt
COPY --from=builder /tmp/sigrift-gateway-release /app/sigrift-gateway
COPY --chmod=755 src/gateway/healthcheck.sh /app/healthcheck.sh

RUN mkdir -p /app/data && chown -R appuser:appuser /app/data
USER appuser

ENV UC_HOST=0.0.0.0
ENV UC_PORT=8444

# The release this image was built for (release.yml: the tag;
# build-and-push.yml: main-<sha12>; otherwise "dev"). The gateway does not
# read it: it is for `docker image inspect` and the installers. The
# bridge reports its own copy in /api/version. Runtime stage only, so the
# cargo build is unaffected.
ARG SIGRIFT_RELEASE=dev
ENV SIGRIFT_RELEASE=${SIGRIFT_RELEASE}
LABEL org.opencontainers.image.version=${SIGRIFT_RELEASE}

EXPOSE 8444

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/app/healthcheck.sh"]

ENTRYPOINT ["/app/sigrift-gateway"]
