#!/usr/bin/env bash
# Regenerate the bridge's hashed Python dependency locks.
#
#   scripts/lock-requirements.sh            # re-lock, keeping current pins
#   scripts/lock-requirements.sh --upgrade  # re-lock at the newest allowed
#
# Inputs (edit these) → locks (generated, every package pinned with its
# sha256 hashes; installed with pip --require-hashes):
#
#   src/sigrift/bridge/requirements.in            → requirements.txt
#       runtime dependencies, PyPI only
#   src/sigrift/bridge/requirements-test.in       → requirements-test.txt
#       pytest + plugins, constrained to requirements.txt's versions
#   src/sigrift/bridge/requirements-torch-cpu.in  → requirements-torch-cpu.txt
#       the torch CPU wheel, PyTorch CPU index only, installed --no-deps
#   src/sigrift/bridge/requirements-torch-cuda.in → requirements-torch-cuda.txt
#       the CUDA torch build + nvidia-* packages, PyPI only (ACCEL=cuda image)
#
# Each lock resolves against exactly one index, so no package can come
# from an index it was not meant to come from. Locks target CPython 3.11
# on Linux (the images' python:3.11-slim); the runtime and test locks are
# checked to resolve identically on x86_64 and aarch64.
#
# Needs uv (https://docs.astral.sh/uv/) — `UV=/path/to/uv` to pick one.
set -euo pipefail

cd "$(dirname "$0")/../src/sigrift/bridge"

UV=${UV:-uv}
PYPI=https://pypi.org/simple
TORCH_CPU_INDEX=https://download.pytorch.org/whl/cpu
X86=x86_64-manylinux_2_28
ARM=aarch64-manylinux_2_28

extra=()
case "${1:-}" in
    "") ;;
    --upgrade) extra+=(--upgrade) ;;
    *) echo "usage: $0 [--upgrade]" >&2; exit 2 ;;
esac

compile() {
    # compile IN OUT PLATFORM INDEX [uv args...]
    local in="$1" out="$2" platform="$3" index="$4"
    shift 4
    "$UV" pip compile --quiet "$in" -o "$out" \
        --python-version 3.11 --python-platform "$platform" \
        --index-url "$index" --generate-hashes \
        --custom-compile-command "scripts/lock-requirements.sh" \
        ${extra[@]+"${extra[@]}"} "$@"
}

pins() {
    grep -E '^[A-Za-z0-9]' "$1" | sed 's/ .*//' | LC_ALL=C sort
}

same_on_arm() {
    # The lock must hold for linux/arm64 images too: resolve again for
    # aarch64 (from the x86_64 lock's pins) and compare name==version.
    local in="$1" out="$2" tmp
    shift 2
    tmp=$(mktemp)
    compile "$in" "$tmp" "$ARM" "$PYPI" -c "$out" "$@"
    if ! diff <(pins "$out") <(pins "$tmp") >&2; then
        rm -f "$tmp"
        echo "ERROR: $out resolves differently on aarch64 (diff above)" >&2
        exit 1
    fi
    rm -f "$tmp"
}

compile requirements.in requirements.txt "$X86" "$PYPI"
same_on_arm requirements.in requirements.txt

compile requirements-test.in requirements-test.txt "$X86" "$PYPI" -c requirements.txt
same_on_arm requirements-test.in requirements-test.txt -c requirements.txt

compile requirements-torch-cpu.in requirements-torch-cpu.txt "$X86" "$TORCH_CPU_INDEX" \
    --no-deps --emit-index-url

compile requirements-torch-cuda.in requirements-torch-cuda.txt "$X86" "$PYPI" \
    -c requirements.txt

echo "Locks written in src/sigrift/bridge. Review and commit them together with the .in files."
