> **Maintainer / infrastructure doc** — not needed to run or evaluate SigRift.

# CI / CD architecture

The GitHub Actions workflows that check every pull request, publish
`:main` images on demand, and build signed releases.
Contributors mostly meet `ci.yml` (the per-PR gate); the rest are listed
so a red or skipped check makes sense.

---

## Workflow map

```
┌─────────────────────────────────────────────────────────────────────────┐
│                             Event sources                                │
│                                                                          │
│   PR push ─────┐                   dispatch ──────┐     tag push ─────┐ │
│                │                                  │                   │ │
└────────────────┼──────────────────────────────────┼───────────────────┼─┘
                 │                                  │                   │
                 ▼                                  ▼                   ▼
  ┌────────────────────────┐        ┌────────────────────────┐   ┌─────────────┐
  │       ci.yml           │        │ build-and-push.yml     │   │ release.yml │
  │  (PRs and main pushes) │        │ (manual runs only)     │   │             │
  │  • lint (ruff)         │        │  • bridge image → GHCR │   │ • coverage  │
  │  • scripts (shellcheck │        │  • gateway image →     │   │   preflight │
  │    + tests)            │        │  • edge image →        │   │ • images    │
  │  • rust (clippy, test) │        │    :main + :main-sha12 │   │ • tarballs  │
  │  • docker-build        │        └────────────────────────┘   │ • SBOM      │
  │  • bridge-tests        │                                     │ • cosign    │
  │    (xdist -n 4)        │                                     │ • GH Release│
  └────────────────────────┘                                     └─────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│            Other workflows (PRs and main pushes unless noted)           │
│                                                                         │
│   gitleaks.yml ─────────── secret scan, blocks on committed secrets     │
│   dep-audit.yml ────────── npm / pip / cargo vulnerability audit        │
│   quickstart-smoke.yml ─── quickstart.sh end-to-end on a clean runner   │
│                            (install/runtime paths; also weekly cron)    │
│   rust-coverage.yml ────── Rust line + branch coverage floor            │
│   javascript-coverage.yml  JavaScript line + branch coverage floor      │
│                            (both: main pushes and security PRs)         │
│   metrics.yml ──────────── regenerates docs/metrics.json; manual commit │
│                                                                         │
│   codeql.yml ───────────── weekly static analysis (cron + dispatch)     │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Workflow inventory

### `.github/workflows/ci.yml` — per-PR gating

**Triggers:** `push: main`, `pull_request: main`.

**Path filters:** none on `pull_request`, so every PR — docs-only ones included — runs the workflow and gets a `CI ok` result; on a docs-only PR the `changes` job skips the heavy jobs and `ci-ok` accepts those skips. This matters for branch protection: when a whole workflow is skipped by a path filter, GitHub leaves its checks **Pending**, and a PR that requires them cannot merge. `push: main` still skips the whole workflow for commits that touch only `**.md`, `docs/**`, `LICENSE` or `.gitignore`. That does not affect required checks (no merge waits on a push run), but such a commit has no CI run of its own, so `release.yml`'s coverage preflight refuses to release it. The preflight also needs that push run's Python jobs (the four test shards, Shiny, the coverage report and the Python floor) to have succeeded, and `changes` runs them only when the push touched a path in the `python` filter: tag a commit whose own `main` push changed such a path (a release-prep change to `pyproject.toml` does).

**Change detection job:** A fast `changes` job (~30 s) runs `dorny/paths-filter@v4` to classify what a PR touches:

| Filter | Matches |
|--------|---------|
| `python` | `src/sigrift/**`, `scripts/**`, `training/**`, `tests/bridge/**`, `tests/docs/**`, `.coveragerc`, `pyproject.toml`, the bridge `requirements*` files, `.github/workflows/ci.yml`, and the gateway files the key-role parity test reads |
| `rust` | `src/gateway/**`, `Cargo.toml`, `Cargo.lock`, `**/Dockerfile`, `docker-compose*.yml`, `.github/workflows/ci.yml` |
| `security` | Authentication, proxy, storage, crypto and installer paths (listed in the workflow), plus `.github/workflows/**` |

Heavy language-specific jobs `if:`-gate on these outputs. Docker-build, lint and the scripts job always run (cheap, broad).

**Jobs (all required to pass before merge, except `docs-vs-metrics`, which is informational):**

| Job | Tool | Gated on | Scope |
|-----|------|----------|-------|
| `changes` | dorny/paths-filter | always runs | Emits `python` / `rust` / `security` outputs consumed below |
| `lint` | ruff | always runs | Python style + format check on `src/sigrift/` |
| `scripts` | shellcheck + pytest | always runs | `bash -n` + shellcheck over the repo's shell scripts, `docker compose config` for every compose overlay combination, and the `scripts/tests` suite (installers, CI and release checks) plus the license-packaging and release-notes docs tests |
| `rust` | cargo fmt / clippy / test / build | `rust` ∨ `python` | Workspace + community-binary boundary check (greps Python source for forbidden enterprise imports — that's why Python changes also trigger it). Heavy (see runner note). |
| `docker-build` | docker compose build | always runs | Builds `bridge` + `gateway` + `edge` images from the compose file. Runs on `ubuntu-latest` (needs a clean Docker daemon). |
| `bridge-tests-shard` | pytest-split + xdist | `python` | 4 shards × ~10 min wall — Rust-only PRs skip the matrix entirely. Heavy (see runner note). |
| `bridge-tests` (aggregation) | bash | always runs | Passes on `skipped` shards **only** when `changes` succeeded and reported no Python changes (Rust-only PRs). Shards skipped because `lint` or `changes` failed — which GitHub would otherwise count as a passing required check — fail it. |
| `shiny-tests` | pytest | `python` | Runs the Shiny signal-browser dashboard suite (`src/sigrift/lib/shiny/tests/`), which is outside pyproject `testpaths` and otherwise never runs. Heavy (see runner note). |
| `python-coverage-report` | `scripts/python-coverage.py` | `python` | Combines the coverage data from the test jobs into an inventory and baseline. |
| `python-coverage-release-gate` | `scripts/python-coverage.py` | main pushes, `security` PRs or the `security` label | Requires Python coverage at or above the floors in `scripts/coverage-floors.json`. Other PRs still get the report but skip this gate. |
| `docs-vs-metrics` | pytest | always runs | Checks numeric claims in docs against `docs/metrics.json`. `continue-on-error: true` — informational, **not** a required check. |
| `ci-ok` (aggregation) | python | always runs (`if: always()`) | Depends on every job above except `docs-vs-metrics` and the coverage gate; fails on any failure or cancellation, and on any skip the change detector does not explain (`rust` may skip only when neither Rust nor Python changed, the Python jobs only when Python did not). **Make `CI ok` the required check** in branch protection — a single check that runs on every PR (there is no PR path filter, so docs-only PRs get it too) and cannot go green while tests were skipped. GitHub offers a check for selection only after it has run in the repository, so add it after the first PR run. Do not make a check from a path-filtered workflow (such as `quickstart-smoke.yml`) required: on a PR outside its paths it stays Pending and blocks the merge. |

**Concurrency:** `group: ci-${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}`, `cancel-in-progress: ${{ github.event_name == 'pull_request' }}`. On PRs a force-push supersedes the prior run; `push: main` runs are grouped by ref but are **not** cancelled, because a release needs this workflow's jobs to have passed on its exact commit (`scripts/check-release-coverage.py`).

> **Runner model.** The heavy jobs (`rust`, the four `bridge-tests-shard`, `shiny-tests`) resolve their `runs-on` from the `CI_HEAVY_RUNNER` repo variable: `runs-on: ${{ vars.CI_HEAVY_RUNNER && fromJSON(vars.CI_HEAVY_RUNNER) || 'ubuntu-latest' }}`. When the variable is **unset** — the default, and the configuration for this public repo — they fall back to GitHub-hosted `ubuntu-latest`, which is free for public repositories. The cheap jobs (`changes`, `lint`, `docker-build`, `docs-vs-metrics`) are pinned to `ubuntu-latest` unconditionally. A maintainer who wants the heavy jobs on their own runners can optionally set `CI_HEAVY_RUNNER` to a JSON label array (e.g. `["self-hosted","<label>"]`); nothing else in the workflow changes. **On a public repo, don't** unless that runner is ephemeral or in a runner group restricted to trusted workflows: `ci.yml` runs on `pull_request`, and a fork PR can also edit the workflow to target any label.

> **Path-filter tradeoffs.** A misclassified change (e.g. a shared workspace file outside the explicit filter lists) could skip the wrong half. The filters intentionally over-include (`.github/workflows/ci.yml` triggers both languages, Python changes still run the Rust job for boundary checks) to bias toward correctness over savings.

### `.github/workflows/build-and-push.yml` — images → GHCR (manual)

**Triggers:** `workflow_dispatch` only, so `:main` images are published only when a maintainer runs it; versioned images come from `release.yml` on release tags (it signs the release files with cosign; the images themselves are not signed yet). Dispatch it from `main`: a run from another branch would still tag its images `:main`.

**Jobs:** matrix-builds the `sigrift-bridge`, `sigrift-gateway`, and `sigrift-edge` images (the three images behind the 7-service compose stack — `edge`, `rtl-tcp`, `scan`, `wifi-scan`, and `bt-scan` all run the edge image) and publishes to `ghcr.io/<owner>/sigrift-{bridge,gateway,edge}` with two tags per image:
- `:main` — moving, latest-on-main
- `:main-<sha12>` — immutable

No signing or SBOM here — that's reserved for `release.yml`. Build cache via `type=gha` so re-builds of unchanged layers skip.

### `.github/workflows/release.yml` — tagged releases

**Triggers:** `push` of a tag matching `v[0-9]+.[0-9]+.[0-9]+` or `v[0-9]+.[0-9]+.[0-9]+-rc[0-9]+` (GitHub filter patterns: other `v*` tags such as `v0.1.0-models` never start it), `workflow_dispatch` (for manual reruns of a specific tag — **dispatch it from the tag itself**: "Use workflow from" → the tag, or `gh workflow run release.yml --ref vX.Y.Z -f tag=vX.Y.Z`; a dispatch from a branch is refused, because its signatures would carry that branch's identity).

**Tags:** must match `^v[0-9]+\.[0-9]+\.[0-9]+(-rc[0-9]+)?$`; `resolve-version` (no permissions at all) refuses anything else before a job with write access starts. The tag reaches later steps only through `env:` — never `${{ }}` inside a script — and is quoted everywhere.

**Permissions:** none at the workflow level; per job only what it needs — `packages: write` for the image builds and the manifest merge, `contents: read` for the tarballs and SBOM, and `contents: write` + `id-token: write` only for `sign-and-release`.

**Jobs:**
1. Check that the tagged commit has passing coverage evidence from its `main` runs (`scripts/check-release-coverage.py`).
2. Build + push multi-arch (linux/amd64 + linux/arm64) `sigrift-bridge` and `sigrift-gateway` images to GHCR, tagged `:<tag>`; final releases also move `:latest`, release candidates (`-rcN`) never do.
3. Build the release gateway binary tarball, the source tarball, and the installer bundle (`install-release.sh` + `VERSION` + `LICENSE` + `README-INSTALL.txt`), plus `install-release.sh` on its own; write SHA-256 checksums for all of them.
4. Generate a CycloneDX SBOM of the whole repo.
5. Sign every artefact (including `install-release.sh` and `SHA256SUMS`) with cosign (keyless, via GitHub OIDC), then verify the signatures with the exact command the docs give users.
6. Draft a GitHub Release with all artefacts + signatures + a verification snippet.

**Signing identity:** `https://github.com/<owner>/<repo>/.github/workflows/release.yml@refs/tags/<tag>`, issuer `https://token.actions.githubusercontent.com`. Every documented verify command pins that exact identity (`--certificate-identity`, never an identity regular expression: a regexp over the repository URL accepts a signature from any workflow or branch of the repository). Users verify `SHA256SUMS` and then `sha256sum --check` what they downloaded — see INSTALL.md "Verifying a release".

### `.github/workflows/quickstart-smoke.yml` — fresh-install smoke

Runs `scripts/quickstart.sh` on a clean Ubuntu 24.04 runner, waits for the stack, then checks it with `scripts/staging-smoke.sh` and the browser suite in `tests/e2e`. **Triggers:** pull requests and `main` pushes that touch `scripts/**`, `src/**`, `tests/e2e/**`, the Cargo files or `docker-compose*.yml`; a weekly cron (Mondays 04:00 UTC); `workflow_dispatch`. It catches orchestration breakage (env generation, TLS cert generation, model fallback, the health wait) that `ci.yml`'s image build cannot see.

### `.github/workflows/rust-coverage.yml` and `javascript-coverage.yml` — coverage floors

Measure line and branch coverage for the Rust workspace and the dashboard JavaScript and fail below the committed floors. They run on `main` pushes (the evidence `release.yml` checks), on `workflow_dispatch`, and on pull requests that touch the security paths or carry the `security` label; other pull requests skip them instead of failing.

### `.github/workflows/dep-audit.yml` — dependency audit

`npm audit`, `pip-audit` over the hashed runtime and torch locks, and `cargo audit`, on pull requests, `main` pushes and `workflow_dispatch`. A known vulnerability fails the job.

### `.github/workflows/metrics.yml` — docs metrics

Regenerates `docs/metrics.json` with `scripts/emit_metrics.py`. On pull requests and `main` pushes it only logs the diff and uploads the file; nothing is committed automatically. A separate job with `contents: write` commits the refreshed file to `main` only when a maintainer runs the workflow by hand (`workflow_dispatch` on `main`); if branch rules refuse that push, commit the uploaded `metrics` file through a PR instead. `ci.yml`'s `docs-vs-metrics` job compares doc claims against it.

### `.github/workflows/gitleaks.yml` — secret scan

Runs on every PR and `main` push. Uses the gitleaks CLI (no license required). SARIF upload is best-effort — tolerated if private-repo Advanced Security is not enabled.

### `.github/workflows/codeql.yml` — static analysis

CodeQL for Python + Rust. **Triggers: weekly cron (Mondays 07:23 UTC) + `workflow_dispatch`.** Push and PR triggers were removed — CodeQL is for drift detection rather than regression prevention, and a weekly cadence matches how findings are reviewed (and saves a few runner minutes on every push).

Skipped on private repos (CodeQL requires Advanced Security licensing there); the workflow reports "skipped" cleanly instead of failing. Use `workflow_dispatch` to force a one-off run when needed.

---

## Pinning policy

- Third-party actions (anything outside `actions/*` and `github/*`) are pinned to full commit SHAs with a `# vX.Y.Z` comment; Dependabot (`.github/dependabot.yml`, `github-actions` ecosystem) proposes the bumps weekly once the maintainers raise its `open-pull-requests-limit`, which is `0` for every ecosystem at launch (no version-update PRs). Review requests come from `CODEOWNERS`.
- `ruff==0.14.14` in `ci.yml` (and `CONTRIBUTING.md`); the rule set is frozen in `pyproject.toml` `[tool.ruff]`, so newer local ruff versions agree with CI.
- Python dependencies: hashed locks in `src/sigrift/bridge/` (`requirements.txt` runtime, `requirements-test.txt` test tooling, `requirements-torch-cpu.txt` / `requirements-torch-cuda.txt`), generated from the `.in` files by `scripts/lock-requirements.sh` (uv; CPython 3.11, checked to resolve the same on x86_64 and aarch64) and installed with `pip --require-hashes`. Each lock resolves against exactly one index; the torch CPU wheel comes from the PyTorch index only (`--index-url`, never `--extra-index-url`) with `--no-deps`. The production image installs the runtime lock only — no pytest. After a Dependabot bump of an `.in` file (or a lock), re-run the script and commit the regenerated locks.
- Docker base images are pinned by digest (`image:tag@sha256:…`, multi-arch index); Dependabot's docker updater bumps tag and digest together. The installers' helper container (`alpine`) is digest-pinned too.
- Downloaded tools are checked against a pinned sha256 before use (gitleaks in `gitleaks.yml`).
- Rust toolchain `1.97.0` in `ci.yml` and `release.yml` (`dtolnay/rust-toolchain` with `toolchain:`), with `cargo clippy … -- -D warnings`. Bump deliberately and fix new lints in the same PR. There is intentionally no `rust-toolchain.toml` (it would also pin the Docker builds).

---

## Design decisions

**Why `continue-on-error: false` on `bridge-tests` now (vs. `true` historically)?**
The job was re-enabled after being commented out during the enterprise-module split. Early runs had ~100 pre-existing failures; `continue-on-error: true` let the job run and surface failures without blocking merges while they were triaged. After triage the suite is green, so the job now runs with `continue-on-error: false` and is required.

**Why pin `-n 4` instead of `-n auto`?**
xdist's auto-detect returned `1/1 workers` in GitHub-hosted runners even though the runner has 4 vCPUs; explicit `-n 4` works around it. If GitHub bumps runner specs or xdist fixes detection, bump this number.

---

## Related docs

- [CONTRIBUTING.md](CONTRIBUTING.md) — running the same checks locally
- [INSTALL.md](INSTALL.md) — production installation
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — common first-run errors
