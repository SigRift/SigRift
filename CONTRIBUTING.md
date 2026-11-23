# Contributing to SigRift

Thanks for considering a contribution. SigRift is an MIT-licensed
RF/TSCM platform with a commercial edition available
separately; these guidelines apply to the open-source community
edition in this repository.

Before you start, please read [LEGAL.md](LEGAL.md) — acceptable-use terms
apply to contributions as well as to end use.

## Ways to Contribute

- **Bug reports** — reproducible issues in the detection pipeline,
  gateway, edge agents, or first-party plugins.
- **Protocol decoders and threat signatures** — new decoders for
  public/unencrypted protocols, or new TSCM signatures with supporting
  references.
- **Hardware support** — SDR driver integration, edge-node packaging.
- **Documentation** — install guides, runbooks, architecture notes,
  translations.
- **Tests** — coverage gaps in the Python or Rust suites.

Enterprise-tier features (TDOA geolocation, PHY-layer fingerprinting,
protocol fuzzing, SSO integrations) are developed in a separate
repository and are **not** accepted as contributions here. If you have
a proposal that touches those interfaces, open an issue first so we can
route it correctly.

## Before You Open a Pull Request

1. **Open an issue first** for anything larger than a one-line fix, so
   we can confirm fit and scope before you invest time.
2. **Search existing issues and PRs** to avoid duplicates.
3. **Never submit exploit code, unpatched vulnerability details, or
   proof-of-concepts for undisclosed issues** in a public PR — use the
   process in [SECURITY.md](SECURITY.md) instead.

## Development Setup

A typical dev environment:

```bash
git clone https://github.com/SigRift/SigRift.git
cd SigRift
python3 -m venv .venv && source .venv/bin/activate
# Hash-checked locks: runtime + test tooling, then torch (CPU wheel,
# PyTorch index only). Change dependencies in the .in files and run
# scripts/lock-requirements.sh (needs uv) to regenerate the locks.
pip install --require-hashes \
    -r src/sigrift/bridge/requirements.txt \
    -r src/sigrift/bridge/requirements-test.txt
pip install --require-hashes --no-deps \
    -r src/sigrift/bridge/requirements-torch-cpu.txt

# Lint tooling. ruff is pinned to the exact version CI uses (newer
# releases change the default rules/formatting; pyproject.toml
# [tool.ruff] freezes the rule selection too). pytest and its plugins
# came from requirements-test.txt above.
pip install "ruff==0.14.14"

# Rust gateway
cargo build --workspace
```

See [INSTALL.md](INSTALL.md) for full environment setup including
SDR hardware, TLS certificates, and database initialization, and
[QUICKSTART.md](QUICKSTART.md) for the 5-minute Docker-Compose
path to first detection.

## Running Tests

All PRs must pass the full test suite and linters. The Python
bridge suite is large (~7,600 bridge tests); the Rust (~1,140 tests)
workspace suite runs separately.

```bash
# Python bridge suite
PYTHONPATH=src python3 -m pytest tests/bridge/ -q --timeout=30

# Rust workspace suite
cargo test --workspace

# Python lint/format
ruff check src/sigrift/
ruff format --check src/sigrift/

# Rust lint/format (CI uses Rust 1.97.0 and fails on any clippy warning)
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
```

CI runs the same checks on every PR. If CI fails, fix the issue locally
and push a new commit — please do not force-push over review history
once a maintainer has started reviewing.

On pushes to `main` and on security-related PRs (those touching the
security paths in the workflows, or labelled `security`), CI checks
coverage against the floors in `scripts/coverage-floors.json`. Floors
are only ever raised. CI does not compare that file with `main`, so a
change to it needs maintainer review.

### End-to-end candidate run

`scripts/test-candidate.py` builds the checked-out source into an
isolated, disposable stack (no SigRift images are pulled; generated
credentials, production-mode authentication and TLS, its own Compose
project and loopback port). It then checks health, the API security
contract, browser behavior, and persistence across a restart and an
installer rerun, writes `results.json` and `junit.xml`, and removes its
own containers and volumes.

Prerequisites: Docker with Compose v2 and a running engine, Python
3.11+, Git, Bash, curl, jq, OpenSSL, and Chromium installed through
Playwright. `--work-dir` must be a directory the Docker engine can see
(with a VM-based engine such as Colima or Docker Desktop, normally one
under your home directory).

```bash
python3 -m venv ~/.venvs/sigrift-e2e
~/.venvs/sigrift-e2e/bin/python -m pip install -r tests/e2e/requirements.txt
~/.venvs/sigrift-e2e/bin/python -m playwright install chromium
python3 scripts/test-candidate.py \
  --work-dir "$PWD/reports/candidates" \
  --python ~/.venvs/sigrift-e2e/bin/python
```

Run it from a clean checkout; `--allow-dirty` is only for developing a
fix and is recorded in the results. Keep run directories private: they
can hold test credentials, service logs and browser diagnostics. Share
only `results.json` and `junit.xml`, or the smallest redacted failure
evidence. `reports/` is ignored by Git.

## Code Style

### Python (PEP 8, enforced by ruff)

- Python 3.11+. Use `tomllib`, `StrEnum`, `ExceptionGroup` where
  appropriate.
- Type hints on all new public function signatures.
- Prefer `pathlib.Path` over `os.path`.
- f-strings over `.format()` or `%`.
- Import order: stdlib, third-party, local — separated by blank lines.
- Use the `logging` module — never bare `print()` for operational
  output. Log format:
  `%(asctime)s [%(levelname)s] %(name)s: %(message)s` with
  `datefmt='%Y-%m-%dT%H:%M:%S%z'`.
- Log to stderr by default; reserve stdout for program output or data.

### Rust

- `cargo fmt` must pass; `cargo clippy` must introduce no new warnings.
- `unsafe` blocks require a comment justifying soundness.
- Prefer `thiserror` for library error types; `anyhow` is fine at
  application boundaries.
- No `unwrap()` or `expect()` in code paths reachable from network
  input — return a proper error.

### Respect local style

If you're editing an existing file and its style doesn't match the rules
above, match the file. Consistency within a file beats consistency with
the style guide.

## Commit Messages

Conventional Commits:

```
type(scope): short imperative summary

Longer body explaining *why* the change is needed, not what the diff
does. Reference issues with `Closes #123` or `Refs #456`.
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `build`,
`perf`, `ci`. Scope is optional but encouraged
(e.g. `feat(decoder): add FLEX support`).

Keep commits atomic — one logical change per commit. We prefer small,
reviewable PRs over large ones.

## Developer Certificate of Origin (DCO)

SigRift uses the [Developer Certificate of Origin](https://developercertificate.org/).
We expect every commit to be signed off:

```bash
git commit -s -m "fix(gateway): correct session-binding IPv6 handling"
```

The `-s` flag appends a `Signed-off-by: Your Name <you@example.com>`
trailer. By adding this trailer you certify the DCO statement — in
short, that you wrote the patch or otherwise have the right to submit
it under the project's licence.

CI does not currently enforce DCO sign-off (no
`.github/workflows/` check exists yet). Reviewers will ask you to
add `-s` and re-push if it's missing.

## Licensing of Contributions

All contributions are accepted under the MIT licence that covers the rest
of this repository (see [LICENSE](LICENSE) and [NOTICE](NOTICE)).

**Dual-licensing note:** SigRift also ships a separate commercial
edition. We do not require a CLA, but we do require DCO sign-off. If
you would prefer an explicit CLA for larger contributions, or if your
employer requires one, say so in your pull request or in GitHub
Discussions and we will work out arrangements case-by-case.

Do not copy code from incompatibly licensed sources: copyleft code
(GPL, LGPL, AGPL, MPL and similar — including ports or line-by-line
translations of it into another language), proprietary code, leaked
datasets, or reverse-engineered protocol specifications that are subject
to NDA. Implementing a protocol from its specification, or for
interoperability with another tool's documented behaviour, is fine;
copying that tool's source is not. If in doubt, ask before you submit.

## Pull Request Checklist

- [ ] Issue opened and discussed (for non-trivial changes).
- [ ] Branch named `feat/…`, `fix/…`, `docs/…`, `refactor/…`, or
      `chore/…`.
- [ ] Commits follow Conventional Commits and are signed off (DCO).
- [ ] Tests added or updated; full suite passes locally.
- [ ] `ruff check`, `ruff format --check`, `cargo fmt --check`, and
      `cargo clippy` (no new warnings) all pass.
- [ ] Documentation updated (README, ARCHITECTURE, INSTALL, etc.) if
      behaviour or interfaces changed.
- [ ] No secrets, credentials, customer data, internal hostnames, or
      proprietary protocol specifications in the diff.
- [ ] PR description explains the motivation and links relevant issues.

## Getting Review

Maintainers triage new issues and PRs on a best-effort basis. Expect an
initial response within **7 days**. If you haven't heard back after
that, feel free to ping the PR.

We're friendly and we will help you land your change — but we will also
push back on scope, design, or style if we think it's warranted. Please
don't take it personally; treat review as collaboration.

## Community Standards

Participation in this project is subject to the
[Code of Conduct](CODE_OF_CONDUCT.md). Please read it before engaging.

## Questions

- General questions: GitHub Discussions.
- Security issues: see [SECURITY.md](SECURITY.md).
- Commercial / enterprise enquiries: GitHub Discussions.
