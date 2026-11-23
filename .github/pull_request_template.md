## Summary

<!-- What does this change, and why? Link any related issue. -->

## Contributor checklist
- [ ] **DCO sign-off** on every commit — `git commit -s` adds `Signed-off-by: Name <email>`. All contributions are accepted under the **MIT** licence.
- [ ] If this touches **shared / enterprise-adjacent code** (see [`CODEOWNERS`](https://github.com/SigRift/SigRift/blob/main/CODEOWNERS) — the `sigrift-gateway-core` crate, the bridge modules that import `sigrift_sentinel`, and the provider / crypto / dsp seams), I understand a **maintainer (code-owner) review is required** before merge.
- [ ] Tests pass (`pytest`, `cargo test`) and linters are clean (`ruff`, `cargo fmt`/`clippy`).
- [ ] Docs/CHANGELOG updated if user-facing.
