## Why

Nook needs a clean crates.io installation path that publishes under an available package name while preserving the established `nook` and `nookd` command names. The current split workspace makes the install story less direct because the client and server are separate packages.

## What Changes

- Introduce a publishable crates.io package named `nook-vault` that installs both binaries with `cargo install nook-vault`.
- Preserve the executable names exactly as `nook` and `nookd`.
- Restructure the workspace so the root remains a workspace manifest and the publishable package contains both binary entry points.
- Prefer consolidating `nook-core`, `nook`, and `nookd` into `crates/nook-vault`; allow a two-crate fallback only if full consolidation is unnecessarily invasive.
- Update README and security/package wording to distinguish the product name Nook, crates.io package `nook-vault`, client executable `nook`, and server executable `nookd`.
- Add validation for formatting, workspace checks/tests, release builds, package listing, crates.io dry-run publishing, and both `--version` commands.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `release-packaging`: Add crates.io package naming, binary naming, workspace structure, installation, and publish dry-run requirements for the `nook-vault` package.

## Impact

- Affected manifests: root `Cargo.toml`, existing crate manifests, and new or updated `crates/nook-vault/Cargo.toml`.
- Affected source layout: client, server, and shared code may move into one publishable package while preserving behavior.
- Affected documentation: README installation/source-build instructions and any SECURITY.md package-name references.
- Affected validation: `cargo fmt --all --check`, `cargo check --workspace`, `cargo test --workspace`, `cargo build --release`, `cargo package -p nook-vault --list`, `cargo publish -p nook-vault --dry-run`, and `target/release/{nook,nookd} --version`.
