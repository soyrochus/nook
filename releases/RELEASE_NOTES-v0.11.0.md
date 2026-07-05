# Nook v0.11.0

This release restructures Nook for crates.io publishing. The project remains
Nook, and the installed commands remain `nook` and `nookd`, but the crates.io
package is now named `nook-vault` because the `nook` package name is already
taken by another, currently unmaintained package.

## Highlights

- Added a single publishable crates.io package: `nook-vault`.
- Preserved the client executable name: `nook`.
- Preserved the server executable name: `nookd`.
- `cargo install nook-vault` installs both binaries.
- Consolidated the previous `nook-core`, `nook`, and `nookd` crates into one
  package under `crates/nook-vault`.
- Updated README, SECURITY notes, CI, Dockerfile paths, and release-tag helper
  scripts for the new package layout.

## Installation

```bash
cargo install nook-vault
```

After installation:

```bash
nook --version
nookd --version
```

Both commands report version `0.11.0`.

## Compatibility

This is a packaging and repository-structure release. It does not intentionally
change Nook's wire protocol, cryptography, storage semantics, command behavior,
or GitHub repository name.

Users who build from source can continue to run:

```bash
cargo build --release
```

The resulting binaries remain:

```text
target/release/nook
target/release/nookd
```

## Validation

The release preparation passed:

- `cargo fmt --all --check`
- `cargo check --workspace`
- `cargo test --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo build --release`
- `cargo package -p nook-vault --list`
- `cargo publish -p nook-vault --dry-run`
- `target/release/nook --version`
- `target/release/nookd --version`

## Note

Cargo currently warns that `num-bigint v0.4.7` in `Cargo.lock` is yanked in the
crates.io registry. The `nook-vault` dry-run publish still verifies
successfully.
