## Context

The repository is currently a Rust workspace with separate `nook-core`, `nook`, and `nookd` crates. That structure works for development, but it does not provide the desired crates.io experience where one package installs both executables. The public crates.io package name must be `nook-vault`, while the user-facing product and commands remain Nook, `nook`, and `nookd`.

## Goals / Non-Goals

**Goals:**

- Publish one primary package named `nook-vault` that installs both `nook` and `nookd`.
- Keep the root manifest as a workspace manifest with shared version and edition metadata.
- Preserve existing runtime behavior, protocol behavior, storage formats, cryptography, tests, and command names.
- Keep documentation accurate about the distinction between product name, package name, and binary names.
- Ensure crates.io packaging can be validated with `cargo package` and `cargo publish --dry-run`.

**Non-Goals:**

- Renaming the GitHub repository or product from Nook.
- Publishing a crates.io package named `nook`.
- Adding protocol endpoints, changing cryptography, or changing user-facing client/server semantics.
- Redesigning the application architecture beyond the packaging restructure needed for publication.

## Decisions

1. Prefer a single publishable crate at `crates/nook-vault`.

   Consolidating the current client, server, and shared modules into one package gives users the cleanest install path: `cargo install nook-vault` produces both binaries. The package manifest will declare `[lib] name = "nook_vault"` and explicit `[[bin]]` targets named `nook` and `nookd`.

   Alternative considered: keep `nook-core` as a separate crate and make `nook-vault` depend on it. This is acceptable only if consolidation creates unnecessary churn or test risk, because it requires `nook-core` to be independently publishable before `nook-vault`.

2. Preserve executable names through explicit binary targets.

   The package name and binary names are independent Cargo concepts. The manifest must declare `name = "nook-vault"` under `[package]` and `[[bin]]` entries for `nook` and `nookd`, preventing accidental installation of `nook-vault` or `nook-vaultd` commands.

3. Keep versioning in workspace metadata.

   The root workspace already defines version `0.10.0` and edition `2021`. The publishable package should inherit these values unless existing metadata requires a more specific package-level value. Additional publish metadata such as license, repository, description, readme, keywords, and categories should be added from existing project files and not conflict with repository reality.

4. Treat documentation and validation as part of the package contract.

   README installation instructions, source-build output paths, and SECURITY.md package references must reflect `nook-vault` as the crates.io package and `nook`/`nookd` as installed commands. Validation must include workspace checks/tests, release build output, package listing, publish dry-run, and both version commands.

## Risks / Trade-offs

- Consolidation may create noisy file moves and import churn -> preserve module boundaries conceptually and keep moves mechanical where possible.
- A separate `nook-core` fallback adds publish ordering and metadata requirements -> use it only when single-package consolidation is materially riskier.
- crates.io packaging can fail on missing metadata or unpublished path dependencies -> run `cargo package -p nook-vault --list` and `cargo publish -p nook-vault --dry-run` before considering implementation complete.
- Binary version commands may not currently exist or may not cover both executables -> add version support through the existing CLI framework without changing command semantics.
