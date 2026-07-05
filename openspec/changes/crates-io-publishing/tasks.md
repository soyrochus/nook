## 1. Package Structure

- [ ] 1.1 Create `crates/nook-vault` as the primary publishable package with `[package] name = "nook-vault"` and workspace-inherited version/edition.
- [ ] 1.2 Add package metadata required for crates.io, including license, repository, description, readme, keywords, categories, and appropriate excludes based on existing project files.
- [ ] 1.3 Define `[lib] name = "nook_vault"` and explicit binary targets `[[bin]] name = "nook"` and `[[bin]] name = "nookd"`.
- [ ] 1.4 Update the root workspace manifest so the publishable workspace builds `crates/nook-vault` and preserves version `0.10.0`.

## 2. Source Consolidation

- [ ] 2.1 Move or adapt shared `nook-core` code into `crates/nook-vault/src` while preserving current module boundaries conceptually.
- [ ] 2.2 Move or adapt the client entry point into `crates/nook-vault/src/bin/nook.rs`.
- [ ] 2.3 Move or adapt the server entry point into `crates/nook-vault/src/bin/nookd.rs`.
- [ ] 2.4 Preserve existing client, server, and core behavior without protocol, cryptography, storage-format, or command-semantics changes.
- [ ] 2.5 If full consolidation is too invasive, keep `nook-core` as a separate publishable crate and make `nook-vault` depend on it with both `path` and `version`.

## 3. Tests And Version Commands

- [ ] 3.1 Move or update existing tests so `cargo test --workspace` still exercises client, server, and shared-code behavior.
- [ ] 3.2 Ensure both binaries support `--version` through the existing CLI framework.
- [ ] 3.3 Verify `cargo build --release` produces `target/release/nook` and `target/release/nookd`.

## 4. Documentation

- [ ] 4.1 Update README installation instructions to use `cargo install nook-vault`.
- [ ] 4.2 Update README source-build instructions to mention `cargo build --release` and the `target/release/nook` and `target/release/nookd` outputs.
- [ ] 4.3 Update any SECURITY.md package-name references to distinguish product name Nook, package `nook-vault`, client executable `nook`, and server executable `nookd`.
- [ ] 4.4 Remove or correct any documentation that implies the crates.io package is named `nook`.

## 5. Validation

- [ ] 5.1 Run `cargo fmt --all --check`.
- [ ] 5.2 Run `cargo check --workspace`.
- [ ] 5.3 Run `cargo test --workspace`.
- [ ] 5.4 Run `cargo build --release`.
- [ ] 5.5 Run `cargo package -p nook-vault --list`.
- [ ] 5.6 Run `cargo publish -p nook-vault --dry-run`.
- [ ] 5.7 Run `target/release/nook --version` and `target/release/nookd --version`.
