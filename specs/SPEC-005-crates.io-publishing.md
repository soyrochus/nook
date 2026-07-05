# Code Generation Prompt — Restructure Nook for crates.io Publishing

You are working in the GitHub repository:

`https://github.com/soyrochus/nook`

The goal is to restructure the Rust workspace so that the public crates.io package can be published under a package name that is not already taken, while preserving the installed executable names.

## Objective

Convert the project into a crates.io-friendly structure where:

* The published package name is `nook-vault`
* The installed client executable remains `nook`
* The installed server executable remains `nookd`
* Users can install both binaries with one command:

```bash
cargo install nook-vault
```

After installation, both commands must be available:

```bash
nook --version
nookd --version
```

The repository name may remain `nook`. Do not rename the GitHub repository.

## Important naming distinction

Cargo package name:

```toml
name = "nook-vault"
```

Binary executable names:

```toml
[[bin]]
name = "nook"

[[bin]]
name = "nookd"
```

Do not rename the binaries to `nook-vault` or `nook-vaultd`.

## Current situation

The repository currently has a workspace-like structure with separate crates, including:

```text
crates/nook-core
crates/nook
crates/nookd
```

This is technically valid, but it creates a less clean crates.io install story because the client and server may need to be published/installed separately.

The desired result is one public package containing two binaries.

## Required target structure

Restructure the project so that `crates/nook-vault` is the main publishable package:

```text
/
├── Cargo.toml
├── crates/
│   └── nook-vault/
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── bin/
│           │   ├── nook.rs
│           │   └── nookd.rs
│           ├── client/
│           ├── server/
│           ├── crypto/
│           ├── protocol/
│           ├── manifest/
│           └── storage/
├── README.md
├── SECURITY.md
└── LICENSE
```

If the existing code is already well separated into `nook-core`, `nook`, and `nookd`, preserve the internal module boundaries conceptually, but consolidate them into the single publishable package unless doing so would be unnecessarily invasive.

Acceptable alternative if consolidation is too risky:

```text
crates/nook-core
crates/nook-vault
```

where `nook-vault` contains both binaries and depends on `nook-core` using both `path` and `version`.

In that fallback case, `nook-core` must also be publishable before `nook-vault`. Prefer the single-package solution unless the codebase strongly resists it.

## Root workspace Cargo.toml

The root `Cargo.toml` should remain a workspace manifest.

Example:

```toml
[workspace]
resolver = "2"
members = [
    "crates/nook-vault"
]

[workspace.package]
version = "0.11.0"
edition = "2021"
license = "Apache-2.0"
repository = "https://github.com/soyrochus/nook"
authors = ["Iwan van der Kleijn"]
```

Use the actual existing license and author metadata if already present. Do not invent metadata that conflicts with existing files.

## Publishable package Cargo.toml

Create or update:

```text
crates/nook-vault/Cargo.toml
```

It must define package name `nook-vault` and two binary targets.

Example:

```toml
[package]
name = "nook-vault"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
description = "Amorphous end-to-end encrypted push/pull file vault with client and server binaries."
readme = "../../README.md"
keywords = ["encryption", "vault", "cli", "storage", "files"]
categories = ["command-line-utilities", "cryptography", "filesystem"]
exclude = [
    "target/**",
    ".github/**"
]

[lib]
name = "nook_vault"
path = "src/lib.rs"

[[bin]]
name = "nook"
path = "src/bin/nook.rs"

[[bin]]
name = "nookd"
path = "src/bin/nookd.rs"
```

If the package currently has existing dependencies, preserve them.

## Binary entry points

Create or adapt:

```text
src/bin/nook.rs
src/bin/nookd.rs
```

`src/bin/nook.rs` must start the client CLI.

`src/bin/nookd.rs` must start the server daemon.

The executable names must be exactly:

```text
nook
nookd
```

## Library/module organization

Move shared code into `src/lib.rs` and submodules.

Example:

```rust
pub mod client;
pub mod server;
pub mod crypto;
pub mod protocol;
pub mod manifest;
pub mod storage;
pub mod config;
pub mod error;
```

Keep the implementation as close as possible to the existing code. Do not redesign Nook. This task is packaging and structure, not architecture.

## README updates

Update the README installation section to say:

````markdown
## Installation

```bash
cargo install nook-vault
````

This installs two executables:

```bash
nook
nookd
```

````

Also update any source-build instructions so they remain valid:

```bash
cargo build --release
````

and mention resulting binaries:

```text
target/release/nook
target/release/nookd
```

Do not claim the crates.io package is named `nook`.

## SECURITY.md updates

If SECURITY.md references crate/package names, update it to distinguish:

* Product name: Nook
* crates.io package: `nook-vault`
* Client executable: `nook`
* Server executable: `nookd`

Do not change the security model unless existing wording becomes inconsistent due to package renaming.

## Versioning

Set the package version to:

```toml
version = "0.11.0"
```

or use the workspace version if already configured.

Do not change the runtime protocol version unless the code currently requires it.

## Validation commands

After restructuring, the following commands must pass from the repository root:

```bash
cargo fmt --all --check
cargo check --workspace
cargo test --workspace
cargo build --release
cargo package -p nook-vault --list
cargo publish -p nook-vault --dry-run
```

The release build must produce:

```text
target/release/nook
target/release/nookd
```

Also verify:

```bash
target/release/nook --version
target/release/nookd --version
```

If `--version` is not currently implemented, add version support through `clap` or the existing CLI framework.

## Constraints

Do not:

* Rename the executables
* Rename the GitHub repository
* Add new protocol endpoints
* Change cryptography
* Weaken metadata opacity
* Change user-facing semantics
* Publish or prepare a package named `nook`

Do:

* Make the crates.io package publishable as `nook-vault`
* Keep both binaries installable from that one package
* Preserve existing tests
* Preserve existing behavior
* Keep the change set focused on Cargo/package structure and documentation

## Expected final state

A user should be able to run:

```bash
cargo install nook-vault
```

and then use:

```bash
nook
nookd
```

The repository should remain branded as Nook, while the crates.io package name is `nook-vault`.

End of task.
