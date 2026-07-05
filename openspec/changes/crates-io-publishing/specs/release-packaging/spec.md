## ADDED Requirements

### Requirement: crates.io package installs both commands
The release packaging SHALL provide a crates.io package named `nook-vault` that installs both the client executable `nook` and the server executable `nookd` from a single `cargo install nook-vault` command.

#### Scenario: Install package provides client and server binaries
- **WHEN** a user installs the package with `cargo install nook-vault`
- **THEN** the installed commands include `nook` and `nookd`

#### Scenario: Package name does not become an executable name
- **WHEN** the `nook-vault` package defines its binary targets
- **THEN** the binary target names are `nook` and `nookd`
- **AND** the package does not install binaries named `nook-vault` or `nook-vaultd`

### Requirement: Publishable package uses the nook-vault package name
The Cargo package prepared for crates.io publishing SHALL be named `nook-vault` and SHALL NOT publish or prepare a package named `nook`.

#### Scenario: Package manifest declares crates.io name
- **WHEN** the publishable package manifest is inspected
- **THEN** its `[package]` name is `nook-vault`

#### Scenario: Repository branding remains Nook
- **WHEN** user-facing documentation describes the project
- **THEN** the product may remain branded as Nook
- **AND** the documentation distinguishes the product name from the crates.io package name `nook-vault`

### Requirement: Workspace contains a publishable package structure
The repository SHALL keep the root `Cargo.toml` as a workspace manifest and SHALL expose a publishable package at `crates/nook-vault` that contains both binary entry points. If implementation keeps `nook-core` as a separate dependency, `nook-core` SHALL also be publishable before `nook-vault`.

#### Scenario: Preferred single-package workspace
- **WHEN** the workspace manifest is inspected after the restructure
- **THEN** it includes `crates/nook-vault` as the package that builds both `nook` and `nookd`

#### Scenario: Separate core fallback remains publishable
- **WHEN** the implementation keeps `crates/nook-core` as a separate crate dependency of `nook-vault`
- **THEN** `nook-core` includes crates.io-compatible metadata and versioning required for publication before `nook-vault`
- **AND** `nook-vault` depends on `nook-core` with both path and version information

### Requirement: Documentation explains crates.io installation
The README SHALL document `cargo install nook-vault` as the crates.io installation command and SHALL state that it installs the `nook` and `nookd` executables.

#### Scenario: README installation section uses package name
- **WHEN** a user reads the installation instructions
- **THEN** the crates.io install command is shown as `cargo install nook-vault`
- **AND** the installed executables are shown as `nook` and `nookd`

#### Scenario: Source build instructions remain valid
- **WHEN** a user reads source-build instructions
- **THEN** the build command remains `cargo build --release`
- **AND** the documented release binaries are `target/release/nook` and `target/release/nookd`

### Requirement: crates.io packaging validation passes
The repository SHALL validate the `nook-vault` package with formatting, workspace checks, workspace tests, release build, package listing, publish dry-run, and version command checks.

#### Scenario: Cargo validation succeeds
- **WHEN** release packaging validation is run from the repository root
- **THEN** `cargo fmt --all --check`, `cargo check --workspace`, `cargo test --workspace`, `cargo build --release`, `cargo package -p nook-vault --list`, and `cargo publish -p nook-vault --dry-run` succeed

#### Scenario: Release build produces versioned commands
- **WHEN** `cargo build --release` completes
- **THEN** `target/release/nook --version` succeeds
- **AND** `target/release/nookd --version` succeeds
