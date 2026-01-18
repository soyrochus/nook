# Nook

[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![FOSS Pluralism](https://img.shields.io/badge/FOSS-Pluralism-green.svg)](FOSS_PLURALISM_MANIFESTO.md)

**Zero-knowledge encrypted file vault for untrusted infrastructure.**

Push and pull files through hostile networks, traffic-intercepting proxies, and compromised servers—without revealing a single filename.

![Nook](./images/nook-logo-small.png)

## Overview

Nook is a minimal private file vault designed to operate correctly in **fully untrusted environments**, including TLS-intercepting firewalls, corporate MITM proxies, hostile networks, and server compromise scenarios.

### Core principle

**No file contents, filenames, directory structure, paths, or filesystem semantics may ever appear outside authenticated encryption.**

The server is a **semantic null**—it understands only random object IDs and ciphertext. All meaning exists exclusively on the client.

### Key features

- **Mandatory end-to-end encryption (E2EE)**: Every file, directory name, and path is encrypted before leaving the client
- **Amorphous traffic**: All payloads are indistinguishable encrypted blobs; the server cannot differentiate between files, manifests, or metadata
- **TLS-MITM resistant**: Confidentiality does not rely on TLS; even complete TLS interception reveals nothing
- **Atomic updates**: Safe concurrent writers using compare-and-swap (CAS) semantics
- **Simple deployment**: One Rust server binary (`nookd`), one Rust CLI binary (`nook`)
- **Zero-knowledge server**: Server compromise yields only ciphertext

### What Nook is NOT

- Not a sync daemon (no background sync)
- Not a version control system (no merge, diff, or conflict resolution)
- Not traffic-analysis resistant (volume and timing remain observable)
- Not a backup system with versioning

Nook is for pushing and pulling complete encrypted snapshots of directory trees between devices you control, through infrastructure you don't trust.

## Requirements

- Rust (stable) + Cargo

## Build / install

From the repo root:

```bash
cargo build --release
```

Binaries will be at:

- `target/release/nook` (CLI client)
- `target/release/nookd` (server daemon)

Optional install to Cargo bin dir:

```bash
cargo install --path crates/nook
cargo install --path crates/nookd
```

## Run the server

```bash
./target/release/nookd --listen 0.0.0.0:8080 --storage ./storage
```

The server stores only encrypted blobs under the storage directory:

```
storage/
  objects/
  temp/
  meta.sqlite
```

## Initialize a vault (client)

```bash
./target/release/nook init --server http://127.0.0.1:8080 --root /path/to/vault
```

This generates a vault key and writes client config to the platform config directory
(`~/.config/nook/config.json` on Linux). Keep this file secure; you need the same vault key on
other devices.

Set or view the local root later:

```bash
./target/release/nook root --set /path/to/vault
./target/release/nook root
```

## Push / pull

Push uploads files to the vault. Pushing merges with existing content—files are added or updated, but other files are preserved:

```bash
./target/release/nook push              # Push entire root directory
./target/release/nook push README.md     # Push a single file
./target/release/nook push docs/         # Push a subdirectory
```

Pull downloads and materializes files from the vault into your local root:

```bash
./target/release/nook pull               # Pull entire vault
./target/release/nook pull docs/spec.md  # Pull a specific file
./target/release/nook pull images/       # Pull a subdirectory
```

Both commands preserve directory structure and support selective sync.

## Status / overrides

Check whether the head object exists on the server:

```bash
./target/release/nook status
```

Override the server URL per command:

```bash
./target/release/nook --server http://other-host:8080 status
./target/release/nook --server http://other-host:8080 push
```

## Browse vault contents

List the top-level entries stored in the encrypted manifest:

```bash
./target/release/nook ls
./target/release/nook ls path/inside/vault   # List a subdirectory
```

View a recursive tree of the vault structure:

```bash
./target/release/nook tree
./target/release/nook tree docs/             # Tree from a subdirectory
```

All discovery happens locally by decrypting the manifest—no server queries reveal structure.

## Usage notes

- The server is a semantic null: it stores only ciphertext and object IDs.
- TLS can be used, but confidentiality does not rely on it; TLS MITM does not expose filenames,
  paths, or file contents.
- To use the same vault on multiple devices, copy the `config.json` (or at least the vault key)
  securely, then set the local root on each device.

## Participation

Contributions are welcome: issues, pull requests, critique, and discussion.

This project follows the [FOSS Pluralism Manifesto](./FOSS_PLURALISM_MANIFESTO.md), affirming respect for people, freedom to critique ideas, and space for diverse perspectives.


## License

Copyright (c) 2026, Iwan van der Kleijn
Licensed under the MIT License. See [`LICENSE`](./LICENSE) for details.
