## Why

An audit of the current implementation (`crates/nook`, `crates/nook-core`, `crates/nookd`) against `specs/SPEC-001-Base Implementation.md` and `specs/SPEC-002-FileNavigation.md` found six items of drift, recorded in `specs/SPEC-003-implementation-fixes.md`, ranging from a critical data-loss/corruption bug (client fabricates a fresh manifest on any fetch/decrypt failure, silently orphaning previously-pushed objects) to missing CI. These must be fixed to restore the guarantees SPEC-001/002 already promise. Separately, the project currently has no way to run `nookd` as a container with durable server-side storage, and no automated way to produce distributable `nook`/`nookd` binaries for a tagged release — both are needed before the project can be handed to users outside the dev environment.

## What Changes

- **Critical fix**: `cmd_push` in `crates/nook/src/main.rs` must only treat a manifest-fetch failure as "no manifest yet" on HTTP 404. Every other failure (network error, integrity mismatch, AEAD decrypt failure, malformed JSON) aborts the push fatally, with no fabricated manifest and no write to the head object. **BREAKING**: pushes that previously "succeeded" by silently overwriting an undecryptable manifest will now fail loudly.
- **High**: Vault Master Key (VMK) storage moves off base64-in-`config.json`. Default path is OS keychain (`keyring` crate); fallback when no keychain is available is an Argon2id-derived passphrase wrapping the VMK with XChaCha20-Poly1305 before it touches disk. `nook init` records which mode is active. **BREAKING**: existing plaintext-equivalent configs are not auto-migrated.
- **Medium**: client config file format changes from JSON to TOML (`crates/nook/src/main.rs`, new `toml` dependency in `crates/nook/Cargo.toml`). The VMK field becomes an opaque reference (keychain handle or encrypted blob), never a raw key. **BREAKING**: old `config.json` is not read; users re-run `nook init`.
- **Medium**: the object wire format's duplicated wrapped-DEK envelope (`crates/nook-core/src/object.rs`) is documented as the authoritative on-wire format (SPEC-001 §17 updated to match), and `decrypt_object` asserts the outer wrapped-key bytes match the one embedded in the decrypted chunk-0 header, failing closed on mismatch.
- **Medium**: `nookd`'s `meta.sqlite` (`crates/nookd/src/main.rs`) gains `created_at`/`updated_at` timestamp columns and quota accounting, rejecting `PUT`s that would exceed a configured quota with `507 Insufficient Storage` and cleaning up any temp file on rejection.
- **Medium**: repository layout is reconciled with SPEC-001 §21 by declaring `specs/` the canonical location (SPEC-001 §21 updated accordingly, since `specs/` is already in active use), adding a `SECURITY.md` summarizing the SPEC-001 §19 guarantees, and adding `.github/workflows/ci.yml` running `cargo build`, `cargo test`, and `cargo clippy` across the workspace on every push/PR.
- Item 7 of SPEC-003 (TLS gap, nonce-derivation wording, `previous_manifest_hash`, CLI surface, optional Argon2id, `nookd` crash window) is informational only — explicitly out of scope for this change, tracked for awareness.
- **New infrastructure, not drift fixes** — packaging and distribution for `nookd` and the CLI, not covered by SPEC-003:
  - A multi-stage `Dockerfile` for `nookd` with a declared `VOLUME` (or documented bind-mount path) for its data directory (object store + `meta.sqlite`), so server-side data persists outside the container's writable layer under Podman or Docker.
  - A `.github/workflows/release.yml` workflow, triggered only on tags matching `v*` (never on push/PR), that cross-compiles and publishes `nook` and `nookd` binaries for Linux x64, Windows x64, and macOS arm64 (Apple Silicon only) as GitHub Release artifacts.

## Capabilities

### New Capabilities
- `manifest-push-safety`: fail-closed error handling for manifest fetch/decrypt in `nook push`, distinguishing "absent" (404) from all other failure modes.
- `client-key-storage`: OS-keychain-first, Argon2id+XChaCha20-Poly1305-fallback storage of the Vault Master Key, replacing base64-in-JSON.
- `client-config-format`: TOML-based client configuration replacing JSON, with opaque key references instead of raw key material.
- `object-wire-format-integrity`: documented on-wire envelope for encrypted objects, with cross-checked wrapped-DEK copies and fail-closed rejection on mismatch.
- `server-metadata-quota`: server-side timestamp tracking and quota enforcement in `nookd`'s metadata store.
- `repo-structure-ci`: canonical repo layout declaration, `SECURITY.md`, and a push/PR CI workflow.
- `server-containerization`: a `Dockerfile` for `nookd` with durable, externally-mounted data storage.
- `release-packaging`: a tag-triggered GitHub Actions workflow producing cross-platform `nook`/`nookd` release binaries.

### Modified Capabilities
(none — `openspec/specs/` has no pre-existing capability specs; all of the above are introduced as new capability specs even though several correspond to drift fixes against the plain-markdown `specs/SPEC-001`/`SPEC-002` documents.)

## Impact

- **Code**: `crates/nook/src/main.rs` (manifest fetch/push error handling, `Config`, `save_config`/`load_config`, `nook init`), `crates/nook/Cargo.toml` (add `keyring`, `argon2`, `toml`, XChaCha20-Poly1305 deps), `crates/nook-core/src/object.rs` (`decrypt_object` cross-check), `crates/nookd/src/main.rs` (`init_db`, `ObjectMeta`, `load_meta`/`store_meta`, `handle_put` quota check).
- **Docs**: `specs/SPEC-001-Base Implementation.md` §17 and §21 updated; new `SECURITY.md` (or `specs/SECURITY.md`).
- **CI/CD**: new `.github/workflows/ci.yml`; new `.github/workflows/release.yml`.
- **Packaging**: new `Dockerfile` (likely `crates/nookd/Dockerfile`), affecting how `nookd` is deployed but not its wire protocol.
- **Compatibility**: existing plaintext `config.json` files and any manifests that were silently overwritten under the old fabrication bug are not auto-repaired by this change; users re-initialize the client.
