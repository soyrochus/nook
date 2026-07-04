## 1. Manifest push safety (critical)

- [x] 1.1 Give `fetch_manifest_with_etag` (and its shared fetch helper, if any) an error type/enum that distinguishes "HTTP 404 / not found" from all other failures (network, integrity mismatch, decrypt/AEAD failure, malformed JSON)
- [x] 1.2 Update `cmd_push` in `crates/nook/src/main.rs` to match on that distinction: 404 → proceed with empty manifest, no `If-Match`; any other error → abort immediately with a fatal error, no fabricated manifest, no `PUT`
- [x] 1.3 Confirm `fetch_manifest` (used by `ls`/`tree`/`pull`) is unaffected and still propagates all errors as before
- [x] 1.4 Add/adjust a test that crafts a corrupted head object (flipped byte) and asserts `nook push` fails loudly and the server's manifest/etag are untouched
- [x] 1.5 Add/adjust a test for the first-push-to-fresh-vault (404) path still working

## 2. Vault key storage (high)

- [x] 2.1 Add `keyring` (and Argon2id + XChaCha20-Poly1305, e.g. `argon2` and `chacha20poly1305`) dependencies to `crates/nook/Cargo.toml`
- [x] 2.2 Implement keychain-backed VMK storage as the default path in `nook init`
- [x] 2.3 Implement the Argon2id-derived passphrase + XChaCha20-Poly1305 encrypted-local-file fallback for when the keychain is unavailable
- [x] 2.4 Add a `key_storage` mode field to `Config` so `load_config` knows whether to read from keychain or prompt for a passphrase
- [x] 2.5 Update `load_config`/callers (`status`, `push`, `pull`, etc.) to retrieve the VMK via the recorded mode
- [x] 2.6 Add a non-interactive passphrase supply path (env var or flag) for scripted/CI use of the fallback mode
- [x] 2.7 Add/adjust a test confirming no plaintext or base64-recoverable VMK appears in the on-disk config after `nook init`

## 3. Client config format (medium)

- [x] 3.1 Add the `toml` dependency to `crates/nook/Cargo.toml`
- [x] 3.2 Switch `save_config`/`load_config` in `crates/nook/src/main.rs` from `serde_json` to `toml`, coordinating with task 2's `Config` struct changes
- [x] 3.3 Represent the vault key field as an opaque reference (keychain handle or encrypted blob) in the TOML structure, never a raw key
- [x] 3.4 Ensure loading a non-TOML (old JSON) config produces a clear "re-run `nook init`" error rather than a silent misparse
- [x] 3.5 Add/adjust a test that `nook init` produces a TOML file parseable by a standard TOML parser

## 4. Object wire format integrity (medium)

- [x] 4.1 Update `specs/SPEC-001-Base Implementation.md` §17 to document the actual on-wire envelope (`[u16 len][wrapped_key][u32 chunk_count][chunks...]`, wrapped DEK also embedded in the encrypted chunk-0 header) as authoritative, replacing the circular description
- [x] 4.2 In `decrypt_object` (`crates/nook-core/src/object.rs`), after decrypting the chunk-0 header, compare the header's wrapped DEK against the outer envelope's wrapped-key bytes and fail closed on mismatch
- [x] 4.3 Add a test that crafts an object with diverging wrapped-key copies and confirms `decrypt_object` rejects it
- [x] 4.4 Add a test confirming normal (matching) objects still decrypt successfully

## 5. Server metadata and quota (medium)

- [x] 5.1 Add `created_at`/`updated_at` columns to the object metadata table in `crates/nookd/src/main.rs` (`init_db`), via `ALTER TABLE ... ADD COLUMN` with safe defaults for backward compatibility
- [x] 5.2 Set `created_at`/`updated_at` on insert and update `updated_at` on overwrite in `store_meta`
- [x] 5.3 Add a configurable quota (CLI flag/config value), defaulting to effectively unlimited if unset
- [x] 5.4 Implement a running total of stored bytes, reconciled from `SUM(size)` over the metadata table on `nookd` startup
- [x] 5.5 Reject `PUT`s that would exceed the configured quota with `507 Insufficient Storage`, ensuring temp files are cleaned up on rejection and no partial object is persisted
- [x] 5.6 Add/adjust tests: timestamps populate on create/update; oversized upload under a small configured quota is rejected without partial writes or leftover temp files

## 6. Repository structure and CI (medium)

- [x] 6.1 Update `specs/SPEC-001-Base Implementation.md` §21 to declare `specs/` as the canonical location for specification documents
- [x] 6.2 Add `SECURITY.md` at the repository root summarizing the SPEC-001 §19 guarantees
- [x] 6.3 Add `.github/workflows/ci.yml` running `cargo build --workspace`, `cargo test --workspace`, and `cargo clippy --workspace -- -D warnings` on `push` and `pull_request`
- [x] 6.4 Confirm CI passes on a clean clone/checkout — verified locally by running the exact `ci.yml` steps (`cargo build --workspace --all-targets`, `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`); all green. Actual GitHub Actions execution will run on the next push.

## 7. `nookd` containerization (new infrastructure)

- [x] 7.1 Confirm whether `nookd`'s data directory is already configurable via CLI flag/env var; if not, add one (default remains CWD-relative for bare-metal use, container image sets it to `/data`) — added `NOOK_DATA_DIR` env support (and `NOOK_QUOTA_BYTES` for the quota) alongside the existing `--storage` flag
- [x] 7.2 Write a multi-stage `Dockerfile` (`crates/nookd/Dockerfile`): builder stage compiles `cargo build --release -p nookd`; runtime stage is `debian:bookworm-slim` containing only the `nookd` binary, running as a fixed non-root UID/GID (10001)
- [x] 7.3 Declare `VOLUME ["/data"]` and set it as the default data directory (`NOOK_DATA_DIR=/data`) in the runtime stage
- [x] 7.4 Document `podman run`/`docker run` usage with a named volume or bind mount at the data path in the README, including the `podman unshare chown` step needed for rootless bind mounts
- [x] 7.5 Manually verify: run the image with a named volume, push objects, remove/recreate the container with the same volume, confirm data survives — verified with Podman in this environment
- [x] 7.6 Manually verify: repeat with a host-directory bind mount — verified with Podman (rootless, via `podman unshare chown`); Docker was not available in this environment to test directly, but uses the same standard bind-mount/VOLUME mechanism and is documented accordingly
- [x] 7.7 Optionally add a CI job (in `ci.yml`) that builds the Docker image (build-only, no push) to catch Dockerfile regressions

## 8. Tag-triggered release workflow (new infrastructure)

- [x] 8.1 Create `.github/workflows/release.yml` with `on: push: tags: ['v*']` only (no `push`/`pull_request` branch triggers)
- [x] 8.2 Define a build matrix: `x86_64-unknown-linux-gnu` (ubuntu runner), `x86_64-pc-windows-msvc` (windows runner), `aarch64-apple-darwin` (macos-14 runner)
- [x] 8.3 Each matrix leg: `cargo build --release --workspace --target <target>`, package both binaries (handle `.exe` suffix on Windows), and produce a checksummed archive (`.tar.gz`+sha256 on Unix, `.zip`+sha256 on Windows)
- [x] 8.4 Publish all per-platform archives as artifacts attached to the GitHub Release for the pushed tag via `gh release create`
- [x] 8.5 Verify end-to-end with a test tag (e.g. `v0.0.0-test`) before cutting a real release tag, then remove the test release/tag — **done 2026-07-05**, with the real `v0.9.0` tag rather than a test tag: the Release workflow ran to completion (after fixing a missing `GH_REPO` in the publish step) and produced all six assets; the Linux archive was downloaded, checksum-verified, and its binaries run.
- [x] 8.6 Confirm the workflow does not trigger on ordinary branch pushes or pull requests — verified by inspection of the `on:` trigger (`push: tags: ['v*']` only, no `pull_request`/plain `push` entry)
