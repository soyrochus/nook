## Context

`nook` (CLI client) and `nookd` (server) implement SPEC-001's E2EE object store and SPEC-002's file-navigation layer. `specs/SPEC-003-implementation-fixes.md` documents six drift items found by audit, ordered by severity, plus a "no fix required" informational item 7. This design covers the six drift fixes and two net-new pieces of infrastructure requested alongside them: a container image for `nookd` and a tag-triggered release build. The client is a single ~900-line `crates/nook/src/main.rs`; the server is a single ~270-line `crates/nookd/src/main.rs` backed by `rusqlite`; shared object framing lives in `crates/nook-core/src/object.rs` (~240 lines). Nothing here changes the wire protocol's cryptographic primitives.

## Goals / Non-Goals

**Goals:**
- Make `nook push` fail closed on every manifest-fetch failure mode except genuine absence (404), per SPEC-001 §18/§20.
- Remove the VMK from recoverable plaintext/base64 storage using OS keychain or passphrase-derived encryption.
- Move client config to TOML per SPEC-001 §5.
- Make the wrapped-DEK duplication in the object envelope a checked invariant instead of a silent divergence risk.
- Give `nookd` timestamps and quota enforcement per SPEC-001 §6/§16.
- Reconcile repo layout with SPEC-001 §21 and stand up push/PR CI.
- Ship a `Dockerfile` for `nookd` where object/meta data survives container recreation via an operator-supplied volume.
- Ship a tag-triggered (`v*`) GitHub Actions workflow producing `nook`/`nookd` binaries for Linux x64, Windows x64, macOS arm64.

**Non-Goals:**
- No change to the AEAD scheme, chunking, manifest format, or protocol semantics beyond the explicit fixes above.
- No auto-migration of existing plaintext `config.json` files or of manifests already corrupted by the fabrication bug — users re-run `nook init`.
- No TLS termination inside `nookd` (SPEC-003 item 7 — informational, out of scope here).
- No Intel macOS target, no ARM Linux/Windows targets, no Docker image publishing to a registry (only a Dockerfile is required; publishing a built image is left for a future change if wanted).
- No general plugin/config system for the Docker volume path beyond a single documented data directory.

## Decisions

**1. 404-only fast path in `cmd_push`.** Replace the current `Err(_) => fabricate empty manifest` with matching on the actual fetch outcome: `Ok(existing)` → normal path; `Err(FetchError::NotFound)` → today's "no manifest yet" behavior (empty manifest, no `If-Match`); any other `Err(_)` (network, integrity/checksum mismatch, AEAD decrypt failure, JSON parse failure) → return an error immediately from `cmd_push` before any `PUT`. This requires `fetch_manifest_with_etag`'s error type to distinguish HTTP 404 from other failures (likely via an enum or by inspecting `reqwest::StatusCode` before treating a non-2xx as a decrypt/parse attempt). `fetch_manifest` (used by `ls`/`tree`/`pull`) already propagates errors and is left alone; the shared fetch helper (if any) must not have its error semantics changed in a way that regresses that path — verified by keeping its Err propagation identical, only the *caller* in `cmd_push` changes.

**2. Keychain-first VMK storage, passphrase fallback.** Use the `keyring` crate (cross-platform: Keychain on macOS, Credential Manager on Windows, Secret Service/kwallet on Linux) as the default. `nook init` attempts a keychain write; on failure (headless Linux without a Secret Service, CI, unsupported platform) it falls back to prompting for a passphrase, deriving a wrapping key via Argon2id (parameters: a conservative interactive profile, e.g. `m=19456, t=2, p=1` per OWASP guidance, stored alongside the salt — not hardcoded as a magic invariant), and encrypting the VMK with XChaCha20-Poly1305 before writing the ciphertext + salt + nonce to disk. The config records a `key_storage` mode tag (`keychain` | `encrypted_file`) so `load_config` knows whether to hit the keychain API or prompt for a passphrase. Passphrase is never cached in the config; it is re-entered per invocation (or held only in-process memory for the command's duration) — this is the same trust boundary SPEC-001 §5 assumes for "encrypted local fallback."

*Alternative considered*: always require a passphrase (no keychain). Rejected — worse UX for the common desktop case, and SPEC-001 §5 explicitly prefers OS keychain.

**3. TOML config, opaque key field.** Swap `serde_json` for `toml` in `save_config`/`load_config`. The `vault_key` field becomes an enum-like structure serialized as either a keychain-reference string (service/account name, no secret) or an encrypted blob (ciphertext, salt, nonce, base64-encoded — base64 here is fine since the payload is genuine ciphertext, not the raw key). `server_url` and `root` remain plain TOML fields. Old JSON configs are not auto-detected/migrated; `load_config` simply expects TOML and errors clearly if it can't parse, directing the user to re-run `nook init`.

**4. Wrapped-DEK cross-check.** Document the existing on-wire framing (`[u16 len][wrapped_key][u32 chunk_count][chunks...]`) in SPEC-001 §17 as the authoritative envelope (it's already safe — the outer copy is itself AEAD ciphertext under the VMK-derived wrap key — the spec text was just circular/stale). In `decrypt_object`, after chunk-0's header is decrypted, compare `header.wrapped_dek` byte-for-byte against the outer envelope's `wrapped_key`; mismatch returns a decrypt error (fail-closed, consistent with SPEC-001 §18) rather than proceeding with the header's copy silently.

**5. `nookd` timestamps + quota.** Add `created_at INTEGER, updated_at INTEGER` (unix seconds) to the object metadata table, set on insert (`created_at = updated_at = now`) and update (`updated_at = now`) in `store_meta`. Add a quota check in `handle_put`: before (or after, with rollback) committing a new object, sum current stored bytes (`SUM(size)` from the metadata table, or a maintained running counter for O(1) checks at scale — running counter preferred to avoid a full-table scan per PUT) and reject with `507 Insufficient Storage` if `current + incoming > configured_quota`. Quota is a server-side config value (CLI flag or config file field), default effectively unlimited if unset, to avoid breaking existing deployments. Temp files written during upload must be cleaned up (`tokio::fs::remove_file` or `tempfile`'s drop-cleanup) on the rejection path — the PUT handler already writes to a temp path before an atomic rename; the quota check must happen before the rename, and any drop path must still trigger cleanup.

**6. Canonical repo structure.** Declare `specs/` canonical in SPEC-001 §21 (lowest-churn option: it's already where SPEC-001/002/003 live) rather than moving files to `docs/`. Add `SECURITY.md` at repo root (not nested under `specs/`, so it's discoverable the way GitHub surfaces root-level `SECURITY.md`) summarizing the SPEC-001 §19 guarantees for an external reader. Add `.github/workflows/ci.yml` running `cargo build --workspace`, `cargo test --workspace`, `cargo clippy --workspace -- -D warnings` on `push` and `pull_request`.

**7. `nookd` Dockerfile with externalized data.** Multi-stage build: a `rust:*-bookworm` (or slim) builder stage running `cargo build --release -p nookd`, and a minimal runtime stage (`debian:bookworm-slim` or `gcr.io/distroless/cc` if the binary's dynamic deps allow) that copies only the `nookd` binary. The runtime stage declares `ENV NOOK_DATA_DIR=/data` (or whatever flag/env `nookd` already accepts, extended if it doesn't yet accept a configurable data directory), sets `VOLUME ["/data"]`, and `WORKDIR /data`. This means a plain `podman run -v myvol:/data ...` or `docker run -v $(pwd)/data:/data ...` persists the SQLite metadata DB and object blobs across container recreation without any container-specific storage code — the existing filesystem-based storage in `nookd` already satisfies this as long as the data directory is configurable and defaults under `/data`. If `nookd` currently hardcodes its data path relative to CWD, this change makes it a CLI flag/env var with `/data`-under-container as the container default, non-breaking for bare-metal runs (default remains CWD-relative there).

*Alternative considered*: bake a default SQLite file into the image and let users `docker cp` it out. Rejected — silently non-durable, contradicts the requirement that data survive container replacement.

**8. Tag-triggered release workflow.** `.github/workflows/release.yml`, `on: push: tags: ['v*']` only (explicitly not `push`/`pull_request`, unlike `ci.yml`). Matrix over three targets: `x86_64-unknown-linux-gnu` (ubuntu runner), `x86_64-pc-windows-msvc` (windows runner), `aarch64-apple-darwin` (macos-14 runner, which is Apple Silicon by default — no cross-compilation needed for that leg, unlike a from-Linux cross-compile). Each matrix leg runs `cargo build --release --workspace` (or targets `-p nook -p nookd` explicitly), packages both binaries (with `.exe` suffix handled per-OS), and uploads them as artifacts attached to a GitHub Release created from the pushed tag (`softprops/action-gh-release` or equivalent, or `gh release create`/`upload` via the `gh` CLI already available in runners). No cross-compilation toolchain (e.g. `cross`) is needed since each OS/arch pair maps to a native runner.

*Alternative considered*: cross-compile everything from Linux using `cross`/`cargo-zigbuild` to cut runner minutes. Rejected for this change — native runners are simpler to get right first; revisit only if build minutes become a real cost concern.

## Risks / Trade-offs

- [Existing users' `config.json` becomes unreadable after the TOML switch] → Acceptable per spec (§3 verification note: "existing JSON configs are not required to migrate automatically"); `load_config` gives an explicit "re-run `nook init`" error rather than a confusing parse failure.
- [Keychain unavailable in CI/headless environments, forcing the passphrase fallback path universally in automated test environments] → Document the fallback clearly and ensure `nook init` supports non-interactive passphrase supply (env var or flag) for scripted/CI use, without weakening the encryption itself.
- [Quota running-counter can drift from actual on-disk state if a crash occurs between file write and counter update] → Reconcile counter from `SUM(size)` over the metadata table on `nookd` startup (cheap one-time cost) rather than trusting an unpersisted in-memory counter indefinitely.
- [Distroless/slim runtime image may be missing a dynamic dependency `nookd` needs (e.g. for `rusqlite`'s bundled SQLite, which statically links, so this is likely fine)] → `rusqlite`'s `bundled` feature (already in `Cargo.toml`) statically links SQLite, so a minimal base image should work; validate at implementation time and fall back to `debian:bookworm-slim` if distroless breaks.
- [macOS runner (`macos-14`) availability/cost or future GitHub runner image changes] → Pin to a specific runner label and revisit if GitHub deprecates it; not a correctness risk for now.
- [Manifest push now failing loudly where it previously "succeeded"] → This is the intended, spec-mandated behavior change (SPEC-003 item 1); call it out prominently in release notes since it is a **BREAKING** behavior change for anyone who was unknowingly relying on the silent-overwrite fallback.

## Migration Plan

1. Land the `cmd_push` fail-closed fix first (item 1) — highest severity, no dependency on other items.
2. Land TOML config + keychain/passphrase VMK storage together (items 2+3 touch the same `Config` struct) — coordinate so `nook init` only writes the new format once, not twice.
3. Land the wrapped-DEK cross-check (item 4) independently — pure `nook-core` change, no config/CLI surface impact.
4. Land `nookd` timestamps + quota (item 5) independently — pure server-side change.
5. Land repo structure/CI docs (item 6) — no code dependency, can land anytime, but useful early so subsequent PRs are covered by CI.
6. Add the `Dockerfile` (item A) after item 5's CI exists, so the Dockerfile build can optionally be smoke-tested in CI (build-only, not push).
7. Add the release workflow (item B) last, since it packages the binaries produced by all prior changes; verify it end-to-end with a test tag (e.g. `v0.0.0-test`) before the first real release tag.

No production rollback beyond reverting the relevant commit/PR — none of these changes involve data migrations on already-deployed servers except the additive `meta.sqlite` columns (item 5), which use `ALTER TABLE ... ADD COLUMN` with safe defaults and are backward-compatible to read.

## Open Questions

- Exact Argon2id parameters and whether they should be user-configurable or fixed — default to a fixed, documented conservative profile unless the user requests tunability.
- Whether `nookd`'s data directory is already configurable today or needs a new CLI flag/env var added as part of the Dockerfile work (needs confirmation against current `crates/nookd/src/main.rs` at implementation time).
- Whether release artifacts should be plain binaries or archives (`.tar.gz`/`.zip`) with checksums — recommend archives + `sha256sum` manifest for a clean release, to be finalized during implementation.
