# SPEC-003 — NOOK IMPLEMENTATION DRIFT FIXES

**Corrective specification, additive on top of `specs/SPEC-001-Base Implementation.md` and `specs/SPEC-002-FileNavigation.md`**

---

## 0. Scope of this specification

This document does not change Nook's cryptographic design, object model, or wire protocol goals. It records the drift found when auditing the current implementation (`crates/nook`, `crates/nook-core`, `crates/nookd`) against SPEC-001 and SPEC-002, and specifies the fixes required to bring the codebase back into compliance.

Findings are ordered by severity. Each item states the problem, the file/location, the required fix, and how to verify it.

---

## 1. Critical — client fabricates a fresh manifest on any fetch/decrypt failure

**Location:** `crates/nook/src/main.rs`, `cmd_push`, the `fetch_manifest_with_etag` error handling (`Err(_) => { ... new empty manifest, etag = None ... }`).

**Problem:** Every failure mode — network error, corrupted download, wrong vault key, integrity-checksum mismatch, AEAD decrypt failure — is treated identically to "no manifest exists yet." SPEC-001 §18 requires: *"All decrypt failures are fatal."* Because the fabricated manifest is pushed with `etag = None`, the subsequent `PUT` to the head object carries no `If-Match` and succeeds unconditionally, silently overwriting the real manifest and orphaning every previously-pushed object. This violates SPEC-001 §20 ("Concurrent writers never corrupt state") and the additive-merge guarantee documented in SPEC-002 §13.

**Required fix:**

* Distinguish "manifest object does not exist" (HTTP 404 from the head GET) from every other failure.
* On 404: proceed with a new empty manifest and no `If-Match`, as today.
* On any other error (network failure, integrity checksum mismatch, decrypt/AEAD failure, malformed JSON): abort the push immediately with a fatal error. Do not fabricate a manifest. Do not upload. Do not touch the head object.
* This applies symmetrically to `fetch_manifest` (used by `ls`/`tree`/`pull`) — it already propagates errors correctly and needs no change, but the fix to `cmd_push` must not regress that path.

**Verification:** Simulate a corrupted head object (flip a byte in a stored ciphertext) and run `nook push`. The command must fail loudly and must not modify server state. Confirm via `nookd`'s etag that the head object is untouched.

---

## 2. High — Vault Master Key stored in plaintext-equivalent form

**Location:** `crates/nook/src/main.rs`, `Config` struct and `save_config`/`load_config`.

**Problem:** The VMK is base64-encoded (not encrypted) and written directly into `config.json` in the OS config directory. SPEC-001 §5 requires: *"Secure storage: OS keychain preferred; Encrypted local fallback."* Base64 provides no confidentiality; anyone with read access to the config directory recovers the VMK and defeats E2EE on that device.

**Required fix:**

* Add OS keychain integration (e.g. via the `keyring` crate) as the default storage path for `vault_key`.
* When no keychain is available (headless/CI/unsupported platform), fall back to an encrypted-at-rest local file: derive a local wrapping key from a user-supplied passphrase via Argon2id (already listed as an optional dependency in SPEC-001 §5) and encrypt the VMK with XChaCha20-Poly1305 before writing to disk.
* `nook init` must support both paths and record which one is in use so `load_config` knows how to retrieve the key back.
* The rest of `Config` (server URL, root path) may remain plaintext — only `vault_key` requires protection.

**Verification:** After `nook init`, inspect the on-disk config file and confirm no recoverable key material is present in plaintext or base64. Confirm `nook status`/`push`/`pull` still work by retrieving the key from the keychain or by passphrase prompt.

---

## 3. Medium — config file format uses JSON instead of `toml`

**Location:** `crates/nook/src/main.rs` (`Config`, `save_config`, `load_config`); `crates/nook/Cargo.toml` (no `toml` dependency).

**Problem:** SPEC-001 §5 specifies `toml` for client config. The implementation uses `serde_json` throughout.

**Required fix:** Add the `toml` crate and switch `save_config`/`load_config` to read/write TOML. This can land independently of item 2 (encrypted key storage) — the VMK field itself may be represented as an opaque reference (keychain handle or encrypted blob) inside the TOML file rather than a raw key.

**Verification:** `nook init` produces a `.toml` config file readable by a TOML parser; existing JSON configs are not required to migrate automatically unless desired.

---

## 4. Medium — object wire format has undocumented framing and a redundant, unverified wrapped-key copy

**Location:** `crates/nook-core/src/object.rs` (`serialize_encrypted_object`, `deserialize_encrypted_object`, `decrypt_object`).

**Problem:** SPEC-001 §17 describes the wrapped DEK as living only inside the encrypted chunk-0 header. That's circular as written (the header can't be decrypted without the DEK, and the DEK is only recoverable from inside the header), so the implementation stores the `WrappedKey` a second time, unencrypted, in a bespoke envelope in front of the chunk stream (`[u16 len][wrapped_key][u32 chunk_count][chunks...]`). This envelope is undocumented, and `decrypt_object` never checks the outer copy against the one embedded in the decrypted header — the two can silently diverge.

**Required fix:**

* Document the actual on-wire envelope format in SPEC-001 §17 (replace or annotate the existing description), since exposing the wrapped DEK outside the AEAD-encrypted chunk is safe (it is itself AEAD ciphertext under the VMK-derived wrap key) and is the correct resolution of the circularity.
* In `decrypt_object`, after decrypting the header, assert `header.wrapped_dek == outer wrapped_key bytes` and fail closed (per SPEC-001 §18: "all decrypt failures are fatal") if they differ, rather than silently ignoring the header's copy.

**Verification:** Craft a test object where the two wrapped-key copies differ and confirm `decrypt_object` rejects it instead of succeeding.

---

## 5. Medium — server storage omits documented metadata fields

**Location:** `crates/nookd/src/main.rs` (`init_db`, `ObjectMeta`, `load_meta`/`store_meta`).

**Problem:** SPEC-001 §6 lists `timestamps` as a server-visible field; §16 lists `quota accounting` in `meta.sqlite`. Neither is implemented — the table has only `object_id, size, etag`.

**Required fix:**

* Add `created_at`/`updated_at` columns, set on insert/update.
* Add minimal quota accounting: a running total of bytes stored (globally or per configured limit) checked on `PUT`, rejecting uploads that would exceed a configured quota with an appropriate status code (e.g. `507 Insufficient Storage`).

**Verification:** Confirm timestamps populate on create/update. Confirm a configured quota causes oversized uploads to be rejected without partial writes (temp file must still be cleaned up on rejection).

---

## 6. Medium — repository structure doesn't match SPEC-001 §21

**Location:** repository root.

**Problem:** SPEC-001 §21 expects `docs/SPEC.md`, `docs/SECURITY.md`, and `.github/workflows/ci.yml`. None exist; specs live under `specs/` instead, and there is no CI.

**Required fix:**

* Either update SPEC-001 §21 to reflect `specs/` as the canonical location (recommended, since it's already in use across SPEC-001/002/003), or move the spec files to `docs/`.
* Add `docs/SECURITY.md` (or `specs/SECURITY.md`) summarizing the guarantees in SPEC-001 §19 for external reference.
* Add `.github/workflows/ci.yml` running at minimum `cargo build`, `cargo test`, and `cargo clippy` across the workspace on push/PR.

**Verification:** CI runs and passes on a clean clone; repository layout matches whichever location is declared canonical in the spec.

---

## 7. Low / informational — no fix required, tracked for awareness

* **`nookd` has no TLS support** (`crates/nookd/src/main.rs` binds a plain `TcpListener` and serves via `axum::serve` with no `rustls`/`tokio-rustls` layer; `crates/nookd/Cargo.toml` has zero TLS dependencies). SPEC-001 §5 lists `TLS: rustls` under the server stack, so this is a real gap against the documented tech stack — but it is *not* a confidentiality regression. SPEC-001's design is explicit that the "absolute invariant" (§1) and security guarantees (§19) must hold **even when TLS is intercepted or absent** (§22: "Do not rely on TLS for confidentiality"); object IDs are random and meaningless, payloads are AEAD ciphertext, and any tampering is caught by fail-closed decryption regardless of transport. What plain HTTP actually gives up is narrower: defense-in-depth against on-path tampering/injection (e.g. forged responses, connection-reset DoS) and basic server authentication to the client — availability/robustness properties, not the confidentiality/integrity guarantees the spec makes. Recommended as a follow-up (add `rustls`/`tokio-rustls` or front `nookd` with a TLS-terminating proxy) to match the documented stack and harden availability, but it should not be treated as a security defect in the E2EE model.
* **Nonce derivation** (`crates/nook-core/src/object.rs::derive_nonce`) uses `HKDF(salt=object_id, ikm=data_key, info=chunk_index)` rather than the literal `derive(object_nonce, i)` described in SPEC-001 §17. This is cryptographically sound (unique per object+chunk since `data_key` is fresh per object) — SPEC-001 §17 should be reworded to match the implementation rather than the implementation changed.
* **`Manifest.previous_manifest_hash`** is defined in the data model (SPEC-001 §7) but never populated by `cmd_push`. No hash-chain history is currently built. Optional field — implement only if history/audit trail becomes a requirement.
* **CLI surface is larger than SPEC-001 §15's terse contract** (`nook init` requires `--server`; a global `--server` override flag exists). Reasonable extension; SPEC-001 §15 should be updated to document the actual flags rather than left as a bare command list.
* **No Argon2id passphrase path** exists yet; SPEC-001 §5 lists it as optional. Only becomes required if item 2's encrypted-local-fallback is implemented via passphrase (as recommended above).
* **Crash window in `nookd`** between atomic rename and `store_meta` (`handle_put`) can leave an object file on disk with no DB record until the next successful `PUT` for that ID. Self-heals; no fix required unless orphan-file cleanup tooling is desired later.

---

## 8. Acceptance criteria for this spec

Applying the fixes above must not regress any SPEC-001/SPEC-002 acceptance criteria. In addition:

* A push that hits a corrupted or undecryptable existing manifest fails loudly and leaves server state untouched (§1).
* `nook init` never writes a recoverable VMK to plain disk storage (§2).
* Client config is TOML (§3).
* A tampered wrapped-key envelope is rejected at decrypt time rather than silently accepted (§4).
* `meta.sqlite` records timestamps and enforces a configurable quota (§5).
* CI builds, tests, and lints the workspace on every push/PR (§6).
