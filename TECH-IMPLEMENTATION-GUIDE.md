# Technical Implementation Guide

This document explains how Nook is built, for contributors and reviewers who
want the implementation overview without reading every spec. It is the
engineering counterpart to [`SECURITY.md`](SECURITY.md): that file summarizes
*what is guaranteed*; this one summarizes *how the code delivers it*. The
authoritative details live in [`specs/`](specs/) (SPEC-001 through SPEC-004)
and the archived/active changes under [`openspec/`](openspec/).

## Repository layout

```text
crates/
  nook-core/   Shared library: crypto, object format, manifest, request auth
  nook/        CLI client (push/pull/rm/ls/tree/init/...)
  nookd/       Server daemon + vault-management CLI
specs/         Numbered design specs (SPEC-001..)
openspec/      Spec-driven change workflow (proposals, deltas, tasks)
```

`nook-core` exists so the client and server can never drift on anything they
must agree on byte-for-byte: the canonical signing string, the object wire
format, path shapes, and ID validation all live there and nowhere else.

## Core concepts

* **Vault** — a server-side storage/access container, provisioned only via
  the local `nookd vault create` CLI (never over the network). Identified by
  a random 256-bit `vault_id`; access is gated by a random 256-bit
  `vault_credential`. Quotas are per-vault.
* **Namespace** — a client-side encrypted volume inside a vault. Identified
  by a random `namespace_id` (non-secret routing label); its contents are
  readable only with the **namespace key**, which never leaves clients.
  Namespace boundaries are cryptographic, not access-controlled.
* **Object** — the only thing the server stores: an opaque blob addressed by
  `(vault_id, namespace_id, object_id)`, all three being 64-char lowercase
  hex. The server cannot distinguish content from manifests.
* **Manifest / head object** — the encrypted directory tree of a namespace,
  stored at a *derived, deterministic* object ID (`HKDF(namespace_key,
  "nook-head")`), so any keyholder can find it without the server knowing
  which object it is.

## Cryptography (`nook-core/src/crypto.rs`, `object.rs`)

All encryption is XChaCha20-Poly1305 AEAD.

* **Per-object data keys.** Every object gets a fresh random 32-byte DEK.
  The DEK is wrapped with a key derived from the namespace key via
  HKDF-SHA256 (`info = "nook-wrap-key"`), with AAD `"nook-key-wrap"`.
* **Chunked framing.** Plaintext is split into fixed 64 KiB chunks,
  zero-padded to full size (so ciphertext lengths only reveal coarse size).
  Chunk 0 is an encrypted header (`bincode`: magic `NOOK1`, object type,
  protocol version, wrapped DEK, logical size, chunk size); subsequent
  chunks carry the data. An empty file still produces one padded data chunk.
* **Nonces are derived, not stored**: `HKDF(salt = object_id, ikm = DEK,
  info = chunk_index)` → 24-byte XNonce. AAD binds each chunk to
  `object_id || chunk_index || protocol_version`, so chunks cannot be
  reordered, truncated, or transplanted between objects without AEAD
  failure.
* **Envelope.** The serialized object is `wrapped_dek_len || wrapped_dek ||
  chunk_count || (chunk_len || chunk)*`. The wrapped DEK appears twice — in
  the clear envelope (needed to bootstrap decryption) and inside the
  AEAD-protected header — and the two copies are cross-checked; any mismatch
  fails closed.
* **Local secret storage.** The client keeps `namespace_key ||
  vault_credential` as one 64-byte blob in the OS keychain, or — when no
  keychain exists — encrypted with a key derived from a passphrase via
  Argon2id (19 MiB, 2 iterations, per OWASP interactive profile) under
  XChaCha20-Poly1305. Key material is zeroized on drop.

## Manifest (`nook-core/src/manifest.rs`)

A flat JSON list of nodes (`node_id`, `parent_id`, `name`, file/directory
type, and for files: `content_object_id`, `wrapped_dek`, `logical_size`)
plus a `root_node_id`. An `integrity_checksum` (SHA-256 over a canonical
serialization of everything except the checksum itself) is validated on
every fetch, on top of AEAD integrity. The manifest is serialized to JSON
and then encrypted exactly like any content object — on the wire it is
indistinguishable from one.

All structure discovery (`ls`, `tree`, path resolution) happens by
decrypting the manifest locally; no server query ever reveals structure.

## Wire protocol and authentication (`nook-core/src/auth.rs`, `nookd`)

| Verb | Path | Purpose |
|------|------|---------|
| `GET`/`HEAD` | `/v1/vault/{v}/ns/{n}/obj/{o}` | Fetch object / etag probe |
| `PUT` | `/v1/vault/{v}/ns/{n}/obj/{o}` | Store object (CAS via `If-Match`) |
| `DELETE` | `/v1/vault/{v}/ns/{n}/obj/{o}` | Delete object (SPEC-005) |
| `GET` | `/v1/vault/{v}/ns/{n}/objects` | List object IDs/sizes/timestamps (SPEC-005) |

Every request is signed: `X-Nook-Signature = HMAC-SHA256(vault_credential,
method \n path \n timestamp \n hex(sha256(body)))`, with `X-Nook-Timestamp`
bounded to ±300 s of server time (replay containment without a nonce store).
The credential itself never travels. "Vault does not exist", "vault
revoked", and "bad signature" produce an identical `401`, so vault IDs
cannot be enumerated. All three path IDs are validated as 64-char lowercase
hex before any filesystem or SQL access. Body hashing is streaming-friendly
on the server: `PUT` spools to a temp file while hashing, then verifies the
signature before committing.

## Server (`crates/nookd`)

One binary, two roles: `nookd serve` (axum HTTP server) and `nookd vault
create|list|revoke` (local, one-shot admin CLI against the same storage).

* **Storage layout**: `objects/<vault_id>/<namespace_id>/<object_id>` plus
  `temp/` and `meta.sqlite` (WAL mode + busy timeout, since the CLI and the
  server access it concurrently from separate processes).
* **`meta.sqlite` schema**: `vaults(vault_id, credential, created_at,
  quota_bytes, bytes_used, revoked)` and `objects(vault_id, namespace_id,
  object_id, size, etag, created_at, updated_at)` with a composite primary
  key — which is what makes cross-vault/namespace collisions structurally
  impossible.
* **PUT path**: stream body → temp file (hashing as it goes) → verify
  signature → single SQLite transaction: CAS check (integer `etag` vs
  `If-Match`; no header means unconditional overwrite), quota check
  (`507 Insufficient Storage`, temp file removed, no partial state), atomic
  rename into place, upsert metadata, adjust `bytes_used`.
* **DELETE path** (SPEC-005): one transaction removes the metadata row and
  decrements `bytes_used`, then the file is unlinked. `404` if absent, with
  no metadata change. A crash between commit and unlink leaves only an
  orphan *file* with no DB row — the same self-healing crash-window class
  SPEC-003 accepted for PUT.
* **Listing** (SPEC-005): returns `server_time` plus `object_id`, `size`,
  `updated_at` per object — only facts the operator could already read off
  the disk. The server never deletes anything on its own initiative; policy
  lives entirely client-side.
* **Vault revocation** flips a flag checked on every request; data is
  retained (access control, not destruction).

## Client (`crates/nook`)

Single binary, config in the platform config dir as TOML (`server`, `root`,
`vault_id`, `namespace_id`, optional `gc_grace_seconds`, and an opaque
`secrets` reference — never raw key material).

* **`push`**: fetch manifest + etag (fail-closed: only a 404 may proceed
  with a fresh manifest; any other fetch/decrypt/integrity failure aborts
  before any write — SPEC-003). Walk the local tree, encrypt each file under
  a fresh random `object_id`, splice nodes into the manifest, upload content
  objects, then upload the manifest with `If-Match` (CAS). A lost race is a
  `412` → error; re-run to retry. After a successful swap, the automatic
  sweep runs (below).
* **`pull`**: fetch + validate manifest, materialize the requested subtree,
  writing files atomically (temp file + rename). A content `404` suggests
  re-running pull, since a concurrent writer may have replaced and swept it.
* **`rm <path>`** (SPEC-005): remove a file node or directory subtree from
  the manifest, CAS-push it, then sweep. The path argument is mandatory,
  removing the namespace root is refused, and local files are never touched.
* **`namespace export` / `init --import-namespace`**: shares the
  `namespace_id` + key as a `nookns1:` bundle over an out-of-band channel,
  which is how multiple devices join one namespace.

## Automatic garbage collection (SPEC-005)

There is no `gc` command. After — and only after — a manifest CAS swap
succeeds, the pushing/removing client sweeps its namespace:

1. **Live set** = head object ID + every `content_object_id` in the manifest
   it just installed.
2. **Tier 1 — immediate**: objects the *previous* manifest referenced but
   the new one doesn't. Safe without any age check: winning the CAS proves
   no concurrent writer linked them since.
3. **Tier 2 — grace-windowed**: any other listed object outside the live set
   is deleted only if `server_time − updated_at` exceeds the grace window
   (default 24 h; `gc_grace_seconds` config or `NOOK_GC_GRACE_SECONDS`).
   This protects a concurrent pusher's uploaded-but-not-yet-linked objects.
   Ages compare server-issued timestamps only — the client clock is never
   consulted, so clock skew cannot cause data loss.

The sweep is strictly post-commit and non-fatal: every failure in it
(listing error, delete error, a pre-SPEC-005 server answering `404`/`405`)
downgrades to a warning and the command still succeeds; the next successful
swap re-sweeps. A `404` on DELETE counts as success (someone else already
swept it). Crashes between swap and sweep therefore self-heal.

## Concurrency and failure semantics, in one place

* Manifest updates are serialized by CAS (`If-Match` on an integer etag);
  content objects are immutable-in-practice (random IDs, never reused for
  different plaintext), so they need no CAS.
* Server-side writes are atomic: temp file + rename inside the metadata
  transaction; rejected uploads leave no partial state.
* Client-side writes are atomic: temp file + rename per pulled file.
* Quota is enforced per vault at PUT time and released transactionally at
  DELETE time; `bytes_used` is reconcilable from `SUM(size)` per vault.
* A `pull` racing a sweep can see a content `404`; the fix is re-running
  pull (documented, and the error message says so).

## Testing

* `cargo test --workspace` runs everything. Server behavior is tested by
  spawning the real `nookd` binary against temp storage
  (`crates/nookd/tests/`); client behavior by driving the real `nook` binary
  with an isolated `XDG_CONFIG_HOME` and `NOOK_PASSPHRASE`
  (`crates/nook/tests/`, shared harness in `tests/support/mod.rs`).
* `crates/nook/tests/gc_and_rm.rs` includes a minimal in-test HTTP stand-in
  for a pre-SPEC-005 server to verify graceful degradation.
* Round-trip and tamper tests for the object format live in
  `crates/nook-core/tests/`.

## Spec map

| Spec | Scope |
|------|-------|
| SPEC-001 | Base E2EE design: object format, manifest, key model |
| SPEC-002 | File navigation (`ls`/`tree`, subpath push/pull) |
| SPEC-003 | Fail-closed push, metadata timestamps, quota, packaging |
| SPEC-004 | Multi-vault/multi-tenant: vaults, namespaces, HMAC auth, per-vault quota |
| SPEC-005 | Remote deletion (`rm`, `DELETE`, listing) and automatic GC (`openspec/changes/remote-deletion-auto-gc/`) |
