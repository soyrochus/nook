# SPEC — NOOK

**Amorphous, End-to-End Encrypted Push/Pull File Vault**
**Rust server + Rust CLI client**

---

## 1. Purpose and non-negotiable properties

Nook is a minimal private file vault designed to operate correctly in **fully untrusted environments**, including:

* TLS-intercepting firewalls
* Corporate MITM proxies
* Hostile networks
* Server compromise scenarios

**Absolute invariant**

> No file contents, filenames, directory structure, paths, or filesystem semantics may ever appear outside authenticated encryption.

The server is a **semantic null**.
All meaning exists exclusively on the client.

---

## 2. Explicit goals

* Push and pull entire directory trees between devices.
* Preserve filenames and directory structure **only inside encrypted payloads**.
* Mandatory end-to-end encryption (E2EE).
* Amorphous traffic: all payloads indistinguishable encrypted blobs.
* Atomic updates and safe concurrent writers.
* Simple deployment: one Rust server binary, one Rust CLI binary.
* Correctness under TLS MITM.

---

## 3. Explicit non-goals

* No background sync.
* No merge, diff, or conflict resolution.
* No server-side indexing or interpretation.
* No plaintext metadata of any kind.
* No full traffic-analysis resistance (volume/timing remain observable).

---

## 4. Architecture overview

```
Client (Rust CLI)
 ├─ Local filesystem
 ├─ Encrypted Virtual Filesystem (VFS)
 ├─ Encrypted manifests
 └─ HTTPS (possibly MITM)

Server (Rust daemon)
 ├─ Generic encrypted object store
 ├─ Object IDs only
 ├─ Atomic blob replacement
 └─ No semantic awareness
```

---

## 5. Technology stack

### Language

* Rust (stable)

### Shared

* Async runtime: `tokio`
* Serialization (internal only): `serde`
* Cryptography:

  * AEAD: **XChaCha20-Poly1305**
  * KDF: **HKDF**
  * Password KDF (optional): **Argon2id**
* Randomness: OS CSPRNG

### Client (`nook`)

* CLI parsing: `clap`
* HTTP client: `reqwest` + `rustls`
* Config: `toml`, `directories`
* Secure storage:

  * OS keychain preferred
  * Encrypted local fallback

### Server (`nookd`)

* HTTP server: `axum`
* TLS: `rustls`
* Storage:

  * Local filesystem
  * SQLite (object refs, CAS state, quotas)

---

## 6. Object model (server-visible)

The server understands **only**:

* `object_id` — 256-bit random identifier
* `ciphertext` — opaque bytes
* `size`
* `etag` / version
* timestamps

The server never understands:

* paths
* filenames
* directories
* manifests
* file types
* semantics

---

## 7. Encrypted Virtual Filesystem (client-side)

### Manifest (plaintext before encryption)

The encrypted manifest encodes the entire filesystem state.

Fields:

* manifest_version
* root_node_id
* nodes:

  * node_id
  * parent_id
  * name (UTF-8)
  * type: file | directory
  * for files:

    * content_object_id
    * wrapped_dek
    * logical_size
    * optional timestamps
* previous_manifest_hash (optional)
* integrity checksum

### Manifest storage

* Manifest is encrypted and stored as a normal object.
* Server cannot distinguish manifest objects from file objects.

---

## 8. Manifest head (amorphous coordination)

There is **no named root**.

The current filesystem state is identified by a **head object ID** derived from a secret:

```
head_object_id = H(vault_master_key, "nook-head")
```

Properties:

* Fixed object_id
* Overwritten atomically
* Indistinguishable from any other object
* Server cannot identify it as special

---

## 9. Key hierarchy (mandatory)

* **Vault Master Key (VMK)**

  * Generated once
  * Shared across devices out-of-band
  * Stored securely client-side

* **Data Encryption Key (DEK)**

  * Random per object
  * Wrapped using VMK
  * Stored inside encrypted object header

* **AEAD**

  * XChaCha20-Poly1305
  * Associated data:

    * object_id
    * chunk index
    * protocol version

Server never sees keys.

---

## 10. Chunking, padding, amorphous traffic

* Fixed chunk size (default 64 KiB).
* Final chunk padded to full size.
* Padding is authenticated.
* All objects follow identical transfer patterns.

---

## 11. Server API (generic blob store)

There are **exactly three endpoints**.

### Upload / replace object

```
PUT /v1/obj/{object_id}
Headers:
  If-Match: <etag> (optional)
Body:
  ciphertext bytes
```

### Download object

```
GET /v1/obj/{object_id}
```

### Object existence / CAS

```
HEAD /v1/obj/{object_id}
```

No semantic endpoints exist.

---

## 12. Atomicity and concurrency (CAS)

* Server writes uploads to temporary storage.
* Atomic rename on completion.
* CAS via ETag prevents concurrent overwrite.

Workflow:

1. Client reads head (H₀).
2. Client uploads new objects.
3. Client writes new manifest (H₁).
4. Client conditionally overwrites head:

   ```
   PUT head_object_id
   If-Match: etag(H₀)
   ```

Failure = retry.

---

## 13. Push semantics (client-side)

Push = rewrite encrypted snapshot.

Steps:

1. Walk local tree.
2. Build new manifest.
3. Encrypt and upload new objects.
4. CAS-update head.

Overwrite is implicit.

---

## 14. Pull semantics (client-side)

Pull = materialize encrypted snapshot.

Steps:

1. Download head.
2. Decrypt manifest.
3. Recreate directories.
4. Download content objects.
5. Decrypt to temp files.
6. Atomic rename.

---

## 15. CLI contract (`nook`)

```
nook init
nook root [--set <path>]
nook push [<subpath>]
nook pull [<subpath>]
nook status
```

Subpaths are **local only**.

---

## 16. Server storage layout

```
/storage
 ├─ objects/
 │   └─ <object_id>
 ├─ temp/
 └─ meta.sqlite
```

`meta.sqlite` contains:

* object_id
* size
* etag/version
* quota accounting

No semantic data.

---

## 17. Wire format (encrypted object layout)

Each stored object is a sequence of encrypted chunks.

### Encrypted object header (chunk 0, plaintext before encryption)

```
struct ObjectHeader {
  magic: "NOOK1"
  object_type: MANIFEST | CONTENT
  protocol_version: u16
  wrapped_dek: bytes
  logical_size: u64
  chunk_size: u32
}
```

* Header is encrypted with DEK.
* `object_type` is not visible outside encryption.

### Chunk structure

For each chunk `i`:

* Plaintext:

  * data bytes
  * padding (if final)
* AEAD:

  * key: DEK
  * nonce: derive(object_nonce, i)
  * associated data:

    * object_id
    * chunk_index
    * protocol_version

---

## 18. Crypto module API (`nook-core::crypto`)

This API **must be used verbatim** by client code.

```rust
pub struct VaultKey([u8; 32]);

pub struct DataKey([u8; 32]);

pub struct WrappedKey(Vec<u8>);

pub fn generate_vault_key() -> VaultKey;

pub fn generate_data_key() -> DataKey;

pub fn wrap_data_key(
    vault: &VaultKey,
    data: &DataKey,
) -> WrappedKey;

pub fn unwrap_data_key(
    vault: &VaultKey,
    wrapped: &WrappedKey,
) -> Result<DataKey>;

pub fn encrypt_chunk(
    key: &DataKey,
    nonce: &[u8; 24],
    associated_data: &[u8],
    plaintext: &[u8],
) -> Vec<u8>;

pub fn decrypt_chunk(
    key: &DataKey,
    nonce: &[u8; 24],
    associated_data: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>>;

pub fn derive_head_object_id(vault: &VaultKey) -> [u8; 32];
```

Rules:

* Nonce reuse is forbidden.
* All decrypt failures are fatal.
* No plaintext is written before verification.

---

## 19. Security guarantees

Guaranteed:

* Confidentiality under TLS MITM.
* No readable metadata.
* Server compromise yields only ciphertext.
* Tampering detected and rejected.

Not guaranteed:

* Traffic volume concealment.
* Timing concealment.

---

## 20. Acceptance criteria

* TLS MITM reveals no filenames, paths, or structure.
* Server disk inspection reveals only ciphertext.
* Concurrent writers never corrupt state.
* Interrupted transfers never expose partial files.
* Push → pull roundtrip yields identical trees.

---

## 21. Repository structure

```
/
 ├─ crates/
 │   ├─ nook-core
 │   ├─ nook
 │   └─ nookd
 ├─ docs/
 │   ├─ SPEC.md
 │   └─ SECURITY.md
 └─ .github/workflows/ci.yml
```

---

## 22. Implementation constraints (for the agent)

* Do not add endpoints.
* Do not leak metadata.
* Do not rely on TLS for confidentiality.
* Fail closed on any crypto error.
* Keep semantics client-side only.


