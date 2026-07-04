# SPEC-004 — MULTI-VAULT, MULTI-USER ACCESS CONTROL

**Additive on top of `specs/SPEC-001-Base Implementation.md`, `specs/SPEC-002-FileNavigation.md`, and `specs/SPEC-003-implementation-fixes.md`**

---

## 0. Scope of this specification

This document introduces server-side, access-controlled multi-tenancy to Nook. Today, `nookd` is a single flat, unauthenticated object store: any client that can reach the server can read or write any object, and there is exactly one implicit encryption domain per deployment (whatever `VaultKey` the client happens to hold). This is fine for a single-user, single-machine-pair deployment, but does not support:

* Rejecting writes (and reads) from anyone who does not hold a specific credential.
* Multiple independent encrypted "volumes" sharing one running `nookd` instance and one storage quota.
* Sharing a subset of data between specific people without sharing everything.

This spec adds exactly two new concepts — **vault** (server-side access/storage container) and **namespace** (client-side encryption boundary) — and specifies the request-authentication, storage-layout, concurrency, and quota changes needed to support them. It does **not** change the cryptographic object model, wire format, manifest format, or chunk framing described in SPEC-001 §7–10 and §17–18: those apply verbatim, just inside a namespace instead of what SPEC-001 called "the vault."

**Terminology migration note.** SPEC-001 uses "vault" to mean the client-side encryption domain (one `VaultKey`, one head object, one manifest). This spec reassigns "vault" to mean the new server-side access/storage container, and introduces **namespace** and **namespace key** for what SPEC-001 called "the vault" and "the Vault Master Key (VMK)." Everywhere SPEC-001 §7–10 and §17–18 say "vault"/"VMK," read "namespace"/"namespace key." No cryptographic behavior changes.

---

## 1. Problem statement

The current design (SPEC-001 §1, §6, §11) makes the server a semantic null with respect to file content, but it is also an **access null**: it accepts any read or write from anyone who can reach it. There is no way to:

* Run one `nookd` for multiple people/teams without each of them being able to read, overwrite, or delete each other's data outright (not merely fail to decrypt it — actually be denied the bytes).
* Account for storage per tenant rather than globally.
* Share a specific subset of data with specific collaborators without sharing everything on the server.

This spec closes that gap while preserving the absolute invariant in SPEC-001 §1 (no file content, filename, directory structure, path, or filesystem semantics may ever appear outside authenticated encryption) — access control is layered strictly outside that boundary and never weakens it.

---

## 2. Core model

```
nookd (one running server)
  └─ vault A   (server-side access + storage container, credential-gated)
       ├─ namespace fred-personal   → encrypted with Fred's namespace key
       ├─ namespace mary-personal   → encrypted with Mary's namespace key
       └─ namespace shared-team     → encrypted with an imported/shared namespace key
  └─ vault B   (a different access container, different credential, different tenant)
       └─ namespace ...
```

* **Vault** — a server-side storage/access container. Identified by an opaque `vault_id`. Gated by a `vault_credential`. Possessing the credential grants the ability to store and retrieve opaque objects inside that vault. It grants **no** cryptographic capability whatsoever.
* **Namespace** — a client-defined encrypted volume that lives inside exactly one vault. Identified by an opaque `namespace_id`. Encrypted end-to-end with a **namespace key** (this is exactly SPEC-001's `VaultKey`/VMK, renamed). Possessing the namespace key grants the ability to decrypt (and produce valid ciphertext for) that namespace's manifest and content objects. It grants **no** server-side access on its own — a namespace key without the enclosing vault's credential cannot reach the server at all.
* **Object** — unchanged from SPEC-001 §6/§17: an opaque, AEAD-encrypted blob, now addressed by the triple `(vault_id, namespace_id, object_id)` instead of `object_id` alone.

All three identifiers (`vault_id`, `namespace_id`, `object_id`) are **opaque, non-secret, server-generated-or-client-generated random 256-bit values, hex-encoded (64 hex characters)** — the same shape as today's `object_id`, so the same validation routine (`valid_object_id`-style: 64 hex chars) applies uniformly to all three path segments. None of them are human-readable labels. **IDs MUST NOT be derived from or encode any human-meaningful name** (a person's name, team name, etc.); any friendly label a user wants to remember a namespace by is a purely local, client-side concept and is never transmitted to or stored by the server. The person names from previous examples are just that: examples onl.

---

## 3. Vault lifecycle (admin-controlled, not self-service)

Vault creation is a **local, operator-run administrative action**, not a network-reachable endpoint. This is deliberate: an unauthenticated "create a vault" HTTP call would let anyone consume unlimited storage/quota slots (a Sybil/DoS vector), which would undermine the entire point of adding access control.

```
nookd vault create [--quota-bytes N] [--storage <dir>]
```

* Generates a random 256-bit `vault_id` and a random 256-bit `vault_credential`.
* Inserts a new row into the vault table (see §7).
* Prints `vault_id` and `vault_credential` to stdout **exactly once**. `nookd` never displays a vault's credential again after creation (standard secret-hygiene practice — if it's lost, revoke and create a new vault).
* `--quota-bytes` sets a **per-vault** quota override; if omitted, the vault inherits the server's default (`--quota-bytes`/`NOOK_QUOTA_BYTES`, per SPEC-003 §5, now scoped as the default applied to new vaults rather than a single global pool — see §9).

```
nookd vault list [--storage <dir>]
```

* Lists `vault_id`, `created_at`, `quota_bytes`, `bytes_used`, and namespace count, for operator visibility. Never prints credentials.

```
nookd vault revoke <vault_id> [--storage <dir>]
```

* Invalidates the vault's credential immediately; all subsequent requests against that `vault_id` are rejected (§4). Data is **retained**, not deleted — revocation is an access control action, not a data-destruction action. (Actual deletion/purge tooling is left as a future extension; not specified here.)

The admin distributes `vault_id` + `vault_credential` to exactly one initial user through the same out-of-band channel SPEC-001 §9 already requires for namespace-key distribution (in person, a password manager entry, an encrypted message — whatever the operator already trusts for that). This one-time handoff is unavoidable for any shared-secret scheme, HMAC-based or not (see §4's "transmitted exactly once" rule) — it is not a gap introduced by this spec, just the same existing bootstrap trust assumption applied to a second secret. That user decides, independently and entirely client-side, whether to repeat this same out-of-band handoff to onboard collaborators into the same vault, and separately, whether to export/import namespace keys to share specific encrypted content with them (§6).

---

## 4. Request authentication (vault credential)

**The vault credential is transmitted exactly once: out of band, at enrollment** (admin→user per §3, or user→user for onboarding a collaborator into the same vault) — through the same channel and trust assumption SPEC-001 §9 already requires for namespace-key distribution. This one-time handoff is unavoidable; no shared-secret scheme, HMAC or otherwise, can bootstrap trust without it.

After that, it is never transmitted again. Every request to the object API (§5) must be signed with the vault's credential, but the credential itself never goes on the `nook`↔`nookd` wire, in either direction, at request time — consistent with SPEC-001's refusal to rely on TLS for confidentiality (SPEC-001 §22: "do not rely on TLS for confidentiality"). This is the actual value of choosing HMAC over a bearer token: a bearer token *is* the credential, re-exposed to exactly the on-path attacker SPEC-001 is designed to tolerate on every single subsequent call for the credential's entire lifetime; an HMAC signature never lets an observer recover the key no matter how many requests they observe. Choosing HMAC does not remove the one-time bootstrap transmission in §3 — nothing can — it removes the *repeated* exposure on every call after that.

### Signing scheme

```
canonical_string =
  METHOD + "\n" +
  PATH   + "\n" +          # e.g. /v1/vault/{vault_id}/ns/{namespace_id}/obj/{object_id}
  TIMESTAMP + "\n" +       # unix seconds, client clock
  SHA256_HEX(BODY)         # hash of an empty body for GET/HEAD

signature = HMAC-SHA256(vault_credential, canonical_string)
```

Request headers:

```
X-Nook-Timestamp: <unix seconds>
X-Nook-Signature: <hex HMAC-SHA256>
```

Server verification:

* Reject (see below) if `|server_time - X-Nook-Timestamp| > 300` seconds. This bounds replay exposure without requiring a nonce/dedup store: a replayed `GET` discloses nothing an on-path attacker didn't already see in the original request, and a replayed `PUT` is already guarded by per-object CAS (§8) — either it's a no-op (identical content) or it fails the `If-Match` check, so full nonce-tracking replay defense would be complexity without a corresponding threat.
* Recompute the signature using the credential on file for the claimed `vault_id`, compare using constant-time equality.
* On **any** failure — vault does not exist, vault revoked, missing/malformed headers, timestamp out of window, signature mismatch — respond identically: `401 Unauthorized`, same body, same timing profile as far as practical. **The server must not let a client distinguish "no such vault" from "wrong credential."** Any distinguishable response here is an oracle for enumerating valid `vault_id`s.

This is the one new category of secret `nookd` holds server-side (§12 makes this explicit): verifying an HMAC requires the raw credential, not just a hash of it, so `nookd`'s vault table is now something worth protecting, unlike the rest of its storage (which remains fully leak-safe ciphertext).

---

## 5. HTTP API

Replaces SPEC-001 §11's three endpoints with the same three verbs, re-addressed:

```
PUT /v1/vault/{vault_id}/ns/{namespace_id}/obj/{object_id}
Headers:
  X-Nook-Timestamp, X-Nook-Signature (required)
  If-Match: <etag> (optional)
Body:
  ciphertext bytes

GET /v1/vault/{vault_id}/ns/{namespace_id}/obj/{object_id}
Headers:
  X-Nook-Timestamp, X-Nook-Signature (required)

HEAD /v1/vault/{vault_id}/ns/{namespace_id}/obj/{object_id}
Headers:
  X-Nook-Timestamp, X-Nook-Signature (required)
```

No new endpoint *types* are added (SPEC-001 §22's "do not add endpoints" is respected) — the existing three verbs are re-scoped under a longer, explicit path instead of gaining new semantics.

**Namespaces require no registration.** Any request signed with a valid vault credential may read or write any `namespace_id` under that vault, including one invented on the spot by the first `PUT`. There is no per-namespace permission to check, by design (§2: namespace boundaries are cryptographic, not access-controlled) — see §12 for the resulting guarantee this does and does not provide.

---

## 6. Namespace key management (client-side, `nook`)

A namespace is fully defined by two pieces of client-held state: `namespace_id` (opaque, random, non-secret) and `namespace_key` (secret; this is SPEC-001's `VaultKey` — same generation, same key hierarchy in SPEC-001 §9, same storage treatment as built in SPEC-003 §2: OS keychain by default, Argon2id + XChaCha20-Poly1305 passphrase-encrypted fallback otherwise). The `vault_id` and `vault_credential` needed to reach the server are additional client-held state, protected the same way (bundled under the same keychain entry / encrypted blob as the namespace key — one passphrase, not two, for a usable default).

```
nook init --vault-id <id> --vault-credential <cred> [--root <path>]
```

* Generates a fresh random `namespace_id` and `namespace_key`.
* Stores `vault_id`, `vault_credential`, `namespace_id`, `namespace_key` together, protected as above.
* Behaves exactly as SPEC-001/SPEC-003 describe from here on (manifest, push, pull, status), just addressed via the new path shape.

```
nook namespace export
```

* Prints an opaque bundle encoding `(namespace_id, namespace_key)`, for transfer over a secure out-of-band channel chosen by the user (this spec does not prescribe the channel — that's the user's problem, same as sharing the original vault credential).

```
nook init --vault-id <id> --vault-credential <cred> --import-namespace <bundle> [--root <path>]
```

* Adopts an existing namespace instead of generating a new one. The importing client can now read and write everything in that namespace — sharing is symmetric and total within a namespace, by design (§2).

Exact flag names/bundle encoding are implementation details left to the design/tasks phase; the requirement is the three capabilities above (generate, export, import) must exist.

---

## 7. Server storage layout

Replaces SPEC-001 §16:

```
/storage
 ├─ objects/
 │   └─ <vault_id>/
 │       └─ <namespace_id>/
 │           └─ <object_id>
 ├─ temp/
 └─ meta.sqlite
```

`meta.sqlite` gains a `vaults` table alongside the existing (now re-keyed) `objects` table:

```
vaults:
  vault_id      TEXT PRIMARY KEY
  credential    BLOB NOT NULL        -- raw HMAC key; see §12 for the trust implication
  created_at    INTEGER NOT NULL
  quota_bytes   INTEGER              -- NULL = inherit server default
  bytes_used    INTEGER NOT NULL     -- running total, summed across this vault's namespaces
  revoked       INTEGER NOT NULL DEFAULT 0

objects:
  vault_id      TEXT NOT NULL
  namespace_id  TEXT NOT NULL
  object_id     TEXT NOT NULL
  size          INTEGER NOT NULL
  etag          INTEGER NOT NULL
  created_at    INTEGER NOT NULL
  updated_at    INTEGER NOT NULL
  PRIMARY KEY (vault_id, namespace_id, object_id)
```

`vault_id`/`namespace_id`/`object_id` are validated as 64-char lowercase hex before touching the filesystem (path traversal defense — same check already used for `object_id` today, applied to all three segments).

---

## 8. Concurrency (CAS)

Extends SPEC-001 §12:

* CAS (`If-Match`/`ETag`) is enforced per `(vault_id, namespace_id, object_id)` — i.e., exactly the existing per-object CAS mechanism, now keyed by the full tuple instead of `object_id` alone. No new concurrency logic is required; this falls out of the primary key change in §7.
* The namespace's manifest head is one particular `object_id` within `(vault_id, namespace_id)` — computed client-side exactly as SPEC-001 §8 describes (`head_object_id = HKDF(namespace_key, "nook-head")`). The server has no special knowledge of which object is "the head"; it never has, and still doesn't.
* Concurrent reads are always allowed.
* Concurrent writes to the same namespace head require `If-Match`/CAS, exactly as today. CAS failure (`412`) means the client must re-fetch the namespace's manifest and retry — this spec does not add automatic retry/merge to `nook push`; that remains a manual re-run, as it is today (SPEC-003's fail-closed fix to `cmd_push` is unaffected and continues to apply per-namespace).

---

## 9. Quota

Extends SPEC-003 §5. Quota is enforced **per vault only** (not per-namespace): a vault's `bytes_used` sums the sizes of every object across every namespace inside it, checked against that vault's `quota_bytes` (or the server default if unset) on every `PUT`, exactly as SPEC-003 specified — just re-scoped from one global counter to one counter per `vault_id`, reconciled from `SUM(size) WHERE vault_id = ?` on `nookd` startup instead of a single global `SUM(size)`. Rejection behavior (`507 Insufficient Storage`, temp file cleanup, no partial writes) is unchanged. Per-namespace sub-quotas within a vault are explicitly out of scope for this spec (see §13).

---

## 10. Server-visible data model (amends SPEC-001 §6)

The server understands **only**:

* `vault_id`, `namespace_id`, `object_id` — opaque 256-bit identifiers
* `vault_credential` — for the owning vault only, held to verify signatures (new; see §12)
* `ciphertext` — opaque bytes
* `size`, `etag`/version, `created_at`/`updated_at` (SPEC-003 §5)
* `bytes_used`/`quota_bytes` per vault

The server never understands:

* People, teams, or any notion of "user" — Nook is not user-based; `nookd` manages vaults and namespaces, never users.
* Which namespaces "belong together" logically, beyond their both existing under the same `vault_id`.
* paths, filenames, directories, manifests, file types, or any other semantics (unchanged from SPEC-001 §6).

---

## 11. Sharing model (informative, ties §3/§6 together)

Fred and Mary sharing a vault:

1. The admin runs `nookd vault create`, gets `(vault_id, vault_credential)`, and gives it to Fred.
2. Fred runs `nook init --vault-id ... --vault-credential ...`, which generates his own `fred-personal` namespace (random ID + key, known only to him).
3. Fred decides to let Mary use the same server-side storage: he gives her the same `vault_id`/`vault_credential` out of band. Mary runs `nook init` with those, generating her own independent `mary-personal` namespace. Fred and Mary can now both store data in the same vault, but neither can decrypt the other's namespace — and, per §12, each *can* fetch the other's raw ciphertext (ask for it by `namespace_id`/`object_id`, since the vault credential is all that's needed to reach any namespace in the vault) but gains nothing from it without the corresponding namespace key.
4. To collaborate, Fred creates a `shared-team` namespace, runs `nook namespace export`, and gives the resulting bundle to Mary out of band. Mary runs `nook init --import-namespace <bundle>` (with the same vault credentials) to join it. They now have full symmetric read/write access to that one namespace — sharing a namespace key is sharing a volume, with no per-person distinction inside it.

---

## 12. Security guarantees (amends SPEC-001 §1 and §19)

SPEC-001 §1's absolute invariant — no file content, filename, directory structure, path, or filesystem semantics may appear outside authenticated encryption — **is unchanged and continues to hold** regardless of any vault credential compromise: namespace keys are never transmitted to or held by the server, full stop, so no vault-credential leak can expose plaintext.

**New guarantee:**

* A request lacking a valid signature for its claimed `vault_id` is rejected (`401`) before any object read or write is attempted, for both reads and writes.
* "No such vault" and "wrong credential" are indistinguishable to the client, preventing vault-ID enumeration via response oracle.

**New, explicit non-guarantees (extends SPEC-001 §19's "not guaranteed" list):**

* **Namespace-level structure within a vault is visible to the server.** The count of namespaces in a vault, their relative sizes, and their write frequency are observable server-side metadata (consistent with SPEC-001 §19 already not guaranteeing traffic-volume or timing concealment — this extends that non-goal to namespace structure specifically).
* **Vault credential compromise allows storage-level forgery, not decryption.** Anyone holding a vault's credential can read or write raw ciphertext for any namespace in that vault, whether or not they hold that namespace's key. This is a deliberate consequence of "namespace boundaries are cryptographic, not access-controlled" (§2) — within one vault, the credential is an all-or-nothing storage-access grant. If per-namespace access control (not just per-namespace encryption) is later required, that is a bigger feature explicitly out of scope here (§13).
* **`nookd` now holds one class of secret whose compromise matters:** vault credentials, stored in raw (not hashed) form because HMAC verification requires the actual key. This is a genuine, new expansion of the trust placed in the server process/storage compared to SPEC-001's original position (where 100% of server-held bytes were safe to leak). A leaked `vaults` table lets an attacker forge valid requests against those vaults — read/write/delete ciphertext, exhaust quota — but still cannot decrypt any namespace's content. Operators should treat `meta.sqlite` with the same care as any credential store.
* **Vault credential distribution at bootstrap relies on an out-of-band trust channel**, exactly once per user enrolled (§3/§4) — the admin handing `vault_id`/`vault_credential` to the first user, and that user repeating the same handoff for any collaborator they onboard. This spec does not define or automate that channel; it is the operator's/user's responsibility, the same way distributing a namespace key between devices already is in SPEC-001 §9. This is not something the HMAC-based request scheme in §4 removes — it only removes *repeated* exposure of the credential on every subsequent request, not the one unavoidable initial transmission.

---

## 13. Non-goals / explicitly out of scope

* Per-namespace access control (only per-namespace *encryption* is provided; see §12). Modeling actual user identities or per-person audit trails within a shared namespace is not part of this spec.
* Per-namespace quota sub-limits within a vault (§9 — vault-level only).
* Automatic retry/merge in `nook push` on CAS conflict (§8 — still a manual re-run).
* Vault data deletion/purge tooling beyond `nookd vault revoke` (which only blocks access).
* Any change to the AEAD scheme, manifest format, chunk framing, or key-wrapping described in SPEC-001 §7–10, §17–18. None of that changes.
* A network-reachable vault-provisioning endpoint (§3 — deliberately admin/local-CLI-only).

---

## 14. Migration and compatibility

**This is a breaking change.** The flat `/v1/obj/{object_id}` API, the flat `objects/<object_id>` storage layout, and the single global quota counter from SPEC-003 are all replaced by the vault/namespace-scoped equivalents in §5, §7, and §9. There is no automatic migration path from a pre-SPEC-004 deployment: operators upgrading must run `nookd vault create`, distribute the resulting credential, and re-push existing data into the new namespace. This mirrors the precedent already set in SPEC-003 (the TOML config-format change was likewise not auto-migrated).

---

## 15. Acceptance criteria

* A request without a valid signature for its claimed `vault_id` is rejected with `401`, for `GET`, `HEAD`, and `PUT` alike, before touching any object.
* "Vault does not exist" and "signature invalid for an existing vault" produce identical responses.
* Two different vaults' data never collide in storage, even under adversarial/colliding `namespace_id`/`object_id` choices (enforced by the `(vault_id, namespace_id, object_id)` composite key).
* A vault credential holder with no namespace key can `PUT`/`GET` objects in any namespace under that vault, but cannot produce a decryptable manifest or file for a namespace whose key they don't hold.
* Revoking a vault causes all subsequent requests against it to fail with `401`, without deleting its stored data.
* Quota is enforced per vault (sum across its namespaces); one vault exceeding its quota does not affect another vault's ability to write.
* CAS (`If-Match`) continues to prevent concurrent-writer corruption, now scoped per `(vault_id, namespace_id, object_id)`.
* All SPEC-001/SPEC-002/SPEC-003 acceptance criteria continue to hold, with "vault"/"VMK" in those documents read as "namespace"/"namespace key" per the terminology note in §0.
