## Why

`nookd` is currently a single flat, unauthenticated object store: any client that can reach it may read or write any object, and there is exactly one implicit encryption domain per deployment. This is fine for a single-user, single-machine-pair setup, but it cannot support multiple people or teams sharing one running server without each of them being able to read, overwrite, or delete each other's data outright — not merely fail to decrypt it, but actually access the raw bytes and corrupt state. `specs/SPEC-004-multi-vault-user-concurrecny-changes.md` specifies the fix: a server-side access-control boundary (**vault**) decoupled from the client-side encryption boundary (**namespace**, what SPEC-001 called "the vault"/VMK), so one `nookd` instance can safely host multiple credential-gated tenants, each able to hold multiple independently encrypted namespaces, with per-tenant storage quota and unchanged per-object concurrency safety.

## What Changes

- **Terminology renaming**: what SPEC-001 calls "vault"/"Vault Master Key (VMK)" becomes **namespace**/**namespace key** everywhere. "Vault" is reassigned to mean the new server-side access/storage container. No cryptographic behavior changes — SPEC-001 §7–10 and §17–18 (manifest, key hierarchy, chunk framing, wire format) apply verbatim to namespaces. **BREAKING** (terminology only, not wire format).
- **New: vault lifecycle**, admin/operator-controlled only (never a network-reachable endpoint, to avoid a Sybil/DoS self-service vector): `nookd vault create [--quota-bytes N]`, `nookd vault list`, `nookd vault revoke <vault_id>`. Creating a vault generates a random `vault_id` and `vault_credential`, printed once.
- **New: request authentication.** Every `GET`/`HEAD`/`PUT` must be signed with the requesting vault's credential via HMAC-SHA256 over a canonical request string; the credential itself is never transmitted on the wire at request time (only transmitted once, out of band, at enrollment). Requests with a missing/invalid signature, an expired timestamp, or an unknown/revoked `vault_id` are all rejected identically with `401 Unauthorized`, so vault existence cannot be enumerated via a response oracle.
- **New: namespaces require no registration.** Any request signed with a valid vault credential may read or write any `namespace_id` under that vault, including one invented on the spot by the first `PUT` — namespace boundaries are cryptographic only, not access-controlled, by design.
- **Modified: HTTP API surface.** `/v1/obj/{object_id}` becomes `/v1/vault/{vault_id}/ns/{namespace_id}/obj/{object_id}` for all three existing verbs (no new verbs/endpoint types added). **BREAKING**.
- **Modified: server storage layout.** `objects/<object_id>` becomes `objects/<vault_id>/<namespace_id>/<object_id>`; `meta.sqlite`'s `objects` table is re-keyed to the composite `(vault_id, namespace_id, object_id)`, and gains a new `vaults` table (`vault_id`, `credential`, `quota_bytes`, `bytes_used`, `revoked`, timestamps). **BREAKING**, no automatic migration.
- **Modified: concurrency (CAS)**, from SPEC-001 §12 / SPEC-003: `If-Match`/`ETag` CAS is now scoped per `(vault_id, namespace_id, object_id)` rather than per `object_id` alone. No new concurrency mechanism — this falls out of the composite-key change.
- **Modified: quota**, from SPEC-003 §5: the single global running-total counter becomes one counter per `vault_id` (summed across all of that vault's namespaces), checked against that vault's own `quota_bytes` (or the server default). Per-namespace sub-quotas are explicitly out of scope.
- **New: `nook` namespace key management.** `nook init --vault-id <id> --vault-credential <cred>` generates a namespace; `nook namespace export` / `nook init ... --import-namespace <bundle>` share one. The vault credential and namespace key are protected client-side using the same keychain/passphrase-encrypted storage already built for the VMK (SPEC-003 §2).

## Capabilities

### New Capabilities
- `vault-lifecycle`: admin-only creation/listing/revocation of server-side vaults, each with a generated credential and quota, never exposed as a network endpoint.
- `vault-request-authentication`: HMAC-based signing/verification of every object-API request against the claimed vault's credential, with indistinguishable rejection of invalid/unknown/revoked vaults.
- `namespace-management`: client-side generation, export, and import of namespace identities (namespace_id + namespace key), requiring no server-side registration.
- `multi-tenant-object-routing`: the `(vault_id, namespace_id, object_id)`-addressed HTTP API and storage layout replacing the current flat `object_id`-only scheme.
- `multi-tenant-concurrency`: CAS/ETag scoping extended to the full `(vault_id, namespace_id, object_id)` tuple.
- `multi-tenant-quota`: per-vault storage quota accounting (summed across a vault's namespaces), replacing the single global quota counter.

### Modified Capabilities
(none — `openspec/specs/` has no existing capability specs yet; the SPEC-003 change that introduced `server-metadata-quota` has not been archived into `openspec/specs/` at the time of this proposal, so `multi-tenant-quota` above is listed as new rather than as a delta against it. Once SPEC-003 is archived, a future change should reconcile `server-metadata-quota` into `multi-tenant-quota`.)

## Impact

- **Code**: `crates/nookd/src/main.rs` (routing, `AppState`, `init_db`, new `vaults` table, HMAC verification middleware, new `vault` CLI subcommands), `crates/nook/src/main.rs` (`nook init`/`namespace export`/`namespace import`, request signing, extended `Config`), `crates/nook-core` (no change to the encrypted-object envelope; namespace-key terminology only).
- **Docs**: `specs/SPEC-001-Base Implementation.md` terminology note (vault→namespace), `SECURITY.md` amendments per SPEC-004 §12 (new non-guarantees: namespace-level structure visible to server, vault-credential compromise allows storage-level forgery, `nookd` now holds one class of secret worth protecting).
- **Wire protocol / API**: breaking change to the object API path shape and to server storage layout; no automatic migration (operators re-provision a vault and re-push data).
- **Compatibility**: any existing pre-SPEC-004 deployment must create a vault and re-push; no in-place upgrade path is specified.
