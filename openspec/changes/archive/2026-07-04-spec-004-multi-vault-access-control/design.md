## Context

`nookd` (`crates/nookd/src/main.rs`, ~350 lines post-SPEC-003) is currently a flat, unauthenticated key-value store: `object_id → ciphertext`, one shared namespace across the whole deployment, no concept of tenancy or access control. `nook` (`crates/nook/src/main.rs`) holds one `VaultKey` per client config (SPEC-003 already added keychain/passphrase-encrypted storage for it). `specs/SPEC-004-multi-vault-user-concurrecny-changes.md` is the source of truth for this change; it was arrived at after rejecting an earlier proposal (double-encrypting the object envelope with a server-held key) in favor of a cleaner separation: a server-side access boundary ("vault") fully decoupled from the client-side encryption boundary ("namespace", i.e. today's vault/VMK renamed). This design covers how to implement that spec.

## Goals / Non-Goals

**Goals:**
- Reject (not merely fail to decrypt) reads and writes from anyone who doesn't hold a given vault's credential.
- Support multiple independent encrypted namespaces sharing one `nookd` process and one storage quota pool per vault.
- Support sharing a specific namespace between specific people without exposing the rest of a vault's contents to them any differently than today (namespace keys are the only thing that grants decryption, as before).
- Preserve every existing cryptographic guarantee verbatim: no change to AEAD scheme, manifest format, chunk framing, or key wrapping (SPEC-001 §7–10, §17–18).

**Non-Goals:**
- Per-namespace access control (only per-namespace *encryption* is provided — a vault-credential holder can reach any namespace under that vault, per SPEC-004 §12).
- Per-namespace quota sub-limits (vault-level only, per SPEC-004 §9).
- Automatic retry/merge on CAS conflict in `nook push` (still a manual re-run).
- Vault data deletion/purge tooling beyond `revoke` (access-blocking only).
- Any in-place migration from the current flat single-tenant deployment.

## Decisions

**1. HMAC-signed requests, not bearer tokens, and not a second encryption layer.** The vault credential is used as an HMAC-SHA256 key over a canonical request string (`method + path + timestamp + sha256(body)`), sent as `X-Nook-Timestamp`/`X-Nook-Signature` headers. It is never put on the wire itself, at request time.

*Alternatives considered:* (a) A second AEAD-encrypted header inside the object envelope, decrypted by the server to "recognize" the vault — rejected because it conflates authentication with confidentiality, expands the already-audited object wire format (risking the same class of divergent-copy bug SPEC-003 §4 just fixed), and gives the server a *decryption* capability it doesn't otherwise need. (b) A plain bearer token compared against a stored hash — simpler to implement, but retransmits the actual credential on every request; on the hostile-network threat model SPEC-001 §1/§22 already assumes (TLS-intercepting proxies, MITM), that's a live credential-theft channel for the entire lifetime of the credential, not just a one-time bootstrap exposure. HMAC signing was chosen specifically to stay consistent with SPEC-001's "do not rely on TLS" stance.

**2. Replay defense is a timestamp window only (±300s), no nonce-tracking store.** A replayed `GET` discloses nothing an on-path observer didn't already see; a replayed `PUT` is already caught by the existing per-object CAS (`If-Match`) — it's either a harmless no-op (identical content) or rejected outright. A dedicated nonce/replay cache would add real complexity (storage, cleanup, clock-sync sensitivity) for a threat that's already mitigated elsewhere.

**3. Indistinguishable `401` for "no such vault" vs. "wrong credential."** Both must produce the same status, body, and (as far as practical) timing, otherwise the auth check becomes an oracle for enumerating valid `vault_id`s. This applies uniformly to missing headers, expired timestamps, and signature mismatches too — one failure mode, one response.

**4. Path-based namespacing: `/v1/vault/{vault_id}/ns/{namespace_id}/obj/{object_id}`.** Explicit and declared beats implicit and inferred. The alternative — tagging an object with whichever vault's credential first wrote it ("claim on first write") — avoids a URL shape change but makes ownership an emergent property of write order rather than a stated fact, which is harder to reason about and test, and doesn't extend cleanly to namespace-level scoping (two concerns, not one). This is a deliberate, narrow protocol change, not "adding an endpoint" in the sense SPEC-001 §22 warns against — the same three verbs, re-addressed.

**5. Namespaces require no server-side registration.** Because access control is vault-scoped, not namespace-scoped, there is nothing to register — any vault-credential-signed request may address a namespace_id that doesn't exist yet, and it's created implicitly by the first `PUT`. This is a direct, deliberate consequence of decision-driver #2 above (namespace boundaries are cryptographic only), not an oversight.

**6. Vault provisioning is admin/local-CLI-only (`nookd vault create/list/revoke`), never a network endpoint.** A self-service "create a vault" HTTP call would let any anonymous caller consume unlimited storage/quota slots — a Sybil/DoS vector that would undermine the entire point of adding access control. The credential is printed once at creation time and never re-displayed (standard secret-hygiene practice, same as a cloud provider's access-key creation flow); losing it means revoke-and-recreate.

**7. Vault credential bootstrap is out-of-band, exactly once per enrolled user, and this spec deliberately does not automate it.** SPEC-001 §9 already requires the same out-of-band trust assumption for namespace-key (VMK) distribution; this reuses that exact pattern rather than inventing a new one. HMAC signing (decision 1) removes *repeated* exposure of the credential on every request — it does not and cannot remove this one unavoidable initial transmission.

**8. Terminology rename, zero cryptographic change.** SPEC-001's "vault"/VMK becomes "namespace"/namespace key; "vault" is reassigned to the new server-side container. `crates/nook-core` needs no source changes for this — it's a documentation/terminology-only rename at the type/API level in `crates/nook` (e.g. renaming local variables/config fields for clarity is optional, not required for correctness) plus the concrete new fields (`vault_id`, `vault_credential`) added to `nook`'s `Config`.

**9. `meta.sqlite` schema: composite primary key + new `vaults` table.** `objects` table's primary key becomes `(vault_id, namespace_id, object_id)`; storage on disk becomes `objects/<vault_id>/<namespace_id>/<object_id>`. All three ID segments are validated as 64-char lowercase hex before touching the filesystem (reusing the existing `valid_object_id`-style check for all three, since they're deliberately the same shape). A new `vaults` table holds `vault_id`, `credential` (raw bytes — HMAC verification needs the actual key, not a hash), `created_at`, `quota_bytes` (nullable = inherit server default), `bytes_used` (running total, reconciled from `SUM(size) WHERE vault_id = ?` on startup, same pattern SPEC-003 §5 already established for the global counter), and `revoked`.

**10. Vault credential and namespace key share the same client-side protection.** Reuse the keychain/passphrase-encrypted-file infrastructure built in SPEC-003 §2 rather than inventing a second protection mechanism — one passphrase prompt, not two, for the common case (both secrets protected under the same keychain entry or encrypted blob).

## Risks / Trade-offs

- [`nookd` now holds a class of secret whose leak matters (`vaults.credential`, needed in raw form for HMAC verification)] → Previously 100% of server-held bytes were safe to leak (SPEC-001's core selling point); this is a genuine, honestly-unavoidable expansion of that guarantee for any authenticated-write scheme. Documented explicitly in SPEC-004 §12 and to be reflected in `SECURITY.md`; operators should treat `meta.sqlite` with the care due a credential store.
- [A vault-credential holder can read/write raw ciphertext for *any* namespace in that vault, even ones whose key they don't hold] → Deliberate consequence of decision 5, not a bug. Must be documented prominently (SPEC-004 §12) so it isn't mistaken for per-person isolation.
- [Namespace-level metadata (count, relative sizes, write frequency within a vault) becomes visible to the server, which is new structure it couldn't previously infer from an undifferentiated object pool] → Consistent with SPEC-001 §19's pre-existing non-guarantee of traffic-volume/timing concealment; extend that documented non-goal explicitly to cover namespace structure.
- [Breaking API/storage change with no migration path] → Deliberate and precedented (SPEC-003's TOML config change was likewise not auto-migrated); acceptable given no production deployments exist yet.
- [HMAC canonical-string construction must be implemented identically on client and server, or all requests fail closed] → Low risk of silent divergence (unlike a crypto format, a signature mismatch fails loudly and immediately, it doesn't corrupt data) — cover with an integration test that exercises a real signed request end-to-end, not just unit tests of the signing function in isolation.

## Migration Plan

1. Land `nookd`'s schema/storage-layout change and HMAC verification together (they're inseparable: the composite key and the auth check both gate the same request path).
2. Land `nookd vault create/list/revoke` CLI alongside step 1 — nothing works without a vault to authenticate against.
3. Land `nook`'s signing logic and `Config` extension (`vault_id`, `vault_credential`) together with `nook init`'s new required flags.
4. Land `nook namespace export`/`--import-namespace` last — it's additive on top of a working single-namespace flow and isn't needed for the base multi-tenant case to work.
5. Update `specs/SPEC-001-Base Implementation.md`'s terminology (vault→namespace) and `SECURITY.md`'s guarantees list once the above is implemented and tested.

No live migration for existing deployments: this is pre-1.0, breaking, and documented as such (SPEC-004 §14).

## Open Questions

- Exact bundle encoding for `nook namespace export`/`--import-namespace` (SPEC-004 §6 leaves this to implementation) — a simple concatenation of hex-encoded `namespace_id` + `namespace_key` with a version prefix seems sufficient; finalize during implementation.
- Whether `nookd vault list`'s namespace count should be computed live (`COUNT(DISTINCT namespace_id)`) or maintained incrementally — likely live-computed is fine given expected vault counts are small; revisit only if this proves slow in practice.
