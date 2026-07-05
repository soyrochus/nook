## Why

Nook currently has no way to remove anything from a namespace, ever: the client exposes no delete command, `nookd` exposes no DELETE verb, and every push of a changed file mints a fresh `object_id` and abandons the old object as permanently unreachable ciphertext. Combined with SPEC-004's per-vault quotas this makes storage a one-way ratchet — updating a 100 MB file ten times burns 1 GB of quota, 900 MB of it garbage — ending in `507 Insufficient Storage` with no recovery short of the operator wiping the vault. Both SPEC-003 (§ known issues) and SPEC-004 (§5) explicitly deferred deletion/cleanup tooling; this change delivers it.

## What Changes

- `nookd` gains an HMAC-authenticated `DELETE /v1/vault/{vault_id}/ns/{namespace_id}/obj/{object_id}` that removes the object file and its metadata row and immediately decrements the vault's `bytes_used`.
- `nookd` gains an HMAC-authenticated namespace-scoped listing endpoint returning, per object: `object_id`, `size`, and the server-side `updated_at` timestamp. This stays within the semantic-null model — the server still discloses nothing it doesn't already know.
- `nook rm <path>` removes a file or directory subtree from the manifest via the existing CAS-guarded manifest push flow.
- Garbage collection is **automatic and built into every successful manifest write** (`push` and `rm`) — there is no separate `gc` command. After the new manifest wins the CAS swap, the client lists the namespace's objects and deletes every object not referenced by the manifest it just installed, including objects replaced by this push and historical orphans from earlier versions.
- GC safety rules: no deletion is ever issued before the CAS swap succeeds; unreferenced objects younger than a grace window (measured by the server's `updated_at`) are skipped, so a concurrent pusher's uploaded-but-not-yet-linked objects survive until their own manifest swap; GC/delete failures are non-fatal to the push (a later push re-sweeps).
- **BREAKING** (spec-level): the SPEC-004 requirement that the object API expose exactly `GET`/`HEAD`/`PUT` is replaced — the surface grows by `DELETE` and the namespace listing. No change to the AEAD scheme, manifest format, chunk framing, or key wrapping.

## Capabilities

### New Capabilities
- `object-deletion-api`: server-side `DELETE` verb and namespace object-listing endpoint — authentication, validation, idempotency, quota decrement, and what the listing may (and may not) reveal.
- `namespace-file-removal`: the `nook rm <path>` client command — manifest editing, CAS semantics, and local-file non-interference.
- `automatic-garbage-collection`: the client-driven post-CAS sweep — live-set computation, grace window, ordering guarantees, and failure tolerance.

### Modified Capabilities
- `multi-tenant-object-routing`: the "no new endpoint types are introduced" requirement is replaced; `DELETE` joins the per-object verbs and a namespace-scoped listing route is added, with the same path-segment validation.
- `multi-tenant-quota`: `bytes_used` accounting now also decrements on delete, immediately, and startup reconciliation remains correct in the presence of deletions.
- `vault-request-authentication`: the signing requirement extends to the new `DELETE` and listing requests (same HMAC scheme, same replay bounds).
- `manifest-push-safety`: `nook push` gains a post-CAS GC phase whose failures do not fail the push; all pre-existing fail-closed fetch behavior is unchanged.

## Impact

- **Server** (`crates/nookd`): new routes + handlers, metadata-store delete/list queries against `meta.sqlite`, per-vault `bytes_used` decrement path.
- **Client** (`crates/nook`): new `Rm` subcommand; `cmd_push` (and the new rm flow) gain a post-swap GC phase; new HTTP helpers for DELETE and listing.
- **Wire/API**: two new authenticated endpoints; existing endpoints untouched, so old clients keep working against a new server (they simply never delete).
- **Docs**: README (`rm`, automatic space reclamation), SECURITY.md (listing endpoint disclosure analysis, delete-as-forgery note under vault-credential compromise).
- **Out of scope**: versioning/undelete, per-namespace access control, vault-level purge tooling, any crypto-format change.
