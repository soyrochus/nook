## Context

A namespace's objects are only reachable through the encrypted manifest: file nodes carry `content_object_id`s, and the manifest itself lives at a head object ID derived from the namespace key. `cmd_push` mints a fresh random `object_id` for every changed file and repoints the manifest node, abandoning the old object forever; nothing on the client or server can delete anything. The server (`crates/nookd`) already keeps everything the sweep needs in `meta.sqlite`: `objects(vault_id, namespace_id, object_id, size, etag, created_at, updated_at)` and `vaults.bytes_used`, with `PUT` doing quota accounting inside a transaction. Manifest writes are CAS-guarded via `If-Match` on an integer etag.

Constraint that shapes everything: the server is a semantic null. It cannot know which objects are live — only a client holding the namespace key can compute the live set by decrypting the manifest. Therefore deletion is client-driven, and the server's role is limited to two mechanical verbs (delete one object, list a namespace's object IDs).

## Goals / Non-Goals

**Goals:**
- Users can remove files/directories from a namespace (`nook rm`).
- Storage is reclaimed automatically: every successful manifest write (push or rm) sweeps unreferenced ("disconnected") objects — no separate `gc` command, no operator involvement.
- Quota (`bytes_used`) reflects deletions immediately.
- No data a live manifest references is ever deleted, even with concurrent pushers.
- Old clients keep working against a new server.

**Non-Goals:**
- Versioning, trash, or undelete — deletion is final.
- Server-side GC policy of any kind (the server never decides what is garbage).
- Vault-level purge/wipe tooling for operators.
- Per-namespace access control; any change to AEAD scheme, manifest format, chunk framing, or key wrapping.
- Traffic-analysis resistance improvements (listing responses reveal object count/sizes to a credential holder — see Risks).

## Decisions

### D1: Client-driven mark-and-sweep, triggered by every successful manifest swap
After `push` or `rm` wins the CAS swap of the manifest, the same command computes the live set — `{head object ID} ∪ {every content_object_id in the manifest it just installed}` — lists the namespace's objects, and deletes the rest, subject to D4. GC never runs before a successful swap: a client that failed CAS has no authority over what is live.
*Alternative rejected:* a manual `nook gc` command (user requirement is automatic); server-side sweeping (impossible without breaking zero-knowledge — the server can't distinguish a live chunk from garbage).

### D2: Two new server endpoints, same auth scheme
- `DELETE /v1/vault/{vault_id}/ns/{namespace_id}/obj/{object_id}` — removes the object file and its `objects` row and decrements `vaults.bytes_used` by the row's `size`, all in one transaction (mirroring `handle_put`). Returns `204` on success, `404` if absent. Not conditional (no `If-Match`) — see D5.
- `GET /v1/vault/{vault_id}/ns/{namespace_id}/objects` — returns JSON `{ "server_time": <unix_secs>, "objects": [ { "object_id", "size", "updated_at" }, ... ] }` for that namespace. `server_time` exists so age computations never involve the client's clock.

Both verbs use the existing HMAC-SHA256 signing (`method + path + timestamp + sha256(body)`) and the existing 64-hex path-segment validation, and are rejected `401` for revoked/unknown vaults exactly like `PUT`. This formally replaces SPEC-004's "exactly three verbs" requirement.
*Alternative rejected:* batch DELETE with a body of IDs — fewer round-trips, but a new request shape to sign and parse for marginal gain at Nook's scale; can be added later without breaking anything.

### D3: Two-tier sweep — immediate diff deletion plus grace-windowed full sweep
On each successful swap the client deletes, in order:
1. **Diff set, immediately:** objects referenced by the *previous* manifest (the one the CAS etag proves was current) but not by the new one — i.e. content replaced or removed by this very operation. Safe regardless of age: the CAS win proves no other writer has linked them since, and any concurrent pusher who fetched the old manifest will fail CAS and refetch.
2. **Full sweep, grace-windowed:** every listed object not in the new live set *and* whose `updated_at` is older than `server_time − grace_window`. This reclaims historical orphans (pre-GC garbage, residue of crashed/failed pushes) while protecting a concurrent pusher's uploaded-but-not-yet-linked objects, whose `updated_at` is by definition fresh.

The common case — updating a file — reclaims space instantly via tier 1, because the replaced object's `updated_at` is its original (old) upload time. The window only delays reclaiming *recently uploaded* garbage, which is exactly the set that might still be about to be linked.
*Alternative rejected:* full sweep only (delays all reclamation by the window); diff only (never cleans historical orphans, which is half the point).

### D4: Grace window default 24 h, client-configurable
The window must exceed the longest plausible gap between a pusher's first object upload and its manifest swap (large trees over slow links). 24 h is conservatively safe and costs little: tier 1 handles the high-volume case instantly, so the window governs only failure residue. Configurable via client config / `NOOK_GC_GRACE_SECONDS` for testing and unusual deployments; the server neither knows nor enforces it.

### D5: GC failures are non-fatal and deletes are best-effort idempotent
The push/rm itself is complete once the manifest swap succeeds; every listing/delete error after that point degrades to a warning and a nonzero-orphan note, never a failed command — the next successful swap re-sweeps. Client treats `404` on DELETE as success (someone else already swept it). No `If-Match` on DELETE: object IDs are random and never reused for different content, so there is no lost-update hazard to guard.

### D6: `nook rm <path>` reuses the push pipeline
`rm` fetches the manifest with etag, removes the named file node or directory subtree (error if the path doesn't exist; a bare `nook rm` with no path is rejected — wiping a namespace must be explicit, e.g. `rm` of each top-level entry), pushes the manifest with `If-Match`, then runs the same D3 sweep. It never touches local files under the root. The manifest head object is always live and never enters any delete set, even for an empty manifest.

### D7: Quota accounting
`bytes_used` decrements inside the DELETE transaction, so a quota-blocked vault becomes writable the moment garbage is swept — and since sweep runs *after* the manifest PUT, a completely full vault may need its next push to fit within remaining quota before reclamation kicks in. Startup reconciliation (`SUM(size) WHERE vault_id = ?`) is already deletion-correct since it recomputes from surviving rows.

## Risks / Trade-offs

- [Concurrent `pull` may 404 on a content object swept mid-download] → Accepted: puller retries with a fresh manifest; pull error message updated to say so. The window shrinks tier-1 exposure only for pathological timing; Nook explicitly targets "devices you control," not high-concurrency teams.
- [A pusher slower than the grace window (first upload → swap > 24 h) could have unlinked objects swept by a concurrent writer] → Documented limit; window is configurable upward. Re-running the failed push re-uploads.
- [Listing endpoint lets any vault-credential holder enumerate a namespace's object IDs, sizes, and timestamps, and DELETE lets them destroy ciphertext] → No new trust break: SPEC-004 already defines the credential as an all-or-nothing storage grant whose compromise permits forgery/destruction, and the server operator always saw this metadata. SECURITY.md gains an explicit paragraph.
- [Client clock skew corrupting age math] → Eliminated by design: ages compare server-issued `updated_at` against server-issued `server_time` only.
- [Crash between manifest swap and sweep leaves orphans] → Self-healing: next successful swap sweeps them (after the window).
- [Two clients sweeping concurrently double-delete] → Harmless: DELETE is idempotent from the client's perspective (D5).

## Migration Plan

Additive server change: new routes, no schema migration (`objects` already has `size`/`updated_at`), no storage-layout change. Old clients work unchanged against a new server. New clients against an old server get 404/405 on listing/DELETE — GC degrades to a warning per D5, push/rm-manifest-edit still work. No flag day; historical orphans in existing deployments are reclaimed by the first post-upgrade push after the grace window.

## Open Questions

- None blocking. (Batch DELETE and an operator-side vault purge remain future extensions.)
