## 1. Server: DELETE endpoint (`crates/nookd`)

- [x] 1.1 Add `DELETE` route on `/v1/vault/{vault_id}/ns/{namespace_id}/obj/{object_id}` with the existing hex-segment validation and HMAC signature check (reject `401` before any storage access, identically for unknown/revoked vaults)
- [x] 1.2 Implement `handle_delete`: in one `meta.sqlite` transaction, look up the object row, delete it, and decrement `vaults.bytes_used` by its size; then remove the object file; respond `204` (deleted) or `404` (absent, no metadata change)
- [x] 1.3 Server tests: delete existing → 204 + subsequent GET 404 + `bytes_used` decremented; delete missing → 404 with no counter change; unsigned/badly-signed delete → 401; same `object_id` in another vault/namespace unaffected; quota-full vault becomes writable after delete

## 2. Server: namespace listing endpoint (`crates/nookd`)

- [x] 2.1 Add `GET /v1/vault/{vault_id}/ns/{namespace_id}/objects` with the same validation and signing rules, returning JSON `{ "server_time", "objects": [ { "object_id", "size", "updated_at" } ] }` from `meta.sqlite`
- [x] 2.2 Server tests: listing returns exactly the namespace's objects with only the three fields plus `server_time`; empty/unknown namespace → 200 with empty list; unsigned request → 401; listing does not leak objects from other vaults/namespaces

## 3. Client: HTTP helpers and shared sweep (`crates/nook`)

- [x] 3.1 Add signed `delete_object` and `list_namespace_objects` HTTP helpers alongside the existing GET/PUT helpers
- [x] 3.2 Implement live-set computation from a manifest: head object ID plus every file node's `content_object_id`
- [x] 3.3 Implement the sweep routine per design D3: tier 1 deletes the previous-manifest-minus-new-manifest diff set immediately; tier 2 deletes listed objects outside the live set whose `updated_at` is older than `server_time − grace_window`; `404` on delete counts as success
- [x] 3.4 Add grace-window configuration: config field with 24 h default, `NOOK_GC_GRACE_SECONDS` override; age math uses server timestamps only
- [x] 3.5 Make the sweep strictly post-commit and non-fatal: runs only after a successful CAS swap, every sweep-phase error (including 404/405 from a pre-deletion server) downgrades to a warning with a successful exit

## 4. Client: wire sweep into push, add `nook rm`

- [x] 4.1 Capture the pre-push manifest's referenced object set in `cmd_push`, and invoke the sweep after the manifest PUT succeeds (both the update and first-push paths)
- [x] 4.2 Add the `Rm { path }` subcommand: mandatory path, fetch manifest + etag with the fail-closed rules, remove the file node or directory subtree (error if the path is absent), CAS-guarded manifest upload, then the same sweep; never touch local files
- [x] 4.3 Update the pull-side content-object 404 error message to suggest re-running pull (object may have been reclaimed by a concurrent writer)

## 5. Integration tests

- [x] 5.1 End-to-end reclamation: push file, modify, push again → old content object gone from server and `bytes_used` shrunk, pull still yields the new content
- [x] 5.2 `nook rm` end-to-end: rm a file and a directory subtree → entries gone from `ls`/`tree`, content objects deleted, local files untouched; `rm` of a missing path and bare `rm` both fail with no server writes
- [x] 5.3 Grace-window safety: an unreferenced object with fresh `updated_at` survives a sweep; the same object is reclaimed once older than the window (use a small `NOOK_GC_GRACE_SECONDS`)
- [x] 5.4 Concurrency: a push losing CAS issues no deletes; manifest head object survives sweeps even when the namespace is emptied
- [x] 5.5 Degradation: push against a server without the new endpoints still succeeds with a warning

## 6. Documentation

- [x] 6.1 README: document `nook rm`, automatic space reclamation on push/rm, and the grace-window setting; remove/adjust any "no deletion" caveats
- [x] 6.2 SECURITY.md: note the listing endpoint's metadata disclosure (IDs/sizes/timestamps, already operator-visible) and that a vault-credential holder can now enumerate and destroy ciphertext, per the SPEC-004 trust model
