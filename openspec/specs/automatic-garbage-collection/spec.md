# automatic-garbage-collection Specification

## Purpose
TBD - created by archiving change remote-deletion-auto-gc. Update Purpose after archive.
## Requirements
### Requirement: Every successful manifest swap triggers an automatic sweep
After — and only after — a manifest upload wins its CAS swap, `nook push` and `nook rm` SHALL automatically sweep the namespace: compute the live set as the manifest head object ID plus every `content_object_id` referenced by the just-installed manifest, list the namespace's stored objects, and issue `DELETE` for disconnected objects per the tiering rules below. No `DELETE` SHALL ever be issued before the CAS swap succeeds, and no separate user-invoked GC command SHALL be required.

#### Scenario: Replaced content is reclaimed by the push that replaced it
- **WHEN** a file already stored in the namespace is modified locally and `nook push` succeeds
- **THEN** the same invocation deletes the file's previous content object from the server without any further user action

#### Scenario: Failed CAS swap performs no deletions
- **WHEN** a `nook push` manifest upload is rejected because another client updated the manifest first (`If-Match` mismatch)
- **THEN** the command issues no `DELETE` requests

### Requirement: Objects dereferenced by this swap are deleted immediately
Objects referenced by the previous manifest (the one whose etag the winning CAS swap was conditioned on) but absent from the new manifest SHALL be deleted immediately, without any age condition: the CAS win proves no concurrent writer has since linked them.

#### Scenario: Old version of an updated file is deleted regardless of age
- **WHEN** a push replaces a file whose previous content object was uploaded only moments earlier
- **THEN** that previous content object is deleted in the same sweep, with no grace-window delay

### Requirement: Unreferenced objects are swept only after a grace window
Objects that are not in the new live set and were not referenced by the previous manifest (historical orphans, residue of failed or crashed pushes) SHALL be deleted only if their server-reported `updated_at` is older than a grace window relative to the listing's `server_time`. The window SHALL default to 24 hours and be client-configurable (config field and `NOOK_GC_GRACE_SECONDS`). Age comparison SHALL use only server-issued timestamps, never the client clock.

#### Scenario: A concurrent pusher's unlinked uploads survive
- **WHEN** client B has uploaded content objects but not yet swapped its manifest, and client A's push sweeps the namespace within the grace window of B's uploads
- **THEN** A's sweep does not delete B's freshly uploaded objects

#### Scenario: Historical orphans are reclaimed
- **WHEN** a namespace contains objects unreachable from any manifest whose `updated_at` predates the grace window
- **THEN** the next successful push or rm deletes them

### Requirement: The manifest head object is never swept
The manifest head object SHALL be part of the live set unconditionally, including when the manifest is empty.

#### Scenario: Emptying a namespace preserves its manifest
- **WHEN** every file has been removed and a sweep runs
- **THEN** the manifest head object remains stored and `nook ls` still succeeds (showing an empty namespace)

### Requirement: Sweep failures never fail the push or rm
Once the manifest swap has succeeded, any failure in the sweep phase — listing errors, `DELETE` errors, or a server lacking the deletion API — SHALL be reported as a warning while the command still exits successfully; `404` on `DELETE` SHALL be treated as success. Unswept garbage SHALL be reclaimed by a later invocation's sweep.

#### Scenario: Old server without deletion support degrades gracefully
- **WHEN** `nook push` succeeds against a `nookd` that does not implement the listing or `DELETE` endpoints
- **THEN** the push exits successfully with a warning that space reclamation was skipped

#### Scenario: Crash between swap and sweep self-heals
- **WHEN** a client crashes after its manifest swap but before its sweep completes
- **THEN** the objects it would have deleted are deleted by the next successful push or rm in that namespace (subject to the grace window)

