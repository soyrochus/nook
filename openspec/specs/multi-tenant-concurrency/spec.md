# multi-tenant-concurrency Specification

## Purpose
TBD - created by archiving change spec-004-multi-vault-access-control. Update Purpose after archive.
## Requirements
### Requirement: CAS is scoped to the full vault/namespace/object tuple
`nookd` SHALL enforce `If-Match`/`ETag` compare-and-swap semantics per `(vault_id, namespace_id, object_id)`, such that concurrent-write protection for one tuple is entirely independent of any other.

#### Scenario: Concurrent writers to the same tuple are serialized by CAS
- **WHEN** two clients both attempt to `PUT` the same `(vault_id, namespace_id, object_id)` using an `If-Match` etag obtained from the same prior read
- **THEN** the first write to complete succeeds and advances the etag; the second write's `If-Match` no longer matches and is rejected with `412 Precondition Failed`

#### Scenario: Writes to different namespaces never contend
- **WHEN** two clients write to the same `object_id` value but under different `namespace_id`s (or different `vault_id`s)
- **THEN** neither write's CAS check is affected by the other; both may succeed independently

### Requirement: Concurrent reads are always permitted
`nookd` SHALL NOT apply any concurrency restriction to `GET` or `HEAD` requests beyond the authentication check.

#### Scenario: Simultaneous reads succeed regardless of concurrent writes
- **WHEN** multiple `GET` requests for the same object are made concurrently, including while a `PUT` to that same object is in flight
- **THEN** all `GET` requests complete successfully, each returning either the prior or updated content, never an error due to concurrency

### Requirement: A namespace's manifest head requires no server-side special-casing
The server SHALL treat the namespace's manifest head object as an ordinary object identified by `(vault_id, namespace_id, object_id)`, with no server-side logic that distinguishes it from any other object in that namespace.

#### Scenario: Manifest head object is indistinguishable from content objects to the server
- **WHEN** the server processes a request for the object that happens to be a namespace's manifest head
- **THEN** it applies the same generic CAS, validation, and storage logic used for any other object in that namespace, with no special-case code path

