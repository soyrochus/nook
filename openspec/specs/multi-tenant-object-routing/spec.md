# multi-tenant-object-routing Specification

## Purpose
TBD - created by archiving change spec-004-multi-vault-access-control. Update Purpose after archive.
## Requirements
### Requirement: Objects are addressed by the vault/namespace/object triple
The object API SHALL address every object by the path `/v1/vault/{vault_id}/ns/{namespace_id}/obj/{object_id}` for all three verbs (`GET`, `HEAD`, `PUT`), replacing the previous flat `/v1/obj/{object_id}` addressing.

#### Scenario: Writing an object under a specific vault and namespace
- **WHEN** a client sends `PUT /v1/vault/{vault_id}/ns/{namespace_id}/obj/{object_id}` with a valid signature and body
- **THEN** the object is stored and is retrievable only via that same `(vault_id, namespace_id, object_id)` triple

#### Scenario: Same object_id under different vaults or namespaces does not collide
- **WHEN** two different `(vault_id, namespace_id)` pairs each write an object using the identical `object_id` value
- **THEN** both objects are stored independently and retrieving one does not return the other

### Requirement: Path segments are validated before touching storage
`nookd` SHALL validate `vault_id`, `namespace_id`, and `object_id` as 64-character lowercase hexadecimal strings before performing any filesystem or database operation, rejecting requests with malformed segments.

#### Scenario: Malformed vault_id is rejected
- **WHEN** a request path contains a `vault_id` that is not exactly 64 lowercase hex characters
- **THEN** the server responds with a client error and does not attempt any filesystem or database access using that value

#### Scenario: Path traversal attempt is rejected
- **WHEN** a request path segment contains characters outside the valid hex alphabet (e.g. `..`, `/`, or other path-traversal sequences)
- **THEN** the request is rejected before any filesystem path is constructed from it

### Requirement: No new endpoint types are introduced
The object API SHALL continue to expose exactly the same three verbs (`GET`, `HEAD`, `PUT`) with no additional HTTP methods or semantic endpoints.

#### Scenario: API surface remains three verbs
- **WHEN** the full set of routes exposed by `nookd` is enumerated
- **THEN** only `GET`, `HEAD`, and `PUT` against the vault/namespace/object path exist; no vault- or namespace-management actions are reachable over HTTP

