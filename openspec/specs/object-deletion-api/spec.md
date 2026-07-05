# object-deletion-api Specification

## Purpose
TBD - created by archiving change remote-deletion-auto-gc. Update Purpose after archive.
## Requirements
### Requirement: Objects can be deleted by their vault/namespace/object triple
`nookd` SHALL support `DELETE /v1/vault/{vault_id}/ns/{namespace_id}/obj/{object_id}`, which removes the stored object file and its metadata row and decrements the vault's `bytes_used` by the deleted object's recorded size, all within a single metadata transaction. The response SHALL be `204 No Content` on successful deletion and `404 Not Found` if no such object exists.

#### Scenario: Deleting an existing object removes it and frees quota
- **WHEN** a validly signed `DELETE` names an existing `(vault_id, namespace_id, object_id)` triple
- **THEN** the server responds `204`, a subsequent `GET`/`HEAD` for that triple returns `404`, and the vault's `bytes_used` has decreased by exactly that object's previously recorded size

#### Scenario: Deleting a nonexistent object is harmless
- **WHEN** a validly signed `DELETE` names a triple with no stored object
- **THEN** the server responds `404` and no metadata (including `bytes_used`) changes

#### Scenario: Delete does not cross vault or namespace boundaries
- **WHEN** the same `object_id` value exists under two different `(vault_id, namespace_id)` pairs and one of them is deleted
- **THEN** the other remains stored and retrievable

### Requirement: A namespace's objects can be enumerated
`nookd` SHALL support `GET /v1/vault/{vault_id}/ns/{namespace_id}/objects`, returning a JSON body containing the server's current Unix time (`server_time`) and, for every object stored under that `(vault_id, namespace_id)`, its `object_id`, `size`, and `updated_at` (server-side Unix timestamp of last write). No other object attributes are exposed.

#### Scenario: Listing returns IDs, sizes, and timestamps only
- **WHEN** a validly signed listing request names a namespace containing stored objects
- **THEN** the response enumerates exactly that namespace's objects with `object_id`, `size`, and `updated_at` per entry, plus a top-level `server_time`, and nothing else

#### Scenario: Listing an empty or unknown namespace succeeds with an empty set
- **WHEN** a validly signed listing request names a namespace with no stored objects
- **THEN** the server responds `200` with an empty object list (a namespace's existence is not a server-side concept beyond its stored objects)

### Requirement: Deletion and listing preserve the semantic-null property
The `DELETE` and listing endpoints SHALL NOT require, accept, or expose any plaintext-derived information: they operate solely on opaque IDs, byte sizes, and server-side timestamps the server already possesses. The server SHALL NOT decide on its own initiative to delete any object.

#### Scenario: Server never self-initiates deletion
- **WHEN** `nookd` runs for any length of time without receiving a `DELETE` request for a given object
- **THEN** that object remains stored, regardless of age, reference status, or quota pressure

