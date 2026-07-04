## ADDED Requirements

### Requirement: Manifest fetch failures other than "not found" MUST abort the push
`nook push` SHALL distinguish "manifest object does not exist" (an HTTP 404 response from the manifest HEAD/GET) from every other failure mode when fetching the current manifest, including network errors, integrity/checksum mismatches, AEAD decrypt failures, and malformed JSON. On any failure mode other than 404, `nook push` SHALL abort immediately with a fatal error, SHALL NOT fabricate a replacement manifest, and SHALL NOT issue any write (`PUT`) to the server.

#### Scenario: Corrupted existing manifest aborts the push
- **WHEN** `nook push` fetches the current manifest and the stored ciphertext fails AEAD decryption (e.g. a flipped byte in the stored object)
- **THEN** the command exits with a fatal error, no new manifest is uploaded, and the server's existing head object and its `etag` remain unchanged

#### Scenario: Network failure during manifest fetch aborts the push
- **WHEN** `nook push` cannot reach the server while fetching the current manifest (connection error, timeout)
- **THEN** the command exits with a fatal error and no `PUT` request is made to the head object

### Requirement: Absent manifest is the only case that proceeds with an empty manifest
`nook push` SHALL proceed with a new empty manifest and no `If-Match` precondition only when the manifest fetch returns HTTP 404 (manifest object does not exist yet).

#### Scenario: First push to a fresh vault
- **WHEN** `nook push` runs against a server that returns 404 for the manifest object because no manifest has ever been pushed
- **THEN** the command proceeds with a new empty manifest and uploads it without an `If-Match` header

### Requirement: `ls`/`tree`/`pull` manifest fetch error propagation is unaffected
The manifest-fetch path used by `ls`, `tree`, and `pull` SHALL continue to propagate all fetch/decrypt errors to the caller unchanged; the fail-closed fix to `cmd_push` SHALL NOT alter this existing behavior.

#### Scenario: `nook ls` against a corrupted manifest still reports an error
- **WHEN** `nook ls` fetches a manifest that fails AEAD decryption
- **THEN** the command reports the fetch/decrypt error to the user exactly as it did before this change, without falling back to an empty listing
