# vault-request-authentication Specification

## Purpose
TBD - created by archiving change spec-004-multi-vault-access-control. Update Purpose after archive.
## Requirements
### Requirement: Every object-API request must be signed with the claimed vault's credential
`nookd` SHALL require every `GET`, `HEAD`, and `PUT` request to the object API to include a valid HMAC-SHA256 signature computed with the credential of the `vault_id` named in the request path, and SHALL reject any request lacking one.

#### Scenario: Correctly signed request is accepted
- **WHEN** a client sends a `PUT` request with a valid `X-Nook-Timestamp` and an `X-Nook-Signature` computed as `HMAC-SHA256(vault_credential, method + path + timestamp + sha256(body))` matching the credential on file for the named `vault_id`
- **THEN** the request proceeds to normal object-API handling (CAS, storage, etc.)

#### Scenario: Missing signature headers are rejected
- **WHEN** a request to the object API omits `X-Nook-Timestamp` or `X-Nook-Signature`
- **THEN** the server responds `401 Unauthorized` without performing any read or write

### Requirement: The vault credential is never transmitted at request time
The signing scheme SHALL NOT require the raw vault credential to appear in any request or response; only a value derived from it (the HMAC signature) SHALL be transmitted.

#### Scenario: Credential absent from request contents
- **WHEN** any request is sent to the object API
- **THEN** the raw `vault_credential` value does not appear anywhere in the request line, headers, or body — only `X-Nook-Signature`, which does not allow recovery of the credential

### Requirement: Signatures are time-bounded to limit replay exposure
`nookd` SHALL reject requests whose `X-Nook-Timestamp` differs from the server's current time by more than 300 seconds.

#### Scenario: Stale signed request is rejected
- **WHEN** a request is sent with an otherwise-valid signature but a timestamp more than 300 seconds in the past or future relative to the server's clock
- **THEN** the server responds `401 Unauthorized`

#### Scenario: Fresh signed request is accepted
- **WHEN** a request is sent with a valid signature and a timestamp within 300 seconds of the server's current time
- **THEN** the timestamp check does not block the request

### Requirement: Authentication failures are indistinguishable regardless of cause
`nookd` SHALL respond identically (same status code and body) whether the presented `vault_id` does not exist, has been revoked, or the signature/timestamp is invalid, so that a client cannot determine which case occurred.

#### Scenario: Nonexistent vault produces the same response as a bad signature
- **WHEN** a request names a `vault_id` that was never created, versus a separate request naming a real `vault_id` but with an incorrect signature
- **THEN** both requests receive the same `401 Unauthorized` response, with no observable difference that would let a client distinguish "vault does not exist" from "vault exists but credential is wrong"

#### Scenario: Revoked vault produces the same response as a bad signature
- **WHEN** a request is correctly signed for a `vault_id` that has since been revoked
- **THEN** the response is the same `401 Unauthorized` used for nonexistent vaults and invalid signatures

### Requirement: Signature comparison is constant-time
`nookd` SHALL compare the computed and presented signatures using a constant-time equality check.

#### Scenario: Signature verification does not leak timing information
- **WHEN** the server verifies a presented signature against the expected value
- **THEN** the comparison is performed in constant time regardless of how many leading bytes match

