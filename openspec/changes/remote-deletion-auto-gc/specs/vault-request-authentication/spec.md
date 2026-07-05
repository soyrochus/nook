## MODIFIED Requirements

### Requirement: Every object-API request must be signed with the claimed vault's credential
`nookd` SHALL require every `GET`, `HEAD`, `PUT`, and `DELETE` request to the object API, and every request to the namespace listing endpoint, to include a valid HMAC-SHA256 signature computed with the credential of the `vault_id` named in the request path, and SHALL reject any request lacking one.

#### Scenario: Correctly signed request is accepted
- **WHEN** a client sends a `PUT` request with a valid `X-Nook-Timestamp` and an `X-Nook-Signature` computed as `HMAC-SHA256(vault_credential, method + path + timestamp + sha256(body))` matching the credential on file for the named `vault_id`
- **THEN** the request proceeds to normal object-API handling (CAS, storage, etc.)

#### Scenario: Missing signature headers are rejected
- **WHEN** a request to the object API omits `X-Nook-Timestamp` or `X-Nook-Signature`
- **THEN** the server responds `401 Unauthorized` without performing any read or write

#### Scenario: Unsigned deletion or listing is rejected
- **WHEN** a `DELETE` request for an object, or a `GET` request to the namespace listing endpoint, lacks a valid signature for the claimed `vault_id`
- **THEN** the server responds `401 Unauthorized` without deleting anything or disclosing any object metadata
