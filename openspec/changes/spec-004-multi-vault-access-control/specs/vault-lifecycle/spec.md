## ADDED Requirements

### Requirement: Vault creation is an admin-only, non-network action
`nookd` SHALL provide a local CLI subcommand, `nookd vault create`, that generates a new vault and SHALL NOT expose vault creation via any network-reachable HTTP endpoint.

#### Scenario: Operator creates a vault
- **WHEN** an operator with local access to the `nookd` host runs `nookd vault create`
- **THEN** a new vault is created with a randomly generated `vault_id` and `vault_credential`, both printed to stdout

#### Scenario: No network path to create a vault
- **WHEN** any HTTP request is sent to `nookd`'s object API attempting to create or provision a new vault
- **THEN** no such request is possible — vault creation is not reachable via any HTTP endpoint

### Requirement: Vault credentials are displayed exactly once
`nookd` SHALL print a newly created vault's credential to stdout at creation time and SHALL NOT provide any subsequent way to retrieve that credential.

#### Scenario: Credential is not retrievable later
- **WHEN** an operator runs `nookd vault list` or any other subcommand after a vault has been created
- **THEN** the vault's credential is never displayed again; only non-secret fields (`vault_id`, `created_at`, `quota_bytes`, `bytes_used`, namespace count) are shown

### Requirement: Vault listing shows operational metadata without secrets
`nookd vault list` SHALL display each vault's `vault_id`, creation time, quota, bytes used, and namespace count, and SHALL NOT display any vault's credential.

#### Scenario: Operator inspects vault usage
- **WHEN** an operator runs `nookd vault list`
- **THEN** the output includes each vault's `vault_id`, `created_at`, `quota_bytes`, `bytes_used`, and namespace count, with no credential material present

### Requirement: Vault revocation blocks access without deleting data
`nookd vault revoke <vault_id>` SHALL invalidate that vault's credential such that all subsequent requests against it are rejected, and SHALL NOT delete any of that vault's stored objects.

#### Scenario: Revoked vault rejects further requests
- **WHEN** a vault has been revoked via `nookd vault revoke <vault_id>`
- **THEN** any subsequent request (`GET`, `HEAD`, or `PUT`) signed with that vault's former credential is rejected with `401 Unauthorized`

#### Scenario: Revocation preserves stored data
- **WHEN** a vault is revoked
- **THEN** the objects previously stored under that vault remain on disk and in `meta.sqlite`, unaffected by the revocation

### Requirement: Per-vault quota is configurable at creation, defaulting to the server default
`nookd vault create` SHALL accept an optional `--quota-bytes` override; when omitted, the vault SHALL inherit the server's default quota configuration.

#### Scenario: Vault created with an explicit quota
- **WHEN** an operator runs `nookd vault create --quota-bytes 1000000`
- **THEN** the created vault's quota is 1,000,000 bytes, independent of the server's default quota setting

#### Scenario: Vault created without an explicit quota
- **WHEN** an operator runs `nookd vault create` with no `--quota-bytes` flag
- **THEN** the created vault inherits the server's configured default quota (or unlimited, if the server has none configured)
