# multi-tenant-quota Specification

## Purpose
TBD - created by archiving change spec-004-multi-vault-access-control. Update Purpose after archive.
## Requirements
### Requirement: Storage quota is accounted per vault
`nookd` SHALL maintain a running total of bytes stored per `vault_id`, summed across every namespace within that vault, and SHALL check this total against that vault's configured quota (or the server default, if the vault has none) on every `PUT`.

#### Scenario: Quota is shared across a vault's namespaces
- **WHEN** a vault contains multiple namespaces and objects are written to more than one of them
- **THEN** the vault's `bytes_used` reflects the sum of object sizes across all of its namespaces combined, not tracked separately per namespace

#### Scenario: One vault's usage does not affect another vault's quota
- **WHEN** vault A is at or near its quota limit and vault B has ample remaining quota
- **THEN** writes to vault B are unaffected by vault A's usage, and vice versa

### Requirement: Uploads exceeding a vault's quota are rejected without partial writes
`nookd` SHALL reject a `PUT` that would cause a vault's total stored bytes to exceed its quota with `507 Insufficient Storage`, without persisting the object and without leaving a temporary file behind.

#### Scenario: Oversized upload under a vault's quota is rejected
- **WHEN** a `PUT` request's object size, added to that vault's current total stored bytes, would exceed the vault's quota
- **THEN** the server responds `507 Insufficient Storage`, the object is not stored, and no temporary file remains afterward

### Requirement: Per-vault quota is reconciled from persisted state on startup
`nookd` SHALL, on startup, compute each vault's `bytes_used` from the sum of its stored objects' sizes, rather than trusting only an in-memory counter across restarts.

#### Scenario: Restarting nookd preserves accurate quota accounting
- **WHEN** `nookd` is restarted after previously storing objects across multiple vaults
- **THEN** each vault's in-memory running total is reinitialized to the sum of that vault's currently stored object sizes before serving any request

### Requirement: No per-namespace quota sub-limits are enforced
`nookd` SHALL NOT enforce any quota limit scoped to an individual namespace within a vault; quota enforcement is per-vault only.

#### Scenario: A single namespace may consume a vault's entire quota
- **WHEN** all writes within a vault happen to target a single namespace
- **THEN** that namespace may consume up to the vault's full quota, with no separate per-namespace limit preventing it

