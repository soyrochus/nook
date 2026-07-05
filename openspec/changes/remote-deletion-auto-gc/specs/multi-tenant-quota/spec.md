## ADDED Requirements

### Requirement: Deletions immediately release quota
`nookd` SHALL decrement the owning vault's `bytes_used` by the deleted object's recorded size within the same transaction that removes the object's metadata row, so freed space is available to the very next `PUT` against that vault.

#### Scenario: Quota freed by deletion is immediately writable
- **WHEN** a vault is at its quota limit and an object of size N is deleted from one of its namespaces
- **THEN** an immediately following `PUT` of size ≤ N to that vault succeeds

#### Scenario: Startup reconciliation remains correct after deletions
- **WHEN** `nookd` restarts after objects have been deleted from a vault
- **THEN** the vault's reconciled `bytes_used` equals the sum of its currently stored objects' sizes, with deleted objects contributing nothing
