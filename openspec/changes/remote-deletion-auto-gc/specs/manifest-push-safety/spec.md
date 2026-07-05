## ADDED Requirements

### Requirement: The post-swap sweep phase cannot fail the push
`nook push` SHALL treat the automatic garbage-collection sweep as a strictly post-commit phase: it runs only after the manifest CAS swap has succeeded, and no error occurring in it (listing failure, `DELETE` failure, missing server support) SHALL change the push's exit status from success. All fail-closed behavior of the pre-swap manifest fetch is unchanged by the addition of this phase.

#### Scenario: Sweep error still reports a successful push
- **WHEN** the manifest swap succeeds but a subsequent sweep `DELETE` fails with a network error
- **THEN** `nook push` exits successfully, printing a warning that space reclamation was incomplete

#### Scenario: Pre-swap failures still issue no writes and no deletes
- **WHEN** the manifest fetch at the start of a push fails for any reason other than HTTP 404
- **THEN** the push aborts fatally with no `PUT` and no `DELETE` issued, exactly as before
