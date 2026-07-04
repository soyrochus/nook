## ADDED Requirements

### Requirement: Namespaces require no server-side registration
`nookd` SHALL accept reads and writes to any `namespace_id` under a vault the caller is authenticated for, without any prior namespace-creation or registration step.

#### Scenario: First write to a new namespace succeeds implicitly
- **WHEN** a validly signed `PUT` request addresses a `namespace_id` that has never been used before under that vault
- **THEN** the write succeeds and that namespace now exists implicitly, with no separate registration call having been made

### Requirement: `nook init` generates a fresh namespace identity
`nook init` SHALL, given a vault ID and vault credential, generate a new random `namespace_id` and a new random namespace key, and store all four values (`vault_id`, `vault_credential`, `namespace_id`, `namespace_key`) client-side.

#### Scenario: Fresh init produces a new namespace
- **WHEN** a user runs `nook init --vault-id <id> --vault-credential <cred>`
- **THEN** a new random `namespace_id` and namespace key are generated and stored in the client configuration, distinct from any other namespace previously created by any other client

### Requirement: Namespace identity can be exported and imported
`nook` SHALL provide a way to export the current namespace's identity (`namespace_id` and namespace key) as a portable bundle, and a way to initialize a client from an imported bundle instead of generating a new namespace.

#### Scenario: Exporting a namespace produces a portable bundle
- **WHEN** a user runs the namespace export command on a client with an existing namespace
- **THEN** a bundle encoding that namespace's `namespace_id` and namespace key is produced, suitable for transfer over a channel the user chooses

#### Scenario: Importing a namespace bundle joins that namespace
- **WHEN** a second user runs `nook init` with a valid vault ID and vault credential and supplies a previously exported bundle
- **THEN** their client adopts the same `namespace_id` and namespace key, and can subsequently read and write everything in that namespace exactly as the exporting user can

### Requirement: Namespace identifiers are opaque and non-human-readable
Namespace IDs SHALL be randomly generated opaque values and SHALL NOT be derived from or encode any human-meaningful name.

#### Scenario: Namespace ID carries no naming information
- **WHEN** a namespace is created by `nook init`
- **THEN** its `namespace_id` is a random value with no relationship to any user-chosen or human-readable label; any friendly name the user wants to associate with it is stored only in local client state and never transmitted to the server
