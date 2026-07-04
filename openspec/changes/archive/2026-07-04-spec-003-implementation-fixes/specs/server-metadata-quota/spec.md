## ADDED Requirements

### Requirement: Object metadata records creation and update timestamps
`nookd`'s metadata store SHALL record `created_at` and `updated_at` timestamps for every stored object, set on insert and updated on every subsequent write to that object.

#### Scenario: Timestamps populate on object creation
- **WHEN** a new object is stored via `PUT`
- **THEN** its metadata record has `created_at` and `updated_at` set to the time of the write

#### Scenario: Timestamps update on object overwrite
- **WHEN** an existing object is overwritten via a subsequent `PUT`
- **THEN** its metadata record's `updated_at` reflects the time of the new write while `created_at` remains unchanged

### Requirement: Server enforces a configurable storage quota
`nookd` SHALL support a configured storage quota and SHALL reject a `PUT` that would cause total stored bytes to exceed that quota with `507 Insufficient Storage`, without partially writing the rejected object.

#### Scenario: Upload within quota succeeds
- **WHEN** a `PUT` request's object size, added to the current total stored bytes, does not exceed the configured quota
- **THEN** the object is stored normally and the running total is updated

#### Scenario: Upload exceeding quota is rejected without partial writes
- **WHEN** a `PUT` request's object size, added to the current total stored bytes, would exceed the configured quota
- **THEN** the server responds with `507 Insufficient Storage`, does not persist the object, and cleans up any temporary file created during the upload attempt
