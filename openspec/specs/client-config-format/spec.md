# client-config-format Specification

## Purpose
TBD - created by archiving change spec-003-implementation-fixes. Update Purpose after archive.
## Requirements
### Requirement: Client configuration is stored as TOML
The client SHALL persist its configuration (`server URL`, `root path`, key-storage reference) in TOML format rather than JSON.

#### Scenario: `nook init` produces a TOML config
- **WHEN** `nook init` runs successfully
- **THEN** the resulting config file is valid TOML, parseable by a standard TOML parser

### Requirement: Vault key field is an opaque reference, never raw key material
Within the TOML config, the field representing the Vault Master Key SHALL contain only a keychain reference or an encrypted blob (per the `client-key-storage` capability), never the raw key.

#### Scenario: Inspecting the vault key field
- **WHEN** a user opens the TOML config file after `nook init`
- **THEN** the vault key field contains either a keychain reference string or an encrypted blob (ciphertext/salt/nonce), and in neither case can the raw VMK be recovered directly from that field

### Requirement: Existing JSON configs are not silently migrated
The client SHALL NOT attempt to automatically read or migrate a pre-existing `config.json` written by a prior version. Loading a non-TOML config SHALL produce a clear error directing the user to re-run `nook init`.

#### Scenario: Old JSON config present
- **WHEN** a user who previously ran an older version of `nook init` (producing `config.json`) runs any `nook` command after upgrading
- **THEN** the client reports a clear error indicating the config format is unreadable and instructs the user to re-run `nook init`, rather than silently failing or misinterpreting the file

