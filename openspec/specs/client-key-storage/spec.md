# client-key-storage Specification

## Purpose
TBD - created by archiving change spec-003-implementation-fixes. Update Purpose after archive.
## Requirements
### Requirement: Vault Master Key MUST NOT be stored as recoverable plaintext or base64
The client SHALL NOT write the Vault Master Key (VMK) to disk as plaintext or as a base64 encoding of the raw key. `nook init` SHALL store the VMK either in the OS keychain or, when unavailable, in an encrypted-at-rest local file.

#### Scenario: Config file contains no recoverable key material
- **WHEN** `nook init` completes successfully
- **THEN** inspecting the on-disk config file reveals no plaintext or base64-decodable copy of the VMK

### Requirement: OS keychain is the default VMK storage backend
`nook init` SHALL attempt to store the VMK in the OS keychain (e.g. via the `keyring` crate) by default.

#### Scenario: Keychain available on the host platform
- **WHEN** `nook init` runs on a platform with a working OS keychain/credential store
- **THEN** the VMK is written to the keychain and the config file records a keychain-reference (no secret material) for later retrieval

### Requirement: Encrypted local file is the fallback when no keychain is available
When the OS keychain is unavailable (headless environment, CI, unsupported platform), `nook init` SHALL fall back to deriving a wrapping key from a user-supplied passphrase via Argon2id and encrypting the VMK with XChaCha20-Poly1305 before writing it to disk.

#### Scenario: Headless environment without a keychain
- **WHEN** `nook init` runs on a platform where the keychain backend is unavailable
- **THEN** the user is prompted for a passphrase, the VMK is encrypted with a passphrase-derived (Argon2id) XChaCha20-Poly1305 key, and only the ciphertext, salt, and nonce are written to disk

### Requirement: Config records which key-storage mode is active
The config SHALL record which storage mode (keychain or encrypted local file) is in use so `load_config` can retrieve the VMK correctly on subsequent invocations.

#### Scenario: Loading config after keychain-backed init
- **WHEN** `nook status`, `push`, or `pull` runs after a keychain-backed `nook init`
- **THEN** the client retrieves the VMK from the OS keychain using the reference recorded in the config, without prompting for a passphrase

#### Scenario: Loading config after passphrase-backed init
- **WHEN** `nook status`, `push`, or `pull` runs after a passphrase-fallback `nook init`
- **THEN** the client prompts for the passphrase, re-derives the wrapping key via Argon2id, and decrypts the VMK before proceeding

