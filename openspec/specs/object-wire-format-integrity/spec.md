# object-wire-format-integrity Specification

## Purpose
TBD - created by archiving change spec-003-implementation-fixes. Update Purpose after archive.
## Requirements
### Requirement: On-wire encrypted object envelope is documented
The on-wire framing produced by `serialize_encrypted_object` (`[u16 len][wrapped_key][u32 chunk_count][chunks...]`, with the wrapped DEK additionally embedded inside the encrypted chunk-0 header) SHALL be documented as the authoritative object format, replacing the circular description in `specs/SPEC-001-Base Implementation.md` §17.

#### Scenario: Spec matches implementation
- **WHEN** a reader consults `specs/SPEC-001-Base Implementation.md` §17 for the on-wire object format
- **THEN** the documented envelope layout matches exactly what `serialize_encrypted_object`/`deserialize_encrypted_object` produce and consume

### Requirement: Duplicate wrapped-DEK copies MUST be cross-checked at decrypt time
`decrypt_object` SHALL, after decrypting the chunk-0 header, compare the header's embedded wrapped DEK against the outer envelope's wrapped-key bytes and SHALL fail the decryption if they differ.

#### Scenario: Matching wrapped-key copies decrypt normally
- **WHEN** an object's outer envelope wrapped-key bytes match the wrapped DEK embedded in the decrypted chunk-0 header
- **THEN** `decrypt_object` proceeds and returns the decrypted plaintext as before

#### Scenario: Tampered or diverging wrapped-key copies are rejected
- **WHEN** an object is crafted (or corrupted) such that the outer envelope's wrapped-key bytes differ from the wrapped DEK embedded in the decrypted chunk-0 header
- **THEN** `decrypt_object` fails closed with a decrypt error instead of silently using either copy

