## ADDED Requirements

### Requirement: `specs/` is the canonical location for specification documents
`specs/SPEC-001-Base Implementation.md` §21 SHALL declare `specs/` as the canonical repository location for specification documents, matching current practice, rather than requiring a `docs/` directory.

#### Scenario: Repository layout matches the declared canonical location
- **WHEN** a contributor checks the repository layout against SPEC-001 §21
- **THEN** the specification documents' actual location (`specs/`) matches what §21 declares canonical

### Requirement: A SECURITY.md summarizes the project's security guarantees
The repository SHALL include a `SECURITY.md` summarizing the guarantees documented in `specs/SPEC-001-Base Implementation.md` §19, for external reference.

#### Scenario: External reader looks up security guarantees
- **WHEN** a user or security researcher opens `SECURITY.md` at the repository root
- **THEN** they find a summary of the E2EE guarantees described in SPEC-001 §19

### Requirement: Continuous integration runs build, test, and lint on every push and PR
The repository SHALL include a `.github/workflows/ci.yml` workflow that runs `cargo build`, `cargo test`, and `cargo clippy` across the workspace on every push and pull request.

#### Scenario: CI runs on a clean clone
- **WHEN** a push or pull request is made against the repository
- **THEN** the CI workflow builds, tests, and lints the full workspace and reports pass/fail status

#### Scenario: CI fails on a broken build
- **WHEN** a push or pull request introduces a compile error, failing test, or clippy warning treated as an error
- **THEN** the CI workflow reports a failure
