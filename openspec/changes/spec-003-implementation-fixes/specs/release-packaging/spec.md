## ADDED Requirements

### Requirement: Release builds trigger only on `v*` tags
The GitHub Actions release workflow SHALL trigger only on pushes of tags matching `v*`, and SHALL NOT run on ordinary branch pushes or pull requests.

#### Scenario: Tag push triggers the release workflow
- **WHEN** a tag matching `v*` (e.g. `v1.0.0`) is pushed to the repository
- **THEN** the release workflow runs

#### Scenario: Branch push or pull request does not trigger the release workflow
- **WHEN** a commit is pushed to a branch, or a pull request is opened/updated, without a `v*` tag
- **THEN** the release workflow does not run

### Requirement: Release workflow builds both `nook` and `nookd` for all target platforms
The release workflow SHALL build both the `nook` and `nookd` binaries for each of: Linux x64, Windows x64, and macOS arm64 (Apple Silicon), and SHALL NOT build for macOS x64 (Intel).

#### Scenario: Successful tag build produces all expected binaries
- **WHEN** the release workflow runs for a pushed `v*` tag
- **THEN** the workflow produces `nook` and `nookd` binaries for Linux x64, Windows x64, and macOS arm64 — six binaries total, with no macOS x64 (Intel) build

### Requirement: Release artifacts are published to the GitHub release
The release workflow SHALL make the built binaries available as downloadable artifacts on the GitHub release corresponding to the pushed tag.

#### Scenario: Binaries attached to the GitHub release
- **WHEN** the release workflow completes successfully for a pushed `v*` tag
- **THEN** the corresponding GitHub release for that tag has the built `nook` and `nookd` binaries for all three target platforms attached and downloadable
