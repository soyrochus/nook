# server-containerization Specification

## Purpose
TBD - created by archiving change spec-003-implementation-fixes. Update Purpose after archive.
## Requirements
### Requirement: A Dockerfile builds a runnable `nookd` container image
The repository SHALL include a `Dockerfile` that builds a container image running `nookd`, using a multi-stage build (a builder stage compiling the Rust workspace and a minimal runtime stage containing only the built `nookd` binary and its runtime dependencies).

#### Scenario: Building the image succeeds
- **WHEN** `docker build` or `podman build` is run against the repository using the provided `Dockerfile`
- **THEN** the build completes successfully and produces an image capable of running `nookd`

### Requirement: Server data directory MUST be an externally mountable volume
The container image SHALL declare its data directory (containing the object store and `meta.sqlite`) as a `VOLUME` or otherwise clearly documented mount point, such that data persists across container removal/recreation when the operator supplies a bind mount or named volume under Docker or Podman.

#### Scenario: Data survives container recreation with a named volume
- **WHEN** an operator runs the image with a named volume mounted at the declared data directory, pushes objects to `nookd`, then removes and recreates the container using the same named volume
- **THEN** the previously pushed objects and metadata are still present and served correctly after recreation

#### Scenario: Data survives container recreation with a bind mount
- **WHEN** an operator runs the image with a host directory bind-mounted at the declared data directory under either Docker or Podman, pushes objects to `nookd`, then removes and recreates the container using the same bind mount
- **THEN** the previously pushed objects and metadata are still present and served correctly after recreation

#### Scenario: Data directory is not baked into the image's writable layer
- **WHEN** the container is run without any mount at the declared data directory
- **THEN** the documented behavior (data lost on container removal) makes clear that a mount is required for durability, and no undocumented alternate write location is used for persistent data

