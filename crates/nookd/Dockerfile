# Build and run from the repository root, e.g.:
#   podman build -f crates/nookd/Dockerfile -t nookd .
#   docker build -f crates/nookd/Dockerfile -t nookd .

FROM rust:1-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release -p nookd

FROM debian:bookworm-slim AS runtime
# Fixed, predictable UID/GID (rather than an auto-assigned system UID) so
# bind-mount ownership can be documented reliably: `chown 10001:10001 <dir>`.
RUN groupadd --system --gid 10001 nookd \
    && useradd --system --uid 10001 --gid 10001 --create-home --home-dir /data --shell /usr/sbin/nologin nookd \
    && chown -R nookd:nookd /data
COPY --from=builder /build/target/release/nookd /usr/local/bin/nookd

# /data holds the object store and meta.sqlite. It MUST be backed by a
# named volume or bind mount at runtime (see README) — anything written
# here that isn't on a mount is lost when the container is removed.
ENV NOOK_DATA_DIR=/data
VOLUME ["/data"]

USER nookd
WORKDIR /data
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/nookd"]
CMD ["serve", "--listen", "0.0.0.0:8080"]

# To create/manage vaults against this same mounted volume, run the vault
# CLI as a one-off container overriding the default command, e.g.:
#   podman run --rm -v nookd-data:/data --entrypoint /usr/local/bin/nookd nookd \
#     vault create --storage /data
