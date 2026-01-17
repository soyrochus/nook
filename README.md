# Nook

Amorphous, end-to-end encrypted push/pull file vault. The server stores only opaque blobs; all
filesystem meaning and encryption live on the client.

## Requirements

- Rust (stable) + Cargo

## Build / install

From the repo root:

```bash
cargo build --release
```

Binaries will be at:

- `target/release/nook` (CLI client)
- `target/release/nookd` (server daemon)

Optional install to Cargo bin dir:

```bash
cargo install --path crates/nook
cargo install --path crates/nookd
```

## Run the server

```bash
./target/release/nookd --listen 0.0.0.0:8080 --storage ./storage
```

The server stores only encrypted blobs under the storage directory:

```
storage/
  objects/
  temp/
  meta.sqlite
```

## Initialize a vault (client)

```bash
./target/release/nook init --server http://127.0.0.1:8080 --root /path/to/vault
```

This generates a vault key and writes client config to the platform config directory
(`~/.config/nook/config.json` on Linux). Keep this file secure; you need the same vault key on
other devices.

Set or view the local root later:

```bash
./target/release/nook root --set /path/to/vault
./target/release/nook root
```

## Push / pull

Push uploads an encrypted snapshot of the root (or a subpath) and atomically updates the head:

```bash
./target/release/nook push
./target/release/nook push subdir/inside/root
```

Pull downloads the latest snapshot and materializes it into the local root:

```bash
./target/release/nook pull
```

Note: `pull` currently ignores the optional subpath argument.

## Status / overrides

Check whether the head object exists on the server:

```bash
./target/release/nook status
```

Override the server URL per command:

```bash
./target/release/nook --server http://other-host:8080 status
./target/release/nook --server http://other-host:8080 push
```

## Usage notes

- The server is a semantic null: it stores only ciphertext and object IDs.
- TLS can be used, but confidentiality does not rely on it; TLS MITM does not expose filenames,
  paths, or file contents.
- To use the same vault on multiple devices, copy the `config.json` (or at least the vault key)
  securely, then set the local root on each device.

## Participation

Contributions are welcome: issues, pull requests, critique, and discussion.

This project follows the [FOSS Pluralism Manifesto](./FOSS_PLURALISM_MANIFESTO.md), affirming respect for people, freedom to critique ideas, and space for diverse perspectives.


## License

Copyright (c) 2026, Iwan van der Kleijn
Licensed under the MIT License. See [`LICENSE`](./LICENSE) for details.
