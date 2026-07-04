# Security

Nook is an end-to-end encrypted (E2EE) file vault. This document summarizes
the security guarantees described in detail in
[`specs/SPEC-001-Base Implementation.md`](specs/SPEC-001-Base%20Implementation.md)
§19, for readers who want the short version without reading the full spec.

## Threat model

Nook is designed to behave correctly even in fully untrusted network and
server environments, including TLS-intercepting firewalls, corporate MITM
proxies, hostile networks, and a fully compromised server. The server is
treated as a semantic null: it stores and serves opaque ciphertext blobs and
is never trusted with any information about file contents, filenames,
directory structure, or paths. All meaning exists exclusively on the client.

## Guaranteed

* **Confidentiality under TLS MITM.** Even if the transport is intercepted
  or absent, object payloads remain AEAD ciphertext; nothing readable is
  exposed to a network observer.
* **No readable metadata.** Filenames, directory structure, and file sizes
  are never visible to the server or on the wire outside of encrypted
  payloads.
* **Server compromise yields only ciphertext.** Full read access to the
  server's disk (object store and `meta.sqlite`) reveals only random-looking
  object IDs and AEAD ciphertext — no plaintext, filenames, or structure.
* **Tampering detected and rejected.** All decrypt failures are fatal
  (fail-closed): a corrupted, truncated, or tampered object — including a
  manifest — is rejected outright rather than partially trusted or silently
  replaced. See the manifest-push-safety fix in
  [`specs/SPEC-003-implementation-fixes.md`](specs/SPEC-003-implementation-fixes.md)
  for a concrete case this rules out (a client no longer fabricates a
  replacement manifest when it cannot fetch or decrypt the existing one).

## Not guaranteed

* **Traffic volume concealment.** The size and timing of requests are
  visible to a network observer.
* **Timing concealment.** Nook does not attempt to defend against timing
  side channels.

## Reporting a vulnerability

If you believe you've found a security issue in Nook, please open an issue
in this repository describing the problem. Since this project does not yet
have a dedicated security contact channel, avoid including exploit details
or sensitive data in the initial report — a maintainer will follow up to
establish a private channel if needed.
