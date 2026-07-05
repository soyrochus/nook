# Security

Nook is an end-to-end encrypted (E2EE) file vault. This document summarizes
the security guarantees described in detail in
[`specs/SPEC-001-Base Implementation.md`](specs/SPEC-001-Base%20Implementation.md)
§19, for readers who want the short version without reading the full spec.

Naming note: the product is Nook, the crates.io package is `nook-vault`, and
the installed executables are `nook` for the client and `nookd` for the server.

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
* **Server disk compromise never exposes file content, names, or structure.**
  Full read access to the server's disk (object store and `meta.sqlite`)
  reveals only random-looking object IDs and AEAD ciphertext for file/manifest
  data — no plaintext, filenames, or directory structure. (As of
  [`specs/SPEC-004-multi-vault-user-concurrecny-changes.md`](specs/SPEC-004-multi-vault-user-concurrecny-changes.md),
  the same disk also holds vault access credentials — see "Not guaranteed"
  below for what that does change.)
* **Tampering detected and rejected.** All decrypt failures are fatal
  (fail-closed): a corrupted, truncated, or tampered object — including a
  manifest — is rejected outright rather than partially trusted or silently
  replaced. See the manifest-push-safety fix in
  [`specs/SPEC-003-implementation-fixes.md`](specs/SPEC-003-implementation-fixes.md)
  for a concrete case this rules out (a client no longer fabricates a
  replacement manifest when it cannot fetch or decrypt the existing one).
* **Reads and writes require a valid vault credential.** Every request is
  HMAC-signed with the target vault's credential, which is never transmitted
  on the wire; requests for a nonexistent vault, a revoked vault, or a valid
  vault with an invalid signature all receive the identical `401`, so vault
  IDs cannot be enumerated via a response oracle. See
  [`specs/SPEC-004-multi-vault-user-concurrecny-changes.md`](specs/SPEC-004-multi-vault-user-concurrecny-changes.md)
  §4/§12.

## Not guaranteed

* **Traffic volume concealment.** The size and timing of requests are
  visible to a network observer.
* **Timing concealment.** Nook does not attempt to defend against timing
  side channels.
* **Namespace-level structure within a vault.** The number of namespaces in
  a vault, their relative sizes, and their write frequency are visible
  server-side metadata (an extension of the traffic-volume/timing non-goals
  above to namespace structure specifically — SPEC-004 §12).
* **Isolation between namespaces sharing one vault credential.** Namespace
  boundaries are cryptographic only, not access-controlled: anyone holding a
  vault's credential can read or write raw ciphertext for *any* namespace in
  that vault, whether or not they hold that namespace's key — they simply
  can't decrypt data for namespaces whose key they don't have. Vault
  credential compromise means storage-level forgery (read/write/delete
  ciphertext, exhaust quota) across every namespace in that vault, not
  decryption of any of them. Since SPEC-005 added the `DELETE` verb and the
  namespace object-listing endpoint (both HMAC-authenticated like every
  other request), a credential holder can also *enumerate* a namespace's
  object IDs, sizes, and last-write timestamps and *destroy* its ciphertext
  outright. This discloses nothing the server operator couldn't already see
  on disk, and destruction was already possible by overwriting objects with
  garbage — but it makes the "credential = full storage grant" trade-off
  concrete: a leaked credential now permits convenient, targeted deletion of
  every namespace in the vault. Encryption never protects *availability*;
  keep independent backups of anything you cannot afford to lose.
* **`nookd`'s vault-credential store is a genuine secret store, not
  leak-safe ciphertext.** Unlike the rest of `nookd`'s storage, the `vaults`
  table holds credentials in raw (not hashed) form, because HMAC
  verification requires the actual key. A leaked `meta.sqlite` lets an
  attacker forge valid requests against those vaults; it still cannot
  decrypt any namespace's content. Operators should protect `meta.sqlite`
  with the same care as any credential store.
* **Vault credential bootstrap relies on an out-of-band trust channel** —
  the operator handing a newly created vault's ID/credential to its first
  user, and that user repeating the same handoff to onboard collaborators —
  exactly the same trust assumption SPEC-001 §9 already requires for
  namespace-key distribution, applied to a second secret. Nook does not
  define or automate this channel.

## Reporting a vulnerability

If you believe you've found a security issue in Nook, please open an issue
in this repository describing the problem. Since this project does not yet
have a dedicated security contact channel, avoid including exploit details
or sensitive data in the initial report — a maintainer will follow up to
establish a private channel if needed.
