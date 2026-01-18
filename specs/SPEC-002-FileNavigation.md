Below is a **second, additive specification** whose sole purpose is to **correct, constrain, and extend the original codebase generated from your first `specs/SPEC-001-Base Implementation.md`**, without rewriting the whole system or weakening the security model.

This is written explicitly as a **delta / corrective spec** that you can feed to Codex or GitHub Copilot **together with the original specs/SPEC-001-Base Implementation.md**, telling the agent: *“apply these changes to the existing codebase.”*

I will reference the original specs/SPEC-001-Base Implementation.md explicitly once, as requested.


---

# SPEC-Δ — NOOK CLIENT-SIDE DISCOVERY & USABILITY CORRECTIONS

**Additive specification to be applied on top of the original specs/SPEC-001-Base Implementation.md**

---

## 0. Scope of this specification

This document **does not redefine Nook’s cryptographic or server architecture**.

Its purpose is to:

* Correct a usability regression introduced by an overly literal interpretation of “no server metadata”.
* Explicitly define **client-side discovery semantics** (`ls`, `tree`, path resolution).
* Instruct how to **modify the existing client codebase** so users can browse and selectively pull content safely.

All security guarantees from the original spec remain intact.

---

## 1. Problem statement (why this delta exists)

The original specs/SPEC-001-Base Implementation.md correctly enforced:

* No server-side metadata
* No server-side listing
* Fully amorphous encrypted storage

However, the generated client code implicitly assumed:

> “If the server cannot list data, the user cannot browse data.”

This is **incorrect**.

The missing concept was that:

> **The encrypted manifest is the filesystem index.**

This delta spec makes that explicit and operational.

---

## 2. Mandatory client-side discovery model (new invariant)

Add the following invariant to the client implementation:

> The client MUST treat the decrypted manifest as the authoritative and complete filesystem index.

Consequences:

* Discovery (`ls`, `tree`) is **always local**
* Discovery requires **decrypting the manifest**
* The server is never queried for structure
* The absence of a server `ls` is irrelevant to usability

---

## 3. Required new client commands (must be implemented)

The following commands MUST exist in the client:

```
nook ls [<path>]
nook tree [<path>]
```

### Semantics

* Both commands:

  * Download the current manifest head
  * Decrypt it locally
  * Render structure from the manifest
* `<path>` is resolved **only against the manifest**
* No server enumeration is permitted

### Explicit prohibition

The client MUST NOT:

* Attempt to enumerate object IDs on the server
* Infer structure from object storage
* Cache any plaintext metadata outside encrypted storage

---

## 4. Required change to existing `pull` behavior

### Current (incorrect) implicit behavior

The generated client assumes:

* `pull <path>` requires prior user knowledge
* No discovery phase exists

### Correct behavior (must be implemented)

`nook pull <path>` MUST:

1. Download and decrypt the manifest
2. Resolve `<path>` against the manifest tree
3. Identify referenced content objects
4. Fetch only those objects
5. Materialize them locally

If `<path>` does not exist in the manifest:

* Fail with a clear error
* Do not query the server further

---

## 5. Required behavior for `pull` with no arguments

```
nook pull
```

MUST mean:

> “Materialize the entire vault filesystem locally.”

Implementation steps:

* Decrypt manifest
* Walk full tree
* Pull all referenced content objects

This mirrors the behavior of mounting an encrypted container.

---

## 6. Manifest handling requirements (clarification)

The client MUST:

* Cache the decrypted manifest in memory for the duration of a command
* Treat the manifest as immutable unless performing `push`
* Never write plaintext manifest data to disk unless explicitly requested (debug mode)

Optional (recommended):

* Keep a short-lived encrypted cache on disk to speed up repeated commands

---

## 7. UX expectations (non-negotiable)

From a user perspective:

* Running `nook ls` on a new machine MUST show the vault contents
* Users MUST NOT need to remember full paths blindly
* Users MUST be able to:

  * browse
  * explore
  * selectively pull files

Any implementation that fails this is considered **incorrect**, even if cryptographically sound.

---

## 8. Changes required in the existing codebase (concrete)

### Client changes

You MUST add:

* A `manifest` module that:

  * fetches the head object
  * decrypts it
  * exposes an in-memory tree API

* Path resolution utilities:

  * normalize paths
  * walk manifest nodes
  * return object references

* Output renderers:

  * `ls`: single directory
  * `tree`: recursive view

### No server changes required

The server implementation generated from the original specs/SPEC-001-Base Implementation.md remains valid and unchanged.

---

## 9. Explicit guidance to the code-generation agent

Add this instruction verbatim to the agent prompt:

> The absence of server-side metadata does NOT imply the absence of user-visible structure.
>
> The encrypted manifest MUST be treated as a client-side filesystem index.
>
> Implement `ls`, `tree`, and path resolution by decrypting and interpreting the manifest locally.
>
> Do NOT weaken encryption, add metadata endpoints, or query the server for discovery.

This sentence alone prevents the original mistake.

---

## 10. Non-goals of this delta spec

This spec does NOT:

* Introduce plaintext metadata
* Add server listing APIs
* Change encryption primitives
* Change the object store protocol
* Reduce threat resistance

It only restores **expected usability** under the original security model.

---

## 11. Acceptance criteria (for this delta)

After applying this spec:

* `nook ls` works on any device with the vault key
* `nook pull source/secret.rs` works without prior manual knowledge
* TLS MITM still learns nothing about structure
* The server still has zero semantic knowledge

Failure to meet any of these means the delta was not applied correctly.

---

## 12. Final positioning statement

This second spec does not weaken Nook.
It **completes it**.

The original specs/SPEC-001-Base Implementation.md defined *what must not exist*.
This delta defines *what must exist on the client* so the system is usable.

---

## 13. Implementation status (updated 2026-01-18)

All requirements from this spec have been implemented:

### Completed

* ✅ `nook ls [<path>]` — Lists directory contents from decrypted manifest
* ✅ `nook tree [<path>]` — Recursive tree view with proper formatting
* ✅ `nook pull [<path>]` — Selective pulling of files/directories
* ✅ `nook pull` — Full vault materialization
* ✅ Path resolution against manifest tree
* ✅ Manifest merge on push (additive semantics, preserves existing files)

### Behavior notes

* **Push is additive**: Pushing new files merges them into the existing manifest. Files with the same path are updated; other files are preserved.
* **Pull respects structure**: Directory hierarchies are correctly recreated locally.
* **Discovery is local-only**: All `ls`, `tree`, and path resolution operates on the decrypted manifest. The server is never queried for structure.

