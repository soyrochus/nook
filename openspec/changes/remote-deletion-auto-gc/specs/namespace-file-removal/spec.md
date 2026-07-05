## ADDED Requirements

### Requirement: `nook rm` removes a file or directory subtree from the manifest
`nook rm <path>` SHALL fetch the current manifest (with its etag), remove the file node or directory subtree named by `<path>`, and upload the updated manifest using the existing CAS (`If-Match`) flow. It SHALL error without any server write if `<path>` does not exist in the manifest, and SHALL follow the same fail-closed manifest-fetch rules as `nook push` (only HTTP 404 is a tolerable fetch outcome, and for `rm` even 404 is an error since there is nothing to remove).

#### Scenario: Removing a file
- **WHEN** `nook rm docs/spec.md` runs and the manifest contains that file
- **THEN** the new manifest no longer contains the node, the upload carries `If-Match` with the fetched etag, and a subsequent `nook ls docs/` does not list `spec.md`

#### Scenario: Removing a directory removes its entire subtree
- **WHEN** `nook rm docs/` runs and `docs/` contains nested files and subdirectories
- **THEN** the directory node and all descendant nodes are removed from the manifest in one CAS-guarded manifest write

#### Scenario: Removing a nonexistent path fails without server writes
- **WHEN** `nook rm no/such/path` runs
- **THEN** the command exits with an error and no `PUT` or `DELETE` is issued

### Requirement: A path argument is mandatory
`nook rm` SHALL reject invocation without a path argument; emptying an entire namespace requires explicitly naming its entries.

#### Scenario: Bare `nook rm` is rejected
- **WHEN** `nook rm` runs with no path argument
- **THEN** the command exits with a usage error and performs no network requests

### Requirement: `rm` never modifies local files
`nook rm` SHALL NOT create, modify, or delete any file under the configured local root; it operates on the remote manifest and remote objects only.

#### Scenario: Local copy survives remote removal
- **WHEN** `nook rm README.md` succeeds while `README.md` exists in the local root
- **THEN** the local `README.md` is untouched

### Requirement: Removal triggers the automatic sweep
A successful `nook rm` manifest swap SHALL run the same automatic garbage-collection sweep as `nook push`, so the removed nodes' content objects are deleted from the server in the same invocation (subject to the sweep's safety rules).

#### Scenario: Removed file's content object is reclaimed
- **WHEN** `nook rm big.bin` succeeds and the sweep completes without errors
- **THEN** the content object previously referenced by `big.bin` is no longer stored on the server and the vault's `bytes_used` has decreased accordingly
