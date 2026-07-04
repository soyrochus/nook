## 1. `nookd` storage layout and routing

- [ ] 1.1 Add a `vaults` table to `meta.sqlite` (`vault_id`, `credential`, `created_at`, `quota_bytes`, `bytes_used`, `revoked`)
- [ ] 1.2 Re-key the `objects` table to the composite primary key `(vault_id, namespace_id, object_id)`, adding `vault_id`/`namespace_id` columns
- [ ] 1.3 Change on-disk object storage from `objects/<object_id>` to `objects/<vault_id>/<namespace_id>/<object_id>`
- [ ] 1.4 Extend `valid_object_id`-style validation to `vault_id` and `namespace_id` (64-char lowercase hex), rejecting malformed path segments before any filesystem/DB access
- [ ] 1.5 Update the Axum router to `/v1/vault/:vault_id/ns/:namespace_id/obj/:object_id` for `GET`/`HEAD`/`PUT`, replacing `/v1/obj/:object_id`
- [ ] 1.6 Add/adjust tests: same `object_id` under two different `(vault_id, namespace_id)` pairs does not collide; malformed vault_id/namespace_id is rejected before touching storage

## 2. Vault request authentication

- [ ] 2.1 Implement HMAC-SHA256 request signing verification: canonical string `method + path + timestamp + sha256(body)`, headers `X-Nook-Timestamp` / `X-Nook-Signature`
- [ ] 2.2 Reject requests with a timestamp more than 300s from server time
- [ ] 2.3 Reject requests with missing/malformed signature headers, unknown vault_id, revoked vault_id, or signature mismatch — all with an identical `401 Unauthorized` response (status, body, and best-effort constant timing)
- [ ] 2.4 Use a constant-time comparison for signature verification
- [ ] 2.5 Wire the auth check in as middleware/guard ahead of all existing GET/HEAD/PUT handler logic
- [ ] 2.6 Add/adjust tests: valid signature accepted; missing/invalid signature rejected; expired timestamp rejected; nonexistent vault and wrong-signature-on-existing-vault produce identical responses; revoked vault rejected

## 3. Vault lifecycle CLI (`nookd`)

- [ ] 3.1 Add `nookd vault create [--quota-bytes N] [--storage <dir>]`: generates random `vault_id` + `vault_credential`, inserts into `vaults`, prints both once
- [ ] 3.2 Add `nookd vault list [--storage <dir>]`: prints `vault_id`, `created_at`, `quota_bytes`, `bytes_used`, namespace count — never credentials
- [ ] 3.3 Add `nookd vault revoke <vault_id> [--storage <dir>]`: marks the vault revoked; retains stored data
- [ ] 3.4 Ensure none of the above are reachable via any HTTP route
- [ ] 3.5 Add/adjust tests: created vault's credential authenticates successfully; revoked vault's former credential is rejected; `vault list` output never contains credential material

## 4. Per-vault quota accounting

- [ ] 4.1 Reconcile each vault's `bytes_used` from `SUM(size) WHERE vault_id = ?` on `nookd` startup
- [ ] 4.2 Check the requesting vault's `quota_bytes` (or server default if unset) against `bytes_used` on `PUT`, rejecting with `507 Insufficient Storage` and cleaning up temp files on rejection (reusing the SPEC-003 mechanism, re-scoped per vault)
- [ ] 4.3 Confirm one vault exceeding its quota does not affect another vault's writes
- [ ] 4.4 Add/adjust tests: quota shared correctly across a vault's namespaces; oversized upload rejected without partial writes; independent vaults' quotas don't interfere; startup reconciliation restores correct totals after restart

## 5. Concurrency (CAS) re-scoping

- [ ] 5.1 Confirm `If-Match`/`ETag` CAS logic operates against the new composite key with no additional server-side logic required
- [ ] 5.2 Confirm the namespace manifest head requires no special-case server code (it's an ordinary object under the new addressing)
- [ ] 5.3 Add/adjust tests: concurrent writers to the same `(vault_id, namespace_id, object_id)` are serialized via CAS as before; writes to the same `object_id` under different namespaces/vaults never contend; concurrent reads always succeed

## 6. `nook` client: vault + namespace identity

- [ ] 6.1 Extend `Config` with `vault_id` and `vault_credential` fields, protected via the same keychain/passphrase-encrypted mechanism as the namespace key (SPEC-003 §2)
- [ ] 6.2 Update `nook init` to require `--vault-id`/`--vault-credential` and generate a fresh random `namespace_id` + namespace key
- [ ] 6.3 Implement request signing in the HTTP client layer (`http_client`/`put_object`/`get_object`/`head_object`/manifest fetch helpers): compute and attach `X-Nook-Timestamp`/`X-Nook-Signature` on every request
- [ ] 6.4 Update all request paths to the new `/v1/vault/{vault_id}/ns/{namespace_id}/obj/{object_id}` shape
- [ ] 6.5 Add/adjust tests: a full init→push→pull round trip succeeds against a locally running `nookd` vault; requests are correctly signed and accepted

## 7. `nook` client: namespace export/import

- [ ] 7.1 Design and implement a bundle encoding for `(namespace_id, namespace_key)` (see design.md open question)
- [ ] 7.2 Add `nook namespace export`: prints the bundle for the current client's namespace
- [ ] 7.3 Add `--import-namespace <bundle>` to `nook init`: adopts an existing namespace instead of generating a new one
- [ ] 7.4 Add/adjust tests: exporting then importing a namespace on a second client config yields full read/write access to the same namespace's data

## 8. Documentation

- [ ] 8.1 Update `specs/SPEC-001-Base Implementation.md` with the vault/namespace terminology migration note (vault→namespace, VMK→namespace key)
- [ ] 8.2 Update `SECURITY.md` with the SPEC-004 §12 amendments: namespace-level structure visible to the server, vault-credential compromise allows storage-level forgery (not decryption), `nookd` now holds one class of secret worth protecting (`vaults.credential`), vault-credential bootstrap trust channel
- [ ] 8.3 Update `README.md`'s server/init instructions for the new vault-based `nook init` flow and `nookd vault` CLI
- [ ] 8.4 Update `crates/nookd/Dockerfile`/README container instructions if the vault CLI needs to run against the same mounted data directory as the server process
