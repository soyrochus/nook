//! Request authentication shared by `nook` (signs) and `nookd` (verifies).
//!
//! Kept in one place deliberately: client and server must construct the
//! exact same canonical string, or every request fails closed. See
//! SPEC-004 §4.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// The vault/namespace/object-addressed path used both to build request
/// URLs and as the `PATH` component of the signed canonical string.
pub fn object_path(vault_id: &str, namespace_id: &str, object_id: &str) -> String {
    format!("/v1/vault/{vault_id}/ns/{namespace_id}/obj/{object_id}")
}

/// SHA-256 digest of a full, in-memory body. For streamed request bodies
/// (server-side, where holding the whole body in memory to re-hash it would
/// defeat the point of streaming), compute the digest incrementally instead
/// and pass its bytes to [`sign_with_body_hash`]/[`verify_with_body_hash`].
pub fn body_sha256(body: &[u8]) -> Vec<u8> {
    Sha256::digest(body).to_vec()
}

fn canonical_string(method: &str, path: &str, timestamp: i64, body_hash: &[u8]) -> String {
    format!("{method}\n{path}\n{timestamp}\n{}", hex::encode(body_hash))
}

/// Computes the hex-encoded HMAC-SHA256 signature for a request, given the
/// full body available in memory (the common case for the client, which
/// already reads whole files into memory before encrypting them).
pub fn sign_request(credential: &[u8], method: &str, path: &str, timestamp: i64, body: &[u8]) -> String {
    sign_with_body_hash(credential, method, path, timestamp, &body_sha256(body))
}

/// Same as [`sign_request`], but takes an already-computed body digest —
/// for signing/verifying a streamed body without buffering it.
pub fn sign_with_body_hash(credential: &[u8], method: &str, path: &str, timestamp: i64, body_hash: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(credential).expect("HMAC accepts a key of any length");
    mac.update(canonical_string(method, path, timestamp, body_hash).as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Verifies a hex-encoded signature against the expected credential, using
/// the constant-time comparison built into `Mac::verify_slice`.
pub fn verify_request(
    credential: &[u8],
    method: &str,
    path: &str,
    timestamp: i64,
    body: &[u8],
    signature_hex: &str,
) -> bool {
    verify_with_body_hash(credential, method, path, timestamp, &body_sha256(body), signature_hex)
}

/// Same as [`verify_request`], but takes an already-computed body digest —
/// for verifying a streamed body without buffering it.
pub fn verify_with_body_hash(
    credential: &[u8],
    method: &str,
    path: &str,
    timestamp: i64,
    body_hash: &[u8],
    signature_hex: &str,
) -> bool {
    let Ok(signature_bytes) = hex::decode(signature_hex) else {
        return false;
    };
    let mut mac = HmacSha256::new_from_slice(credential).expect("HMAC accepts a key of any length");
    mac.update(canonical_string(method, path, timestamp, body_hash).as_bytes());
    mac.verify_slice(&signature_bytes).is_ok()
}

/// Shared shape for `vault_id`/`namespace_id`/`object_id`: opaque, random,
/// 256-bit values, hex-encoded (64 lowercase hex characters). Used to
/// validate all three path segments identically before they ever touch a
/// filesystem path or SQL query.
pub fn is_valid_hex_id(id: &str) -> bool {
    id.len() == 64 && id.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}
