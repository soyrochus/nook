use crate::{NookError, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroize;

#[derive(Clone)]
pub struct VaultKey(pub [u8; 32]);

impl VaultKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for VaultKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone)]
pub struct DataKey(pub [u8; 32]);

impl DataKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for DataKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Debug)]
pub struct WrappedKey(pub Vec<u8>);

pub fn generate_vault_key() -> VaultKey {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    VaultKey(bytes)
}

pub fn generate_data_key() -> DataKey {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    DataKey(bytes)
}

fn derive_wrap_key(vault: &VaultKey) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, vault.as_bytes());
    let mut out = [0u8; 32];
    hk.expand(b"nook-wrap-key", &mut out)
        .map_err(|e| NookError::Crypto(format!("wrap key derivation failed: {e}")))?;
    Ok(out)
}

pub fn wrap_data_key(vault: &VaultKey, data: &DataKey) -> WrappedKey {
    let key_bytes = derive_wrap_key(vault).expect("hkdf expansion to fixed size never fails");
    let cipher = XChaCha20Poly1305::new((&key_bytes).into());
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: data.as_bytes(),
                aad: b"nook-key-wrap",
            },
        )
        .expect("encryption with generated key must succeed");
    let mut out = Vec::with_capacity(nonce.len() + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    WrappedKey(out)
}

pub fn unwrap_data_key(vault: &VaultKey, wrapped: &WrappedKey) -> Result<DataKey> {
    if wrapped.0.len() < 24 {
        return Err(NookError::Crypto("wrapped key too short".into()));
    }
    let key_bytes = derive_wrap_key(vault)?;
    let cipher = XChaCha20Poly1305::new((&key_bytes).into());
    let (nonce, body) = wrapped.0.split_at(24);
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: body,
                aad: b"nook-key-wrap",
            },
        )
        .map_err(|_| NookError::Crypto("failed to unwrap data key".into()))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&plaintext);
    Ok(DataKey(out))
}

pub fn encrypt_chunk(
    key: &DataKey,
    nonce: &[u8; 24],
    associated_data: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes()).unwrap();
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .expect("encrypt_chunk: encrypt should not fail with correct sizes")
}

pub fn decrypt_chunk(
    key: &DataKey,
    nonce: &[u8; 24],
    associated_data: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes()).unwrap();
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|_| NookError::Crypto("decrypt_chunk failed".into()))
}

/// Length in bytes of the random salt used for `derive_passphrase_key`.
pub const PASSPHRASE_SALT_LEN: usize = 16;

/// Derives a 32-byte wrapping key from a user passphrase via Argon2id, for
/// encrypting the Vault Master Key at rest when no OS keychain is available.
/// Uses a conservative interactive profile (19 MiB memory, 2 iterations, 1
/// lane), per OWASP password-hashing guidance.
pub fn derive_passphrase_key(passphrase: &[u8], salt: &[u8]) -> Result<DataKey> {
    let params = Params::new(19_456, 2, 1, Some(32))
        .map_err(|e| NookError::Crypto(format!("invalid argon2 parameters: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|e| NookError::Crypto(format!("argon2 key derivation failed: {e}")))?;
    Ok(DataKey(out))
}

pub fn derive_head_object_id(vault: &VaultKey) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, vault.as_bytes());
    let mut out = [0u8; 32];
    hk.expand(b"nook-head", &mut out)
        .expect("hkdf expansion to fixed size never fails");
    out
}
