use crate::crypto::{
    decrypt_chunk, encrypt_chunk, generate_data_key, unwrap_data_key, VaultKey, WrappedKey,
};
use crate::manifest::ObjectType;
use crate::{NookError, Result};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;
pub const PROTOCOL_VERSION: u16 = 1;
const MAGIC: &[u8; 5] = b"NOOK1";
const AEAD_TAG_SIZE: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectHeader {
    pub magic: [u8; 5],
    pub object_type: ObjectType,
    pub protocol_version: u16,
    pub wrapped_dek: Vec<u8>,
    pub logical_size: u64,
    pub chunk_size: u32,
}

#[derive(Debug, Clone)]
pub struct EncryptedObject {
    pub object_id: [u8; 32],
    pub wrapped_key: WrappedKey,
    pub header: ObjectHeader,
    pub chunks: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct DecryptedObject {
    pub header: ObjectHeader,
    pub plaintext: Vec<u8>,
}

pub fn encrypt_object(
    object_id: [u8; 32],
    object_type: ObjectType,
    data: &[u8],
    vault: &VaultKey,
) -> Result<EncryptedObject> {
    let data_key = generate_data_key();
    let wrapped_key = crate::crypto::wrap_data_key(vault, &data_key);
    let header = ObjectHeader {
        magic: *MAGIC,
        object_type,
        protocol_version: PROTOCOL_VERSION,
        wrapped_dek: wrapped_key.0.clone(),
        logical_size: data.len() as u64,
        chunk_size: DEFAULT_CHUNK_SIZE as u32,
    };
    let serialized_header =
        bincode::serialize(&header).map_err(|e| NookError::Serialization(e.to_string()))?;
    if serialized_header.len() + 2 > DEFAULT_CHUNK_SIZE {
        return Err(NookError::Serialization(
            "object header exceeds chunk size".into(),
        ));
    }

    let mut plaintext_chunks = Vec::new();
    let mut header_chunk = Vec::with_capacity(DEFAULT_CHUNK_SIZE);
    header_chunk.extend_from_slice(&(serialized_header.len() as u16).to_le_bytes());
    header_chunk.extend_from_slice(&serialized_header);
    header_chunk.resize(DEFAULT_CHUNK_SIZE, 0u8);
    plaintext_chunks.push(header_chunk);

    if data.is_empty() {
        let buf = vec![0u8; DEFAULT_CHUNK_SIZE];
        plaintext_chunks.push(buf);
    } else {
        for chunk in data.chunks(DEFAULT_CHUNK_SIZE) {
            let mut buf = Vec::with_capacity(DEFAULT_CHUNK_SIZE);
            buf.extend_from_slice(chunk);
            buf.resize(DEFAULT_CHUNK_SIZE, 0u8);
            plaintext_chunks.push(buf);
        }
    }

    let mut chunks = Vec::with_capacity(plaintext_chunks.len());
    for (idx, chunk) in plaintext_chunks.iter().enumerate() {
        let nonce = derive_nonce(&data_key, &object_id, idx as u64)?;
        let ad = associated_data(&object_id, idx as u64);
        let encrypted = encrypt_chunk(&data_key, &nonce, &ad, chunk);
        chunks.push(encrypted);
    }

    Ok(EncryptedObject {
        object_id,
        wrapped_key,
        header,
        chunks,
    })
}

pub fn serialize_encrypted_object(obj: &EncryptedObject) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    if obj.wrapped_key.0.len() > u16::MAX as usize {
        return Err(NookError::Serialization(
            "wrapped key too long for envelope".into(),
        ));
    }
    out.extend_from_slice(&(obj.wrapped_key.0.len() as u16).to_le_bytes());
    out.extend_from_slice(&obj.wrapped_key.0);
    out.extend_from_slice(&(obj.chunks.len() as u32).to_le_bytes());
    for chunk in &obj.chunks {
        out.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
        out.extend_from_slice(chunk);
    }
    Ok(out)
}

pub fn deserialize_encrypted_object(bytes: &[u8]) -> Result<(WrappedKey, Vec<Vec<u8>>)> {
    if bytes.len() < 2 {
        return Err(NookError::Serialization("object too small".into()));
    }
    let wrapped_len = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
    if bytes.len() < 2 + wrapped_len + 4 {
        return Err(NookError::Serialization(
            "object missing chunk metadata".into(),
        ));
    }
    let wrapped_key = WrappedKey(bytes[2..2 + wrapped_len].to_vec());
    let mut cursor = 2 + wrapped_len;
    let chunk_count = u32::from_le_bytes([
        bytes[cursor],
        bytes[cursor + 1],
        bytes[cursor + 2],
        bytes[cursor + 3],
    ]) as usize;
    cursor += 4;
    let mut chunks = Vec::with_capacity(chunk_count);
    for _ in 0..chunk_count {
        if bytes.len() < cursor + 4 {
            return Err(NookError::Serialization("chunk length missing".into()));
        }
        let len = u32::from_le_bytes([
            bytes[cursor],
            bytes[cursor + 1],
            bytes[cursor + 2],
            bytes[cursor + 3],
        ]) as usize;
        cursor += 4;
        if bytes.len() < cursor + len {
            return Err(NookError::Serialization("chunk data missing".into()));
        }
        chunks.push(bytes[cursor..cursor + len].to_vec());
        cursor += len;
    }
    Ok((wrapped_key, chunks))
}

pub fn decrypt_object(
    object_id: [u8; 32],
    wrapped_key: &WrappedKey,
    chunks: &[Vec<u8>],
    vault: &VaultKey,
) -> Result<DecryptedObject> {
    if chunks.is_empty() {
        return Err(NookError::Serialization("no chunks present".into()));
    }
    let data_key = unwrap_data_key(vault, wrapped_key)?;
    let header_plain = decrypt_chunk(
        &data_key,
        &derive_nonce(&data_key, &object_id, 0)?,
        &associated_data(&object_id, 0),
        &chunks[0],
    )?;
    if header_plain.len() < 2 {
        return Err(NookError::Serialization("header chunk too small".into()));
    }
    let header_len = u16::from_le_bytes([header_plain[0], header_plain[1]]) as usize;
    if header_len + 2 > header_plain.len() {
        return Err(NookError::Serialization("header length invalid".into()));
    }
    let header: ObjectHeader = bincode::deserialize(&header_plain[2..2 + header_len])
        .map_err(|e| NookError::Serialization(e.to_string()))?;
    if header.magic != *MAGIC {
        return Err(NookError::Crypto("magic mismatch".into()));
    }
    if header.protocol_version != PROTOCOL_VERSION {
        return Err(NookError::Crypto("protocol version mismatch".into()));
    }
    // The wrapped DEK is present twice on the wire: once inside this
    // AEAD-encrypted header, and once unencrypted in the outer envelope
    // (needed to unwrap the DEK before the header itself can be decrypted).
    // The outer copy is untrusted until checked against the one just
    // decrypted; a mismatch means the envelope was tampered with or the two
    // have otherwise diverged, so fail closed rather than silently trusting
    // either copy.
    if header.wrapped_dek != wrapped_key.0 {
        return Err(NookError::Crypto(
            "wrapped key mismatch between outer envelope and encrypted header".into(),
        ));
    }
    let chunk_size = header.chunk_size as usize;
    if chunk_size != DEFAULT_CHUNK_SIZE {
        return Err(NookError::Crypto("unexpected chunk size".into()));
    }
    let mut data = Vec::with_capacity(header.logical_size as usize);
    for (idx, chunk) in chunks.iter().enumerate().skip(1) {
        let plain = decrypt_chunk(
            &data_key,
            &derive_nonce(&data_key, &object_id, idx as u64)?,
            &associated_data(&object_id, idx as u64),
            chunk,
        )?;
        let remaining = header.logical_size.saturating_sub(data.len() as u64) as usize;
        if remaining == 0 {
            break;
        }
        let take = remaining.min(plain.len());
        data.extend_from_slice(&plain[..take]);
    }
    Ok(DecryptedObject {
        header,
        plaintext: data,
    })
}

fn derive_nonce(
    key: &crate::crypto::DataKey,
    object_id: &[u8; 32],
    chunk_index: u64,
) -> Result<[u8; 24]> {
    let hk = Hkdf::<Sha256>::new(Some(object_id), key.as_bytes());
    let mut out = [0u8; 24];
    hk.expand(&chunk_index.to_le_bytes(), &mut out)
        .map_err(|e| NookError::Crypto(format!("nonce derivation failed: {e}")))?;
    Ok(out)
}

fn associated_data(object_id: &[u8; 32], chunk_index: u64) -> Vec<u8> {
    let mut ad = Vec::with_capacity(object_id.len() + 8 + 2);
    ad.extend_from_slice(object_id);
    ad.extend_from_slice(&chunk_index.to_le_bytes());
    ad.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    ad
}

pub fn encrypted_size_for_chunks(chunk_count: usize) -> usize {
    let chunk = DEFAULT_CHUNK_SIZE + AEAD_TAG_SIZE;
    chunk_count * chunk
}
