use nook_core::{
    decrypt_object, deserialize_encrypted_object, encrypt_object, generate_vault_key,
    serialize_encrypted_object, unwrap_data_key, wrap_data_key, EncryptedObject, ObjectType,
};

#[test]
fn matching_wrapped_key_copies_decrypt_successfully() {
    let vault = generate_vault_key();
    let object_id = [7u8; 32];
    let plaintext = b"hello nook".to_vec();

    let encrypted = encrypt_object(object_id, ObjectType::Content, &plaintext, &vault).unwrap();
    let bytes = serialize_encrypted_object(&encrypted).unwrap();
    let (wrapped, chunks) = deserialize_encrypted_object(&bytes).unwrap();

    let decrypted = decrypt_object(object_id, &wrapped, &chunks, &vault).unwrap();
    assert_eq!(decrypted.plaintext, plaintext);
}

/// Crafts an object whose outer envelope wrapped-key bytes differ from the
/// wrapped DEK embedded in the encrypted chunk-0 header, while both still
/// unwrap to the identical underlying DEK (achieved by re-wrapping the same
/// DEK a second time, which yields different ciphertext bytes due to the
/// fresh random nonce but unwraps to the same key). This isolates the
/// header/envelope cross-check from the unrelated case of an outer key that
/// simply fails to unwrap at all.
#[test]
fn diverging_wrapped_key_copies_are_rejected() {
    let vault = generate_vault_key();
    let object_id = [9u8; 32];
    let plaintext = b"tamper me".to_vec();

    let encrypted = encrypt_object(object_id, ObjectType::Content, &plaintext, &vault).unwrap();

    // Recover the DEK and re-wrap it under a fresh nonce: a different byte
    // string that still unwraps to the same DEK as the header expects.
    let data_key = unwrap_data_key(&vault, &encrypted.wrapped_key).unwrap();
    let diverged_wrapped_key = wrap_data_key(&vault, &data_key);
    assert_ne!(diverged_wrapped_key.0, encrypted.wrapped_key.0);

    let tampered = EncryptedObject {
        object_id: encrypted.object_id,
        wrapped_key: diverged_wrapped_key,
        header: encrypted.header,
        chunks: encrypted.chunks,
    };

    let bytes = serialize_encrypted_object(&tampered).unwrap();
    let (wrapped, chunks) = deserialize_encrypted_object(&bytes).unwrap();

    let result = decrypt_object(object_id, &wrapped, &chunks, &vault);
    assert!(
        result.is_err(),
        "decrypt_object must reject diverging wrapped-key copies instead of silently using either one"
    );
}
