mod support;

use std::collections::HashMap;
use std::fs;
use support::{create_vault, run_nook, Nookd};
use walkdir::WalkDir;

fn setup(tmp: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let storage_dir = tmp.join("storage");
    let config_home = tmp.join("config");
    let vault_root = tmp.join("vault");
    fs::create_dir_all(&vault_root).unwrap();
    fs::create_dir_all(&config_home).unwrap();
    (storage_dir, config_home, vault_root)
}

/// Object files now live nested under `objects/<vault_id>/<namespace_id>/`
/// (SPEC-004 §7) rather than flat under `objects/`, so tests must walk
/// recursively to find the actual stored files.
fn stored_object_files(objects_dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    WalkDir::new(objects_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf())
        .collect()
}

fn init_and_set_root(
    config_home: &std::path::Path,
    server_url: &str,
    vault_id: &str,
    vault_credential: &str,
    vault_root: &std::path::Path,
) {
    let init = run_nook(
        config_home,
        &[
            "init",
            "--server",
            server_url,
            "--vault-id",
            vault_id,
            "--vault-credential",
            vault_credential,
        ],
    );
    assert!(init.status.success(), "init failed: {init:?}");
    let root = run_nook(
        config_home,
        &["root", "--set", vault_root.to_str().unwrap()],
    );
    assert!(root.status.success(), "root --set failed: {root:?}");
}

#[test]
fn first_push_to_fresh_vault_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let (storage_dir, config_home, vault_root) = setup(tmp.path());
    fs::write(vault_root.join("hello.txt"), b"hello world").unwrap();

    let (vault_id, vault_credential) = create_vault(&storage_dir);
    let server = Nookd::start(&storage_dir);
    let server_url = server.url();
    init_and_set_root(
        &config_home,
        &server_url,
        &vault_id,
        &vault_credential,
        &vault_root,
    );

    let push = run_nook(&config_home, &["push"]);
    assert!(
        push.status.success(),
        "push against a fresh (404) vault should succeed: {push:?}"
    );

    // One object for the manifest (head) plus one for hello.txt's content.
    let objects_dir = storage_dir.join("objects");
    let count = stored_object_files(&objects_dir).len();
    assert_eq!(
        count, 2,
        "expected the manifest object and one content object"
    );
}

#[test]
fn corrupted_manifest_aborts_push_and_leaves_server_untouched() {
    let tmp = tempfile::tempdir().unwrap();
    let (storage_dir, config_home, vault_root) = setup(tmp.path());
    fs::write(vault_root.join("hello.txt"), b"hello world").unwrap();

    let (vault_id, vault_credential) = create_vault(&storage_dir);
    let server = Nookd::start(&storage_dir);
    let server_url = server.url();
    init_and_set_root(
        &config_home,
        &server_url,
        &vault_id,
        &vault_credential,
        &vault_root,
    );

    assert!(
        run_nook(&config_home, &["push"]).status.success(),
        "initial push must succeed"
    );

    let objects_dir = storage_dir.join("objects");
    let entries = stored_object_files(&objects_dir);
    assert_eq!(
        entries.len(),
        2,
        "manifest + one content object after first push"
    );

    // Corrupt every stored object (flip a byte in the middle) so the
    // manifest is corrupted regardless of which file it turns out to be,
    // without needing to decrypt anything to identify it.
    let mut corrupted_bytes: HashMap<std::path::PathBuf, Vec<u8>> = HashMap::new();
    for path in &entries {
        let original = fs::read(path).unwrap();
        let mut corrupted = original.clone();
        let mid = corrupted.len() / 2;
        corrupted[mid] ^= 0xFF;
        fs::write(path, &corrupted).unwrap();
        corrupted_bytes.insert(path.clone(), corrupted);
    }

    // Add a new file so a naive "fabricate a fresh empty manifest"
    // implementation would have something new to push instead of failing.
    fs::write(vault_root.join("second.txt"), b"more data").unwrap();

    let second_push = run_nook(&config_home, &["push"]);
    assert!(
        !second_push.status.success(),
        "push over a corrupted manifest must fail: {second_push:?}"
    );

    for path in &entries {
        let bytes_now = fs::read(path).unwrap();
        assert_eq!(
            &bytes_now,
            corrupted_bytes.get(path).unwrap(),
            "stored object must remain untouched after a failed push: {path:?}"
        );
    }

    let entries_after = stored_object_files(&objects_dir);
    assert_eq!(
        entries_after.len(),
        2,
        "no new content object should have been uploaded on a failed push either"
    );
}
