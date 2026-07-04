mod support;

use std::collections::HashMap;
use std::fs;
use support::{run_nook, Nookd};

fn setup(tmp: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let storage_dir = tmp.join("storage");
    let config_home = tmp.join("config");
    let vault_root = tmp.join("vault");
    fs::create_dir_all(&vault_root).unwrap();
    fs::create_dir_all(&config_home).unwrap();
    (storage_dir, config_home, vault_root)
}

#[test]
fn first_push_to_fresh_vault_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let (storage_dir, config_home, vault_root) = setup(tmp.path());
    fs::write(vault_root.join("hello.txt"), b"hello world").unwrap();

    let server = Nookd::start(&storage_dir);
    let server_url = server.url();

    let init = run_nook(&config_home, &["init", "--server", &server_url]);
    assert!(init.status.success(), "init failed: {init:?}");

    let root = run_nook(&config_home, &["root", "--set", vault_root.to_str().unwrap()]);
    assert!(root.status.success(), "root --set failed: {root:?}");

    let push = run_nook(&config_home, &["push"]);
    assert!(
        push.status.success(),
        "push against a fresh (404) vault should succeed: {push:?}"
    );

    // One object for the manifest (head) plus one for hello.txt's content.
    let objects_dir = storage_dir.join("objects");
    let count = fs::read_dir(&objects_dir).unwrap().count();
    assert_eq!(count, 2, "expected the manifest object and one content object");
}

#[test]
fn corrupted_manifest_aborts_push_and_leaves_server_untouched() {
    let tmp = tempfile::tempdir().unwrap();
    let (storage_dir, config_home, vault_root) = setup(tmp.path());
    fs::write(vault_root.join("hello.txt"), b"hello world").unwrap();

    let server = Nookd::start(&storage_dir);
    let server_url = server.url();

    assert!(run_nook(&config_home, &["init", "--server", &server_url]).status.success());
    assert!(
        run_nook(&config_home, &["root", "--set", vault_root.to_str().unwrap()])
            .status
            .success()
    );
    assert!(run_nook(&config_home, &["push"]).status.success(), "initial push must succeed");

    let objects_dir = storage_dir.join("objects");
    let entries: Vec<_> = fs::read_dir(&objects_dir).unwrap().map(|e| e.unwrap().path()).collect();
    assert_eq!(entries.len(), 2, "manifest + one content object after first push");

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

    let entries_after: Vec<_> = fs::read_dir(&objects_dir).unwrap().map(|e| e.unwrap().path()).collect();
    assert_eq!(
        entries_after.len(),
        2,
        "no new content object should have been uploaded on a failed push either"
    );
}
