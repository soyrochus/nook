mod support;

use std::fs;
use support::run_nook;

/// `run_nook`'s support helper always sets `NOOK_PASSPHRASE`, and this
/// sandboxed test environment has no OS keychain daemon available, so
/// `nook init` is expected to take the passphrase-encrypted-local-file
/// fallback path here. That's exactly the path these tests want to exercise.
fn init_fresh_config() -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let config_home = tmp.path().join("config");
    fs::create_dir_all(&config_home).unwrap();
    let init = run_nook(&config_home, &["init", "--server", "http://127.0.0.1:1"]);
    assert!(init.status.success(), "init failed: {init:?}");
    (tmp, config_home)
}

fn config_file(config_home: &std::path::Path) -> std::path::PathBuf {
    // directories::ProjectDirs::from("dev", "nook", "nook") on Linux resolves
    // the config dir under XDG_CONFIG_HOME/nook.
    let mut candidates = Vec::new();
    if let Ok(entries) = fs::read_dir(config_home) {
        for entry in entries.flatten() {
            candidates.push(entry.path());
        }
    }
    let nook_dir = candidates
        .into_iter()
        .find(|p| p.is_dir())
        .expect("expected a config subdirectory under XDG_CONFIG_HOME");
    nook_dir.join("config.toml")
}

#[test]
fn init_produces_valid_toml_with_no_recoverable_key_material() {
    let (_tmp, config_home) = init_fresh_config();
    let path = config_file(&config_home);
    let contents = fs::read_to_string(&path).expect("config.toml should exist");

    let parsed: toml::Value = toml::from_str(&contents).expect("config must be valid TOML");
    assert!(parsed.get("server").is_some());

    let vault_key = parsed.get("vault_key").expect("vault_key table present");
    let mode = vault_key.get("mode").and_then(|v| v.as_str());
    assert_eq!(
        mode,
        Some("encrypted_file"),
        "no keychain daemon is available in this test environment, so init must have used the passphrase fallback"
    );

    // The only byte-ish fields present are salt/nonce/ciphertext, which are
    // legitimate encrypted material, not the raw 32-byte vault key. A raw
    // key would appear as its own unlabeled 32-byte base64 blob under
    // `vault_key` directly; instead every field here is one of the expected
    // three ciphertext components.
    let table = vault_key.as_table().expect("vault_key is a table");
    let mut keys: Vec<&str> = table.keys().map(|s| s.as_str()).collect();
    keys.sort();
    assert_eq!(keys, vec!["ciphertext", "mode", "nonce", "salt"]);
}

#[test]
fn wrong_passphrase_is_rejected_on_load() {
    let (_tmp, config_home) = init_fresh_config();

    // `status` will fail on the network call regardless (server doesn't
    // exist), but with the right passphrase it must get past key decryption
    // first, whereas a wrong passphrase must fail before ever attempting
    // the network call, with a decryption-specific error.
    let bin = support::ensure_built("nook");
    let right = std::process::Command::new(&bin)
        .args(["status"])
        .env("XDG_CONFIG_HOME", &config_home)
        .env("NOOK_PASSPHRASE", "test-passphrase-not-for-real-use")
        .output()
        .unwrap();
    let right_stderr = String::from_utf8_lossy(&right.stderr);
    assert!(
        !right_stderr.contains("incorrect passphrase"),
        "correct passphrase must not be rejected: {right_stderr}"
    );

    let wrong = std::process::Command::new(&bin)
        .args(["status"])
        .env("XDG_CONFIG_HOME", &config_home)
        .env("NOOK_PASSPHRASE", "definitely-the-wrong-passphrase")
        .output()
        .unwrap();
    assert!(!wrong.status.success(), "wrong passphrase must not succeed");
    let wrong_stderr = String::from_utf8_lossy(&wrong.stderr);
    assert!(
        wrong_stderr.contains("incorrect passphrase"),
        "expected a clear incorrect-passphrase error, got: {wrong_stderr}"
    );
}

#[test]
fn non_toml_config_produces_a_clear_reinit_error() {
    let tmp = tempfile::tempdir().unwrap();
    let config_home = tmp.path().join("config");
    let nook_dir = config_home.join("nook");
    fs::create_dir_all(&nook_dir).unwrap();
    fs::write(nook_dir.join("config.toml"), b"{ \"this\": \"is json, not toml\" }").unwrap();

    let out = run_nook(&config_home, &["status"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("nook init") || stderr.to_lowercase().contains("toml"),
        "expected a clear error pointing at TOML/reinit, got: {stderr}"
    );
}
