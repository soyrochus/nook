mod support;

use std::fs;
use support::{create_vault, run_nook, Nookd};

/// Exporting a namespace from one client and importing it into another
/// (with the same vault credentials) must yield full read/write access to
/// the same namespace's data — sharing a namespace key is sharing a volume
/// (SPEC-004 §6/§11).
#[test]
fn exported_namespace_can_be_imported_by_a_second_client() {
    let tmp = tempfile::tempdir().unwrap();
    let storage_dir = tmp.path().join("storage");
    let (vault_id, vault_credential) = create_vault(&storage_dir);
    let server = Nookd::start(&storage_dir);
    let server_url = server.url();

    // Fred: fresh namespace, pushes a file.
    let fred_config = tmp.path().join("fred-config");
    let fred_root = tmp.path().join("fred-root");
    fs::create_dir_all(&fred_config).unwrap();
    fs::create_dir_all(&fred_root).unwrap();
    fs::write(fred_root.join("shared.txt"), b"shared team data").unwrap();

    let init = run_nook(
        &fred_config,
        &[
            "init",
            "--server",
            &server_url,
            "--vault-id",
            &vault_id,
            "--vault-credential",
            &vault_credential,
        ],
    );
    assert!(init.status.success(), "fred init failed: {init:?}");
    assert!(run_nook(
        &fred_config,
        &["root", "--set", fred_root.to_str().unwrap()]
    )
    .status
    .success());
    assert!(
        run_nook(&fred_config, &["push"]).status.success(),
        "fred push failed"
    );

    let export = run_nook(&fred_config, &["namespace", "export"]);
    assert!(
        export.status.success(),
        "namespace export failed: {export:?}"
    );
    let bundle = String::from_utf8_lossy(&export.stdout).trim().to_string();
    assert!(
        bundle.starts_with("nookns1:"),
        "unexpected bundle format: {bundle}"
    );

    // Mary: imports Fred's namespace using the same vault credentials.
    let mary_config = tmp.path().join("mary-config");
    let mary_root = tmp.path().join("mary-root");
    fs::create_dir_all(&mary_config).unwrap();
    fs::create_dir_all(&mary_root).unwrap();

    let mary_init = run_nook(
        &mary_config,
        &[
            "init",
            "--server",
            &server_url,
            "--vault-id",
            &vault_id,
            "--vault-credential",
            &vault_credential,
            "--import-namespace",
            &bundle,
        ],
    );
    assert!(
        mary_init.status.success(),
        "mary init failed: {mary_init:?}"
    );
    assert!(run_nook(
        &mary_config,
        &["root", "--set", mary_root.to_str().unwrap()]
    )
    .status
    .success());

    let pull = run_nook(&mary_config, &["pull"]);
    assert!(pull.status.success(), "mary pull failed: {pull:?}");

    let pulled =
        fs::read_to_string(mary_root.join("shared.txt")).expect("shared.txt pulled by mary");
    assert_eq!(pulled, "shared team data");
}

/// Two different, independently generated namespaces under the same vault
/// must not be able to read each other's content, even though both share
/// the same vault credential (crypto-only separation between namespaces,
/// SPEC-004 §2/§12).
#[test]
fn independent_namespaces_cannot_read_each_others_data() {
    let tmp = tempfile::tempdir().unwrap();
    let storage_dir = tmp.path().join("storage");
    let (vault_id, vault_credential) = create_vault(&storage_dir);
    let server = Nookd::start(&storage_dir);
    let server_url = server.url();

    let fred_config = tmp.path().join("fred-config");
    let fred_root = tmp.path().join("fred-root");
    fs::create_dir_all(&fred_config).unwrap();
    fs::create_dir_all(&fred_root).unwrap();
    fs::write(fred_root.join("private.txt"), b"fred's private data").unwrap();

    assert!(run_nook(
        &fred_config,
        &[
            "init",
            "--server",
            &server_url,
            "--vault-id",
            &vault_id,
            "--vault-credential",
            &vault_credential
        ]
    )
    .status
    .success());
    assert!(run_nook(
        &fred_config,
        &["root", "--set", fred_root.to_str().unwrap()]
    )
    .status
    .success());
    assert!(run_nook(&fred_config, &["push"]).status.success());

    // Mary: a brand-new namespace under the same vault (no import).
    let mary_config = tmp.path().join("mary-config");
    let mary_root = tmp.path().join("mary-root");
    fs::create_dir_all(&mary_config).unwrap();
    fs::create_dir_all(&mary_root).unwrap();
    assert!(run_nook(
        &mary_config,
        &[
            "init",
            "--server",
            &server_url,
            "--vault-id",
            &vault_id,
            "--vault-credential",
            &vault_credential
        ]
    )
    .status
    .success());
    assert!(run_nook(
        &mary_config,
        &["root", "--set", mary_root.to_str().unwrap()]
    )
    .status
    .success());

    // Mary's namespace has no manifest of its own yet: pulling must not see Fred's data.
    let mary_pull = run_nook(&mary_config, &["pull"]);
    assert!(
        !mary_pull.status.success(),
        "mary must not see fred's namespace: {mary_pull:?}"
    );
    assert!(!mary_root.join("private.txt").exists());
}
