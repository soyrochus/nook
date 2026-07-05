//! SPEC-005 end-to-end tests: `nook rm` and the automatic post-push sweep.

mod support;

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use support::{create_vault, ensure_built, run_nook, run_nook_env, Nookd};
use walkdir::WalkDir;

fn setup(tmp: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let storage_dir = tmp.join("storage");
    let config_home = tmp.join("config");
    let vault_root = tmp.join("vault");
    fs::create_dir_all(&vault_root).unwrap();
    fs::create_dir_all(&config_home).unwrap();
    (storage_dir, config_home, vault_root)
}

fn init_and_set_root(config_home: &Path, server_url: &str, vault_id: &str, vault_credential: &str, vault_root: &Path) {
    let init = run_nook(
        config_home,
        &["init", "--server", server_url, "--vault-id", vault_id, "--vault-credential", vault_credential],
    );
    assert!(init.status.success(), "init failed: {init:?}");
    let root = run_nook(config_home, &["root", "--set", vault_root.to_str().unwrap()]);
    assert!(root.status.success(), "root --set failed: {root:?}");
}

fn stored_object_files(objects_dir: &Path) -> Vec<PathBuf> {
    WalkDir::new(objects_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf())
        .collect()
}

/// Reads `bytes_used` for a vault by running `nookd vault list` (columns:
/// vault_id, created_at, quota_bytes, bytes_used, revoked, namespaces).
fn vault_bytes_used(storage: &Path, vault_id: &str) -> u64 {
    let bin = ensure_built("nookd");
    let out = std::process::Command::new(bin)
        .args(["vault", "list", "--storage"])
        .arg(storage)
        .output()
        .expect("failed to run nookd vault list");
    assert!(out.status.success(), "vault list failed: {out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout
        .lines()
        .find(|l| l.starts_with(vault_id))
        .expect("vault row in list output");
    line.split_whitespace().nth(3).unwrap().parse().unwrap()
}

/// The client's namespace_id is non-secret and stored in plain TOML.
fn namespace_id_from_config(config_home: &Path) -> String {
    let cfg = fs::read_to_string(config_home.join("nook/config.toml")).expect("client config");
    cfg.lines()
        .find_map(|l| l.strip_prefix("namespace_id = \""))
        .expect("namespace_id in config")
        .trim_end_matches('"')
        .to_string()
}

/// Uploads a deliberately unreferenced ("orphan") object via a raw signed
/// PUT, simulating residue of a crashed/failed push.
fn put_orphan(server_url: &str, vault_id: &str, credential_hex: &str, namespace_id: &str, object_id: &str) {
    let credential = hex::decode(credential_hex).unwrap();
    let path = nook_core::object_path(vault_id, namespace_id, object_id);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let body: &[u8] = b"orphaned bytes";
    let sig = nook_core::sign_request(&credential, "PUT", &path, timestamp, body);
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let res = reqwest::Client::new()
            .put(format!("{server_url}{path}"))
            .header("X-Nook-Timestamp", timestamp.to_string())
            .header("X-Nook-Signature", sig)
            .body(body.to_vec())
            .send()
            .await
            .unwrap();
        assert!(res.status().is_success(), "orphan PUT failed: {}", res.status());
    });
}

fn random_hex_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[test]
fn push_reclaims_replaced_content_and_quota_matches_disk() {
    let tmp = tempfile::tempdir().unwrap();
    let (storage_dir, config_home, vault_root) = setup(tmp.path());
    fs::write(vault_root.join("a.txt"), b"version one").unwrap();

    let (vault_id, vault_credential) = create_vault(&storage_dir);
    let server = Nookd::start(&storage_dir);
    init_and_set_root(&config_home, &server.url(), &vault_id, &vault_credential, &vault_root);

    assert!(run_nook(&config_home, &["push"]).status.success());
    let objects_dir = storage_dir.join("objects");
    assert_eq!(stored_object_files(&objects_dir).len(), 2, "head + one content object");

    // Replacing the file must not leave the old content object behind.
    fs::write(vault_root.join("a.txt"), b"version two, somewhat longer").unwrap();
    let push = run_nook(&config_home, &["push"]);
    assert!(push.status.success(), "second push failed: {push:?}");
    let files = stored_object_files(&objects_dir);
    assert_eq!(files.len(), 2, "old content object must be swept: {files:?}");

    // Quota accounting matches what is actually on disk after deletions.
    let disk_total: u64 = files.iter().map(|f| fs::metadata(f).unwrap().len()).sum();
    assert_eq!(vault_bytes_used(&storage_dir, &vault_id), disk_total);

    // The surviving content is the new version.
    fs::write(vault_root.join("a.txt"), b"local scribble").unwrap();
    assert!(run_nook(&config_home, &["pull"]).status.success());
    assert_eq!(fs::read(vault_root.join("a.txt")).unwrap(), b"version two, somewhat longer");
}

#[test]
fn rm_removes_files_and_subtrees_remotely_only() {
    let tmp = tempfile::tempdir().unwrap();
    let (storage_dir, config_home, vault_root) = setup(tmp.path());
    fs::write(vault_root.join("a.txt"), b"keep me").unwrap();
    fs::create_dir_all(vault_root.join("docs/sub")).unwrap();
    fs::write(vault_root.join("docs/b.txt"), b"doc b").unwrap();
    fs::write(vault_root.join("docs/sub/c.txt"), b"doc c").unwrap();

    let (vault_id, vault_credential) = create_vault(&storage_dir);
    let server = Nookd::start(&storage_dir);
    init_and_set_root(&config_home, &server.url(), &vault_id, &vault_credential, &vault_root);
    assert!(run_nook(&config_home, &["push"]).status.success());

    let objects_dir = storage_dir.join("objects");
    assert_eq!(stored_object_files(&objects_dir).len(), 4, "head + three content objects");

    // Remove a single file.
    let rm = run_nook(&config_home, &["rm", "docs/b.txt"]);
    assert!(rm.status.success(), "rm file failed: {rm:?}");
    let ls = run_nook(&config_home, &["ls", "docs"]);
    assert!(ls.status.success());
    assert!(!String::from_utf8_lossy(&ls.stdout).contains("b.txt"));
    assert_eq!(stored_object_files(&objects_dir).len(), 3);
    assert!(vault_root.join("docs/b.txt").exists(), "rm must never touch local files");

    // Remove a directory subtree.
    let rm = run_nook(&config_home, &["rm", "docs"]);
    assert!(rm.status.success(), "rm dir failed: {rm:?}");
    let tree = run_nook(&config_home, &["tree"]);
    assert!(tree.status.success());
    let tree_out = String::from_utf8_lossy(&tree.stdout).to_string();
    assert!(!tree_out.contains("docs"), "tree still shows docs: {tree_out}");
    assert!(tree_out.contains("a.txt"));
    assert_eq!(stored_object_files(&objects_dir).len(), 2);
    assert!(vault_root.join("docs/sub/c.txt").exists());

    // Missing path fails without server writes.
    let before = stored_object_files(&objects_dir).len();
    let rm = run_nook(&config_home, &["rm", "no/such/path"]);
    assert!(!rm.status.success(), "rm of a missing path must fail");
    assert_eq!(stored_object_files(&objects_dir).len(), before);

    // Bare rm is a usage error, no server writes.
    let rm = run_nook(&config_home, &["rm"]);
    assert!(!rm.status.success(), "bare rm must be rejected");
    assert_eq!(stored_object_files(&objects_dir).len(), before);
}

#[test]
fn grace_window_protects_fresh_orphans_and_reclaims_old_ones() {
    let tmp = tempfile::tempdir().unwrap();
    let (storage_dir, config_home, vault_root) = setup(tmp.path());
    fs::write(vault_root.join("a.txt"), b"content").unwrap();

    let (vault_id, vault_credential) = create_vault(&storage_dir);
    let server = Nookd::start(&storage_dir);
    init_and_set_root(&config_home, &server.url(), &vault_id, &vault_credential, &vault_root);
    assert!(run_nook(&config_home, &["push"]).status.success());

    // Plant an orphan, as if another pusher uploaded it but hasn't linked it
    // into a manifest yet.
    let namespace_id = namespace_id_from_config(&config_home);
    let orphan_id = random_hex_id();
    put_orphan(&server.url(), &vault_id, &vault_credential, &namespace_id, &orphan_id);
    let orphan_path = storage_dir.join("objects").join(&vault_id).join(&namespace_id).join(&orphan_id);
    assert!(orphan_path.exists());

    // A sweep with the default (24 h) grace window must not touch it.
    assert!(run_nook(&config_home, &["push"]).status.success());
    assert!(orphan_path.exists(), "fresh orphan must survive the grace window");

    // Once older than the window, it is reclaimed.
    std::thread::sleep(std::time::Duration::from_secs(2));
    let push = run_nook_env(&config_home, &[("NOOK_GC_GRACE_SECONDS", "1")], &["push"]);
    assert!(push.status.success(), "push failed: {push:?}");
    assert!(!orphan_path.exists(), "aged orphan must be reclaimed");
}

#[test]
fn manifest_head_survives_emptying_the_namespace() {
    let tmp = tempfile::tempdir().unwrap();
    let (storage_dir, config_home, vault_root) = setup(tmp.path());
    fs::write(vault_root.join("only.txt"), b"soon gone").unwrap();

    let (vault_id, vault_credential) = create_vault(&storage_dir);
    let server = Nookd::start(&storage_dir);
    init_and_set_root(&config_home, &server.url(), &vault_id, &vault_credential, &vault_root);
    assert!(run_nook(&config_home, &["push"]).status.success());

    let rm = run_nook(&config_home, &["rm", "only.txt"]);
    assert!(rm.status.success(), "rm failed: {rm:?}");

    let objects_dir = storage_dir.join("objects");
    assert_eq!(
        stored_object_files(&objects_dir).len(),
        1,
        "exactly the manifest head object must remain"
    );
    let ls = run_nook(&config_home, &["ls"]);
    assert!(ls.status.success(), "ls after emptying must still work: {ls:?}");
}

/// A minimal stand-in for a pre-SPEC-005 `nookd`: serves the object API
/// (unauthenticated, since the client under test signs anyway) but has no
/// DELETE verb and no listing route.
fn start_legacy_server() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let _ = handle_legacy_conn(stream);
            });
        }
    });
    format!("http://127.0.0.1:{}", addr.port())
}

fn handle_legacy_conn(stream: std::net::TcpStream) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut stream = stream;
    loop {
        let mut request_line = String::new();
        if reader.read_line(&mut request_line)? == 0 {
            return Ok(());
        }
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("").to_string();

        let mut content_length = 0usize;
        loop {
            let mut header = String::new();
            if reader.read_line(&mut header)? == 0 {
                return Ok(());
            }
            let header = header.trim().to_ascii_lowercase();
            if header.is_empty() {
                break;
            }
            if let Some(v) = header.strip_prefix("content-length:") {
                content_length = v.trim().parse().unwrap_or(0);
            }
        }
        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body)?;

        let response = match method.as_str() {
            // Old servers accept uploads normally...
            "PUT" => "HTTP/1.1 201 Created\r\nETag: 1\r\nContent-Length: 0\r\n\r\n",
            // ...but the obj route has no DELETE verb (405, matching axum's
            // behavior for a known path with an unrouted method)...
            "DELETE" => "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n",
            // ...and neither the manifest (fresh vault) nor the listing
            // route exist (404).
            _ => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
        };
        stream.write_all(response.as_bytes())?;
        stream.flush()?;
    }
}

#[test]
fn push_against_pre_deletion_server_succeeds_with_warning() {
    let tmp = tempfile::tempdir().unwrap();
    let (_storage_dir, config_home, vault_root) = setup(tmp.path());
    fs::write(vault_root.join("a.txt"), b"content").unwrap();

    let server_url = start_legacy_server();
    // Any well-formed vault identity works; the legacy stand-in doesn't
    // verify signatures.
    let vault_id = random_hex_id();
    let credential = random_hex_id();
    init_and_set_root(&config_home, &server_url, &vault_id, &credential, &vault_root);

    let push = run_nook(&config_home, &["push"]);
    assert!(
        push.status.success(),
        "push must succeed even when the server lacks SPEC-005 endpoints: {push:?}"
    );
    let stderr = String::from_utf8_lossy(&push.stderr);
    assert!(
        stderr.contains("could not list namespace objects"),
        "expected a skipped-cleanup warning, got: {stderr}"
    );
}
