//! SPEC-005 server-side tests: the `DELETE` object verb and the
//! namespace-scoped listing endpoint.

use rand::rngs::OsRng;
use rand::RngCore;
use rusqlite::Connection;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn free_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    format!("127.0.0.1:{}", addr.port())
}

fn random_hex_id() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

struct Nookd {
    child: Child,
    addr: String,
}

impl Nookd {
    fn start(storage: &std::path::Path) -> Self {
        let addr = free_addr();
        let child = Command::new(env!("CARGO_BIN_EXE_nookd"))
            .args(["serve", "--listen", &addr, "--storage"])
            .arg(storage)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("failed to spawn nookd serve");
        let server = Nookd { child, addr };
        server.wait_ready();
        server
    }

    fn wait_ready(&self) {
        for _ in 0..100 {
            if std::net::TcpStream::connect(&self.addr).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("nookd did not become ready in time");
    }
}

impl Drop for Nookd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn create_vault(storage: &std::path::Path, quota_bytes: Option<u64>) -> (String, Vec<u8>) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_nookd"));
    cmd.args(["vault", "create", "--storage"]).arg(storage);
    if let Some(quota) = quota_bytes {
        cmd.args(["--quota-bytes", &quota.to_string()]);
    }
    let out = cmd.output().expect("failed to run nookd vault create");
    assert!(out.status.success(), "vault create failed: {out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let vault_id = stdout
        .lines()
        .find_map(|l| l.strip_prefix("vault_id:         "))
        .expect("vault_id in output")
        .trim()
        .to_string();
    let credential_hex = stdout
        .lines()
        .find_map(|l| l.strip_prefix("vault_credential: "))
        .expect("vault_credential in output")
        .trim()
        .to_string();
    (vault_id, hex::decode(credential_hex).unwrap())
}

struct SignedClient {
    client: reqwest::blocking::Client,
    base: String,
    vault_id: String,
    credential: Vec<u8>,
}

impl SignedClient {
    fn new(addr: &str, vault_id: &str, credential: Vec<u8>) -> Self {
        SignedClient {
            client: reqwest::blocking::Client::new(),
            base: format!("http://{addr}"),
            vault_id: vault_id.to_string(),
            credential,
        }
    }

    fn signed(&self, method: reqwest::Method, path: &str, body: &'static [u8]) -> reqwest::blocking::Response {
        let timestamp = now_unix();
        let sig = nook_core::sign_request(&self.credential, method.as_str(), path, timestamp, body);
        self.client
            .request(method, format!("{}{}", self.base, path))
            .header("X-Nook-Timestamp", timestamp.to_string())
            .header("X-Nook-Signature", sig)
            .body(body)
            .send()
            .unwrap()
    }

    fn put(&self, namespace_id: &str, object_id: &str, body: &'static str) -> reqwest::blocking::Response {
        let path = nook_core::object_path(&self.vault_id, namespace_id, object_id);
        self.signed(reqwest::Method::PUT, &path, body.as_bytes())
    }

    fn get(&self, namespace_id: &str, object_id: &str) -> reqwest::blocking::Response {
        let path = nook_core::object_path(&self.vault_id, namespace_id, object_id);
        self.signed(reqwest::Method::GET, &path, b"")
    }

    fn delete(&self, namespace_id: &str, object_id: &str) -> reqwest::blocking::Response {
        let path = nook_core::object_path(&self.vault_id, namespace_id, object_id);
        self.signed(reqwest::Method::DELETE, &path, b"")
    }

    fn list(&self, namespace_id: &str) -> reqwest::blocking::Response {
        let path = nook_core::namespace_objects_path(&self.vault_id, namespace_id);
        self.signed(reqwest::Method::GET, &path, b"")
    }
}

fn bytes_used(db_path: &PathBuf, vault_id: &str) -> i64 {
    let conn = Connection::open(db_path).unwrap();
    conn.query_row("SELECT bytes_used FROM vaults WHERE vault_id = ?1", [vault_id], |row| row.get(0))
        .unwrap()
}

#[test]
fn delete_removes_object_and_frees_quota() {
    let tmp = tempfile::tempdir().unwrap();
    let (vault_id, credential) = create_vault(tmp.path(), None);
    let server = Nookd::start(tmp.path());
    let client = SignedClient::new(&server.addr, &vault_id, credential);
    let db_path = tmp.path().join("meta.sqlite");
    let ns = random_hex_id();
    let obj = random_hex_id();

    assert_eq!(client.put(&ns, &obj, "hello").status(), 201);
    let used_before = bytes_used(&db_path, &vault_id);

    let res = client.delete(&ns, &obj);
    assert_eq!(res.status(), 204);

    assert_eq!(client.get(&ns, &obj).status(), 404);
    assert_eq!(bytes_used(&db_path, &vault_id), used_before - "hello".len() as i64);
}

#[test]
fn delete_missing_object_is_404_without_metadata_change() {
    let tmp = tempfile::tempdir().unwrap();
    let (vault_id, credential) = create_vault(tmp.path(), None);
    let server = Nookd::start(tmp.path());
    let client = SignedClient::new(&server.addr, &vault_id, credential);
    let db_path = tmp.path().join("meta.sqlite");
    let ns = random_hex_id();

    assert_eq!(client.put(&ns, &random_hex_id(), "keep").status(), 201);
    let used_before = bytes_used(&db_path, &vault_id);

    let res = client.delete(&ns, &random_hex_id());
    assert_eq!(res.status(), 404);
    assert_eq!(bytes_used(&db_path, &vault_id), used_before);
}

#[test]
fn unsigned_or_badly_signed_delete_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let (vault_id, credential) = create_vault(tmp.path(), None);
    let server = Nookd::start(tmp.path());
    let client = SignedClient::new(&server.addr, &vault_id, credential);
    let ns = random_hex_id();
    let obj = random_hex_id();

    assert_eq!(client.put(&ns, &obj, "hello").status(), 201);

    // Unsigned.
    let http = reqwest::blocking::Client::new();
    let url = format!("http://{}{}", server.addr, nook_core::object_path(&vault_id, &ns, &obj));
    assert_eq!(http.delete(&url).send().unwrap().status(), 401);

    // Wrong credential.
    let wrong = SignedClient::new(&server.addr, &vault_id, vec![0u8; 32]);
    assert_eq!(wrong.delete(&ns, &obj).status(), 401);

    // Object untouched by either attempt.
    assert_eq!(client.get(&ns, &obj).status(), 200);
}

#[test]
fn delete_does_not_cross_vault_or_namespace_boundaries() {
    let tmp = tempfile::tempdir().unwrap();
    let (vault_a, cred_a) = create_vault(tmp.path(), None);
    let (vault_b, cred_b) = create_vault(tmp.path(), None);
    let server = Nookd::start(tmp.path());
    let client_a = SignedClient::new(&server.addr, &vault_a, cred_a);
    let client_b = SignedClient::new(&server.addr, &vault_b, cred_b);
    let ns = random_hex_id();
    let other_ns = random_hex_id();
    let obj = random_hex_id();

    assert_eq!(client_a.put(&ns, &obj, "vault a").status(), 201);
    assert_eq!(client_a.put(&other_ns, &obj, "other ns").status(), 201);
    assert_eq!(client_b.put(&ns, &obj, "vault b").status(), 201);

    assert_eq!(client_a.delete(&ns, &obj).status(), 204);

    assert_eq!(client_a.get(&other_ns, &obj).text().unwrap(), "other ns");
    assert_eq!(client_b.get(&ns, &obj).text().unwrap(), "vault b");
}

#[test]
fn quota_full_vault_becomes_writable_after_delete() {
    let tmp = tempfile::tempdir().unwrap();
    let (vault_id, credential) = create_vault(tmp.path(), Some(10));
    let server = Nookd::start(tmp.path());
    let client = SignedClient::new(&server.addr, &vault_id, credential);
    let ns = random_hex_id();

    let filler = random_hex_id();
    assert_eq!(client.put(&ns, &filler, "1234567890").status(), 201);
    assert_eq!(client.put(&ns, &random_hex_id(), "x").status(), 507);

    assert_eq!(client.delete(&ns, &filler).status(), 204);

    assert_eq!(client.put(&ns, &random_hex_id(), "1234567890").status(), 201);
}

#[test]
fn listing_returns_namespace_objects_with_expected_fields() {
    let tmp = tempfile::tempdir().unwrap();
    let (vault_id, credential) = create_vault(tmp.path(), None);
    let server = Nookd::start(tmp.path());
    let client = SignedClient::new(&server.addr, &vault_id, credential);
    let ns = random_hex_id();
    let obj_a = random_hex_id();
    let obj_b = random_hex_id();

    assert_eq!(client.put(&ns, &obj_a, "aaa").status(), 201);
    assert_eq!(client.put(&ns, &obj_b, "bbbbb").status(), 201);

    let res = client.list(&ns);
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().unwrap();

    let server_time = body["server_time"].as_i64().expect("server_time present");
    assert!((server_time - now_unix()).abs() < 60);

    let objects = body["objects"].as_array().expect("objects array");
    assert_eq!(objects.len(), 2);
    for entry in objects {
        let map = entry.as_object().unwrap();
        assert_eq!(map.len(), 3, "exactly object_id/size/updated_at: {map:?}");
        assert!(map["updated_at"].as_i64().unwrap() > 0);
    }
    let sizes: std::collections::HashMap<&str, i64> = objects
        .iter()
        .map(|e| (e["object_id"].as_str().unwrap(), e["size"].as_i64().unwrap()))
        .collect();
    assert_eq!(sizes[obj_a.as_str()], 3);
    assert_eq!(sizes[obj_b.as_str()], 5);
}

#[test]
fn listing_empty_or_unknown_namespace_is_empty_200() {
    let tmp = tempfile::tempdir().unwrap();
    let (vault_id, credential) = create_vault(tmp.path(), None);
    let server = Nookd::start(tmp.path());
    let client = SignedClient::new(&server.addr, &vault_id, credential);

    let res = client.list(&random_hex_id());
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().unwrap();
    assert_eq!(body["objects"].as_array().unwrap().len(), 0);
}

#[test]
fn unsigned_listing_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let (vault_id, _credential) = create_vault(tmp.path(), None);
    let server = Nookd::start(tmp.path());
    let http = reqwest::blocking::Client::new();
    let url = format!(
        "http://{}{}",
        server.addr,
        nook_core::namespace_objects_path(&vault_id, &random_hex_id())
    );
    assert_eq!(http.get(&url).send().unwrap().status(), 401);
}

#[test]
fn listing_does_not_leak_other_vaults_or_namespaces() {
    let tmp = tempfile::tempdir().unwrap();
    let (vault_a, cred_a) = create_vault(tmp.path(), None);
    let (vault_b, cred_b) = create_vault(tmp.path(), None);
    let server = Nookd::start(tmp.path());
    let client_a = SignedClient::new(&server.addr, &vault_a, cred_a);
    let client_b = SignedClient::new(&server.addr, &vault_b, cred_b);
    let ns = random_hex_id();
    let mine = random_hex_id();

    assert_eq!(client_a.put(&ns, &mine, "mine").status(), 201);
    assert_eq!(client_a.put(&random_hex_id(), &random_hex_id(), "other ns").status(), 201);
    assert_eq!(client_b.put(&ns, &random_hex_id(), "other vault, same ns id").status(), 201);

    let body: serde_json::Value = client_a.list(&ns).json().unwrap();
    let objects = body["objects"].as_array().unwrap();
    assert_eq!(objects.len(), 1);
    assert_eq!(objects[0]["object_id"].as_str().unwrap(), mine);
}
