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
    fn start(storage: &std::path::Path, quota_bytes: Option<u64>) -> Self {
        let addr = free_addr();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_nookd"));
        cmd.args(["serve", "--listen", &addr, "--storage"])
            .arg(storage)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        if let Some(quota) = quota_bytes {
            cmd.args(["--quota-bytes", &quota.to_string()]);
        }
        let child = cmd.spawn().expect("failed to spawn nookd serve");
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

/// Runs `nookd vault create` against the same storage dir and parses the
/// printed `vault_id`/`vault_credential` (hex-encoded).
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

fn revoke_vault(storage: &std::path::Path, vault_id: &str) {
    let out = Command::new(env!("CARGO_BIN_EXE_nookd"))
        .args(["vault", "revoke", vault_id, "--storage"])
        .arg(storage)
        .output()
        .expect("failed to run nookd vault revoke");
    assert!(out.status.success(), "vault revoke failed: {out:?}");
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

    fn url(&self, namespace_id: &str, object_id: &str) -> String {
        format!("{}{}", self.base, nook_core::object_path(&self.vault_id, namespace_id, object_id))
    }

    fn path(&self, namespace_id: &str, object_id: &str) -> String {
        nook_core::object_path(&self.vault_id, namespace_id, object_id)
    }

    fn put(&self, namespace_id: &str, object_id: &str, body: &'static str) -> reqwest::blocking::Response {
        let timestamp = now_unix();
        let path = self.path(namespace_id, object_id);
        let sig = nook_core::sign_request(&self.credential, "PUT", &path, timestamp, body.as_bytes());
        self.client
            .put(self.url(namespace_id, object_id))
            .header("X-Nook-Timestamp", timestamp.to_string())
            .header("X-Nook-Signature", sig)
            .body(body)
            .send()
            .unwrap()
    }

    fn get(&self, namespace_id: &str, object_id: &str) -> reqwest::blocking::Response {
        let timestamp = now_unix();
        let path = self.path(namespace_id, object_id);
        let sig = nook_core::sign_request(&self.credential, "GET", &path, timestamp, b"");
        self.client
            .get(self.url(namespace_id, object_id))
            .header("X-Nook-Timestamp", timestamp.to_string())
            .header("X-Nook-Signature", sig)
            .send()
            .unwrap()
    }
}

fn db_row(db_path: &PathBuf, vault_id: &str, namespace_id: &str, object_id: &str) -> Option<(i64, i64, i64, i64)> {
    let conn = Connection::open(db_path).unwrap();
    conn.query_row(
        "SELECT size, etag, created_at, updated_at FROM objects WHERE vault_id = ?1 AND namespace_id = ?2 AND object_id = ?3",
        (vault_id, namespace_id, object_id),
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )
    .ok()
}

#[test]
fn signed_request_round_trip_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let (vault_id, credential) = create_vault(tmp.path(), None);
    let server = Nookd::start(tmp.path(), None);
    let client = SignedClient::new(&server.addr, &vault_id, credential);
    let ns = random_hex_id();
    let obj = random_hex_id();

    let put_res = client.put(&ns, &obj, "hello");
    assert_eq!(put_res.status(), 201);

    let get_res = client.get(&ns, &obj);
    assert_eq!(get_res.status(), 200);
    assert_eq!(get_res.text().unwrap(), "hello");
}

#[test]
fn missing_signature_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let (vault_id, _credential) = create_vault(tmp.path(), None);
    let server = Nookd::start(tmp.path(), None);
    let http = reqwest::blocking::Client::new();
    let ns = random_hex_id();
    let obj = random_hex_id();
    let url = format!("http://{}{}", server.addr, nook_core::object_path(&vault_id, &ns, &obj));

    let res = http.put(&url).body("hello").send().unwrap();
    assert_eq!(res.status(), 401);
}

#[test]
fn nonexistent_and_wrong_credential_are_indistinguishable() {
    let tmp = tempfile::tempdir().unwrap();
    let (real_vault_id, real_credential) = create_vault(tmp.path(), None);
    let server = Nookd::start(tmp.path(), None);
    let ns = random_hex_id();
    let obj = random_hex_id();

    // Real vault, wrong credential.
    let wrong_credential = vec![0u8; 32];
    let wrong_client = SignedClient::new(&server.addr, &real_vault_id, wrong_credential);
    let wrong_cred_res = wrong_client.get(&ns, &obj);

    // Nonexistent vault, made-up credential.
    let fake_vault_id = random_hex_id();
    let fake_client = SignedClient::new(&server.addr, &fake_vault_id, real_credential);
    let fake_vault_res = fake_client.get(&ns, &obj);

    assert_eq!(wrong_cred_res.status(), 401);
    assert_eq!(fake_vault_res.status(), 401);
    assert_eq!(wrong_cred_res.status(), fake_vault_res.status());
}

#[test]
fn revoked_vault_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let (vault_id, credential) = create_vault(tmp.path(), None);
    let server = Nookd::start(tmp.path(), None);
    let client = SignedClient::new(&server.addr, &vault_id, credential.clone());
    let ns = random_hex_id();
    let obj = random_hex_id();

    assert_eq!(client.put(&ns, &obj, "hello").status(), 201);

    revoke_vault(tmp.path(), &vault_id);

    let res = client.get(&ns, &obj);
    assert_eq!(res.status(), 401);
}

#[test]
fn same_object_id_under_different_vaults_or_namespaces_does_not_collide() {
    let tmp = tempfile::tempdir().unwrap();
    let (vault_a, cred_a) = create_vault(tmp.path(), None);
    let (vault_b, cred_b) = create_vault(tmp.path(), None);
    let server = Nookd::start(tmp.path(), None);
    let client_a = SignedClient::new(&server.addr, &vault_a, cred_a);
    let client_b = SignedClient::new(&server.addr, &vault_b, cred_b);
    let ns = random_hex_id();
    let obj = random_hex_id();

    assert_eq!(client_a.put(&ns, &obj, "from vault a").status(), 201);
    assert_eq!(client_b.put(&ns, &obj, "from vault b").status(), 201);

    assert_eq!(client_a.get(&ns, &obj).text().unwrap(), "from vault a");
    assert_eq!(client_b.get(&ns, &obj).text().unwrap(), "from vault b");
}

#[test]
fn timestamps_populate_on_create_and_update() {
    let tmp = tempfile::tempdir().unwrap();
    let (vault_id, credential) = create_vault(tmp.path(), None);
    let server = Nookd::start(tmp.path(), None);
    let client = SignedClient::new(&server.addr, &vault_id, credential);
    let ns = random_hex_id();
    let obj = random_hex_id();
    let db_path = tmp.path().join("meta.sqlite");

    assert_eq!(client.put(&ns, &obj, "first").status(), 201);
    let (_, _, created_at, updated_at) = db_row(&db_path, &vault_id, &ns, &obj).expect("row after create");
    assert!(created_at > 0);
    assert_eq!(created_at, updated_at);

    std::thread::sleep(Duration::from_millis(1100));

    assert_eq!(client.put(&ns, &obj, "second-longer").status(), 200);
    let (_, _, created_at2, updated_at2) = db_row(&db_path, &vault_id, &ns, &obj).expect("row after update");
    assert_eq!(created_at2, created_at);
    assert!(updated_at2 > updated_at);
}

#[test]
fn oversized_upload_is_rejected_without_partial_writes() {
    let tmp = tempfile::tempdir().unwrap();
    let (vault_id, credential) = create_vault(tmp.path(), Some(10));
    let server = Nookd::start(tmp.path(), None);
    let client = SignedClient::new(&server.addr, &vault_id, credential);
    let ns = random_hex_id();

    let small_obj = random_hex_id();
    assert_eq!(client.put(&ns, &small_obj, "12345").status(), 201);

    let big_obj = random_hex_id();
    let res = client.put(&ns, &big_obj, "this payload is definitely over ten bytes");
    assert_eq!(res.status(), 507);

    assert_eq!(client.get(&ns, &big_obj).status(), 404);

    let temp_dir = tmp.path().join("temp");
    let leftover: Vec<_> = std::fs::read_dir(&temp_dir).unwrap().map(|e| e.unwrap().path()).collect();
    assert!(leftover.is_empty(), "temp dir must be clean after a rejected upload: {leftover:?}");

    assert_eq!(client.get(&ns, &small_obj).status(), 200);
}

#[test]
fn quota_is_independent_per_vault() {
    let tmp = tempfile::tempdir().unwrap();
    let (vault_a, cred_a) = create_vault(tmp.path(), Some(10));
    let (vault_b, cred_b) = create_vault(tmp.path(), Some(1000));
    let server = Nookd::start(tmp.path(), None);
    let client_a = SignedClient::new(&server.addr, &vault_a, cred_a);
    let client_b = SignedClient::new(&server.addr, &vault_b, cred_b);
    let ns = random_hex_id();

    // Exhaust vault A's tiny quota.
    assert_eq!(client_a.put(&ns, &random_hex_id(), "1234567890").status(), 201);
    let over_res = client_a.put(&ns, &random_hex_id(), "one more byte!");
    assert_eq!(over_res.status(), 507);

    // Vault B is unaffected.
    assert_eq!(client_b.put(&ns, &random_hex_id(), "plenty of room here").status(), 201);
}
