use rusqlite::Connection;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;

fn free_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    format!("127.0.0.1:{}", addr.port())
}

struct Nookd {
    child: Child,
    addr: String,
}

impl Nookd {
    fn start(storage: &std::path::Path, quota_bytes: Option<u64>) -> Self {
        let addr = free_addr();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_nookd"));
        cmd.args(["--listen", &addr, "--storage"])
            .arg(storage)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        if let Some(quota) = quota_bytes {
            cmd.args(["--quota-bytes", &quota.to_string()]);
        }
        let child = cmd.spawn().expect("failed to spawn nookd");
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

    fn url(&self, object_id: &str) -> String {
        format!("http://{}/v1/obj/{object_id}", self.addr)
    }
}

impl Drop for Nookd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn object_id(byte: u8) -> String {
    hex::encode([byte; 32])
}

fn meta_row(db_path: &PathBuf, object_id: &str) -> Option<(i64, i64, i64, i64)> {
    let conn = Connection::open(db_path).unwrap();
    conn.query_row(
        "SELECT size, etag, created_at, updated_at FROM objects WHERE object_id = ?1",
        [object_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )
    .ok()
}

#[test]
fn timestamps_populate_on_create_and_update() {
    let tmp = tempfile::tempdir().unwrap();
    let server = Nookd::start(tmp.path(), None);
    let client = reqwest::blocking::Client::new();
    let id = object_id(1);
    let db_path = tmp.path().join("meta.sqlite");

    let res = client.put(server.url(&id)).body("first").send().unwrap();
    assert_eq!(res.status(), 201);
    let (_, _, created_at, updated_at) = meta_row(&db_path, &id).expect("row after create");
    assert!(created_at > 0);
    assert_eq!(created_at, updated_at);

    // Ensure the next write lands in a different unix-second bucket so
    // updated_at is observably different from created_at.
    std::thread::sleep(Duration::from_millis(1100));

    let res = client.put(server.url(&id)).body("second-longer").send().unwrap();
    assert_eq!(res.status(), 200);
    let (_, _, created_at2, updated_at2) = meta_row(&db_path, &id).expect("row after update");
    assert_eq!(created_at2, created_at, "created_at must not change on overwrite");
    assert!(updated_at2 > updated_at, "updated_at must advance on overwrite");
}

#[test]
fn oversized_upload_is_rejected_without_partial_writes() {
    let tmp = tempfile::tempdir().unwrap();
    // Small enough that a modest payload trips it, generous enough that the
    // first (accepted) object fits.
    let server = Nookd::start(tmp.path(), Some(10));
    let client = reqwest::blocking::Client::new();

    let small_id = object_id(2);
    let res = client.put(server.url(&small_id)).body("12345").send().unwrap();
    assert_eq!(res.status(), 201, "5-byte upload should fit under a 10-byte quota");

    let big_id = object_id(3);
    let res = client
        .put(server.url(&big_id))
        .body("this payload is definitely over ten bytes")
        .send()
        .unwrap();
    assert_eq!(res.status(), 507, "oversized upload must be rejected with 507 Insufficient Storage");

    // Rejected object must not be readable...
    let get_res = client.get(server.url(&big_id)).send().unwrap();
    assert_eq!(get_res.status(), 404);

    // ...and must leave no temp file behind.
    let temp_dir = tmp.path().join("temp");
    let leftover: Vec<_> = std::fs::read_dir(&temp_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert!(leftover.is_empty(), "temp dir must be clean after a rejected upload: {leftover:?}");

    // The accepted object must be unaffected.
    let get_small = client.get(server.url(&small_id)).send().unwrap();
    assert_eq!(get_small.status(), 200);
}
