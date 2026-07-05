// Shared across multiple integration test binaries; not every binary uses
// every helper.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::Duration;

/// Locate a package binary, building it if necessary.
pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

pub fn ensure_built(bin_name: &str) -> PathBuf {
    let root = workspace_root();
    for profile in ["debug", "release"] {
        let path = root.join("target").join(profile).join(bin_name);
        if path.exists() {
            return path;
        }
    }
    let status = Command::new(env!("CARGO"))
        .args(["build", "-p", "nook-vault", "--bin", bin_name])
        .current_dir(&root)
        .status()
        .expect("failed to invoke cargo build");
    assert!(
        status.success(),
        "cargo build -p nook-vault --bin {bin_name} failed"
    );
    root.join("target/debug").join(bin_name)
}

pub fn free_addr() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    format!("127.0.0.1:{}", addr.port())
}

pub struct Nookd {
    child: Child,
    addr: String,
}

impl Nookd {
    pub fn start(storage: &Path) -> Self {
        let bin = ensure_built("nookd");
        let addr = free_addr();
        let child = Command::new(bin)
            .args(["serve", "--listen", &addr, "--storage"])
            .arg(storage)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
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

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

impl Drop for Nookd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Runs `nookd vault create --storage <dir>` and parses the printed
/// `vault_id`/`vault_credential` (hex-encoded), for use with `nook init
/// --vault-id ... --vault-credential ...` in tests.
pub fn create_vault(storage: &Path) -> (String, String) {
    let bin = ensure_built("nookd");
    let out = Command::new(bin)
        .args(["vault", "create", "--storage"])
        .arg(storage)
        .output()
        .expect("failed to run nookd vault create");
    assert!(out.status.success(), "nookd vault create failed: {out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let vault_id = stdout
        .lines()
        .find_map(|l| l.strip_prefix("vault_id:         "))
        .expect("vault_id in output")
        .trim()
        .to_string();
    let vault_credential = stdout
        .lines()
        .find_map(|l| l.strip_prefix("vault_credential: "))
        .expect("vault_credential in output")
        .trim()
        .to_string();
    (vault_id, vault_credential)
}

/// Runs `nook` as a subprocess with an isolated config directory (via
/// `XDG_CONFIG_HOME`, honored by the `directories` crate on Linux) and a
/// fixed passphrase, so tests never touch the real user config or block on
/// an interactive prompt regardless of whether an OS keychain is present.
pub fn run_nook(config_home: &Path, args: &[&str]) -> Output {
    run_nook_env(config_home, &[], args)
}

/// Like [`run_nook`], with extra environment variables (e.g.
/// `NOOK_GC_GRACE_SECONDS` for sweep tests).
pub fn run_nook_env(config_home: &Path, extra_env: &[(&str, &str)], args: &[&str]) -> Output {
    let bin = ensure_built("nook");
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .env("XDG_CONFIG_HOME", config_home)
        .env("NOOK_PASSPHRASE", "test-passphrase-not-for-real-use");
    for (key, value) in extra_env {
        cmd.env(key, value);
    }
    cmd.output().expect("failed to run nook")
}
