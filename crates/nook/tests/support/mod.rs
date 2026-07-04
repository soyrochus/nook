// Shared across multiple integration test binaries; not every binary uses
// every helper.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::Duration;

/// `nookd` is a different workspace package, so Cargo does not set
/// `CARGO_BIN_EXE_nookd` for `nook`'s integration tests (that mechanism only
/// covers binaries of the current package). Locate (building if necessary)
/// the sibling binary via the workspace target directory instead.
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
        .args(["build", "-p", bin_name])
        .current_dir(&root)
        .status()
        .expect("failed to invoke cargo build");
    assert!(status.success(), "cargo build -p {bin_name} failed");
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
            .args(["--listen", &addr, "--storage"])
            .arg(storage)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn nookd");
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

/// Runs `nook` as a subprocess with an isolated config directory (via
/// `XDG_CONFIG_HOME`, honored by the `directories` crate on Linux) and a
/// fixed passphrase, so tests never touch the real user config or block on
/// an interactive prompt regardless of whether an OS keychain is present.
pub fn run_nook(config_home: &Path, args: &[&str]) -> Output {
    let bin = ensure_built("nook");
    Command::new(bin)
        .args(args)
        .env("XDG_CONFIG_HOME", config_home)
        .env("NOOK_PASSPHRASE", "test-passphrase-not-for-real-use")
        .output()
        .expect("failed to run nook")
}
