use anyhow::{Context, Result};
use axum::{
    body::Body,
    extract::{Path, State},
    http::header::{CONTENT_LENGTH, ETAG, IF_MATCH},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use clap::{Parser, Subcommand};
use futures_util::StreamExt;
use rand::rngs::OsRng;
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::path::{Path as FsPath, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::task;
use tokio_util::io::ReaderStream;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

/// How far a request's `X-Nook-Timestamp` may drift from the server's clock
/// before it's rejected. Bounds replay exposure without a nonce store (see
/// SPEC-004 §4): a replayed GET discloses nothing new, a replayed PUT is
/// still caught by CAS.
const MAX_TIMESTAMP_SKEW_SECS: i64 = 300;

#[derive(Parser)]
#[command(author, version, about = "nookd — encrypted push/pull vault server")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the server.
    Serve {
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: String,
        /// Directory holding the object store and meta.sqlite. Also settable
        /// via NOOK_DATA_DIR (used by the container image, where it should
        /// point at a mounted volume for durable storage).
        #[arg(long, env = "NOOK_DATA_DIR", default_value = "storage")]
        storage: PathBuf,
        /// Default per-vault quota in bytes for vaults created without an
        /// explicit `--quota-bytes`. Unset means unlimited.
        #[arg(long, env = "NOOK_QUOTA_BYTES")]
        quota_bytes: Option<u64>,
    },
    /// Manage server-side vaults (access/storage containers). Deliberately
    /// local-CLI-only, never a network endpoint (SPEC-004 §3).
    Vault {
        #[command(subcommand)]
        action: VaultCommand,
    },
}

#[derive(Subcommand)]
enum VaultCommand {
    /// Create a new vault, printing its ID and credential exactly once.
    Create {
        #[arg(long)]
        quota_bytes: Option<u64>,
        #[arg(long, env = "NOOK_DATA_DIR", default_value = "storage")]
        storage: PathBuf,
    },
    /// List known vaults and their usage. Never prints credentials.
    List {
        #[arg(long, env = "NOOK_DATA_DIR", default_value = "storage")]
        storage: PathBuf,
    },
    /// Revoke a vault's credential. Stored data is retained.
    Revoke {
        vault_id: String,
        #[arg(long, env = "NOOK_DATA_DIR", default_value = "storage")]
        storage: PathBuf,
    },
}

#[derive(Clone)]
struct AppState {
    objects_dir: PathBuf,
    temp_dir: PathBuf,
    db_path: PathBuf,
    default_quota_bytes: Option<u64>,
}

struct VaultRecord {
    credential: Vec<u8>,
    quota_bytes: Option<i64>,
    revoked: bool,
}

#[derive(Debug, Clone)]
struct ObjectMeta {
    size: i64,
    etag: i64,
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("nookd=info".parse()?))
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Serve {
            listen,
            storage,
            quota_bytes,
        } => run_server(listen, storage, quota_bytes).await,
        Command::Vault { action } => run_vault_command(action),
    }
}

async fn run_server(listen: String, storage: PathBuf, default_quota_bytes: Option<u64>) -> Result<()> {
    let objects_dir = storage.join("objects");
    let temp_dir = storage.join("temp");
    let db_path = storage.join("meta.sqlite");

    fs::create_dir_all(&objects_dir)
        .await
        .context("creating objects directory")?;
    fs::create_dir_all(&temp_dir)
        .await
        .context("creating temp directory")?;
    init_db(&db_path)?;

    let state = AppState {
        objects_dir,
        temp_dir,
        db_path,
        default_quota_bytes,
    };
    let app = Router::new()
        .route(
            "/v1/vault/:vault_id/ns/:namespace_id/obj/:object_id",
            get(handle_get).put(handle_put).head(handle_head),
        )
        .with_state(state);

    info!("listening on {listen}");
    let listener = TcpListener::bind(&listen).await?;
    axum::serve(listener, app).await.context("server failed")?;
    Ok(())
}

/// Vault CLI is a separate, one-shot process invocation that talks to the
/// same `meta.sqlite` a `serve` process may be running against concurrently
/// — this is the first genuinely multi-process access pattern to the DB, so
/// it runs synchronously and relies on `init_db`'s WAL mode + busy timeout
/// for safe concurrent access rather than any in-process coordination.
fn run_vault_command(action: VaultCommand) -> Result<()> {
    match action {
        VaultCommand::Create { quota_bytes, storage } => {
            let db_path = ensure_storage(&storage)?;
            let mut vault_id = [0u8; 32];
            OsRng.fill_bytes(&mut vault_id);
            let mut credential = [0u8; 32];
            OsRng.fill_bytes(&mut credential);
            let vault_id_hex = hex::encode(vault_id);

            let conn = Connection::open(&db_path)?;
            conn.execute(
                "INSERT INTO vaults(vault_id, credential, created_at, quota_bytes, bytes_used, revoked)
                 VALUES (?1, ?2, ?3, ?4, 0, 0)",
                (
                    &vault_id_hex,
                    credential.to_vec(),
                    now_unix(),
                    quota_bytes.map(|q| q as i64),
                ),
            )?;

            println!("vault_id:         {vault_id_hex}");
            println!("vault_credential: {}", hex::encode(credential));
            println!("(the credential above is shown exactly once — store it securely; if lost, revoke this vault and create a new one)");
            Ok(())
        }
        VaultCommand::List { storage } => {
            let db_path = ensure_storage(&storage)?;
            let conn = Connection::open(&db_path)?;
            let mut stmt = conn.prepare(
                "SELECT v.vault_id, v.created_at, v.quota_bytes, v.bytes_used, v.revoked,
                        (SELECT COUNT(DISTINCT namespace_id) FROM objects o WHERE o.vault_id = v.vault_id)
                 FROM vaults v ORDER BY v.created_at",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)? != 0,
                    row.get::<_, i64>(5)?,
                ))
            })?;
            println!(
                "{:<64}  {:<12}  {:<12}  {:<12}  {:<8}  namespaces",
                "vault_id", "created_at", "quota_bytes", "bytes_used", "revoked"
            );
            for row in rows {
                let (vault_id, created_at, quota_bytes, bytes_used, revoked, ns_count) = row?;
                println!(
                    "{:<64}  {:<12}  {:<12}  {:<12}  {:<8}  {}",
                    vault_id,
                    created_at,
                    quota_bytes.map(|q| q.to_string()).unwrap_or_else(|| "unlimited".to_string()),
                    bytes_used,
                    revoked,
                    ns_count
                );
            }
            Ok(())
        }
        VaultCommand::Revoke { vault_id, storage } => {
            let db_path = ensure_storage(&storage)?;
            if !nook_core::is_valid_hex_id(&vault_id) {
                return Err(anyhow::anyhow!("invalid vault_id"));
            }
            let conn = Connection::open(&db_path)?;
            let updated = conn.execute("UPDATE vaults SET revoked = 1 WHERE vault_id = ?1", [&vault_id])?;
            if updated == 0 {
                return Err(anyhow::anyhow!("no such vault: {vault_id}"));
            }
            println!("vault {vault_id} revoked; stored data retained");
            Ok(())
        }
    }
}

fn ensure_storage(storage: &FsPath) -> Result<PathBuf> {
    std::fs::create_dir_all(storage.join("objects")).context("creating objects directory")?;
    std::fs::create_dir_all(storage.join("temp")).context("creating temp directory")?;
    let db_path = storage.join("meta.sqlite");
    init_db(&db_path)?;
    Ok(db_path)
}

async fn handle_head(
    State(state): State<AppState>,
    Path((vault_id, namespace_id, object_id)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !valid_path_ids(&vault_id, &namespace_id, &object_id) {
        return (StatusCode::BAD_REQUEST, "invalid id").into_response();
    }
    let path = nook_core::object_path(&vault_id, &namespace_id, &object_id);
    if let Some(resp) = authenticate(&state, "HEAD", &path, &headers, &[]).await {
        return resp;
    }
    match load_meta(state.db_path.clone(), vault_id, namespace_id, object_id).await {
        Ok(Some(meta)) => Response::builder()
            .status(StatusCode::OK)
            .header(ETAG, meta.etag.to_string())
            .header(CONTENT_LENGTH, meta.size.to_string())
            .body(Body::empty())
            .unwrap(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            error!("HEAD error: {err:?}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn handle_get(
    State(state): State<AppState>,
    Path((vault_id, namespace_id, object_id)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !valid_path_ids(&vault_id, &namespace_id, &object_id) {
        return (StatusCode::BAD_REQUEST, "invalid id").into_response();
    }
    let path = nook_core::object_path(&vault_id, &namespace_id, &object_id);
    if let Some(resp) = authenticate(&state, "GET", &path, &headers, &[]).await {
        return resp;
    }

    let object_path = state.objects_dir.join(&vault_id).join(&namespace_id).join(&object_id);
    let file = match fs::File::open(&object_path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            error!("open error: {e:?}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);
    let mut resp = Response::builder().status(StatusCode::OK);
    if let Ok(Some(meta)) = load_meta(state.db_path.clone(), vault_id, namespace_id, object_id).await {
        resp = resp.header(ETAG, meta.etag.to_string()).header(CONTENT_LENGTH, meta.size.to_string());
    }
    resp.body(body).unwrap()
}

async fn handle_put(
    State(state): State<AppState>,
    Path((vault_id, namespace_id, object_id)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Body,
) -> impl IntoResponse {
    if !valid_path_ids(&vault_id, &namespace_id, &object_id) {
        return (StatusCode::BAD_REQUEST, "invalid id").into_response();
    }

    // Fail fast (no body read) if the vault doesn't exist or is revoked —
    // avoids absorbing an upload for a request that can never succeed.
    let vault = match load_vault(state.db_path.clone(), vault_id.clone()).await {
        Ok(Some(v)) if !v.revoked => v,
        Ok(_) => return unauthorized(),
        Err(err) => {
            error!("vault lookup failed: {err:?}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let if_match = headers.get(IF_MATCH).and_then(|v| v.to_str().ok()).map(|s| s.to_string());

    let namespace_dir = state.objects_dir.join(&vault_id).join(&namespace_id);
    if let Err(err) = fs::create_dir_all(&namespace_dir).await {
        error!("creating namespace directory failed: {err:?}");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let temp_name = format!("{object_id}.tmp-{}", rand::thread_rng().next_u64());
    let temp_path = state.temp_dir.join(temp_name);
    let mut file = match fs::File::create(&temp_path).await {
        Ok(f) => f,
        Err(err) => {
            error!("temp file create failed: {err:?}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let mut stream = body.into_data_stream();
    let mut size: u64 = 0;
    let mut hasher = Sha256::new();
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(bytes) => {
                size += bytes.len() as u64;
                hasher.update(&bytes);
                if let Err(err) = file.write_all(&bytes).await {
                    error!("write error: {err:?}");
                    let _ = fs::remove_file(&temp_path).await;
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            }
            Err(err) => {
                error!("body error: {err:?}");
                let _ = fs::remove_file(&temp_path).await;
                return StatusCode::BAD_REQUEST.into_response();
            }
        }
    }
    if let Err(err) = file.sync_all().await {
        error!("sync failed: {err:?}");
        let _ = fs::remove_file(&temp_path).await;
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let body_hash = hasher.finalize().to_vec();

    let path = nook_core::object_path(&vault_id, &namespace_id, &object_id);
    if let Some(resp) = verify_signature(&vault.credential, "PUT", &path, &headers, &body_hash) {
        let _ = fs::remove_file(&temp_path).await;
        return resp;
    }

    let dest = namespace_dir.join(&object_id);
    let quota = vault.quota_bytes.map(|q| q as u64).or(state.default_quota_bytes);

    let outcome = task::spawn_blocking({
        let db_path = state.db_path.clone();
        let vault_id = vault_id.clone();
        let namespace_id = namespace_id.clone();
        let object_id = object_id.clone();
        let now = now_unix();
        move || -> Result<PutOutcome> {
            commit_put(
                &db_path,
                &vault_id,
                &namespace_id,
                &object_id,
                if_match.as_deref(),
                &temp_path,
                &dest,
                size,
                quota,
                now,
            )
        }
    })
    .await;

    let outcome = match outcome {
        Ok(Ok(o)) => o,
        Ok(Err(err)) => {
            error!("commit_put failed: {err:?}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Err(err) => {
            error!("commit_put task panicked: {err:?}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    match outcome {
        PutOutcome::Committed { etag, created } => Response::builder()
            .status(if created { StatusCode::CREATED } else { StatusCode::OK })
            .header(ETAG, etag.to_string())
            .body(Body::empty())
            .unwrap(),
        PutOutcome::CasConflict => StatusCode::PRECONDITION_FAILED.into_response(),
        PutOutcome::QuotaExceeded => StatusCode::INSUFFICIENT_STORAGE.into_response(),
    }
}

fn valid_path_ids(vault_id: &str, namespace_id: &str, object_id: &str) -> bool {
    nook_core::is_valid_hex_id(vault_id) && nook_core::is_valid_hex_id(namespace_id) && nook_core::is_valid_hex_id(object_id)
}

fn unauthorized() -> Response {
    StatusCode::UNAUTHORIZED.into_response()
}

/// Shared GET/HEAD auth path: looks up the vault (existence + revocation +
/// credential) and verifies the signature, in one step since neither has a
/// body to stream first. Returns `Some(response)` to short-circuit with,
/// or `None` if authentication succeeded.
async fn authenticate(state: &AppState, method: &str, path: &str, headers: &HeaderMap, body: &[u8]) -> Option<Response> {
    let vault_id = extract_vault_id_from_path(path);
    let vault = match load_vault(state.db_path.clone(), vault_id).await {
        Ok(Some(v)) if !v.revoked => v,
        Ok(_) => return Some(unauthorized()),
        Err(err) => {
            error!("vault lookup failed: {err:?}");
            return Some(StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }
    };
    verify_signature(&vault.credential, method, path, headers, &nook_core::body_sha256(body))
}

fn extract_vault_id_from_path(path: &str) -> String {
    // path shape: /v1/vault/{vault_id}/ns/{namespace_id}/obj/{object_id}
    path.split('/').nth(3).unwrap_or_default().to_string()
}

/// `body_hash` must already be the SHA-256 digest of the request body (see
/// `nook_core::body_sha256`/streaming equivalent) — never the raw body — so
/// callers with a streamed body never need to buffer it to authenticate.
/// Returns `Some(response)` to short-circuit with, or `None` if the
/// signature is valid.
fn verify_signature(credential: &[u8], method: &str, path: &str, headers: &HeaderMap, body_hash: &[u8]) -> Option<Response> {
    let timestamp = headers
        .get("X-Nook-Timestamp")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<i64>().ok());
    let signature = headers.get("X-Nook-Signature").and_then(|v| v.to_str().ok());

    let (Some(timestamp), Some(signature)) = (timestamp, signature) else {
        return Some(unauthorized());
    };
    if (now_unix() - timestamp).abs() > MAX_TIMESTAMP_SKEW_SECS {
        return Some(unauthorized());
    }
    if !nook_core::verify_with_body_hash(credential, method, path, timestamp, body_hash, signature) {
        return Some(unauthorized());
    }
    None
}

enum PutOutcome {
    Committed { etag: i64, created: bool },
    CasConflict,
    QuotaExceeded,
}

#[allow(clippy::too_many_arguments)]
fn commit_put(
    db_path: &FsPath,
    vault_id: &str,
    namespace_id: &str,
    object_id: &str,
    if_match: Option<&str>,
    temp_path: &FsPath,
    dest: &FsPath,
    size: u64,
    quota: Option<u64>,
    now: i64,
) -> Result<PutOutcome> {
    let mut conn = Connection::open(db_path)?;
    let tx = conn.transaction()?;

    let existing: Option<(i64, i64)> = tx
        .query_row(
            "SELECT size, etag FROM objects WHERE vault_id = ?1 AND namespace_id = ?2 AND object_id = ?3",
            (vault_id, namespace_id, object_id),
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;

    // No If-Match supplied: unconditional overwrite is allowed (matches
    // pre-SPEC-004 semantics) — CAS is opt-in via If-Match.
    if let Some(expected) = if_match {
        match &existing {
            Some((_, etag)) if expected == etag.to_string() => {}
            _ => {
                let _ = std::fs::remove_file(temp_path);
                return Ok(PutOutcome::CasConflict);
            }
        }
    }

    let old_size = existing.map(|(s, _)| s as u64).unwrap_or(0);
    if let Some(quota) = quota {
        let bytes_used: i64 = tx.query_row("SELECT bytes_used FROM vaults WHERE vault_id = ?1", [vault_id], |row| row.get(0))?;
        let projected = (bytes_used as u64).saturating_sub(old_size).saturating_add(size);
        if projected > quota {
            let _ = std::fs::remove_file(temp_path);
            return Ok(PutOutcome::QuotaExceeded);
        }
    }

    std::fs::rename(temp_path, dest).context("atomic rename")?;

    let new_etag = existing.map(|(_, e)| e + 1).unwrap_or(1);
    tx.execute(
        "INSERT INTO objects(vault_id, namespace_id, object_id, size, etag, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
         ON CONFLICT(vault_id, namespace_id, object_id)
         DO UPDATE SET size=excluded.size, etag=excluded.etag, updated_at=excluded.updated_at",
        (vault_id, namespace_id, object_id, size as i64, new_etag, now),
    )?;

    let delta = size as i64 - old_size as i64;
    tx.execute(
        "UPDATE vaults SET bytes_used = bytes_used + ?1 WHERE vault_id = ?2",
        (delta, vault_id),
    )?;

    tx.commit()?;
    Ok(PutOutcome::Committed {
        etag: new_etag,
        created: existing.is_none(),
    })
}

async fn load_meta(db_path: PathBuf, vault_id: String, namespace_id: String, object_id: String) -> Result<Option<ObjectMeta>> {
    task::spawn_blocking(move || -> Result<Option<ObjectMeta>> {
        let conn = Connection::open(db_path)?;
        conn.query_row(
            "SELECT size, etag FROM objects WHERE vault_id = ?1 AND namespace_id = ?2 AND object_id = ?3",
            (vault_id, namespace_id, object_id),
            |row| Ok(ObjectMeta { size: row.get(0)?, etag: row.get(1)? }),
        )
        .optional()
        .map_err(Into::into)
    })
    .await?
}

async fn load_vault(db_path: PathBuf, vault_id: String) -> Result<Option<VaultRecord>> {
    task::spawn_blocking(move || -> Result<Option<VaultRecord>> {
        let conn = Connection::open(db_path)?;
        conn.query_row(
            "SELECT credential, quota_bytes, revoked FROM vaults WHERE vault_id = ?1",
            [vault_id],
            |row| {
                Ok(VaultRecord {
                    credential: row.get(0)?,
                    quota_bytes: row.get(1)?,
                    revoked: row.get::<_, i64>(2)? != 0,
                })
            },
        )
        .optional()
        .map_err(Into::into)
    })
    .await?
}

fn init_db(path: &FsPath) -> Result<()> {
    let conn = Connection::open(path)?;
    // meta.sqlite is now touched by multiple processes (the long-running
    // `serve` process and one-shot `vault` CLI invocations); WAL mode plus a
    // busy timeout lets concurrent access retry briefly instead of failing
    // immediately with "database is locked".
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS vaults (
            vault_id TEXT PRIMARY KEY,
            credential BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            quota_bytes INTEGER,
            bytes_used INTEGER NOT NULL DEFAULT 0,
            revoked INTEGER NOT NULL DEFAULT 0
        )",
        [],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS objects (
            vault_id TEXT NOT NULL,
            namespace_id TEXT NOT NULL,
            object_id TEXT NOT NULL,
            size INTEGER NOT NULL,
            etag INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            PRIMARY KEY (vault_id, namespace_id, object_id)
        )",
        [],
    )?;
    Ok(())
}
