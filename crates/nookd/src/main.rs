use anyhow::{Context, Result};
use axum::{
    body::Body,
    extract::{Path, State},
    http::header::{CONTENT_LENGTH, ETAG, IF_MATCH},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use clap::Parser;
use futures_util::StreamExt;
use rand::RngCore;
use rusqlite::Connection;
use std::path::{Path as FsPath, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::task;
use tokio_util::io::ReaderStream;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: String,
    /// Directory holding the object store and meta.sqlite. Also settable via
    /// the NOOK_DATA_DIR environment variable (used by the container image,
    /// where it should point at a mounted volume for durable storage).
    #[arg(long, env = "NOOK_DATA_DIR", default_value = "storage")]
    storage: PathBuf,
    /// Maximum total bytes of object storage to accept. Unset means
    /// unlimited. PUTs that would exceed this are rejected with
    /// 507 Insufficient Storage.
    #[arg(long, env = "NOOK_QUOTA_BYTES")]
    quota_bytes: Option<u64>,
}

#[derive(Clone)]
struct AppState {
    objects_dir: PathBuf,
    temp_dir: PathBuf,
    db_path: PathBuf,
    quota_bytes: Option<u64>,
    stored_bytes: Arc<AtomicU64>,
}

#[derive(Debug, Clone)]
struct ObjectMeta {
    size: i64,
    etag: i64,
    #[allow(dead_code)]
    created_at: i64,
    #[allow(dead_code)]
    updated_at: i64,
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Atomically accounts for replacing `old_size` bytes with `new_size` bytes
/// against `quota`, succeeding (and committing the new total) only if the
/// projected total does not exceed the quota. Using compare-and-swap here
/// (rather than load-then-store) avoids two concurrent PUTs both reading a
/// stale total and jointly overshooting the quota.
fn reserve_quota(stored_bytes: &AtomicU64, old_size: u64, new_size: u64, quota: u64) -> std::result::Result<(), ()> {
    let mut current = stored_bytes.load(Ordering::SeqCst);
    loop {
        let projected = current.saturating_sub(old_size).saturating_add(new_size);
        if projected > quota {
            return Err(());
        }
        match stored_bytes.compare_exchange_weak(current, projected, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return Ok(()),
            Err(actual) => current = actual,
        }
    }
}

/// Undoes a previously committed `reserve_quota` when the write that
/// followed it did not ultimately succeed.
fn release_quota(stored_bytes: &AtomicU64, old_size: u64, new_size: u64) {
    let mut current = stored_bytes.load(Ordering::SeqCst);
    loop {
        let restored = current.saturating_sub(new_size).saturating_add(old_size);
        match stored_bytes.compare_exchange_weak(current, restored, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return,
            Err(actual) => current = actual,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("nookd=info".parse()?))
        .init();

    let args = Args::parse();
    let storage = args.storage;
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
    let stored_bytes = total_stored_bytes(&db_path)?;
    if let Some(quota) = args.quota_bytes {
        info!("quota: {stored_bytes}/{quota} bytes used at startup");
    }

    let state = AppState {
        objects_dir,
        temp_dir,
        db_path,
        quota_bytes: args.quota_bytes,
        stored_bytes: Arc::new(AtomicU64::new(stored_bytes)),
    };
    let app = Router::new()
        .route("/v1/obj/:object_id", get(handle_get).put(handle_put).head(handle_head))
        .with_state(state);

    info!("listening on {}", args.listen);
    let listener = TcpListener::bind(&args.listen).await?;
    axum::serve(listener, app).await.context("server failed")?;
    Ok(())
}

async fn handle_head(
    State(state): State<AppState>,
    Path(object_id): Path<String>,
) -> impl IntoResponse {
    if !valid_object_id(&object_id) {
        return (StatusCode::BAD_REQUEST, "invalid object id").into_response();
    }
    match load_meta(state.db_path.clone(), object_id.clone()).await {
        Ok(Some(meta)) => {
            let resp = Response::builder()
                .status(StatusCode::OK)
                .header(ETAG, meta.etag.to_string())
                .header(CONTENT_LENGTH, meta.size.to_string());
            resp.body(Body::empty()).unwrap()
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            error!("HEAD error: {err:?}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn handle_get(
    State(state): State<AppState>,
    Path(object_id): Path<String>,
) -> impl IntoResponse {
    if !valid_object_id(&object_id) {
        return (StatusCode::BAD_REQUEST, "invalid object id").into_response();
    }
    let path = state.objects_dir.join(&object_id);
    let file = match fs::File::open(&path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return StatusCode::NOT_FOUND.into_response()
        }
        Err(e) => {
            error!("open error: {e:?}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);
    let mut resp = Response::builder().status(StatusCode::OK);
    if let Ok(Some(meta)) = load_meta(state.db_path.clone(), object_id.clone()).await {
        resp = resp
            .header(ETAG, meta.etag.to_string())
            .header(CONTENT_LENGTH, meta.size.to_string());
    }
    resp.body(body).unwrap()
}

async fn handle_put(
    State(state): State<AppState>,
    Path(object_id): Path<String>,
    headers: axum::http::HeaderMap,
    body: Body,
) -> impl IntoResponse {
    if !valid_object_id(&object_id) {
        return (StatusCode::BAD_REQUEST, "invalid object id").into_response();
    }
    let if_match = headers
        .get(IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let existing = match load_meta(state.db_path.clone(), object_id.clone()).await {
        Ok(meta) => meta,
        Err(err) => {
            error!("db read failed: {err:?}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    if let (Some(expected), Some(meta)) = (if_match.as_ref(), existing.as_ref()) {
        if expected != &meta.etag.to_string() {
            return StatusCode::PRECONDITION_FAILED.into_response();
        }
    } else if if_match.is_some() && existing.is_none() {
        return StatusCode::PRECONDITION_FAILED.into_response();
    }

    let temp_name = format!("{}.tmp-{}", object_id, rand::thread_rng().next_u64());
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
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(bytes) => {
                size += bytes.len() as u64;
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

    let old_size = existing.as_ref().map(|m| m.size as u64).unwrap_or(0);
    if let Some(quota) = state.quota_bytes {
        match reserve_quota(&state.stored_bytes, old_size, size, quota) {
            Ok(()) => {}
            Err(()) => {
                let _ = fs::remove_file(&temp_path).await;
                return StatusCode::INSUFFICIENT_STORAGE.into_response();
            }
        }
    }

    let dest = state.objects_dir.join(&object_id);
    if let Err(err) = fs::rename(&temp_path, &dest).await {
        error!("atomic rename failed: {err:?}");
        let _ = fs::remove_file(&temp_path).await;
        if state.quota_bytes.is_some() {
            release_quota(&state.stored_bytes, old_size, size);
        }
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let new_etag = existing.as_ref().map(|m| m.etag + 1).unwrap_or(1);
    let now = now_unix();
    if let Err(err) = store_meta(state.db_path.clone(), object_id.clone(), size, new_etag, now).await {
        error!("db write failed: {err:?}");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let status = if existing.is_some() {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Response::builder()
        .status(status)
        .header(ETAG, new_etag.to_string())
        .body(Body::empty())
        .unwrap()
}

async fn load_meta(db_path: PathBuf, object_id: String) -> Result<Option<ObjectMeta>> {
    task::spawn_blocking(move || -> Result<Option<ObjectMeta>> {
        let conn = Connection::open(db_path)?;
        let mut stmt = conn.prepare(
            "SELECT size, etag, created_at, updated_at FROM objects WHERE object_id = ?1 LIMIT 1",
        )?;
        let mut rows = stmt.query([object_id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(ObjectMeta {
                size: row.get(0)?,
                etag: row.get(1)?,
                created_at: row.get(2)?,
                updated_at: row.get(3)?,
            }))
        } else {
            Ok(None)
        }
    })
    .await?
}

async fn store_meta(
    db_path: PathBuf,
    object_id: String,
    size: u64,
    etag: i64,
    now: i64,
) -> Result<()> {
    task::spawn_blocking(move || -> Result<()> {
        let conn = Connection::open(db_path)?;
        conn.execute(
            "INSERT INTO objects(object_id, size, etag, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT(object_id) DO UPDATE SET size=excluded.size, etag=excluded.etag, updated_at=excluded.updated_at",
            (object_id, size as i64, etag, now),
        )?;
        Ok(())
    })
    .await??;
    Ok(())
}

fn init_db(path: &FsPath) -> Result<()> {
    let conn = Connection::open(path)?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS objects (
            object_id TEXT PRIMARY KEY,
            size INTEGER NOT NULL,
            etag INTEGER NOT NULL,
            created_at INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL DEFAULT 0
        )",
        [],
    )?;
    // Backward compatibility with databases created before timestamps were
    // tracked: add the columns if they're missing, ignoring the error SQLite
    // raises when a column already exists.
    for stmt in [
        "ALTER TABLE objects ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE objects ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0",
    ] {
        if let Err(err) = conn.execute(stmt, []) {
            if !err.to_string().contains("duplicate column name") {
                return Err(err.into());
            }
        }
    }
    Ok(())
}

/// Sums the sizes of all currently stored objects, used to seed the
/// in-memory running quota counter from persisted state on startup.
fn total_stored_bytes(path: &FsPath) -> Result<u64> {
    let conn = Connection::open(path)?;
    let total: i64 = conn.query_row("SELECT COALESCE(SUM(size), 0) FROM objects", [], |row| row.get(0))?;
    Ok(total.max(0) as u64)
}

fn valid_object_id(id: &str) -> bool {
    id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit())
}
