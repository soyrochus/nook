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
    #[arg(long, default_value = "storage")]
    storage: PathBuf,
}

#[derive(Clone)]
struct AppState {
    objects_dir: PathBuf,
    temp_dir: PathBuf,
    db_path: PathBuf,
}

#[derive(Debug, Clone)]
struct ObjectMeta {
    size: i64,
    etag: i64,
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

    let state = AppState {
        objects_dir,
        temp_dir,
        db_path,
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

    let dest = state.objects_dir.join(&object_id);
    if let Err(err) = fs::rename(&temp_path, &dest).await {
        error!("atomic rename failed: {err:?}");
        let _ = fs::remove_file(&temp_path).await;
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let new_etag = existing.as_ref().map(|m| m.etag + 1).unwrap_or(1);
    if let Err(err) = store_meta(state.db_path.clone(), object_id.clone(), size, new_etag).await {
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
        let mut stmt =
            conn.prepare("SELECT size, etag FROM objects WHERE object_id = ?1 LIMIT 1")?;
        let mut rows = stmt.query([object_id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(ObjectMeta {
                size: row.get(0)?,
                etag: row.get(1)?,
            }))
        } else {
            Ok(None)
        }
    })
    .await?
}

async fn store_meta(db_path: PathBuf, object_id: String, size: u64, etag: i64) -> Result<()> {
    task::spawn_blocking(move || -> Result<()> {
        let conn = Connection::open(db_path)?;
        conn.execute(
            "INSERT INTO objects(object_id, size, etag) VALUES (?1, ?2, ?3)
             ON CONFLICT(object_id) DO UPDATE SET size=excluded.size, etag=excluded.etag",
            (object_id, size as i64, etag),
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
            etag INTEGER NOT NULL
        )",
        [],
    )?;
    Ok(())
}

fn valid_object_id(id: &str) -> bool {
    id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit())
}
