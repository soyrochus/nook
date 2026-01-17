use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use nook_core::{
    decrypt_object, derive_head_object_id, encrypt_object, serialize_encrypted_object, Manifest, Node,
    NodeType, ObjectType, VaultKey, WrappedKey,
};
use rand::rngs::OsRng;
use rand::RngCore;
use reqwest::header::{HeaderMap, HeaderValue, IF_MATCH};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tokio::fs as tokio_fs;
use walkdir::WalkDir;

#[derive(Parser)]
#[command(author, version, about = "Nook CLI — encrypted push/pull vault")]
struct Cli {
    #[arg(long, global = true)]
    server: Option<String>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init {
        #[arg(long)]
        server: String,
        #[arg(long)]
        root: Option<PathBuf>,
    },
    Root {
        #[arg(long)]
        set: Option<PathBuf>,
    },
    Push {
        subpath: Option<PathBuf>,
    },
    Pull {
        subpath: Option<PathBuf>,
    },
    Status,
}

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    server: String,
    #[serde(with = "base64_bytes")]
    vault_key: [u8; 32],
    root: Option<PathBuf>,
}

mod base64_bytes {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&BASE64.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let decoded = BASE64.decode(s.as_bytes()).map_err(serde::de::Error::custom)?;
        let mut out = [0u8; 32];
        if decoded.len() != 32 {
            return Err(serde::de::Error::custom("expected 32-byte key"));
        }
        out.copy_from_slice(&decoded);
        Ok(out)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init { server, root } => cmd_init(server, root).await?,
        Commands::Root { set } => cmd_root(set).await?,
        Commands::Push { subpath } => cmd_push(cli.server, subpath).await?,
        Commands::Pull { subpath } => cmd_pull(cli.server, subpath).await?,
        Commands::Status => cmd_status(cli.server).await?,
    }
    Ok(())
}

async fn cmd_init(server: String, root: Option<PathBuf>) -> Result<()> {
    let vault_key = nook_core::generate_vault_key();
    let config = Config {
        server,
        vault_key: vault_key.0,
        root,
    };
    save_config(&config)?;
    println!("Vault initialized. Keep this machine secure to retain access.");
    Ok(())
}

async fn cmd_root(set: Option<PathBuf>) -> Result<()> {
    let mut cfg = load_config().context("nook not initialized; run `nook init`")?;
    match set {
        Some(new_root) => {
            cfg.root = Some(new_root.clone());
            save_config(&cfg)?;
            println!("Root set to {}", new_root.display());
        }
        None => {
            if let Some(root) = cfg.root {
                println!("{}", root.display());
            } else {
                println!("Root path not set. Use `nook root --set <path>`.");
            }
        }
    }
    Ok(())
}

async fn cmd_status(server_override: Option<String>) -> Result<()> {
    let cfg = load_config().context("nook not initialized; run `nook init`")?;
    let server = server_override.unwrap_or(cfg.server.clone());
    let client = http_client()?;
    let vault_key = VaultKey(cfg.vault_key);
    let head_id = derive_head_object_id(&vault_key);
    let head_hex = hex::encode(head_id);
    match head_object(&client, &server, &head_hex).await? {
        Some(etag) => println!("Head present (etag {etag})"),
        None => println!("Head not present on server"),
    }
    Ok(())
}

async fn cmd_push(server_override: Option<String>, subpath: Option<PathBuf>) -> Result<()> {
    let cfg = load_config().context("nook not initialized; run `nook init`")?;
    let root = cfg
        .root
        .clone()
        .context("set root via `nook root --set <path>` before pushing")?;
    let server = server_override.unwrap_or(cfg.server.clone());
    let base_path = match subpath {
        Some(p) => root.join(p),
        None => root.clone(),
    };
    let client = http_client()?;
    let vault_key = VaultKey(cfg.vault_key);
    let mut next_node_id = 1u64;
    let root_node_id = next_node_id;
    let mut nodes = Vec::new();
    nodes.push(Node {
        node_id: root_node_id,
        parent_id: None,
        name: base_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string(),
        node_type: NodeType::Directory,
        content_object_id: None,
        wrapped_dek: None,
        logical_size: None,
    });

    let mut path_to_node: HashMap<PathBuf, u64> = HashMap::new();
    path_to_node.insert(base_path.clone(), root_node_id);

    let mut uploads: Vec<([u8; 32], Vec<u8>)> = Vec::new();

    let mut entries: Vec<_> = WalkDir::new(&base_path)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path() != base_path)
        .collect();
    entries.sort_by_key(|e| e.path().to_owned());

    for entry in entries {
        let path = entry.path().to_path_buf();
        let parent_path = path
            .parent()
            .expect("walkdir never yields root without parent")
            .to_path_buf();
        let parent_id = *path_to_node
            .get(&parent_path)
            .expect("parent must already exist");
        let node_id = {
            next_node_id += 1;
            next_node_id
        };
        let name = entry
            .file_name()
            .to_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".into());
        if entry.file_type().is_dir() {
            nodes.push(Node {
                node_id,
                parent_id: Some(parent_id),
                name,
                node_type: NodeType::Directory,
                content_object_id: None,
                wrapped_dek: None,
                logical_size: None,
            });
            path_to_node.insert(path.clone(), node_id);
        } else if entry.file_type().is_file() {
            let mut object_id = [0u8; 32];
            OsRng.fill_bytes(&mut object_id);
            let data = tokio_fs::read(&path).await?;
            let encrypted =
                encrypt_object(object_id, ObjectType::Content, &data, &vault_key).context(format!(
                    "encrypting {}",
                    path.display()
                ))?;
            let serialized = serialize_encrypted_object(&encrypted)?;
            uploads.push((object_id, serialized));
            nodes.push(Node {
                node_id,
                parent_id: Some(parent_id),
                name,
                node_type: NodeType::File,
                content_object_id: Some(object_id),
                wrapped_dek: Some(encrypted.wrapped_key.0.clone()),
                logical_size: Some(data.len() as u64),
            });
        }
    }

    let mut manifest = Manifest {
        manifest_version: 1,
        root_node_id,
        nodes,
        previous_manifest_hash: None,
        integrity_checksum: String::new(),
    };
    manifest.integrity_checksum = manifest.compute_integrity()?;
    let manifest_bytes = serde_json::to_vec(&manifest)?;

    let head_id = derive_head_object_id(&vault_key);
    let manifest_object =
        encrypt_object(head_id, ObjectType::Manifest, &manifest_bytes, &vault_key)?;
    let manifest_serialized = serialize_encrypted_object(&manifest_object)?;

    let head_hex = hex::encode(head_id);
    let etag = head_object(&client, &server, &head_hex).await?;
    for (object_id, bytes) in uploads {
        let hex_id = hex::encode(object_id);
        put_object(&client, &server, &hex_id, bytes, None).await?;
    }
    put_object(&client, &server, &head_hex, manifest_serialized, etag.as_deref()).await?;

    println!("Push complete.");
    Ok(())
}

async fn cmd_pull(server_override: Option<String>, _subpath: Option<PathBuf>) -> Result<()> {
    let cfg = load_config().context("nook not initialized; run `nook init`")?;
    let root = cfg
        .root
        .clone()
        .context("set root via `nook root --set <path>` before pulling")?;
    let server = server_override.unwrap_or(cfg.server.clone());
    let client = http_client()?;
    let vault_key = VaultKey(cfg.vault_key);
    let head_id = derive_head_object_id(&vault_key);
    let head_hex = hex::encode(head_id);
    let manifest_bytes = get_object(&client, &server, &head_hex)
        .await
        .context("manifest not found; push first")?;
    let (wrapped, chunks) = nook_core::deserialize_encrypted_object(&manifest_bytes)?;
    let decrypted = decrypt_object(head_id, &wrapped, &chunks, &vault_key)?;
    let manifest: Manifest = serde_json::from_slice(&decrypted.plaintext)?;
    manifest.validate_integrity()?;

    let mut node_paths: HashMap<u64, PathBuf> = HashMap::new();
    node_paths.insert(manifest.root_node_id, root.clone());
    tokio_fs::create_dir_all(&root).await?;

    let mut sorted_nodes = manifest.nodes.clone();
    sorted_nodes.sort_by_key(|n| n.node_id);

    for node in sorted_nodes {
        if node.node_id == manifest.root_node_id {
            continue;
        }
        let parent = node
            .parent_id
            .and_then(|id| node_paths.get(&id).cloned())
            .context("manifest missing parent linkage")?;
        let path = parent.join(&node.name);
        match node.node_type {
            NodeType::Directory => {
                tokio_fs::create_dir_all(&path).await?;
                node_paths.insert(node.node_id, path);
            }
            NodeType::File => {
                let object_id = node
                    .content_object_id
                    .context("file entry missing object id")?;
                let wrapped_dek = node.wrapped_dek.clone().context("missing wrapped dek")?;
                let wrapped = WrappedKey(wrapped_dek);
                let cipher_bytes = get_object(&client, &server, &hex::encode(object_id)).await?;
                let (wrapped_from_object, chunks) =
                    nook_core::deserialize_encrypted_object(&cipher_bytes)?;
                // Prefer manifest's wrapped key but fall back if object envelope differs.
                let wrapped_to_use = if !wrapped_from_object.0.is_empty() {
                    wrapped_from_object
                } else {
                    wrapped
                };
                let decrypted = decrypt_object(object_id, &wrapped_to_use, &chunks, &vault_key)?;
                if let Some(expected) = node.logical_size {
                    if expected != decrypted.plaintext.len() as u64 {
                        return Err(anyhow::anyhow!("size mismatch for {}", path.display()));
                    }
                }
                write_atomic(&path, &decrypted.plaintext)?;
            }
        }
    }

    println!("Pull complete.");
    Ok(())
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .context("file must have parent directory for atomic write")?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.write_all(data)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path)?;
    Ok(())
}

fn http_client() -> Result<Client> {
    let client = Client::builder()
        .use_rustls_tls()
        .build()
        .context("building HTTP client")?;
    Ok(client)
}

async fn head_object(client: &Client, server: &str, object_id_hex: &str) -> Result<Option<String>> {
    let url = format!("{server}/v1/obj/{object_id_hex}");
    let res = client.head(url).send().await?;
    match res.status() {
        reqwest::StatusCode::OK => Ok(res
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string())),
        reqwest::StatusCode::NOT_FOUND => Ok(None),
        other => Err(anyhow::anyhow!("HEAD failed with status {other}")),
    }
}

async fn put_object(
    client: &Client,
    server: &str,
    object_id_hex: &str,
    bytes: Vec<u8>,
    etag: Option<&str>,
) -> Result<()> {
    let url = format!("{server}/v1/obj/{object_id_hex}");
    let mut headers = HeaderMap::new();
    if let Some(tag) = etag {
        headers.insert(
            IF_MATCH,
            HeaderValue::from_str(tag).context("invalid etag value")?,
        );
    }
    let res = client.put(url).headers(headers).body(bytes).send().await?;
    match res.status() {
        reqwest::StatusCode::OK | reqwest::StatusCode::CREATED => Ok(()),
        reqwest::StatusCode::PRECONDITION_FAILED => {
            Err(anyhow::anyhow!("CAS failure: head modified concurrently"))
        }
        other => Err(anyhow::anyhow!("PUT failed with status {other}")),
    }
}

async fn get_object(client: &Client, server: &str, object_id_hex: &str) -> Result<Vec<u8>> {
    let url = format!("{server}/v1/obj/{object_id_hex}");
    let res = client.get(url).send().await?;
    if res.status().is_success() {
        let bytes = res.bytes().await?;
        return Ok(bytes.to_vec());
    }
    if res.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(anyhow::anyhow!("object {object_id_hex} not found"));
    }
    Err(anyhow::anyhow!(
        "GET failed with status {}",
        res.status()
    ))
}

fn load_config() -> Result<Config> {
    let path = config_path()?;
    let data = fs::read(&path).context("missing config; run `nook init`")?;
    let cfg: Config = serde_json::from_slice(&data)?;
    Ok(cfg)
}

fn save_config(cfg: &Config) -> Result<()> {
    let path = config_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_vec_pretty(cfg)?;
    fs::write(path, data)?;
    Ok(())
}

fn config_path() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("dev", "nook", "nook")
        .context("cannot determine config directory for this platform")?;
    Ok(dirs.config_dir().join("config.json"))
}
