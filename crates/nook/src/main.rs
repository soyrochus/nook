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
use std::path::{Component, Path, PathBuf};
use tokio::fs as tokio_fs;
use walkdir::WalkDir;

/// Fixed keychain coordinates for the vault key. Only one vault config
/// exists per machine (single fixed config path), so a constant service and
/// account name is sufficient to locate the secret.
const KEYCHAIN_SERVICE: &str = "dev.nook.vault";
const KEYCHAIN_ACCOUNT: &str = "vault_key";

/// Associated data binding the passphrase-wrapped vault key to its purpose,
/// so it can never be confused with any other ciphertext produced by nook.
const LOCAL_KEY_AAD: &[u8] = b"nook-local-vault-key-v1";

/// Environment variable allowing non-interactive passphrase supply for
/// scripted or CI use of the encrypted-local-file fallback.
const PASSPHRASE_ENV_VAR: &str = "NOOK_PASSPHRASE";

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
    Ls {
        subpath: Option<PathBuf>,
    },
    Tree {
        subpath: Option<PathBuf>,
    },
    Push {
        subpath: Option<PathBuf>,
    },
    Pull {
        subpath: Option<PathBuf>,
    },
    Status,
}

/// Client configuration, persisted as TOML. `vault_key` is always an opaque
/// reference (a keychain marker or an encrypted blob) — never the raw
/// Vault Master Key — so the config file alone never discloses key material.
#[derive(Debug, Serialize, Deserialize)]
struct Config {
    server: String,
    root: Option<PathBuf>,
    vault_key: KeyStorage,
}

/// How the Vault Master Key is stored: preferentially in the OS keychain, or
/// (when no keychain is available) as an Argon2id-passphrase-wrapped blob
/// encrypted with XChaCha20-Poly1305.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
enum KeyStorage {
    Keychain,
    EncryptedFile {
        #[serde(with = "base64_vec")]
        salt: Vec<u8>,
        #[serde(with = "base64_array24")]
        nonce: [u8; 24],
        #[serde(with = "base64_vec")]
        ciphertext: Vec<u8>,
    },
}

mod base64_vec {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&BASE64.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        BASE64.decode(s.as_bytes()).map_err(serde::de::Error::custom)
    }
}

mod base64_array24 {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 24], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&BASE64.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 24], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let decoded = BASE64.decode(s.as_bytes()).map_err(serde::de::Error::custom)?;
        let mut out = [0u8; 24];
        if decoded.len() != 24 {
            return Err(serde::de::Error::custom("expected 24-byte nonce"));
        }
        out.copy_from_slice(&decoded);
        Ok(out)
    }
}

/// Stores a freshly generated vault key, preferring the OS keychain and
/// falling back to a passphrase-encrypted local blob if the keychain is
/// unavailable (headless environment, CI, unsupported platform).
fn store_vault_key(key_bytes: &[u8; 32]) -> Result<KeyStorage> {
    let keychain_result = (|| -> std::result::Result<(), keyring::Error> {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)?;
        entry.set_secret(key_bytes)
    })();

    match keychain_result {
        Ok(()) => {
            println!("Vault key stored in the OS keychain.");
            Ok(KeyStorage::Keychain)
        }
        Err(err) => {
            eprintln!(
                "OS keychain unavailable ({err}); falling back to a passphrase-encrypted local file."
            );
            let passphrase = read_new_passphrase()?;
            encrypt_vault_key_with_passphrase(key_bytes, &passphrase)
        }
    }
}

/// Retrieves the Vault Master Key referenced by `storage`, from the OS
/// keychain or by decrypting the local blob with a supplied passphrase.
fn retrieve_vault_key(storage: &KeyStorage) -> Result<[u8; 32]> {
    match storage {
        KeyStorage::Keychain => {
            let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
                .context("creating keychain entry")?;
            let secret = entry
                .get_secret()
                .context("reading vault key from OS keychain")?;
            if secret.len() != 32 {
                return Err(anyhow::anyhow!("unexpected vault key length from keychain"));
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(&secret);
            Ok(out)
        }
        KeyStorage::EncryptedFile {
            salt,
            nonce,
            ciphertext,
        } => {
            let passphrase = read_existing_passphrase()?;
            decrypt_vault_key_with_passphrase(salt, nonce, ciphertext, &passphrase)
        }
    }
}

fn load_vault_key(cfg: &Config) -> Result<VaultKey> {
    Ok(VaultKey(retrieve_vault_key(&cfg.vault_key)?))
}

fn encrypt_vault_key_with_passphrase(key_bytes: &[u8; 32], passphrase: &str) -> Result<KeyStorage> {
    let mut salt = [0u8; nook_core::PASSPHRASE_SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let wrap_key = nook_core::derive_passphrase_key(passphrase.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("deriving passphrase key: {e}"))?;
    let ciphertext = nook_core::encrypt_chunk(&wrap_key, &nonce, LOCAL_KEY_AAD, key_bytes);
    Ok(KeyStorage::EncryptedFile {
        salt: salt.to_vec(),
        nonce,
        ciphertext,
    })
}

fn decrypt_vault_key_with_passphrase(
    salt: &[u8],
    nonce: &[u8; 24],
    ciphertext: &[u8],
    passphrase: &str,
) -> Result<[u8; 32]> {
    let wrap_key = nook_core::derive_passphrase_key(passphrase.as_bytes(), salt)
        .map_err(|e| anyhow::anyhow!("deriving passphrase key: {e}"))?;
    let plaintext = nook_core::decrypt_chunk(&wrap_key, nonce, LOCAL_KEY_AAD, ciphertext)
        .map_err(|_| anyhow::anyhow!("incorrect passphrase or corrupted local key file"))?;
    if plaintext.len() != 32 {
        return Err(anyhow::anyhow!("unexpected decrypted key length"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&plaintext);
    Ok(out)
}

/// Passphrase used to newly encrypt the vault key (`nook init`): supports a
/// non-interactive override via `NOOK_PASSPHRASE` for scripted/CI use, and
/// otherwise prompts twice to guard against typos.
fn read_new_passphrase() -> Result<String> {
    if let Ok(p) = std::env::var(PASSPHRASE_ENV_VAR) {
        return Ok(p);
    }
    let first = rpassword::prompt_password("Enter a passphrase to protect the vault key: ")
        .context("reading passphrase")?;
    if first.is_empty() {
        return Err(anyhow::anyhow!("passphrase must not be empty"));
    }
    let confirm =
        rpassword::prompt_password("Confirm passphrase: ").context("reading passphrase confirmation")?;
    if first != confirm {
        return Err(anyhow::anyhow!("passphrases did not match"));
    }
    Ok(first)
}

/// Passphrase used to decrypt an existing vault key: same non-interactive
/// override, single prompt otherwise.
fn read_existing_passphrase() -> Result<String> {
    if let Ok(p) = std::env::var(PASSPHRASE_ENV_VAR) {
        return Ok(p);
    }
    rpassword::prompt_password("Enter vault passphrase: ").context("reading passphrase")
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init { server, root } => cmd_init(server, root).await?,
        Commands::Root { set } => cmd_root(set).await?,
        Commands::Ls { subpath } => cmd_ls(cli.server, subpath).await?,
        Commands::Tree { subpath } => cmd_tree(cli.server, subpath).await?,
        Commands::Push { subpath } => cmd_push(cli.server, subpath).await?,
        Commands::Pull { subpath } => cmd_pull(cli.server, subpath).await?,
        Commands::Status => cmd_status(cli.server).await?,
    }
    Ok(())
}

async fn cmd_init(server: String, root: Option<PathBuf>) -> Result<()> {
    let vault_key = nook_core::generate_vault_key();
    let key_storage = store_vault_key(vault_key.as_bytes())?;
    let config = Config {
        server,
        root,
        vault_key: key_storage,
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
    let vault_key = load_vault_key(&cfg)?;
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
    let base_path = match &subpath {
        Some(p) => root.join(p),
        None => root.clone(),
    };
    let client = http_client()?;
    let vault_key = load_vault_key(&cfg)?;

    // Try to fetch existing manifest, or create empty one
    let head_id = derive_head_object_id(&vault_key);
    let head_hex = hex::encode(head_id);
    let (mut manifest, etag) = match fetch_manifest_with_etag(&client, &server, &vault_key).await {
        Ok((m, e)) => (m, e),
        Err(ManifestFetchError::NotFound) => {
            // No existing manifest, create a new one with root directory
            let new_manifest = Manifest {
                manifest_version: 1,
                root_node_id: 1,
                nodes: vec![Node {
                    node_id: 1,
                    parent_id: None,
                    name: root
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("vault")
                        .to_string(),
                    node_type: NodeType::Directory,
                    content_object_id: None,
                    wrapped_dek: None,
                    logical_size: None,
                }],
                previous_manifest_hash: None,
                integrity_checksum: String::new(),
            };
            (new_manifest, None)
        }
        Err(ManifestFetchError::Other(e)) => {
            return Err(e.context(
                "failed to fetch or decrypt the existing manifest; aborting push without modifying server state",
            ));
        }
    };

    // Build indexes for existing manifest
    let mut next_node_id = manifest.nodes.iter().map(|n| n.node_id).max().unwrap_or(0) + 1;

    // Build a path-to-node mapping for the existing manifest
    // The manifest root corresponds to the configured root directory
    let mut path_to_node: HashMap<PathBuf, u64> = HashMap::new();
    let mut node_to_path: HashMap<u64, PathBuf> = HashMap::new();
    build_path_mappings(&manifest, &root, &mut path_to_node, &mut node_to_path);

    let mut uploads: Vec<([u8; 32], Vec<u8>)> = Vec::new();

    // Check if base_path is a file or directory
    let base_metadata = tokio_fs::metadata(&base_path).await.context(format!(
        "cannot access {}",
        base_path.display()
    ))?;

    if base_metadata.is_file() {
        // Pushing a single file
        let file_name = base_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("file")
            .to_string();
        let parent_path = base_path.parent().unwrap_or(&root).to_path_buf();

        // Ensure parent directory exists in manifest
        let parent_id = ensure_path_exists(&mut manifest, &mut next_node_id, &root, &parent_path, &mut path_to_node)?;

        // Check if file already exists
        let existing_idx = manifest.nodes.iter().position(|n| {
            n.parent_id == Some(parent_id) && n.name == file_name
        });

        // Create encrypted content
        let mut object_id = [0u8; 32];
        OsRng.fill_bytes(&mut object_id);
        let data = tokio_fs::read(&base_path).await?;
        let encrypted =
            encrypt_object(object_id, ObjectType::Content, &data, &vault_key).context(format!(
                "encrypting {}",
                base_path.display()
            ))?;
        let serialized = serialize_encrypted_object(&encrypted)?;
        uploads.push((object_id, serialized));

        if let Some(idx) = existing_idx {
            // Update existing node
            manifest.nodes[idx].content_object_id = Some(object_id);
            manifest.nodes[idx].wrapped_dek = Some(encrypted.wrapped_key.0.clone());
            manifest.nodes[idx].logical_size = Some(data.len() as u64);
        } else {
            // Create new file node
            let file_node_id = next_node_id;
            manifest.nodes.push(Node {
                node_id: file_node_id,
                parent_id: Some(parent_id),
                name: file_name,
                node_type: NodeType::File,
                content_object_id: Some(object_id),
                wrapped_dek: Some(encrypted.wrapped_key.0.clone()),
                logical_size: Some(data.len() as u64),
            });
        }
    } else {
        // Pushing a directory
        let mut entries: Vec<_> = WalkDir::new(&base_path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .collect();
        entries.sort_by_key(|e| e.path().to_owned());

        for entry in entries {
            let path = entry.path().to_path_buf();
            let name = entry
                .file_name()
                .to_str()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "unknown".into());

            if entry.file_type().is_dir() {
                // Ensure directory exists in manifest
                ensure_path_exists(&mut manifest, &mut next_node_id, &root, &path, &mut path_to_node)?;
            } else if entry.file_type().is_file() {
                let parent_path = path.parent().unwrap_or(&root).to_path_buf();
                let parent_id = ensure_path_exists(&mut manifest, &mut next_node_id, &root, &parent_path, &mut path_to_node)?;

                // Check if file already exists
                let existing_idx = manifest.nodes.iter().position(|n| {
                    n.parent_id == Some(parent_id) && n.name == name
                });

                // Create encrypted content
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

                if let Some(idx) = existing_idx {
                    // Update existing node
                    manifest.nodes[idx].content_object_id = Some(object_id);
                    manifest.nodes[idx].wrapped_dek = Some(encrypted.wrapped_key.0.clone());
                    manifest.nodes[idx].logical_size = Some(data.len() as u64);
                } else {
                    // Create new file node
                    let file_node_id = next_node_id;
                    next_node_id += 1;
                    manifest.nodes.push(Node {
                        node_id: file_node_id,
                        parent_id: Some(parent_id),
                        name,
                        node_type: NodeType::File,
                        content_object_id: Some(object_id),
                        wrapped_dek: Some(encrypted.wrapped_key.0.clone()),
                        logical_size: Some(data.len() as u64),
                    });
                }
            }
        }
    }

    manifest.integrity_checksum = manifest.compute_integrity()?;
    let manifest_bytes = serde_json::to_vec(&manifest)?;

    let manifest_object =
        encrypt_object(head_id, ObjectType::Manifest, &manifest_bytes, &vault_key)?;
    let manifest_serialized = serialize_encrypted_object(&manifest_object)?;

    for (object_id, bytes) in uploads {
        let hex_id = hex::encode(object_id);
        put_object(&client, &server, &hex_id, bytes, None).await?;
    }
    put_object(&client, &server, &head_hex, manifest_serialized, etag.as_deref()).await?;

    println!("Push complete.");
    Ok(())
}

/// Builds mappings from filesystem paths to manifest node IDs and vice versa
fn build_path_mappings(
    manifest: &Manifest,
    root: &Path,
    path_to_node: &mut HashMap<PathBuf, u64>,
    node_to_path: &mut HashMap<u64, PathBuf>,
) {
    // Map root node to the configured root path
    path_to_node.insert(root.to_path_buf(), manifest.root_node_id);
    node_to_path.insert(manifest.root_node_id, root.to_path_buf());

    // Build parent->children index
    let mut children_by_parent: HashMap<u64, Vec<&Node>> = HashMap::new();
    for node in &manifest.nodes {
        if let Some(parent_id) = node.parent_id {
            children_by_parent.entry(parent_id).or_default().push(node);
        }
    }

    // BFS to build all paths
    let mut queue = vec![manifest.root_node_id];
    while let Some(node_id) = queue.pop() {
        let parent_path = node_to_path.get(&node_id).cloned().unwrap();
        if let Some(children) = children_by_parent.get(&node_id) {
            for child in children {
                let child_path = parent_path.join(&child.name);
                path_to_node.insert(child_path.clone(), child.node_id);
                node_to_path.insert(child.node_id, child_path);
                if matches!(child.node_type, NodeType::Directory) {
                    queue.push(child.node_id);
                }
            }
        }
    }
}

/// Ensures a path exists in the manifest, creating directories as needed.
/// Returns the node ID for the path.
fn ensure_path_exists(
    manifest: &mut Manifest,
    next_node_id: &mut u64,
    root: &Path,
    target_path: &Path,
    path_to_node: &mut HashMap<PathBuf, u64>,
) -> Result<u64> {
    // If path already exists, return its node ID
    if let Some(&node_id) = path_to_node.get(target_path) {
        return Ok(node_id);
    }

    // Build the path from root to target, creating directories as needed
    let rel_path = target_path.strip_prefix(root).unwrap_or(target_path);
    let mut current_path = root.to_path_buf();
    let mut current_id = manifest.root_node_id;

    for component in rel_path.components() {
        if let Component::Normal(name_os) = component {
            let name = name_os.to_str().context("path must be valid UTF-8")?;
            current_path = current_path.join(name);

            if let Some(&existing_id) = path_to_node.get(&current_path) {
                current_id = existing_id;
            } else {
                // Create new directory node
                let new_id = *next_node_id;
                *next_node_id += 1;
                manifest.nodes.push(Node {
                    node_id: new_id,
                    parent_id: Some(current_id),
                    name: name.to_string(),
                    node_type: NodeType::Directory,
                    content_object_id: None,
                    wrapped_dek: None,
                    logical_size: None,
                });
                path_to_node.insert(current_path.clone(), new_id);
                current_id = new_id;
            }
        }
    }

    Ok(current_id)
}

/// Distinguishes "manifest object does not exist yet" (safe to treat as an
/// empty vault) from every other failure mode, which must abort the push
/// rather than silently fabricating a replacement manifest.
#[derive(Debug)]
enum ManifestFetchError {
    NotFound,
    Other(anyhow::Error),
}

async fn fetch_manifest_with_etag(
    client: &Client,
    server: &str,
    vault_key: &VaultKey,
) -> std::result::Result<(Manifest, Option<String>), ManifestFetchError> {
    let head_id = derive_head_object_id(vault_key);
    let head_hex = hex::encode(head_id);

    let url = format!("{server}/v1/obj/{head_hex}");
    let res = client
        .get(&url)
        .send()
        .await
        .map_err(|e| ManifestFetchError::Other(anyhow::Error::new(e).context("requesting manifest")))?;

    if res.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(ManifestFetchError::NotFound);
    }
    if !res.status().is_success() {
        return Err(ManifestFetchError::Other(anyhow::anyhow!(
            "GET failed with status {}",
            res.status()
        )));
    }

    let etag = res
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let manifest_bytes = res
        .bytes()
        .await
        .map_err(|e| ManifestFetchError::Other(anyhow::Error::new(e).context("reading manifest body")))?
        .to_vec();
    let (wrapped, chunks) = nook_core::deserialize_encrypted_object(&manifest_bytes).map_err(|e| {
        ManifestFetchError::Other(anyhow::anyhow!("deserializing manifest envelope: {e}"))
    })?;
    let decrypted = decrypt_object(head_id, &wrapped, &chunks, vault_key)
        .map_err(|e| ManifestFetchError::Other(anyhow::anyhow!("decrypting manifest: {e}")))?;
    let manifest: Manifest = serde_json::from_slice(&decrypted.plaintext)
        .map_err(|e| ManifestFetchError::Other(anyhow::Error::new(e).context("parsing manifest JSON")))?;
    manifest
        .validate_integrity()
        .map_err(|e| ManifestFetchError::Other(anyhow::anyhow!("manifest integrity check failed: {e}")))?;

    Ok((manifest, etag))
}

async fn cmd_ls(server_override: Option<String>, subpath: Option<PathBuf>) -> Result<()> {
    let cfg = load_config().context("nook not initialized; run `nook init`")?;
    let server = server_override.unwrap_or(cfg.server.clone());
    let client = http_client()?;
    let vault_key = load_vault_key(&cfg)?;
    let manifest = fetch_manifest(&client, &server, &vault_key).await?;

    let (nodes_by_id, children_by_id) = index_manifest(&manifest);
    let target_id = match subpath {
        Some(path) => resolve_subpath(&manifest, &nodes_by_id, &children_by_id, &path)?,
        None => manifest.root_node_id,
    };
    let target_idx = nodes_by_id
        .get(&target_id)
        .context("manifest missing target node")?;
    let target = &manifest.nodes[*target_idx];

    match target.node_type {
        NodeType::File => {
            print_entry(target);
        }
        NodeType::Directory => {
            let mut children = children_by_id
                .get(&target_id)
                .cloned()
                .unwrap_or_default();
            children.sort_by_key(|id| {
                nodes_by_id
                    .get(id)
                    .and_then(|idx| manifest.nodes.get(*idx))
                    .map(|n| n.name.clone())
                    .unwrap_or_default()
            });
            for child_id in children {
                if let Some(idx) = nodes_by_id.get(&child_id) {
                    print_entry(&manifest.nodes[*idx]);
                }
            }
        }
    }

    Ok(())
}

async fn cmd_tree(server_override: Option<String>, subpath: Option<PathBuf>) -> Result<()> {
    let cfg = load_config().context("nook not initialized; run `nook init`")?;
    let server = server_override.unwrap_or(cfg.server.clone());
    let client = http_client()?;
    let vault_key = load_vault_key(&cfg)?;
    let manifest = fetch_manifest(&client, &server, &vault_key).await?;

    let (nodes_by_id, children_by_id) = index_manifest(&manifest);
    let target_id = match subpath {
        Some(path) => resolve_subpath(&manifest, &nodes_by_id, &children_by_id, &path)?,
        None => manifest.root_node_id,
    };
    let target_idx = nodes_by_id
        .get(&target_id)
        .context("manifest missing target node")?;
    let target = &manifest.nodes[*target_idx];

    // Print the root of the tree
    match target.node_type {
        NodeType::File => {
            println!("{}", target.name);
        }
        NodeType::Directory => {
            println!("{}/", target.name);
            print_tree_recursive(&manifest, &nodes_by_id, &children_by_id, target_id, "");
        }
    }

    Ok(())
}

fn print_tree_recursive(
    manifest: &Manifest,
    nodes_by_id: &HashMap<u64, usize>,
    children_by_id: &HashMap<u64, Vec<u64>>,
    node_id: u64,
    prefix: &str,
) {
    let mut children: Vec<u64> = children_by_id
        .get(&node_id)
        .cloned()
        .unwrap_or_default();

    // Sort children by name
    children.sort_by_key(|id| {
        nodes_by_id
            .get(id)
            .and_then(|idx| manifest.nodes.get(*idx))
            .map(|n| n.name.clone())
            .unwrap_or_default()
    });

    let count = children.len();
    for (i, child_id) in children.iter().enumerate() {
        let is_last = i == count - 1;
        let connector = if is_last { "└── " } else { "├── " };
        let child_prefix = if is_last { "    " } else { "│   " };

        if let Some(&idx) = nodes_by_id.get(child_id) {
            let child = &manifest.nodes[idx];
            match child.node_type {
                NodeType::Directory => {
                    println!("{}{}{}/", prefix, connector, child.name);
                    print_tree_recursive(
                        manifest,
                        nodes_by_id,
                        children_by_id,
                        *child_id,
                        &format!("{}{}", prefix, child_prefix),
                    );
                }
                NodeType::File => {
                    println!("{}{}{}", prefix, connector, child.name);
                }
            }
        }
    }
}

async fn cmd_pull(server_override: Option<String>, subpath: Option<PathBuf>) -> Result<()> {
    let cfg = load_config().context("nook not initialized; run `nook init`")?;
    let root = cfg
        .root
        .clone()
        .context("set root via `nook root --set <path>` before pulling")?;
    let server = server_override.unwrap_or(cfg.server.clone());
    let client = http_client()?;
    let vault_key = load_vault_key(&cfg)?;
    let manifest = fetch_manifest(&client, &server, &vault_key).await?;

    let (nodes_by_id, children_by_id) = index_manifest(&manifest);

    // Build complete path mapping for all nodes, rooted at the local root
    let mut node_to_path: HashMap<u64, PathBuf> = HashMap::new();
    node_to_path.insert(manifest.root_node_id, root.clone());

    // BFS to build all paths
    let mut queue = vec![manifest.root_node_id];
    while let Some(node_id) = queue.pop() {
        let parent_path = node_to_path.get(&node_id).cloned().unwrap();
        if let Some(children) = children_by_id.get(&node_id) {
            for &child_id in children {
                if let Some(&idx) = nodes_by_id.get(&child_id) {
                    let child = &manifest.nodes[idx];
                    let child_path = parent_path.join(&child.name);
                    node_to_path.insert(child_id, child_path);
                    if matches!(child.node_type, NodeType::Directory) {
                        queue.push(child_id);
                    }
                }
            }
        }
    }

    // Determine the target node based on subpath
    let target_id = match &subpath {
        Some(path) => resolve_subpath(&manifest, &nodes_by_id, &children_by_id, path)?,
        None => manifest.root_node_id,
    };

    // Collect all nodes that need to be pulled (the target and all descendants)
    let nodes_to_pull = collect_subtree(&manifest, &nodes_by_id, &children_by_id, target_id);

    // Process nodes in BFS order to ensure parents are created before children
    let mut pull_queue = vec![target_id];
    let mut processed = std::collections::HashSet::new();

    while let Some(node_id) = pull_queue.pop() {
        if processed.contains(&node_id) {
            continue;
        }
        processed.insert(node_id);

        let idx = nodes_by_id
            .get(&node_id)
            .context("manifest missing node")?;
        let node = &manifest.nodes[*idx];
        let path = node_to_path
            .get(&node_id)
            .context("missing path mapping for node")?;

        match node.node_type {
            NodeType::Directory => {
                tokio_fs::create_dir_all(path).await?;
                // Add children to queue
                if let Some(children) = children_by_id.get(&node_id) {
                    for &child_id in children {
                        if nodes_to_pull.contains(&child_id) {
                            pull_queue.push(child_id);
                        }
                    }
                }
            }
            NodeType::File => {
                // Ensure parent directory exists
                if let Some(parent) = path.parent() {
                    tokio_fs::create_dir_all(parent).await?;
                }
                pull_file(&client, &server, &vault_key, node, path).await?;
            }
        }
    }

    println!("Pull complete.");
    Ok(())
}

async fn pull_file(
    client: &Client,
    server: &str,
    vault_key: &VaultKey,
    node: &Node,
    path: &Path,
) -> Result<()> {
    let object_id = node
        .content_object_id
        .context("file entry missing object id")?;
    let wrapped_dek = node.wrapped_dek.clone().context("missing wrapped dek")?;
    let wrapped = WrappedKey(wrapped_dek);
    let cipher_bytes = get_object(client, server, &hex::encode(object_id)).await?;
    let (wrapped_from_object, chunks) = nook_core::deserialize_encrypted_object(&cipher_bytes)?;
    // Prefer manifest's wrapped key but fall back if object envelope differs.
    let wrapped_to_use = if !wrapped_from_object.0.is_empty() {
        wrapped_from_object
    } else {
        wrapped
    };
    let decrypted = decrypt_object(object_id, &wrapped_to_use, &chunks, vault_key)?;
    if let Some(expected) = node.logical_size {
        if expected != decrypted.plaintext.len() as u64 {
            return Err(anyhow::anyhow!("size mismatch for {}", path.display()));
        }
    }
    write_atomic(path, &decrypted.plaintext)?;
    Ok(())
}

fn collect_subtree(
    manifest: &Manifest,
    nodes_by_id: &HashMap<u64, usize>,
    children_by_id: &HashMap<u64, Vec<u64>>,
    root_id: u64,
) -> std::collections::HashSet<u64> {
    let mut result = std::collections::HashSet::new();
    result.insert(root_id);
    let mut stack = vec![root_id];

    while let Some(current) = stack.pop() {
        if let Some(children) = children_by_id.get(&current) {
            for &child_id in children {
                result.insert(child_id);
                // Check if this child is a directory to recurse
                if let Some(&idx) = nodes_by_id.get(&child_id) {
                    if matches!(manifest.nodes[idx].node_type, NodeType::Directory) {
                        stack.push(child_id);
                    }
                }
            }
        }
    }

    result
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

async fn fetch_manifest(client: &Client, server: &str, vault_key: &VaultKey) -> Result<Manifest> {
    let head_id = derive_head_object_id(vault_key);
    let head_hex = hex::encode(head_id);
    let manifest_bytes = get_object(client, server, &head_hex)
        .await
        .context("manifest not found; push first")?;
    let (wrapped, chunks) = nook_core::deserialize_encrypted_object(&manifest_bytes)?;
    let decrypted = decrypt_object(head_id, &wrapped, &chunks, vault_key)?;
    let manifest: Manifest = serde_json::from_slice(&decrypted.plaintext)?;
    manifest.validate_integrity()?;
    Ok(manifest)
}

fn index_manifest(manifest: &Manifest) -> (HashMap<u64, usize>, HashMap<u64, Vec<u64>>) {
    let mut nodes_by_id = HashMap::new();
    for (idx, node) in manifest.nodes.iter().enumerate() {
        nodes_by_id.insert(node.node_id, idx);
    }
    let mut children_by_id: HashMap<u64, Vec<u64>> = HashMap::new();
    for node in &manifest.nodes {
        if let Some(parent) = node.parent_id {
            children_by_id.entry(parent).or_default().push(node.node_id);
        }
    }
    (nodes_by_id, children_by_id)
}

fn resolve_subpath(
    manifest: &Manifest,
    nodes_by_id: &HashMap<u64, usize>,
    children_by_id: &HashMap<u64, Vec<u64>>,
    subpath: &Path,
) -> Result<u64> {
    let mut current = manifest.root_node_id;
    let mut components = subpath.components().peekable();
    while let Some(component) = components.next() {
        match component {
            Component::CurDir => continue,
            Component::ParentDir => {
                return Err(anyhow::anyhow!("subpath must not contain '..'"));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(anyhow::anyhow!("subpath must be relative to the vault root"));
            }
            Component::Normal(os) => {
                let name = os
                    .to_str()
                    .context("subpath must be valid UTF-8")?;
                let mut found = None;
                if let Some(children) = children_by_id.get(&current) {
                    for child_id in children {
                        let idx = nodes_by_id
                            .get(child_id)
                            .context("manifest missing child node")?;
                        let child = &manifest.nodes[*idx];
                        if child.name == name {
                            found = Some(child.node_id);
                            break;
                        }
                    }
                }
                let child_id =
                    found.ok_or_else(|| anyhow::anyhow!("subpath not found: {}", subpath.display()))?;
                let idx = nodes_by_id
                    .get(&child_id)
                    .context("manifest missing child node")?;
                let child = &manifest.nodes[*idx];
                if components.peek().is_some() && matches!(child.node_type, NodeType::File) {
                    return Err(anyhow::anyhow!(
                        "subpath traverses into file: {}",
                        subpath.display()
                    ));
                }
                current = child.node_id;
            }
        }
    }
    Ok(current)
}

fn print_entry(node: &Node) {
    match node.node_type {
        NodeType::Directory => println!("{}/", node.name),
        NodeType::File => println!("{}", node.name),
    }
}

fn load_config() -> Result<Config> {
    let path = config_path()?;
    let data = fs::read_to_string(&path).context("missing config; run `nook init`")?;
    let cfg: Config = toml::from_str(&data).context(
        "failed to parse config as TOML (configs from older nook versions are not migrated automatically; re-run `nook init`)",
    )?;
    Ok(cfg)
}

fn save_config(cfg: &Config) -> Result<()> {
    let path = config_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let data = toml::to_string_pretty(cfg).context("serializing config")?;
    fs::write(path, data)?;
    Ok(())
}

fn config_path() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("dev", "nook", "nook")
        .context("cannot determine config directory for this platform")?;
    Ok(dirs.config_dir().join("config.toml"))
}
