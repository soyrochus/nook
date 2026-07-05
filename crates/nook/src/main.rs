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

/// Fixed keychain coordinates for the local secrets blob. Only one vault
/// config exists per machine (single fixed config path), so a constant
/// service and account name is sufficient to locate the secret.
const KEYCHAIN_SERVICE: &str = "dev.nook.vault";
const KEYCHAIN_ACCOUNT: &str = "vault_key";

/// Associated data binding the passphrase-wrapped secrets blob to its
/// purpose, so it can never be confused with any other ciphertext produced
/// by nook.
const LOCAL_KEY_AAD: &[u8] = b"nook-local-vault-key-v1";

/// Environment variable allowing non-interactive passphrase supply for
/// scripted or CI use of the encrypted-local-file fallback.
const PASSPHRASE_ENV_VAR: &str = "NOOK_PASSPHRASE";

/// Environment override for the garbage-collection grace window (seconds),
/// taking precedence over the config field.
const GC_GRACE_ENV_VAR: &str = "NOOK_GC_GRACE_SECONDS";

/// Default GC grace window: must exceed the longest plausible gap between a
/// pusher's first object upload and its manifest swap, so a concurrent
/// writer's not-yet-linked uploads are never swept (SPEC-005, design D4).
const DEFAULT_GC_GRACE_SECONDS: u64 = 24 * 60 * 60;

/// Bundle format tag for exported/imported namespace identities (SPEC-004 §6).
const NAMESPACE_BUNDLE_PREFIX: &str = "nookns1";

/// A namespace key (SPEC-001's VaultKey/VMK, renamed) is 32 bytes; a vault
/// credential is also 32 bytes. Both are protected together as one 64-byte
/// blob under the same keychain entry / passphrase-encrypted file, so a user
/// only ever has one passphrase to manage.
const SECRETS_LEN: usize = 64;

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
        /// Vault ID issued by the server operator (`nookd vault create`).
        #[arg(long)]
        vault_id: String,
        /// Vault credential issued alongside the vault ID. Never stored in
        /// recoverable form — only used once here to protect it locally.
        #[arg(long)]
        vault_credential: String,
        /// Adopt an existing namespace (from `nook namespace export`)
        /// instead of generating a new one.
        #[arg(long)]
        import_namespace: Option<String>,
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
    /// Remove a file or directory subtree from the namespace (SPEC-005).
    /// Operates on the remote manifest only; local files are never touched.
    Rm {
        /// Path inside the namespace to remove. Mandatory: emptying a whole
        /// namespace requires naming its entries explicitly.
        subpath: PathBuf,
    },
    Status,
    /// Manage this client's namespace identity (SPEC-004 §6).
    Namespace {
        #[command(subcommand)]
        action: NamespaceCommand,
    },
}

#[derive(Subcommand)]
enum NamespaceCommand {
    /// Print a portable bundle encoding this client's namespace identity,
    /// for sharing with a collaborator over a secure out-of-band channel.
    Export,
}

/// Client configuration, persisted as TOML. `vault_id`/`namespace_id` are
/// non-secret, opaque routing labels (SPEC-004 §2). `secrets` is always an
/// opaque reference (a keychain marker or an encrypted blob) — never the raw
/// namespace key or vault credential — so the config file alone never
/// discloses key material.
#[derive(Debug, Serialize, Deserialize)]
struct Config {
    server: String,
    root: Option<PathBuf>,
    vault_id: String,
    namespace_id: String,
    /// Grace window (seconds) for the automatic post-push sweep: unreferenced
    /// objects younger than this survive, protecting a concurrent pusher's
    /// uploaded-but-not-yet-linked objects (SPEC-005). Unset means the
    /// default of 24 hours.
    gc_grace_seconds: Option<u64>,
    secrets: KeyStorage,
}

/// Bundles the vault-level access identity needed to reach the server,
/// separate from `VaultKey` (the namespace's cryptographic identity).
struct ClientAuth {
    vault_id: String,
    namespace_id: String,
    vault_credential: [u8; 32],
}

/// How the local secrets blob (namespace key || vault credential) is
/// stored: preferentially in the OS keychain, or (when no keychain is
/// available) as an Argon2id-passphrase-wrapped blob encrypted with
/// XChaCha20-Poly1305.
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

/// Stores a freshly assembled secrets blob (namespace key || vault
/// credential), preferring the OS keychain and falling back to a
/// passphrase-encrypted local blob if the keychain is unavailable (headless
/// environment, CI, unsupported platform).
fn store_local_secrets(secrets: &[u8]) -> Result<KeyStorage> {
    let keychain_result = (|| -> std::result::Result<(), keyring::Error> {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)?;
        entry.set_secret(secrets)
    })();

    match keychain_result {
        Ok(()) => {
            println!("Vault secrets stored in the OS keychain.");
            Ok(KeyStorage::Keychain)
        }
        Err(err) => {
            eprintln!(
                "OS keychain unavailable ({err}); falling back to a passphrase-encrypted local file."
            );
            let passphrase = read_new_passphrase()?;
            encrypt_secrets_with_passphrase(secrets, &passphrase)
        }
    }
}

/// Retrieves the secrets blob referenced by `storage`, from the OS keychain
/// or by decrypting the local blob with a supplied passphrase.
fn retrieve_local_secrets(storage: &KeyStorage) -> Result<Vec<u8>> {
    match storage {
        KeyStorage::Keychain => {
            let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
                .context("creating keychain entry")?;
            let secret = entry
                .get_secret()
                .context("reading vault secrets from OS keychain")?;
            if secret.len() != SECRETS_LEN {
                return Err(anyhow::anyhow!("unexpected secrets length from keychain"));
            }
            Ok(secret)
        }
        KeyStorage::EncryptedFile {
            salt,
            nonce,
            ciphertext,
        } => {
            let passphrase = read_existing_passphrase()?;
            decrypt_secrets_with_passphrase(salt, nonce, ciphertext, &passphrase)
        }
    }
}

/// Loads and splits the local secrets blob into the namespace key (used for
/// all object encryption, unchanged from SPEC-001) and the `ClientAuth`
/// needed to sign requests (SPEC-004 §4).
fn load_client_identity(cfg: &Config) -> Result<(VaultKey, ClientAuth)> {
    let secrets = retrieve_local_secrets(&cfg.secrets)?;
    if secrets.len() != SECRETS_LEN {
        return Err(anyhow::anyhow!("unexpected secrets length"));
    }
    let mut namespace_key = [0u8; 32];
    namespace_key.copy_from_slice(&secrets[..32]);
    let mut vault_credential = [0u8; 32];
    vault_credential.copy_from_slice(&secrets[32..]);
    Ok((
        VaultKey(namespace_key),
        ClientAuth {
            vault_id: cfg.vault_id.clone(),
            namespace_id: cfg.namespace_id.clone(),
            vault_credential,
        },
    ))
}

fn encrypt_secrets_with_passphrase(secrets: &[u8], passphrase: &str) -> Result<KeyStorage> {
    let mut salt = [0u8; nook_core::PASSPHRASE_SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let wrap_key = nook_core::derive_passphrase_key(passphrase.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("deriving passphrase key: {e}"))?;
    let ciphertext = nook_core::encrypt_chunk(&wrap_key, &nonce, LOCAL_KEY_AAD, secrets);
    Ok(KeyStorage::EncryptedFile {
        salt: salt.to_vec(),
        nonce,
        ciphertext,
    })
}

fn decrypt_secrets_with_passphrase(
    salt: &[u8],
    nonce: &[u8; 24],
    ciphertext: &[u8],
    passphrase: &str,
) -> Result<Vec<u8>> {
    let wrap_key = nook_core::derive_passphrase_key(passphrase.as_bytes(), salt)
        .map_err(|e| anyhow::anyhow!("deriving passphrase key: {e}"))?;
    nook_core::decrypt_chunk(&wrap_key, nonce, LOCAL_KEY_AAD, ciphertext)
        .map_err(|_| anyhow::anyhow!("incorrect passphrase or corrupted local key file"))
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
        Commands::Init {
            server,
            root,
            vault_id,
            vault_credential,
            import_namespace,
        } => cmd_init(server, root, vault_id, vault_credential, import_namespace).await?,
        Commands::Root { set } => cmd_root(set).await?,
        Commands::Ls { subpath } => cmd_ls(cli.server, subpath).await?,
        Commands::Tree { subpath } => cmd_tree(cli.server, subpath).await?,
        Commands::Push { subpath } => cmd_push(cli.server, subpath).await?,
        Commands::Pull { subpath } => cmd_pull(cli.server, subpath).await?,
        Commands::Rm { subpath } => cmd_rm(cli.server, subpath).await?,
        Commands::Status => cmd_status(cli.server).await?,
        Commands::Namespace { action } => match action {
            NamespaceCommand::Export => cmd_namespace_export().await?,
        },
    }
    Ok(())
}

async fn cmd_init(
    server: String,
    root: Option<PathBuf>,
    vault_id: String,
    vault_credential: String,
    import_namespace: Option<String>,
) -> Result<()> {
    if !nook_core::is_valid_hex_id(&vault_id) {
        return Err(anyhow::anyhow!("--vault-id must be 64 lowercase hex characters"));
    }
    let vault_credential_bytes = hex::decode(&vault_credential).context("--vault-credential must be hex-encoded")?;
    if vault_credential_bytes.len() != 32 {
        return Err(anyhow::anyhow!("--vault-credential must decode to 32 bytes"));
    }

    let (namespace_id, namespace_key) = match import_namespace {
        Some(bundle) => decode_namespace_bundle(&bundle)?,
        None => {
            let mut namespace_id_bytes = [0u8; 32];
            OsRng.fill_bytes(&mut namespace_id_bytes);
            (hex::encode(namespace_id_bytes), nook_core::generate_vault_key().0)
        }
    };

    let mut secrets = Vec::with_capacity(SECRETS_LEN);
    secrets.extend_from_slice(&namespace_key);
    secrets.extend_from_slice(&vault_credential_bytes);
    let key_storage = store_local_secrets(&secrets)?;

    let config = Config {
        server,
        root,
        vault_id,
        namespace_id,
        gc_grace_seconds: None,
        secrets: key_storage,
    };
    save_config(&config)?;
    println!("Vault initialized. Keep this machine secure to retain access.");
    Ok(())
}

async fn cmd_namespace_export() -> Result<()> {
    let cfg = load_config().context("nook not initialized; run `nook init`")?;
    let (vault_key, auth) = load_client_identity(&cfg)?;
    println!("{}", encode_namespace_bundle(&auth.namespace_id, vault_key.as_bytes()));
    Ok(())
}

fn encode_namespace_bundle(namespace_id: &str, namespace_key: &[u8; 32]) -> String {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    format!("{NAMESPACE_BUNDLE_PREFIX}:{namespace_id}:{}", BASE64.encode(namespace_key))
}

fn decode_namespace_bundle(bundle: &str) -> Result<(String, [u8; 32])> {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    let mut parts = bundle.splitn(3, ':');
    let prefix = parts.next().context("malformed namespace bundle")?;
    if prefix != NAMESPACE_BUNDLE_PREFIX {
        return Err(anyhow::anyhow!("unrecognized namespace bundle format"));
    }
    let namespace_id = parts.next().context("malformed namespace bundle: missing namespace_id")?;
    if !nook_core::is_valid_hex_id(namespace_id) {
        return Err(anyhow::anyhow!("malformed namespace bundle: invalid namespace_id"));
    }
    let key_b64 = parts.next().context("malformed namespace bundle: missing key")?;
    let key_bytes = BASE64.decode(key_b64).context("malformed namespace bundle: invalid key encoding")?;
    if key_bytes.len() != 32 {
        return Err(anyhow::anyhow!("malformed namespace bundle: key must be 32 bytes"));
    }
    let mut namespace_key = [0u8; 32];
    namespace_key.copy_from_slice(&key_bytes);
    Ok((namespace_id.to_string(), namespace_key))
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
    let (vault_key, auth) = load_client_identity(&cfg)?;
    let head_id = derive_head_object_id(&vault_key);
    let head_hex = hex::encode(head_id);
    match head_object(&client, &server, &auth, &head_hex).await? {
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
    let (vault_key, auth) = load_client_identity(&cfg)?;

    // Try to fetch existing manifest, or create empty one
    let head_id = derive_head_object_id(&vault_key);
    let head_hex = hex::encode(head_id);
    let (mut manifest, etag) = match fetch_manifest_with_etag(&client, &server, &auth, &vault_key).await {
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
    // Captured before any mutation: the CAS swap below proves this was the
    // current manifest, so anything it referenced that the new manifest
    // doesn't is safe to delete immediately (SPEC-005, sweep tier 1).
    let previous_live = manifest_live_set(&manifest, &head_hex);

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
        put_object(&client, &server, &auth, &hex_id, bytes, None).await?;
    }
    put_object(&client, &server, &auth, &head_hex, manifest_serialized, etag.as_deref()).await?;

    println!("Push complete.");

    // Post-commit only: a failed CAS swap has already returned above, so a
    // client that lost the race never deletes anything.
    let new_live = manifest_live_set(&manifest, &head_hex);
    sweep_namespace(&client, &server, &auth, &previous_live, &new_live, gc_grace_seconds(&cfg)).await;
    Ok(())
}

/// Removes a file or directory subtree from the remote manifest via the
/// CAS-guarded manifest flow, then sweeps the newly unreferenced content
/// objects. Local files under the root are never touched (SPEC-005).
async fn cmd_rm(server_override: Option<String>, subpath: PathBuf) -> Result<()> {
    let cfg = load_config().context("nook not initialized; run `nook init`")?;
    let server = server_override.unwrap_or(cfg.server.clone());
    let client = http_client()?;
    let (vault_key, auth) = load_client_identity(&cfg)?;
    let head_id = derive_head_object_id(&vault_key);
    let head_hex = hex::encode(head_id);

    let (mut manifest, etag) = match fetch_manifest_with_etag(&client, &server, &auth, &vault_key).await {
        Ok((m, e)) => (m, e),
        Err(ManifestFetchError::NotFound) => {
            return Err(anyhow::anyhow!("namespace has no manifest yet; nothing to remove"));
        }
        Err(ManifestFetchError::Other(e)) => {
            return Err(e.context(
                "failed to fetch or decrypt the existing manifest; aborting rm without modifying server state",
            ));
        }
    };
    let previous_live = manifest_live_set(&manifest, &head_hex);

    let (nodes_by_id, children_by_id) = index_manifest(&manifest);
    let target_id = resolve_subpath(&manifest, &nodes_by_id, &children_by_id, &subpath)?;
    if target_id == manifest.root_node_id {
        return Err(anyhow::anyhow!(
            "refusing to remove the namespace root; name the entries to remove explicitly"
        ));
    }
    let subtree = collect_subtree(&manifest, &nodes_by_id, &children_by_id, target_id);
    manifest.nodes.retain(|n| !subtree.contains(&n.node_id));

    manifest.integrity_checksum = manifest.compute_integrity()?;
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    let manifest_object = encrypt_object(head_id, ObjectType::Manifest, &manifest_bytes, &vault_key)?;
    let manifest_serialized = serialize_encrypted_object(&manifest_object)?;
    put_object(&client, &server, &auth, &head_hex, manifest_serialized, etag.as_deref()).await?;

    println!("Removed {}.", subpath.display());

    let new_live = manifest_live_set(&manifest, &head_hex);
    sweep_namespace(&client, &server, &auth, &previous_live, &new_live, gc_grace_seconds(&cfg)).await;
    Ok(())
}

/// The set of object IDs a manifest keeps alive: the manifest head object
/// itself (unconditionally, even for an empty manifest) plus every file
/// node's content object.
fn manifest_live_set(manifest: &Manifest, head_hex: &str) -> std::collections::HashSet<String> {
    let mut live: std::collections::HashSet<String> = manifest
        .nodes
        .iter()
        .filter_map(|n| n.content_object_id.map(hex::encode))
        .collect();
    live.insert(head_hex.to_string());
    live
}

/// Effective GC grace window: env override, then config, then the default.
fn gc_grace_seconds(cfg: &Config) -> u64 {
    if let Ok(raw) = std::env::var(GC_GRACE_ENV_VAR) {
        if let Ok(secs) = raw.parse::<u64>() {
            return secs;
        }
        eprintln!("warning: ignoring unparsable {GC_GRACE_ENV_VAR}={raw}");
    }
    cfg.gc_grace_seconds.unwrap_or(DEFAULT_GC_GRACE_SECONDS)
}

/// Automatic garbage collection (SPEC-005): runs strictly after a successful
/// manifest CAS swap and never fails the surrounding command — every error
/// here degrades to a warning, and a later push re-sweeps whatever was
/// missed.
///
/// Two tiers (design D3):
/// 1. Objects referenced by the previous manifest but not the new one are
///    deleted immediately — the CAS win proves no concurrent writer has
///    linked them since.
/// 2. Any other listed object outside the live set is deleted only once
///    older than the grace window, so a concurrent pusher's
///    uploaded-but-not-yet-linked objects survive until their own swap. Ages
///    compare server-issued timestamps only; the client clock is never
///    consulted.
async fn sweep_namespace(
    client: &Client,
    server: &str,
    auth: &ClientAuth,
    previous_live: &std::collections::HashSet<String>,
    new_live: &std::collections::HashSet<String>,
    grace_seconds: u64,
) {
    let mut to_delete: Vec<String> = previous_live.difference(new_live).cloned().collect();
    let dereferenced: std::collections::HashSet<String> = to_delete.iter().cloned().collect();

    let mut sizes: HashMap<String, u64> = HashMap::new();
    match list_namespace_objects(client, server, auth).await {
        Ok(listing) => {
            for obj in listing.objects {
                sizes.insert(obj.object_id.clone(), obj.size);
                if new_live.contains(&obj.object_id) || dereferenced.contains(&obj.object_id) {
                    continue;
                }
                if listing.server_time.saturating_sub(obj.updated_at) > grace_seconds as i64 {
                    to_delete.push(obj.object_id);
                }
            }
        }
        Err(err) => {
            eprintln!(
                "warning: could not list namespace objects for cleanup ({err:#}); \
                 sweeping only objects dereferenced by this operation"
            );
        }
    }

    let mut deleted = 0usize;
    let mut freed: u64 = 0;
    let mut failures = 0usize;
    for object_id in &to_delete {
        match delete_object(client, server, auth, object_id).await {
            Ok(()) => {
                deleted += 1;
                freed += sizes.get(object_id).copied().unwrap_or(0);
            }
            Err(_) => failures += 1,
        }
    }
    if deleted > 0 {
        println!("Reclaimed {deleted} unreferenced object(s) ({freed} bytes).");
    }
    if failures > 0 {
        eprintln!("warning: {failures} object deletion(s) failed; a later push will reclaim them");
    }
}

/// One entry of the namespace listing: the only attributes the server knows.
#[derive(Debug, Deserialize)]
struct ListedObject {
    object_id: String,
    size: u64,
    updated_at: i64,
}

#[derive(Debug, Deserialize)]
struct NamespaceListing {
    /// Server-side "now", so object ages can be computed without trusting
    /// the client clock.
    server_time: i64,
    objects: Vec<ListedObject>,
}

async fn list_namespace_objects(client: &Client, server: &str, auth: &ClientAuth) -> Result<NamespaceListing> {
    let path = nook_core::namespace_objects_path(&auth.vault_id, &auth.namespace_id);
    let url = format!("{server}{path}");
    let headers = signed_headers(auth, "GET", &path, b"")?;
    let res = client.get(url).headers(headers).send().await?;
    if !res.status().is_success() {
        return Err(anyhow::anyhow!("listing failed with status {}", res.status()));
    }
    res.json::<NamespaceListing>().await.context("parsing namespace listing")
}

/// Deletes one object. A 404 counts as success (another client already swept
/// it); a 405 means the server predates SPEC-005 deletion support.
async fn delete_object(client: &Client, server: &str, auth: &ClientAuth, object_id_hex: &str) -> Result<()> {
    let path = nook_core::object_path(&auth.vault_id, &auth.namespace_id, object_id_hex);
    let url = format!("{server}{path}");
    let headers = signed_headers(auth, "DELETE", &path, b"")?;
    let res = client.delete(url).headers(headers).send().await?;
    match res.status() {
        reqwest::StatusCode::NO_CONTENT | reqwest::StatusCode::NOT_FOUND => Ok(()),
        reqwest::StatusCode::METHOD_NOT_ALLOWED => {
            Err(anyhow::anyhow!("server does not support object deletion"))
        }
        other => Err(anyhow::anyhow!("DELETE failed with status {other}")),
    }
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
    auth: &ClientAuth,
    vault_key: &VaultKey,
) -> std::result::Result<(Manifest, Option<String>), ManifestFetchError> {
    let head_id = derive_head_object_id(vault_key);
    let head_hex = hex::encode(head_id);

    let path = nook_core::object_path(&auth.vault_id, &auth.namespace_id, &head_hex);
    let url = format!("{server}{path}");
    let headers = signed_headers(auth, "GET", &path, b"")
        .map_err(|e| ManifestFetchError::Other(e.context("signing manifest request")))?;
    let res = client
        .get(&url)
        .headers(headers)
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
    let (vault_key, auth) = load_client_identity(&cfg)?;
    let manifest = fetch_manifest(&client, &server, &auth, &vault_key).await?;

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
    let (vault_key, auth) = load_client_identity(&cfg)?;
    let manifest = fetch_manifest(&client, &server, &auth, &vault_key).await?;

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
    let (vault_key, auth) = load_client_identity(&cfg)?;
    let manifest = fetch_manifest(&client, &server, &auth, &vault_key).await?;

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
                pull_file(&client, &server, &auth, &vault_key, node, path).await?;
            }
        }
    }

    println!("Pull complete.");
    Ok(())
}

async fn pull_file(
    client: &Client,
    server: &str,
    auth: &ClientAuth,
    vault_key: &VaultKey,
    node: &Node,
    path: &Path,
) -> Result<()> {
    let object_id = node
        .content_object_id
        .context("file entry missing object id")?;
    let wrapped_dek = node.wrapped_dek.clone().context("missing wrapped dek")?;
    let wrapped = WrappedKey(wrapped_dek);
    let cipher_bytes = get_object(client, server, auth, &hex::encode(object_id))
        .await
        .with_context(|| {
            format!(
                "fetching content for {} — if a concurrent writer replaced or removed it, re-run `nook pull`",
                path.display()
            )
        })?;
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

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Builds the `X-Nook-Timestamp`/`X-Nook-Signature` headers for a request,
/// signed with the vault credential. The credential itself never appears in
/// the request (SPEC-004 §4).
fn signed_headers(auth: &ClientAuth, method: &str, path: &str, body: &[u8]) -> Result<HeaderMap> {
    let timestamp = now_unix();
    let signature = nook_core::sign_request(&auth.vault_credential, method, path, timestamp, body);
    let mut headers = HeaderMap::new();
    headers.insert(
        "X-Nook-Timestamp",
        HeaderValue::from_str(&timestamp.to_string()).context("invalid timestamp header")?,
    );
    headers.insert(
        "X-Nook-Signature",
        HeaderValue::from_str(&signature).context("invalid signature header")?,
    );
    Ok(headers)
}

async fn head_object(client: &Client, server: &str, auth: &ClientAuth, object_id_hex: &str) -> Result<Option<String>> {
    let path = nook_core::object_path(&auth.vault_id, &auth.namespace_id, object_id_hex);
    let url = format!("{server}{path}");
    let headers = signed_headers(auth, "HEAD", &path, b"")?;
    let res = client.head(url).headers(headers).send().await?;
    match res.status() {
        reqwest::StatusCode::OK => Ok(res
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string())),
        reqwest::StatusCode::NOT_FOUND => Ok(None),
        reqwest::StatusCode::UNAUTHORIZED => {
            Err(anyhow::anyhow!("unauthorized: check vault ID/credential"))
        }
        other => Err(anyhow::anyhow!("HEAD failed with status {other}")),
    }
}

async fn put_object(
    client: &Client,
    server: &str,
    auth: &ClientAuth,
    object_id_hex: &str,
    bytes: Vec<u8>,
    etag: Option<&str>,
) -> Result<()> {
    let path = nook_core::object_path(&auth.vault_id, &auth.namespace_id, object_id_hex);
    let url = format!("{server}{path}");
    let mut headers = signed_headers(auth, "PUT", &path, &bytes)?;
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
        reqwest::StatusCode::INSUFFICIENT_STORAGE => {
            Err(anyhow::anyhow!("vault quota exceeded"))
        }
        reqwest::StatusCode::UNAUTHORIZED => {
            Err(anyhow::anyhow!("unauthorized: check vault ID/credential"))
        }
        other => Err(anyhow::anyhow!("PUT failed with status {other}")),
    }
}

async fn get_object(client: &Client, server: &str, auth: &ClientAuth, object_id_hex: &str) -> Result<Vec<u8>> {
    let path = nook_core::object_path(&auth.vault_id, &auth.namespace_id, object_id_hex);
    let url = format!("{server}{path}");
    let headers = signed_headers(auth, "GET", &path, b"")?;
    let res = client.get(url).headers(headers).send().await?;
    if res.status().is_success() {
        let bytes = res.bytes().await?;
        return Ok(bytes.to_vec());
    }
    if res.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(anyhow::anyhow!("object {object_id_hex} not found"));
    }
    if res.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Err(anyhow::anyhow!("unauthorized: check vault ID/credential"));
    }
    Err(anyhow::anyhow!(
        "GET failed with status {}",
        res.status()
    ))
}

async fn fetch_manifest(client: &Client, server: &str, auth: &ClientAuth, vault_key: &VaultKey) -> Result<Manifest> {
    let head_id = derive_head_object_id(vault_key);
    let head_hex = hex::encode(head_id);
    let manifest_bytes = get_object(client, server, auth, &head_hex)
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
