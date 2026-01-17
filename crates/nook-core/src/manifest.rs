use crate::{NookError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObjectType {
    Manifest,
    Content,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeType {
    #[serde(rename = "file")]
    File,
    #[serde(rename = "directory")]
    Directory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub node_id: u64,
    pub parent_id: Option<u64>,
    pub name: String,
    pub node_type: NodeType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_object_id: Option<[u8; 32]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrapped_dek: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logical_size: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub manifest_version: u32,
    pub root_node_id: u64,
    pub nodes: Vec<Node>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_manifest_hash: Option<String>,
    pub integrity_checksum: String,
}

#[derive(Serialize)]
struct ManifestIntegrityView<'a> {
    manifest_version: u32,
    root_node_id: u64,
    nodes: &'a [Node],
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_manifest_hash: &'a Option<String>,
}

impl Manifest {
    pub fn compute_integrity(&self) -> Result<String> {
        let view = ManifestIntegrityView {
            manifest_version: self.manifest_version,
            root_node_id: self.root_node_id,
            nodes: &self.nodes,
            previous_manifest_hash: &self.previous_manifest_hash,
        };
        let bytes =
            serde_json::to_vec(&view).map_err(|e| NookError::Serialization(e.to_string()))?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }

    pub fn validate_integrity(&self) -> Result<()> {
        let expected = self.compute_integrity()?;
        if expected != self.integrity_checksum {
            return Err(NookError::Integrity("manifest checksum mismatch".into()));
        }
        Ok(())
    }
}
