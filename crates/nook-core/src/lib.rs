mod crypto;
mod manifest;
mod object;

pub use crypto::*;
pub use manifest::*;
pub use object::*;

pub type Result<T> = std::result::Result<T, NookError>;

#[derive(Debug, thiserror::Error)]
pub enum NookError {
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("integrity check failed: {0}")]
    Integrity(String),
    #[error("unknown error: {0}")]
    Other(String),
}
