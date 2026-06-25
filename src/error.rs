//! Unified crate error. Shared by the store layer and the ported KeePassHTTP code.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, StoreError>;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("operation not supported by this backend")]
    Unsupported,
    #[error("vault is locked: {0}")]
    Locked(String),
    #[error("account not found: {0}")]
    NotFound(String),
    #[error("invalid TOTP secret: {0}")]
    InvalidSecret(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol/parse error: {0}")]
    Parse(String),
    #[error("request error: {0}")]
    Request(String),
    #[error("http error {status}: {body}")]
    Http { status: u16, body: String },
    #[error("auth error: {body}")]
    Auth { status: u16, body: String },
}
