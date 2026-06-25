//! The pluggable secret-store abstraction.

pub mod gauth;
pub mod macpass;

use crate::account::Account;
use crate::error::{Result, StoreError};

bitflags::bitflags! {
    /// What a backend can do.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Caps: u8 {
        const READ   = 0b001;
        const ADD    = 0b010;
        const REMOVE = 0b100;
    }
}

/// A configurable secret store. `add`/`remove` default to `Unsupported`.
pub trait SecretStore {
    fn caps(&self) -> Caps;

    fn list(&self) -> Result<Vec<Account>>;

    fn add(&mut self, _name: &str, _secret_b32: &str) -> Result<()> {
        Err(StoreError::Unsupported)
    }

    fn remove(&mut self, _name: &str) -> Result<()> {
        Err(StoreError::Unsupported)
    }

    /// Resolve a single account's code by name (default impl scans `list`).
    fn code(&self, name: &str) -> Result<String> {
        self.list()?
            .into_iter()
            .find(|a| a.name == name)
            .ok_or_else(|| StoreError::NotFound(name.to_string()))?
            .code()
    }
}

use crate::config::{expand_tilde, BackendKind, Config};
use crate::keepasshttp::KeePassHttpClient;

/// Build the active store from config.
pub fn open_store(cfg: &Config) -> Result<Box<dyn SecretStore>> {
    match cfg.backend {
        BackendKind::Gauth => {
            Ok(Box::new(gauth::GauthStore::new(expand_tilde(&cfg.gauth.path))))
        }
        BackendKind::Macpass => {
            if cfg.macpass.id.is_empty() || cfg.macpass.key.is_empty() {
                return Err(StoreError::Auth {
                    status: 0,
                    body: "macpass.id/key are empty; run `gauth associate` first".into(),
                });
            }
            let client = KeePassHttpClient::new(
                cfg.macpass.endpoint.clone(),
                reqwest::blocking::Client::new(),
            );
            Ok(Box::new(macpass::MacpassStore::new(
                client,
                cfg.macpass.id.clone(),
                cfg.macpass.key.clone(),
                cfg.macpass.marker_url.clone(),
            )))
        }
    }
}
