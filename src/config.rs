//! TOML config at ~/.config/gauth/config.toml. Single active backend; defaults to gauth.

use crate::error::{Result, StoreError};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub backend: BackendKind,
    #[serde(default)]
    pub gauth: GauthConfig,
    #[serde(default)]
    pub macpass: MacpassConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BackendKind {
    #[default]
    Gauth,
    Macpass,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GauthConfig {
    #[serde(default = "default_gauth_path")]
    pub path: String,
}

impl Default for GauthConfig {
    fn default() -> Self {
        Self { path: default_gauth_path() }
    }
}

fn default_gauth_path() -> String {
    "~/.gauth".into()
}

#[derive(Debug, Clone, Deserialize)]
pub struct MacpassConfig {
    #[serde(default = "default_endpoint")]
    pub endpoint: String,
    #[serde(default = "default_marker_url")]
    pub marker_url: String,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub key: String,
}

impl Default for MacpassConfig {
    fn default() -> Self {
        Self {
            endpoint: default_endpoint(),
            marker_url: default_marker_url(),
            id: String::new(),
            key: String::new(),
        }
    }
}

fn default_endpoint() -> String { "http://127.0.0.1:19455".into() }
fn default_marker_url() -> String { "gauth://".into() }

/// Expand a leading `~/` to the user's home directory.
pub fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(path)
}

impl Config {
    /// Default config file location: ~/.config/gauth/config.toml.
    pub fn default_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("gauth")
            .join("config.toml")
    }

    /// Load from `path`; a missing file yields defaults (zero-config gauth backend).
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text)
                .map_err(|e| StoreError::Parse(format!("config {}: {e}", path.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config {
                backend: BackendKind::default(),
                gauth: GauthConfig::default(),
                macpass: MacpassConfig::default(),
            }),
            Err(e) => Err(StoreError::Io(e)),
        }
    }

    /// Write `id`/`key` into `[macpass]`, creating the file/tables and preserving comments.
    pub fn write_association(path: &Path, id: &str, key: &str) -> Result<()> {
        use toml_edit::{table, value, DocumentMut};
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let mut doc: DocumentMut = text
            .parse()
            .map_err(|e| StoreError::Parse(format!("config {}: {e}", path.display())))?;
        if !doc.contains_key("macpass") {
            doc["macpass"] = table();
        }
        let macpass = doc["macpass"]
            .as_table_mut()
            .ok_or_else(|| StoreError::Parse("[macpass] is not a table".into()))?;
        macpass["id"] = value(id);
        macpass["key"] = value(key);
        std::fs::write(path, doc.to_string())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn missing_file_defaults_to_gauth() {
        let cfg = Config::load(Path::new("/tmp/gauth-no-such-config.toml")).unwrap();
        assert_eq!(cfg.backend, BackendKind::Gauth);
        assert_eq!(cfg.gauth.path, "~/.gauth");
    }

    #[test]
    fn parses_macpass_backend() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(f, "backend = \"macpass\"\n[macpass]\nmarker_url = \"x://\"\n").unwrap();
        let cfg = Config::load(f.path()).unwrap();
        assert_eq!(cfg.backend, BackendKind::Macpass);
        assert_eq!(cfg.macpass.marker_url, "x://");
        assert_eq!(cfg.macpass.endpoint, "http://127.0.0.1:19455"); // default filled
    }

    #[test]
    fn write_association_creates_and_updates() {
        let f = tempfile::NamedTempFile::new().unwrap();
        Config::write_association(f.path(), "the-id", "the-key").unwrap();
        let cfg = Config::load(f.path()).unwrap();
        assert_eq!(cfg.macpass.id, "the-id");
        assert_eq!(cfg.macpass.key, "the-key");
    }

    #[test]
    fn expand_tilde_resolves_home() {
        let p = expand_tilde("~/foo");
        assert!(p.is_absolute());
        assert!(p.ends_with("foo"));
    }
}
