//! Legacy `~/.gauth` INI backend. Sections are account names; each has `secret = <base32>`.

use crate::account::{Account, SecretMaterial};
use crate::error::{Result, StoreError};
use crate::store::{Caps, SecretStore};
use crate::totp;
use ini::Ini;
use std::path::PathBuf;

pub struct GauthStore {
    path: PathBuf,
}

impl GauthStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn load(&self) -> Result<Ini> {
        match Ini::load_from_file(&self.path) {
            Ok(ini) => Ok(ini),
            Err(ini::Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(Ini::new()),
            Err(e) => Err(StoreError::Parse(format!("reading {}: {e}", self.path.display()))),
        }
    }

    fn save(&self, ini: &Ini) -> Result<()> {
        ini.write_to_file(&self.path)
            .map_err(StoreError::Io)
    }
}

impl SecretStore for GauthStore {
    fn caps(&self) -> Caps {
        Caps::READ | Caps::ADD | Caps::REMOVE
    }

    fn list(&self) -> Result<Vec<Account>> {
        let ini = self.load()?;
        let mut out = Vec::new();
        for (section, props) in ini.iter() {
            let Some(name) = section else { continue }; // skip the default/global section
            if let Some(secret) = props.get("secret") {
                out.push(Account {
                    name: name.to_string(),
                    material: SecretMaterial::Secret(secret.to_string()),
                });
            }
        }
        Ok(out)
    }

    fn add(&mut self, name: &str, secret_b32: &str) -> Result<()> {
        // Validate the secret is usable before persisting (mirrors Python is_otp_secret_valid).
        totp::totp_now(secret_b32)
            .map_err(|_| StoreError::InvalidSecret("not a valid base32 TOTP secret".into()))?;
        let mut ini = self.load()?;
        if ini.section(Some(name)).is_some() {
            return Err(StoreError::Parse(format!("account already exists: {name}")));
        }
        ini.with_section(Some(name)).set("secret", secret_b32);
        self.save(&ini)
    }

    fn remove(&mut self, name: &str) -> Result<()> {
        let mut ini = self.load()?;
        if ini.section(Some(name)).is_none() {
            return Err(StoreError::NotFound(name.to_string()));
        }
        ini.delete(Some(name));
        self.save(&ini)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const VALID_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn temp_store(contents: &str) -> (tempfile::NamedTempFile, GauthStore) {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        let store = GauthStore::new(f.path().to_path_buf());
        (f, store)
    }

    #[test]
    fn lists_accounts_from_ini() {
        let (_f, store) = temp_store("[aws]\nsecret = ABCD\n\n[github]\nsecret = WXYZ\n");
        let mut names: Vec<_> = store.list().unwrap().into_iter().map(|a| a.name).collect();
        names.sort();
        assert_eq!(names, vec!["aws", "github"]);
    }

    #[test]
    fn add_then_list_round_trips() {
        let (_f, mut store) = temp_store("");
        store.add("aws", VALID_SECRET).unwrap();
        let accounts = store.list().unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].name, "aws");
        assert_eq!(accounts[0].material, SecretMaterial::Secret(VALID_SECRET.into()));
    }

    #[test]
    fn add_rejects_invalid_secret() {
        let (_f, mut store) = temp_store("");
        let candidate = "totally-not-base32-SUPERSECRET-9999";
        let err = store.add("aws", candidate).unwrap_err();
        assert!(matches!(err, StoreError::InvalidSecret(_)));
        // The candidate secret must never appear in the rendered error (secret hygiene).
        assert!(
            !err.to_string().contains(candidate),
            "error message leaked the candidate secret: {err}"
        );
    }

    #[test]
    fn add_rejects_duplicate() {
        let (_f, mut store) = temp_store("");
        store.add("aws", VALID_SECRET).unwrap();
        assert!(store.add("aws", VALID_SECRET).is_err());
    }

    #[test]
    fn remove_deletes_section() {
        let (_f, mut store) = temp_store("");
        store.add("aws", VALID_SECRET).unwrap();
        store.remove("aws").unwrap();
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn remove_missing_is_not_found() {
        let (_f, mut store) = temp_store("");
        assert!(matches!(store.remove("nope").unwrap_err(), StoreError::NotFound(_)));
    }

    #[test]
    fn missing_file_lists_empty() {
        let store = GauthStore::new("/tmp/gauth-does-not-exist-xyz.ini".into());
        assert!(store.list().unwrap().is_empty());
    }
}
