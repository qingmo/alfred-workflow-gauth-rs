//! MacPass backend over KeePassHTTP. All gauth-managed entries share `marker_url`;
//! each entry's title is the account name and its password is a base32 secret or a
//! live 6-digit code (detected per entry).

use crate::account::{detect_material, Account};
use crate::error::{Result, StoreError};
use crate::keepasshttp::KeePassHttpClient;
use crate::store::{Caps, SecretStore};

pub struct MacpassStore {
    client: KeePassHttpClient,
    id: String,
    key: String,
    marker_url: String,
}

impl MacpassStore {
    pub fn new(client: KeePassHttpClient, id: String, key: String, marker_url: String) -> Self {
        Self { client, id, key, marker_url }
    }

    /// Build entries -> accounts from a fetched login list. Pure; unit-testable.
    fn accounts_from_entries(entries: Vec<crate::keepasshttp::Entry>) -> Vec<Account> {
        entries
            .into_iter()
            .filter(|e| !e.name.is_empty())
            .map(|e| Account { name: e.name, material: detect_material(&e.password) })
            .collect()
    }
}

impl SecretStore for MacpassStore {
    fn caps(&self) -> Caps {
        Caps::READ
    }

    fn list(&self) -> Result<Vec<Account>> {
        let entries = self.client.get_logins(&self.id, &self.key, &self.marker_url)?;
        Ok(Self::accounts_from_entries(entries))
    }

    fn add(&mut self, _name: &str, _secret_b32: &str) -> Result<()> {
        Err(StoreError::Unsupported)
    }

    fn remove(&mut self, _name: &str) -> Result<()> {
        Err(StoreError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::SecretMaterial;
    use crate::keepasshttp::Entry;

    fn entry(name: &str, password: &str) -> Entry {
        Entry { name: name.into(), login: String::new(), password: password.into(), uuid: "u".into() }
    }

    #[test]
    fn maps_entries_to_accounts() {
        let entries = vec![entry("aws", "GEZDGNBVGY3TQOJQ"), entry("vpn", "123456")];
        let accounts = MacpassStore::accounts_from_entries(entries);
        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts[0].material, SecretMaterial::Secret("GEZDGNBVGY3TQOJQ".into()));
        assert_eq!(accounts[1].material, SecretMaterial::Code("123456".into()));
    }

    #[test]
    fn skips_entries_without_title() {
        let entries = vec![entry("", "GEZDGNBVGY3TQOJQ")];
        assert!(MacpassStore::accounts_from_entries(entries).is_empty());
    }
}
