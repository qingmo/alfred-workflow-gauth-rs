pub mod crypto;

use crate::error::{Result, StoreError};
use serde::{Deserialize, Serialize};

/// A decrypted KeePassHTTP entry. `name` is the entry title.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub login: String,
    pub password: String,
    pub uuid: String,
}

#[derive(Serialize, Default)]
#[serde(rename_all = "PascalCase")]
struct Request {
    request_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sort_selection: Option<bool>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct Response {
    success: bool,
    id: Option<String>,
    nonce: Option<String>,
    verifier: Option<String>,
    entries: Option<Vec<RawEntry>>,
    #[allow(dead_code)]
    error: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct RawEntry {
    name: Option<String>,
    login: Option<String>,
    password: Option<String>,
    uuid: Option<String>,
}

/// A blocking KeePassHTTP client for a single MacPassHTTP endpoint.
pub struct KeePassHttpClient {
    endpoint: String,
    http: reqwest::blocking::Client,
}

impl KeePassHttpClient {
    pub fn new(endpoint: String, http: reqwest::blocking::Client) -> Self {
        Self { endpoint, http }
    }

    fn post(&self, body: &Request) -> Result<Response> {
        let resp = self
            .http
            .post(&self.endpoint)
            .json(body)
            .send()
            .map_err(|e| {
                StoreError::Request(format!(
                    "keepasshttp: {e} (is MacPass running with the MacPassHTTP plugin?)"
                ))
            })?;
        let status = resp.status().as_u16();
        let text = resp.text().map_err(|e| StoreError::Request(e.to_string()))?;
        if !(200..300).contains(&status) {
            if status == 400 && text.trim().is_empty() {
                return Err(StoreError::Locked(
                    "MacPass is locked (or no database is open); unlock it and retry".into(),
                ));
            }
            return Err(StoreError::Http { status, body: text });
        }
        serde_json::from_str(&text)
            .map_err(|e| StoreError::Parse(format!("keepasshttp response: {e}")))
    }

    /// One-time association: returns `(id, key_b64)` on approval.
    pub fn associate(&self) -> Result<(String, String)> {
        let key_b64 = crypto::b64(&crypto::random_bytes(32));
        let nonce_b64 = crypto::b64(&crypto::random_bytes(16));
        let verifier = crypto::make_verifier(&key_b64, &nonce_b64)?;
        let req = Request {
            request_type: "associate".into(),
            key: Some(key_b64.clone()),
            nonce: Some(nonce_b64),
            verifier: Some(verifier),
            ..Default::default()
        };
        let resp = self.post(&req)?;
        if !resp.success {
            return Err(StoreError::Auth {
                status: 0,
                body: "association was not approved in MacPass".into(),
            });
        }
        let id = resp.id.ok_or_else(|| StoreError::Parse("associate: missing Id".into()))?;
        Ok((id, key_b64))
    }

    /// Verify a stored association is still valid.
    #[allow(dead_code)]
    pub fn test_associate(&self, id: &str, key_b64: &str) -> Result<bool> {
        let nonce_b64 = crypto::b64(&crypto::random_bytes(16));
        let verifier = crypto::make_verifier(key_b64, &nonce_b64)?;
        let req = Request {
            request_type: "test-associate".into(),
            id: Some(id.into()),
            nonce: Some(nonce_b64),
            verifier: Some(verifier),
            ..Default::default()
        };
        Ok(self.post(&req)?.success)
    }

    /// Fetch entries matching `url` (substring of entry title/url). Returns decrypted entries.
    pub fn get_logins(&self, id: &str, key_b64: &str, url: &str) -> Result<Vec<Entry>> {
        let nonce_b64 = crypto::b64(&crypto::random_bytes(16));
        let verifier = crypto::make_verifier(key_b64, &nonce_b64)?;
        let enc_url = crypto::encrypt_value(key_b64, &nonce_b64, url)?;
        let req = Request {
            request_type: "get-logins".into(),
            id: Some(id.into()),
            nonce: Some(nonce_b64),
            verifier: Some(verifier),
            url: Some(enc_url),
            sort_selection: Some(false),
            ..Default::default()
        };
        let resp = self.post(&req)?;

        let resp_nonce = resp.nonce.ok_or_else(|| StoreError::Auth {
            status: 0,
            body: "MacPass rejected the association (stale key?); re-run `gauth associate`".into(),
        })?;
        let resp_verifier = resp.verifier.clone().unwrap_or_default();
        if !crypto::verify(key_b64, &resp_nonce, &resp_verifier) {
            return Err(StoreError::Auth {
                status: 0,
                body: "MacPass response verifier mismatch (stale key?); re-run `gauth associate`".into(),
            });
        }

        let mut out = Vec::new();
        for raw in resp.entries.unwrap_or_default() {
            let dec = |v: Option<String>| -> Result<String> {
                match v {
                    Some(s) => crypto::decrypt_value(key_b64, &resp_nonce, &s),
                    None => Ok(String::new()),
                }
            };
            out.push(Entry {
                name: dec(raw.name)?,
                login: dec(raw.login)?,
                password: dec(raw.password)?,
                uuid: dec(raw.uuid)?,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keepasshttp::crypto;

    fn encode_get_logins(key_b64: &str, entries: &[(&str, &str, &str, &str)]) -> String {
        let resp_nonce = crypto::b64(&[5u8; 16]);
        let verifier = crypto::make_verifier(key_b64, &resp_nonce).unwrap();
        let enc = |v: &str| crypto::encrypt_value(key_b64, &resp_nonce, v).unwrap();
        let entries_json: Vec<String> = entries
            .iter()
            .map(|(name, login, password, uuid)| {
                format!(
                    r#"{{"Name":"{}","Login":"{}","Password":"{}","Uuid":"{}"}}"#,
                    enc(name), enc(login), enc(password), enc(uuid)
                )
            })
            .collect();
        format!(
            r#"{{"RequestType":"get-logins","Success":true,"Id":"x","Nonce":"{}","Verifier":"{}","Entries":[{}]}}"#,
            resp_nonce, verifier, entries_json.join(",")
        )
    }

    #[test]
    fn get_logins_decrypts_entries() {
        let key_b64 = crypto::b64(&[7u8; 32]);
        let body = encode_get_logins(&key_b64, &[("gauth-aws", "alice", "s3cret", "uuid-1")]);
        let mut server = mockito::Server::new();
        let m = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create();

        let client = KeePassHttpClient::new(server.url(), reqwest::blocking::Client::new());
        let entries = client.get_logins("label", &key_b64, "gauth://").unwrap();
        m.assert();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "gauth-aws");
        assert_eq!(entries[0].password, "s3cret");
    }

    #[test]
    fn get_logins_rejects_missing_verifier() {
        let mut server = mockito::Server::new();
        let _m = server
            .mock("POST", "/")
            .with_status(200)
            .with_body(r#"{"RequestType":"get-logins","Success":false}"#)
            .create();
        let client = KeePassHttpClient::new(server.url(), reqwest::blocking::Client::new());
        let err = client.get_logins("label", &crypto::b64(&[7u8; 32]), "x").unwrap_err();
        assert!(matches!(err, StoreError::Auth { .. }));
    }

    #[test]
    fn locked_db_400_reports_as_locked() {
        let mut server = mockito::Server::new();
        let _m = server.mock("POST", "/").with_status(400).with_body("").create();
        let client = KeePassHttpClient::new(server.url(), reqwest::blocking::Client::new());
        let err = client.get_logins("label", &crypto::b64(&[7u8; 32]), "x").unwrap_err();
        assert!(matches!(err, StoreError::Locked(_)));
    }

    #[test]
    fn associate_returns_id_and_key() {
        let mut server = mockito::Server::new();
        let _m = server
            .mock("POST", "/")
            .with_status(200)
            .with_body(r#"{"RequestType":"associate","Success":true,"Id":"my-label"}"#)
            .create();
        let client = KeePassHttpClient::new(server.url(), reqwest::blocking::Client::new());
        let (id, key) = client.associate().unwrap();
        assert_eq!(id, "my-label");
        assert_eq!(crypto::unb64(&key).unwrap().len(), 32);
    }
}
