//! CLI definition and handlers.

use crate::alfred::{self, Feedback, Item};
use crate::config::{BackendKind, Config};
use crate::error::{Result, StoreError};
use crate::keepasshttp::KeePassHttpClient;
use crate::store::{open_store, Caps};
use crate::totp;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "gauth", version, about = "TOTP generator with pluggable secret stores")]
pub struct Cli {
    /// Path to the config file (default: ~/.config/gauth/config.toml).
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Emit Alfred Script Filter JSON, filtered by an optional query.
    Alfred { query: Option<String> },
    /// List accounts and their current codes.
    List,
    /// Print just the code for one account.
    Code { name: String },
    /// Add an account (where the backend supports it).
    Add { name: String, secret: String },
    /// Remove an account (where the backend supports it).
    Remove { name: String },
    /// Run the one-time MacPass association handshake.
    Associate,
}

impl Cli {
    fn config_path(&self) -> PathBuf {
        self.config.clone().unwrap_or_else(Config::default_path)
    }
}

/// Entry point used by `main`. Returns process exit code.
pub fn run(cli: Cli) -> i32 {
    let config_path = cli.config_path();

    match cli.command.unwrap_or(Command::Alfred { query: None }) {
        Command::Alfred { query } => {
            // Alfred mode must always emit valid JSON and exit 0, even on error
            // (including a failed config load, which `build_alfred` catches).
            let json = match build_alfred(&config_path, query.as_deref().unwrap_or("")) {
                Ok(j) => j,
                Err(e) => alfred::render(&Feedback {
                    items: vec![Item::message("gauth error", &e.to_string(), Some("warning.png"))],
                }),
            };
            println!("{json}");
            0
        }
        // Non-Alfred subcommands report a config-load error to stderr and exit 1.
        other => {
            let cfg = match Config::load(&config_path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("config error: {e}");
                    return 1;
                }
            };
            match other {
                Command::Alfred { .. } => unreachable!("handled above"),
                Command::List => dispatch(list(&cfg)),
                Command::Code { name } => dispatch(code(&cfg, &name)),
                Command::Add { name, secret } => dispatch(add(&cfg, &name, &secret)),
                Command::Remove { name } => dispatch(remove(&cfg, &name)),
                Command::Associate => dispatch(associate(&cfg, &config_path)),
            }
        }
    }
}

fn dispatch(result: Result<String>) -> i32 {
    match result {
        Ok(msg) => {
            if !msg.is_empty() {
                println!("{msg}");
            }
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn build_alfred(config_path: &std::path::Path, query: &str) -> Result<String> {
    let cfg = Config::load(config_path)?;
    let store = open_store(&cfg)?;
    let accounts = store.list()?;
    let mut items = account_items(&accounts, query);
    if items.is_empty() {
        items.push(Item::message(
            "Account not found",
            &format!("no account matching \"{query}\""),
            Some("warning.png"),
        ));
    } else {
        items.push(Item::message(
            &format!("Time remaining: {}s", totp::time_remaining()),
            "",
            Some("time.png"),
        ));
    }
    Ok(alfred::render(&Feedback { items }))
}

/// Resolve each account's code independently, filtering by a lowercased substring
/// of `query`. A bad account (e.g. an unparseable secret) becomes an error item
/// rather than aborting the whole feed. Pure, for testing.
fn account_items(accounts: &[crate::account::Account], query: &str) -> Vec<Item> {
    let q = query.trim().to_lowercase();
    accounts
        .iter()
        .filter(|a| q.is_empty() || a.name.to_lowercase().contains(&q))
        .map(|a| match a.code() {
            Ok(code) => Item::account(&a.name, &code),
            Err(e) => Item::error(&a.name, &e.to_string()),
        })
        .collect()
}

fn list(cfg: &Config) -> Result<String> {
    let store = open_store(cfg)?;
    Ok(list_lines(&store.list()?).join("\n"))
}

/// Render one line per account, resolving each code independently so one bad entry
/// doesn't abort the listing; a bad account shows an inline error. Pure, for testing.
fn list_lines(accounts: &[crate::account::Account]) -> Vec<String> {
    accounts
        .iter()
        .map(|a| match a.code() {
            Ok(code) => format!("{:<24} {code}", a.name),
            Err(e) => format!("{:<24} <error: {e}>", a.name),
        })
        .collect()
}

fn code(cfg: &Config, name: &str) -> Result<String> {
    open_store(cfg)?.code(name)
}

fn add(cfg: &Config, name: &str, secret: &str) -> Result<String> {
    let mut store = open_store(cfg)?;
    if !store.caps().contains(Caps::ADD) {
        return Err(StoreError::Unsupported);
    }
    store.add(name, secret)?;
    Ok(format!("added account: {name}"))
}

fn remove(cfg: &Config, name: &str) -> Result<String> {
    let mut store = open_store(cfg)?;
    if !store.caps().contains(Caps::REMOVE) {
        return Err(StoreError::Unsupported);
    }
    store.remove(name)?;
    Ok(format!("removed account: {name}"))
}

fn associate(cfg: &Config, config_path: &std::path::Path) -> Result<String> {
    if cfg.backend != BackendKind::Macpass {
        return Err(StoreError::Parse(
            "`associate` requires backend = \"macpass\" in config".into(),
        ));
    }
    let client =
        KeePassHttpClient::new(cfg.macpass.endpoint.clone(), reqwest::blocking::Client::new());
    println!("Approve the association in the MacPass dialog...");
    let (id, key) = client.associate()?;
    Config::write_association(config_path, &id, &key)?;
    Ok(format!("associated as id `{id}`; saved to {}", config_path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A malformed config makes `build_alfred` fail; `run`'s Alfred arm then
    /// renders that error as a warning item (exit 0). This test pins the failure
    /// half so the warning-item path is exercised.
    #[test]
    fn build_alfred_errors_on_bad_config() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "this is = not valid TOML [[[").unwrap();
        let err = build_alfred(f.path(), "foo").unwrap_err();
        // The rendered warning is `Item::message("gauth error", &err.to_string(), ...)`.
        let json = alfred::render(&Feedback {
            items: vec![Item::message("gauth error", &err.to_string(), Some("warning.png"))],
        });
        assert!(json.starts_with("{\"items\":["));
        assert!(json.contains("gauth error"));
        assert!(json.contains("\"valid\":false"));
    }

    /// One unparseable secret (e.g. a `{TOTP}` placeholder a vault returned
    /// verbatim) must NOT blank the whole feed: good accounts still render and
    /// the bad one becomes an error item naming the account.
    #[test]
    fn build_alfred_is_resilient_to_one_bad_secret() {
        let mut secrets = tempfile::NamedTempFile::new().unwrap();
        write!(
            secrets,
            "[good]\nsecret = GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n[bad]\nsecret = {{TOTP}}\n"
        )
        .unwrap();
        let mut cfg = tempfile::NamedTempFile::new().unwrap();
        write!(
            cfg,
            "backend = \"gauth\"\n[gauth]\npath = \"{}\"\n",
            secrets.path().display()
        )
        .unwrap();

        // Must be Ok (not Err) — a single bad entry can't fail the whole feed.
        let json = build_alfred(cfg.path(), "").unwrap();
        assert!(json.contains("\"title\":\"good\""), "good account still listed");
        assert!(json.contains("\"title\":\"bad\""), "bad account surfaced, not dropped");
        assert!(json.contains("Time remaining"));
    }

    /// A valid gauth config yields an `{ "items": [...] }` object with the
    /// account's code as `arg` plus a trailing "Time remaining" item.
    #[test]
    fn build_alfred_renders_items_for_valid_config() {
        let mut secrets = tempfile::NamedTempFile::new().unwrap();
        write!(
            secrets,
            "[demo]\nsecret = GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n"
        )
        .unwrap();
        let mut cfg = tempfile::NamedTempFile::new().unwrap();
        write!(
            cfg,
            "backend = \"gauth\"\n[gauth]\npath = \"{}\"\n",
            secrets.path().display()
        )
        .unwrap();

        let json = build_alfred(cfg.path(), "demo").unwrap();
        assert!(json.contains("\"items\""));
        assert!(json.contains("\"title\":\"demo\""));
        assert!(json.contains("Time remaining"));
    }

    use crate::account::{Account, SecretMaterial};

    fn good() -> Account {
        Account {
            name: "good".into(),
            material: SecretMaterial::Secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into()),
        }
    }
    fn bad() -> Account {
        // A `{TOTP}` placeholder a vault returned verbatim — not valid base32.
        Account { name: "bad".into(), material: SecretMaterial::Secret("{TOTP}".into()) }
    }

    #[test]
    fn account_items_renders_good_and_errors_bad_without_dropping() {
        let items = account_items(&[good(), bad()], "");
        assert_eq!(items.len(), 2);
        let g = items.iter().find(|i| i.title == "good").unwrap();
        assert!(g.valid && g.arg.len() == 6);
        let b = items.iter().find(|i| i.title == "bad").unwrap();
        assert!(!b.valid && b.arg.is_empty() && b.subtitle.starts_with('⚠'));
    }

    #[test]
    fn account_items_filters_by_query() {
        let items = account_items(&[good(), bad()], "goo");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].title, "good");
    }

    #[test]
    fn list_lines_keeps_all_accounts_and_marks_bad() {
        let lines = list_lines(&[good(), bad()]);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("good"));
        assert!(lines[1].starts_with("bad") && lines[1].contains("<error:"));
    }
}
