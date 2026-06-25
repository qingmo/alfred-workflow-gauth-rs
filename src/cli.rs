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
#[command(name = "gauth", about = "TOTP generator with pluggable secret stores")]
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
    let cfg = match Config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config error: {e}");
            return 1;
        }
    };

    match cli.command.unwrap_or(Command::Alfred { query: None }) {
        Command::Alfred { query } => {
            // Alfred mode must always emit valid JSON, even on error.
            let json = match build_alfred(&cfg, query.as_deref().unwrap_or("")) {
                Ok(j) => j,
                Err(e) => alfred::render(&Feedback {
                    items: vec![Item::message("gauth error", &e.to_string(), Some("warning.png"))],
                }),
            };
            println!("{json}");
            0
        }
        Command::List => dispatch(list(&cfg)),
        Command::Code { name } => dispatch(code(&cfg, &name)),
        Command::Add { name, secret } => dispatch(add(&cfg, &name, &secret)),
        Command::Remove { name } => dispatch(remove(&cfg, &name)),
        Command::Associate => dispatch(associate(&cfg, &config_path)),
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

fn build_alfred(cfg: &Config, query: &str) -> Result<String> {
    let store = open_store(cfg)?;
    let accounts = store.list()?;
    let q = query.trim().to_lowercase();
    let mut items: Vec<Item> = Vec::new();
    for acc in &accounts {
        if !q.is_empty() && !acc.name.to_lowercase().contains(&q) {
            continue;
        }
        let code = acc.code()?;
        items.push(Item::account(&acc.name, &code));
    }
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

fn list(cfg: &Config) -> Result<String> {
    let store = open_store(cfg)?;
    let mut lines = Vec::new();
    for acc in store.list()? {
        let code = acc.code()?;
        lines.push(format!("{:<24} {code}", acc.name));
    }
    Ok(lines.join("\n"))
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
