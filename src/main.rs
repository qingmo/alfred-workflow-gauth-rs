mod account;
mod alfred;
mod cli;
mod config;
mod error;
mod keepasshttp;
mod store;
mod totp;

use clap::Parser;

fn main() {
    let cli = cli::Cli::parse();
    std::process::exit(cli::run(cli));
}
