# gauth-rs — Rust TOTP generator with pluggable secret stores

**Date:** 2026-06-25
**Status:** Approved design

## Problem

The legacy [`alfred-workflow-gauth`](https://github.com/moul/alfred-workflow-gauth)
is a Python Alfred 2 workflow that reads TOTP secrets from a plaintext
`~/.gauth` INI file and generates Google-Authenticator-style codes. Storing
secrets in plaintext is poor security hygiene.

We want a Rust rewrite that:

1. Reproduces the workflow's behavior (list accounts, generate TOTP, post the
   code at the cursor via Alfred).
2. Abstracts secret storage behind a **trait** so the storage "upstream" is
   configurable.
3. Keeps the original plaintext `~/.gauth` as the **default** backend (zero-config
   backward compatibility) while allowing secure alternatives — **MacPass** (via
   the KeePassHTTP/MacPassHTTP plugin) now, and **1Password** later.

## Reference material

- `~/.gauth`: INI file, one `[account]` section per entry with `secret = <base32>`.
- Python source (`otp.py`, `workflow.py`, `alfred.py`): SHA1 / 30s / 6-digit TOTP;
  Alfred XML feedback; `add`/`update`/`remove` commands.
- `luban-mcp-server` (`/Users/chaos/rustworkspace/luban-mcp-server`): provides
  reusable, already-tested Rust components —
  - `src/totp.rs` — RFC6238 TOTP with passing RFC test vectors.
  - `src/keepasshttp/mod.rs` + `crypto.rs` — full KeePassHTTP client
    (associate / test-associate / get-logins, AES-256-CBC, verifier handshake)
    with `mockito` tests.
  - `src/config.rs` — TOML config plus `write_association` (persists the
    association `id`/`key` with `toml_edit`, preserving comments).

## Key design decisions

| # | Decision | Choice |
|---|----------|--------|
| 1 | What a backend returns | **Per-entry enum**: `Secret(base32)` (core computes TOTP) or `Code(6 digits)` (backend already generated it, e.g. MacPass `{TOTP}`). |
| 2 | Write operations | **Full CRUD where the backend supports it**; capability-aware `Unsupported` otherwise. *(As built: `gauth` is full CRUD; `macpass` is read-only in v1 — see Backends note.)* |
| 3 | Backends in v1 | **`gauth` (default) + `macpass`**; trait shaped so `1password` drops in later. |
| 4 | Binary shape & Alfred format | **Single binary, dual output**: Alfred **JSON** Script Filter mode + plain CLI subcommands. |
| 5 | MacPass account mapping | **Shared marker URL** (default `gauth://`); account name = entry title; secret-vs-code detected per entry. |
| — | Backend selection | **Single active backend** chosen in TOML config; defaults to `gauth`. |
| — | HTTP | **Blocking `reqwest`** (short-lived CLI; no async runtime). |

## Architecture

### Crate layout

```
src/
  main.rs          # clap CLI dispatch
  cli.rs           # subcommands: list, code, add, remove, associate, (default→alfred)
  config.rs        # TOML config load/write (~/.config/gauth/config.toml)
  totp.rs          # RFC6238 TOTP (ported from luban totp.rs, verbatim + tests)
  alfred.rs        # Alfred JSON Script Filter feedback (serde)
  account.rs       # Account, SecretMaterial, code resolution
  keepasshttp/       # reusable transport, kept top-level (not macpass-specific)
    mod.rs           # ported from luban keepasshttp/mod.rs (async -> blocking)
    crypto.rs        # ported from luban keepasshttp/crypto.rs
  store/
    mod.rs         # SecretStore trait + Caps + open_store factory
    gauth.rs       # legacy INI backend (default)
    macpass.rs     # MacpassStore: maps entries <-> accounts via marker_url
```

*(As built, `keepasshttp/` lives at the crate root rather than nested under
`store/macpass/`, since the KeePassHTTP client is a generic transport reusable
beyond the macpass backend. `StoreError` lives in its own `src/error.rs`.)*

### Dependencies

`clap` (derive), `serde` + `serde_json`, `toml` + `toml_edit`, `dirs`,
`hmac` + `sha1` + `base32` (TOTP), `aes` + `cbc` + `base64` + `rand` (KeePassHTTP),
`reqwest` (blocking), `thiserror` (unified `StoreError`), `rust-ini` (`.gauth` backend),
`bitflags` (capability flags). Dev: `mockito`, `tempfile`.

### The `SecretStore` trait

```rust
/// What a store hands back for one account.
pub enum SecretMaterial {
    Secret(String),  // base32 -> core computes TOTP via totp.rs
    Code(String),    // already-generated 6-digit code (e.g. MacPass {TOTP})
}

pub struct Account {
    pub name: String,
    pub material: SecretMaterial,
}

bitflags::bitflags! {
    pub struct Caps: u8 {
        const READ   = 0b001;
        const ADD    = 0b010;
        const REMOVE = 0b100;
    }
}

pub trait SecretStore {
    fn caps(&self) -> Caps;
    fn list(&self) -> Result<Vec<Account>, StoreError>;
    fn add(&mut self, _name: &str, _secret_b32: &str) -> Result<(), StoreError> {
        Err(StoreError::Unsupported)
    }
    fn remove(&mut self, _name: &str) -> Result<(), StoreError> {
        Err(StoreError::Unsupported)
    }
}
```

- Resolving a single code: `Secret` -> `totp::totp_now(secret)`, `Code` -> returned
  as-is. Lives in `account.rs` so it is backend-independent.
- **Secret-vs-code detection**: a value matching `^\d{6}$` is treated as `Code`,
  otherwise `Secret`. Applies when reading MacPass entries.

### Backends

**`gauth` (default).** Read/write `~/.gauth` INI.
- `list`: parse sections -> `Account { name, Secret(secret) }`.
- `add`: validate base32 (port of Python `is_otp_secret_valid`), write a
  `[name]\nsecret=<base32>` section; error if the section already exists.
- `remove`: delete the section; `NotFound` if absent.
- Caps: `READ | ADD | REMOVE`.

**`macpass`.** Ported KeePassHTTP stack; requires a one-time `associate`.
- `list`: single `get-logins(marker_url)`; each returned entry ->
  `Account { name: entry.name, material: detect(entry.password) }`.
- `add` / `remove`: **`Unsupported` in v1** — read-only. (KeePassHTTP `set-login`
  support is inconsistent across MacPass builds and entries are curated in the
  MacPass app, so v1 doesn't attempt writes. The earlier "best-effort `set-login`"
  idea was dropped to avoid build-dependent failure modes; add a TOTP entry in the
  MacPass app and give it the `marker_url`.)
- Caps: `READ`.

### Config

TOML at `~/.config/gauth/config.toml`. Single active backend; defaults to `gauth`
when the file is absent (existing `~/.gauth` users get zero-config behavior).

```toml
backend = "macpass"   # "gauth" (default) | "macpass"

[gauth]
path = "~/.gauth"

[macpass]
endpoint = "http://127.0.0.1:19455"
marker_url = "gauth://"
id = ""    # filled by `gauth associate`
key = ""   # filled by `gauth associate`
```

`gauth associate` performs the KeePassHTTP association (pops the MacPass approval
dialog) and writes `id`/`key` back via `toml_edit`, preserving comments (mirrors
luban's `write_association`).

### CLI & Alfred surfaces

- `gauth` (no args) / `gauth alfred [query]` -> emit **Alfred JSON** feedback:
  one item per matching account (`title` = name, `arg` = code,
  `subtitle` = "Post {code} at cursor"), plus a trailing "Time remaining: Ns" item.
  Substring filter on the query.
- `gauth list` -> human-readable account + code table.
- `gauth code <name>` -> print just the code (for scripting).
- `gauth add <name> <secret>` / `gauth remove <name>` -> CRUD via active store caps.
- `gauth associate` -> MacPass handshake.

The `.alfredworkflow` bundle wraps the binary with a Script Filter that calls
`gauth alfred "{query}"`.

### Error handling

`StoreError` (thiserror) variants: `Unsupported`, `Locked` (MacPass locked/no DB),
`NotFound`, `InvalidSecret`, `Io`, `Protocol`. In Alfred mode, errors render as a
single warning item (matching the Python `warning_item`) rather than a nonzero
exit, so Alfred shows a friendly message.

## Testing strategy

TDD throughout. Reuse and extend luban's tests:

- Port RFC6238 TOTP vectors verbatim (`totp.rs`).
- Port KeePassHTTP `mockito` tests (associate, get-logins, locked-DB, verifier
  mismatch).
- `tempfile`-based tests for the `.gauth` INI round-trip and base32 validation.
- A `SecretStore` mock to test CLI/Alfred rendering independent of any backend
  (account list -> JSON feedback; error -> warning item; secret-vs-code detection).

## Out of scope (v1)

- 1Password backend (designed-for, added later behind the same trait).
- Multiple simultaneously-active backends (single active backend only).
- `update` command (achieved via `remove` + `add`).
- Non-SHA1 / non-30s / non-6-digit TOTP variants.
