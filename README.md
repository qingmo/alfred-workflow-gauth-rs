# gauth-rs

A Rust TOTP generator with pluggable secret stores and Alfred integration.
A modern rewrite of [moul/alfred-workflow-gauth](https://github.com/moul/alfred-workflow-gauth).

- **Pluggable storage** behind a `SecretStore` trait: a legacy plaintext `~/.gauth`
  INI (default) or a **MacPass** vault over KeePassHTTP (secrets stay encrypted).
- **Dual surface:** a plain CLI (`list` / `code` / `add` / `remove` / `associate`)
  and an Alfred Script Filter (`alfred`) emitting JSON.

➡️ **Configuring and using it day-to-day: see [USAGE.md](USAGE.md).**
This README covers building from source and packaging the Alfred workflow.

---

## Build from source

Requires a Rust toolchain (stable). On macOS:

```bash
cargo build --release        # produces target/release/gauth
cargo test                   # run the test suite
cargo clippy --all-targets   # lints
```

The result is a single self-contained binary at `target/release/gauth`.

```bash
# Optionally install onto your PATH for terminal use:
cp target/release/gauth /usr/local/bin/   # or: cargo install --path .
```

---

## Package the Alfred workflow

`bundle.sh` turns the project into an importable `.alfredworkflow` file:

```bash
./bundle.sh
```

This:

1. builds the release binary (`cargo build --release`),
2. validates `alfred/info.plist` with `plutil -lint`,
3. stages the binary + icons + plist, and
4. zips them into **`GAuth.alfredworkflow`** at the repo root.

Install it by double-clicking, or:

```bash
open GAuth.alfredworkflow
```

### What goes in the bundle

```
GAuth.alfredworkflow   (a zip; info.plist must be at the archive root)
├── info.plist         # workflow definition (from alfred/info.plist)
├── gauth              # the release binary (architecture-specific)
├── icon.png           # account-item & workflow icon
├── time.png           # "time remaining" item icon
├── warning.png        # warning/error item icon
└── error.png          # (reserved)
```

The source assets live in `alfred/`; the binary is injected by `bundle.sh`.
`GAuth.alfredworkflow` itself is **git-ignored** because it embeds the compiled,
architecture-specific binary — regenerate it with `bundle.sh` on each machine.

### How the workflow is wired

`alfred/info.plist` defines two connected objects:

1. **Script Filter** (keyword `gauth`, `with space`) runs `./gauth alfred "{query}"`
   from the workflow directory — where the bundled `gauth` binary sits — and Alfred
   renders the JSON it prints. `{query}` is the typed text, used to filter accounts.
2. **Copy to Clipboard** (auto-paste, **transient**) receives the selected item's
   `arg` (the 6-digit code) and pastes it at the cursor. Transient means the code
   is not retained in clipboard history.

> **Input mode caveat.** The Script Filter uses `{query}` substitution
> (`scriptargtype = 0`). If your Alfred build expects argv, open the Script Filter
> and switch the input to argv with script `./gauth alfred "$1"`.

### Distribution notes

- The bundled binary is built for the **current CPU architecture** (e.g. Apple
  Silicon vs Intel). To share the workflow across architectures, rebuild on each,
  or ship a universal binary (`lipo`) — out of scope for v1.
- Auto-paste requires the user to grant **Alfred Accessibility permission**.
- Icons are reused from the original MIT-licensed `moul/alfred-workflow-gauth`.

---

## Project layout

```
src/
  totp.rs              # RFC6238 TOTP (ported from luban-mcp-server)
  account.rs           # SecretMaterial {Secret|Code}, Account, code resolution
  error.rs             # unified StoreError
  keepasshttp/         # blocking KeePassHTTP client (mod.rs + crypto.rs)
  store/
    mod.rs             # SecretStore trait + Caps + open_store factory
    gauth.rs           # legacy INI backend (default, full CRUD)
    macpass.rs         # MacPass backend (read-only v1)
  config.rs            # TOML config + association write-back
  alfred.rs            # Alfred Script Filter JSON
  cli.rs / main.rs     # clap CLI + dispatch
alfred/                # info.plist + icons (workflow source assets)
bundle.sh              # build + package GAuth.alfredworkflow
docs/superpowers/      # design spec & implementation plan
```

Design rationale and the implementation plan are under
[`docs/superpowers/`](docs/superpowers/).

---

## License

MIT (icons inherited from the original MIT-licensed project).
