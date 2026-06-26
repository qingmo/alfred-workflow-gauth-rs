# gauth-rs

A Rust TOTP generator with pluggable secret stores and Alfred integration.
A modern rewrite of [moul/alfred-workflow-gauth](https://github.com/moul/alfred-workflow-gauth).

- **Pluggable storage** behind a `SecretStore` trait: a legacy plaintext `~/.gauth`
  INI (default) or a **MacPass** vault over KeePassHTTP (secrets stay encrypted).
- **Dual surface:** a plain CLI (`list` / `code` / `add` / `remove` / `associate`)
  and an Alfred Script Filter (`alfred`) emitting JSON.

➡️ **Configuring and using it day-to-day: see [USAGE.md](USAGE.md).**
This README covers building and packaging the self-contained Alfred workflow.

---

## Install the workflow (one step)

The workflow is **fully self-contained**: the `gauth` binary is packaged *inside*
the `.alfredworkflow`, and the Script Filter runs it via the relative path
`./gauth`. You do **not** install anything onto your `PATH` — importing the
workflow is all that's needed.

```bash
./bundle.sh            # build + package GAuth.alfredworkflow
open GAuth.alfredworkflow   # import into Alfred
```

`bundle.sh`:

1. builds the release binary (`cargo build --release`),
2. validates `alfred/info.plist` with `plutil -lint`,
3. stages the binary + icons + plist, and
4. zips them into **`GAuth.alfredworkflow`** at the repo root.

That's it. With the default `~/.gauth` backend you never touch a terminal again.

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

## Using `gauth` in a terminal (optional)

The Alfred workflow needs no terminal. You only want a terminal `gauth` for two
things: the **MacPass `associate`** handshake, and ad-hoc scripting
(`gauth code github | pbcopy`). If you use the default `~/.gauth` backend, skip
this entirely.

Either run the binary the bundle already built:

```bash
./target/release/gauth associate
```

…or install it onto your `PATH` so it's available everywhere:

```bash
cargo install --path .     # installs `gauth` into ~/.cargo/bin
# or: cp target/release/gauth /usr/local/bin/
```

This terminal binary and the one inside the workflow are the same program reading
the same `~/.config/gauth/config.toml` — installing to `PATH` is a convenience, not
a requirement for the workflow.

## Develop

```bash
cargo test                   # run the test suite
cargo clippy --all-targets   # lints
cargo build --release        # produce target/release/gauth
```

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
