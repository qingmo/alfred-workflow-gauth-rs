# gauth-rs

A Rust TOTP generator with pluggable secret stores and Alfred integration.
A modern rewrite of [moul/alfred-workflow-gauth](https://github.com/moul/alfred-workflow-gauth).

## Backends

- `gauth` (default): legacy `~/.gauth` INI (`[account]` + `secret = <base32>`).
- `macpass`: MacPass via the KeePassHTTP/MacPassHTTP plugin (secrets stay in the vault).

## Config

`~/.config/gauth/config.toml` (optional — defaults to the `gauth` backend):

```toml
backend = "macpass"          # "gauth" (default) | "macpass"

[gauth]
path = "~/.gauth"

[macpass]
endpoint = "http://127.0.0.1:19455"
marker_url = "gauth://"      # shared URL on every gauth-managed MacPass entry
id = ""                      # filled by `gauth associate`
key = ""                     # filled by `gauth associate`
```

## Usage

```bash
gauth list                   # accounts + current codes
gauth code <name>            # print one code (scripting)
gauth add <name> <secret>    # add (gauth backend)
gauth remove <name>          # remove (gauth backend)
gauth associate              # one-time MacPass association handshake
gauth alfred "<query>"       # Alfred Script Filter JSON
gauth --config <path> ...    # use an alternate config file (global flag)
```

## MacPass setup

1. Set `backend = "macpass"`, run MacPass with the MacPassHTTP plugin.
2. `gauth associate` and approve the dialog (writes `id`/`key` to the config).
3. Give each TOTP entry the URL `gauth://` (the `marker_url`) and store either the
   base32 secret or a `{TOTP}` placeholder in the password field.

## Alfred workflow

### Quick build

```bash
./bundle.sh        # compiles the release binary + zips GAuth.alfredworkflow
open GAuth.alfredworkflow   # import into Alfred
```

`bundle.sh` builds `target/release/gauth`, validates `alfred/info.plist`, and
packages the binary + icons into an importable `GAuth.alfredworkflow`. The bundled
binary is architecture-specific — rebuild on each Mac you install it on.

Then type `gauth ` in Alfred, optionally followed by part of an account name, and
press Enter to paste the current code at the cursor. The code is copied as a
*transient* clipboard item (kept out of clipboard history) and auto-pasted
(requires granting Alfred Accessibility permission).

### How it's wired

The workflow (`alfred/info.plist`) is a Script Filter that runs
`./gauth alfred "{query}"`, where `{query}` is the text typed into Alfred (used to
filter accounts by name). Each result item carries its current code in its `arg`.
The Script Filter connects to a Copy-to-Clipboard output (auto-paste, transient)
that pastes the selected item's `arg` — the code — at the cursor.

> Input mode: the Script Filter uses `{query}` substitution. If your Alfred build
> expects argv instead, open the Script Filter and switch the input to argv with
> script `./gauth alfred "$1"`.
