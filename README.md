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

Add a Script Filter that runs `gauth alfred "{query}"`, where `{query}` is the
text typed into Alfred (used here to filter accounts by name). Each result item
carries its current code in its `arg`. Connect the Script Filter to a "Copy to
Clipboard" / "Paste" action that consumes the selected item's `arg` (the code) —
not `{query}`, which is only the typed input.
Bundle icons named `icon.png`, `warning.png`, `time.png` in the workflow.
