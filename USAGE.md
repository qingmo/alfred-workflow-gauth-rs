# gauth — Usage & Configuration

`gauth` generates TOTP / Google-Authenticator-style 2FA codes from a configurable
secret store. This guide covers configuring a backend and using the CLI.

For building and packaging the Alfred workflow, see [README.md](README.md).

---

## Quick start (zero config)

If you already have a legacy `~/.gauth` file, nothing to configure — it's the
default backend:

```ini
# ~/.gauth
[github]
secret = JBSWY3DPEHPK3PXP

[aws - work]
secret = NB2W45DFOIZA
```

```bash
gauth list           # show every account + its current code
gauth code github    # print just the code for "github"
```

---

## Configuration

Configuration is optional. Without a config file, `gauth` uses the `gauth`
(plaintext `~/.gauth`) backend.

**Location:** `~/.config/gauth/config.toml` (override per-invocation with
`gauth --config <path> …`).

```toml
# Which backend is active. One of: "gauth" (default) | "macpass"
backend = "gauth"

[gauth]
# Path to the legacy INI file. A leading ~/ is expanded to your home dir.
path = "~/.gauth"

[macpass]
endpoint   = "http://127.0.0.1:19455"  # MacPassHTTP plugin endpoint
marker_url = "gauth://"                 # shared URL tagging gauth-managed entries
id  = ""                                # filled in by `gauth associate`
key = ""                                # filled in by `gauth associate`
```

Only one backend is active at a time, chosen by `backend`. Unset fields fall back
to the defaults shown above, so a minimal `config.toml` can be as short as:

```toml
backend = "macpass"
```

### Choosing a backend

| Backend   | Where secrets live                          | Writes (`add`/`remove`) |
|-----------|---------------------------------------------|-------------------------|
| `gauth`   | Plaintext INI at `~/.gauth`                 | ✅ supported            |
| `macpass` | Inside your MacPass database (KeePassHTTP)  | ❌ read-only in v1 — manage entries in the MacPass app |

`gauth` is the simplest and the backward-compatible default, but stores secrets in
plaintext. `macpass` keeps secrets inside your encrypted MacPass vault and only
reads them transiently when generating a code — preferred for security.

---

## CLI commands

```bash
gauth list                   # list accounts with their current 6-digit codes
gauth code <name>            # print one account's code (newline-terminated)
gauth add <name> <secret>    # add an account (where the backend supports writes)
gauth remove <name>          # remove an account (where supported)
gauth associate              # one-time MacPass association handshake
gauth alfred "<query>"       # emit Alfred Script Filter JSON (used by the workflow)
gauth --config <path> <cmd>  # use an alternate config file (global flag)
```

Examples:

```bash
# Add a new account to ~/.gauth and immediately read its code
gauth add dropbox JBSWY3DPEHPK3PXP
gauth code dropbox            # -> 492039

# Scripting: copy a code to the clipboard
gauth code github | pbcopy

# Use a project-local config
gauth --config ./gauth.toml list
```

Exit codes: `0` on success, `1` on error (errors print to stderr). The `alfred`
subcommand is the exception — it always exits `0` and renders any error as a
warning item so Alfred shows a friendly message instead of failing silently.

### Adding accounts

A `secret` is a base32-encoded TOTP key (the string a service shows you when you
enable 2FA, e.g. `JBSWY3DPEHPK3PXP`). `gauth add` validates that the secret
produces a code before saving it; an invalid secret is rejected without writing.

`update` is intentionally not a command — to change a secret, `remove` then `add`.

---

## MacPass setup

MacPass is a macOS KeePass client. `gauth` talks to it over the KeePassHTTP
protocol provided by the **MacPassHTTP** plugin.

1. **Install & run** MacPass with the MacPassHTTP plugin enabled, and unlock your
   database. The plugin listens on `http://127.0.0.1:19455` by default.

2. **Select the backend** in `~/.config/gauth/config.toml`:

   ```toml
   backend = "macpass"
   ```

3. **Associate once** so `gauth` and MacPass share an encryption key. This is the
   only step that needs a terminal. Run the binary — either the one the workflow
   already built, or a `gauth` you've installed on your `PATH` (see the README's
   "Using `gauth` in a terminal" section):

   ```bash
   ./target/release/gauth associate     # from the repo, or just: gauth associate
   ```

   MacPass pops a dialog asking you to name/approve the association. On approval,
   `gauth` writes the resulting `id` and `key` into `[macpass]` in your config
   (your existing comments and other settings are preserved). The workflow's
   bundled binary then reads that same config — no rebuild needed.

4. **Tag your TOTP entries.** For each account you want `gauth` to see, create an
   entry in MacPass and set its **URL** to the `marker_url` (`gauth://` by
   default). The entry's **title** becomes the account name. In the **password**
   field, store either:
   - the **base32 secret** (gauth computes the code), or
   - a `{TOTP}` placeholder (MacPass computes the code; gauth uses it as-is).

   `gauth` distinguishes the two automatically: a bare 6-digit value is treated as
   an already-generated code, anything else as a base32 secret.

5. **Verify:**

   ```bash
   gauth list
   ```

   If you see `MacPass is locked` / `re-run gauth associate`, unlock the database
   or redo step 3 (the stored key may be stale).

---

## Alfred (end-user)

Once the workflow is installed (see [README.md](README.md)):

- Type the keyword `gauth`, then optionally part of an account name to filter.
- Press **Enter** on a result to paste its current code at the cursor.

The code is placed on the clipboard as a **transient** item (kept out of clipboard
history) and auto-pasted — which requires granting Alfred Accessibility permission
(macOS System Settings → Privacy & Security → Accessibility).

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `no account matching "<q>"` in Alfred | No account name contains your query, or the store is empty. |
| `MacPass is locked …` | Unlock the MacPass database (or open one). |
| `macpass.id/key are empty; run gauth associate first` | Run `gauth associate` and approve the dialog. |
| `MacPass response verifier mismatch (stale key?)` | Re-run `gauth associate` to refresh the association. |
| `invalid TOTP secret` on `add` | The secret isn't valid base32. Re-copy it from the service. |
| Alfred pastes nothing | Grant Alfred Accessibility permission. |
