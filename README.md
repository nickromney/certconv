# certconv

Non-invasive certificate inspection and format conversion tool with an optional TUI.

What it does:

- Read local files and show useful properties (cert subject/issuer/dates, public key info, RSA modulus digests, etc.)
- Convert between common formats (PEM, DER, PFX/P12, raw Base64)

What it does not do:

- Generate new certificates
- Talk to remote services
- Overwrite existing files (outputs are created exclusively; you must pick a different name)

## Quick Start

### Installation (GitHub release binary)

Download the latest binary from GitHub Releases:

```bash
# Example: macOS Apple Silicon
curl -fL https://github.com/nickromney/certconv/releases/latest/download/certconv-darwin-arm64 -o certconv
chmod +x certconv
./certconv version
```

Release artifact names:

- `certconv-darwin-arm64`
- `certconv-darwin-amd64`
- `certconv-linux-arm64`
- `certconv-linux-amd64`
- `certconv-windows-amd64.exe`

Optionally move or symlink it into your PATH:

```bash
# Move into PATH
sudo mv ./certconv /usr/local/bin/certconv

# Or keep it where it is and symlink
sudo ln -sf "$PWD/certconv" /usr/local/bin/certconv
```

You can also build locally:

```bash
make build
./bin/certconv version
```

### Open the TUI

Defaults:

- With no directory argument, TUI starts in `CERTCONV_CERTS_DIR`, then config `certs_dir`, then current working directory.
- `certconv` with no subcommand launches the TUI only when `stdin` and `stdout` are interactive TTYs.
- Positional args at root are reserved for CLI input (for example `-d` quick mode). To start TUI in a specific directory, use `tui DIR` (or `--tui DIR`).

Start in a specific directory (including hidden paths):

```bash
./bin/certconv tui ~/.ssh
./bin/certconv --tui ~/Documents
```

### Convert a file

```bash
# PEM -> DER
./bin/certconv to-der certs/example.pem /tmp/example.der

# DER -> PEM
./bin/certconv from-der /tmp/example.der /tmp/example.pem

# Inspect result
./bin/certconv show /tmp/example.pem
```

### Convert to stdout (shell redirection)

```bash
# Quick DER conversion to stdout (works well with POSIX redirection)
./bin/certconv myfile.pfx -d > myfile.der

# Password-protected PFX (prefer stdin/file over inline)
printf '%s' "$PFX_PASSWORD" | ./bin/certconv myfile.pfx -d --password-stdin > myfile.der
```

## CLI Examples

```bash
./bin/certconv show certs/example.pem
./bin/certconv show-full certs/example.pem

./bin/certconv to-der certs/example.pem /tmp/example.der
./bin/certconv from-der /tmp/example.der /tmp/example.pem

./bin/certconv to-base64 certs/example.pfx /tmp/example.pfx.base64
./bin/certconv from-base64 /tmp/example.pfx.base64 /tmp/example.pfx

./bin/certconv match certs/example.pem certs/example.key
./bin/certconv verify certs/example.pem certs/example.pem
```

### CLI Path Input Workflows (non-TUI)

Use these when you want CLI-only flows without launching the TUI.
The CLI is non-interactive: provide inputs via args/stdin flags and consume output via stdout/files.

- `--path-stdin`: read missing path args from `stdin` (newline-delimited).
- `--path0-stdin`: read missing path args from `stdin` (NUL-delimited).

Notes:

- `--path-stdin`/`--path0-stdin` cannot be combined with `--password-stdin` or `--key-password-stdin`.
- Stdin path args are prepended before explicitly passed args.

```bash
# Read FILE arg from stdin
printf '%s\n' "$HOME/.ssh/id_rsa.pub" | ./bin/certconv show --path-stdin

# Read CERT from stdin and pass CA as explicit arg
printf '%s\n' certs/example.pem | ./bin/certconv verify --path-stdin certs/ca.pem

# NUL-delimited args (safe for special characters)
printf '%s\0%s\0' certs/example.pem certs/ca.pem | ./bin/certconv verify --path0-stdin

```

### CLI + fzf pipelines (external, shell-managed)

`certconv` subcommands take file paths as args, so standard shell composition is
`fzf | xargs certconv ...` (not plain `fzf | certconv`).

```bash
# Show a selected cert/key with a bat preview
fzf --preview='bat --color=always --style=numbers --line-range=:500 {}' \
  | xargs -I{} ./bin/certconv show "{}"

# Open selected file in full openssl details view
fzf --preview='bat --color=always --style=numbers --line-range=:500 {}' \
  | xargs -I{} ./bin/certconv show-full "{}"
```

Alias style:

```bash
alias cf="fzf --preview='bat --color=always --style=numbers --line-range=:500 {}' | xargs -I{} ./bin/certconv show '{}'"
alias cff="fzf --preview='bat --color=always --style=numbers --line-range=:500 {}' | xargs -I{} ./bin/certconv show-full '{}'"
```

### TUI (Explicit)

```bash
./bin/certconv tui
./bin/certconv --tui
```

### TUI Keybindings (matches in-app help)

- `v`: toggle all files (including hidden files like `~/.ssh`) vs cert/key-only filter.
- `f` or `@`: open floating file picker (starts at `~` by default, `Enter` opens directories, override start with `CERTCONV_PICKER_START_DIR`).
- `c`: copy selected full path when file pane is focused; other panes copy current view text.
- `o`: show output command for the current view/context in a toast (`Esc` dismisses, `c` copies command).
- `q`: first press arms quit (`Quit? Press q again, or Esc`), second `q` quits, `Esc` cancels.
- `u`: open usage/help panel.

### Output Formatting

- `--no-color` disables ANSI color output (also disabled automatically when stdout is not a TTY or `NO_COLOR` is set).
- `--ascii` forces ASCII-only output (no Unicode glyphs).
- `--json` outputs machine-readable JSON for most commands. In JSON mode, some checks use exit code `1` (silent) for negative results.

### CLI Option Reference (matches `--help`)

Root/global flags:

- `--ascii`
- `-d, --der` (root quick mode only: convert `FILE` to DER and write to stdout)
- `--no-color`
- `--no-warn-inline-secrets`
- `--password`, `--password-stdin`, `--password-file` (root quick mode for PFX input)
- `--key-password`, `--key-password-stdin`, `--key-password-file` (root quick mode for key input)
- `--path-stdin`
- `--path0-stdin`
- `--plain`
- `-q, --quiet`
- `--tui`
- `-v, --version`
- `-h, --help`

Command-specific flags:

- `show`: `--json`, `-p, --password`, `--password-file`, `--password-stdin`
- `show-full`: `-p, --password`, `--password-file`, `--password-stdin`
- `verify`: `--json`
- `match`: `--json`, `--key-password`, `--key-password-file`, `--key-password-stdin`
- `expiry`: `--days`, `--json`
- `to-pfx`: `-a, --ca`, `--json`, `--key-password`, `--key-password-file`, `--key-password-stdin`, `-p, --password`, `--password-file`, `--password-stdin`
- `from-pfx`: `--json`, `-p, --password`, `--password-file`, `--password-stdin`
- `to-der`: `--json`, `--key`, `--key-password`, `--key-password-file`, `--key-password-stdin`
- `from-der`: `--json`, `--key`, `--key-password`, `--key-password-file`, `--key-password-stdin`
- `to-base64`: `--json`
- `from-base64`: `--json`
- `combine`: `-a, --ca`, `--json`, `--key-password`, `--key-password-file`, `--key-password-stdin`
- `tui`, `version`, `completion`: `-h, --help`

### Encrypted Private Keys

Some operations use `openssl` on private keys. To avoid interactive prompts (and
to support encrypted keys), pass `--key-password` where available:

```bash
./bin/certconv match certs/example.pem certs/encrypted.key --key-password '...'
./bin/certconv to-pfx certs/example.pem certs/encrypted.key out.pfx --key-password '...'
./bin/certconv to-der certs/encrypted.key out.der --key --key-password '...'
```

Prefer the `*-stdin` flags for secrets to avoid putting passwords into shell
history and to avoid leaking them via process args:

```bash
printf '%s' \"$PFX_PASSWORD\" | ./bin/certconv show app.pfx --password-stdin
printf '%s' \"$EXPORT_PASSWORD\" | ./bin/certconv to-pfx app.pem app.key out.pfx --password-stdin
printf '%s' \"$KEY_PASSWORD\" | ./bin/certconv match app.pem app.key --key-password-stdin
```

If your environment makes piping awkward, use the `*-file` flags (recommended
over inline `--password`/`--key-password`):

```bash
./bin/certconv show app.pfx --password-file /path/to/pfx-password.txt
./bin/certconv to-pfx app.pem app.key out.pfx --password-file /path/to/export-password.txt
./bin/certconv match app.pem app.key --key-password-file /path/to/key-password.txt
```

## Azure Key Vault (PFX Base64)

Azure Key Vault often wants a base64-encoded blob of the PFX with no newlines:

```bash
./bin/certconv to-base64 app.pfx app.pfx.base64
az keyvault secret set --file app.pfx.base64 --name app --vault-name "$KEYVAULT_NAME"
```

## Config

Keybindings and a few UX defaults can be overridden via:

- `$XDG_CONFIG_HOME/certconv/config.yml`
- `~/.config/certconv/config.yml`

See `config.example.yml`.

## Dev

Generate sample certs used for manual testing:

```bash
make certs
```

Run tests:

```bash
make test
```

## Legacy

The original shell prototypes are kept for reference in `legacy/`.
