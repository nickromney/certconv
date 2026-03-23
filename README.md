# certconv

[![Build](https://github.com/nickromney/certconv/actions/workflows/checks.yml/badge.svg)](https://github.com/nickromney/certconv/actions/workflows/checks.yml)
[![Release](https://github.com/nickromney/certconv/actions/workflows/release.yml/badge.svg)](https://github.com/nickromney/certconv/actions/workflows/release.yml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/nickromney/certconv)](https://go.dev/)
[![Latest Release](https://img.shields.io/github/v/release/nickromney/certconv)](https://github.com/nickromney/certconv/releases/latest)
[![License: FSL-1.1-MIT](https://img.shields.io/badge/License-FSL--1.1--MIT-blue)](LICENSE.md)

Non-invasive certificate inspection and format conversion tool with an interactive TUI and a script-friendly CLI.

Running `certconv` with no arguments launches the interactive TUI (when stdin/stdout are a TTY). All functionality is also available as CLI subcommands for scripting and pipelines.

```
$ certconv
  → launches the interactive TUI (file browser + cert inspector)

$ certconv show cert.pem
  → CLI mode: inspect a certificate

$ certconv to-der cert.pem out.der
  → CLI mode: convert between formats
```

What it does:

- Inspect certificate/key files (subject, issuer, dates, SANs, public key info, modulus digests)
- Convert between PEM, DER, PFX/P12, PKCS#7, and raw Base64
- Lint certificates for common issues (weak keys, expired, missing SANs)
- Order PEM bundles into proper chain order (leaf to root)
- Discover locally trusted CA certificates (mkcert, custom directories)
- Verify chains and match cert/key pairs

What it does not do:

- Generate new certificates
- Talk to remote services
- Overwrite existing files (outputs are created exclusively; you must pick a different name)

## Install

### Homebrew

```bash
brew install nickromney/tap/certconv
```

### Binary download

Download the binary for your platform from [GitHub Releases](https://github.com/nickromney/certconv/releases/latest):

| Platform | Binary |
|---|---|
| macOS Apple Silicon | `certconv-darwin-arm64` |
| macOS Intel | `certconv-darwin-amd64` |
| Linux x86_64 | `certconv-linux-amd64` |
| Linux ARM64 | `certconv-linux-arm64` |
| Windows x86_64 | `certconv-windows-amd64.exe` |

Then rename and install:

```bash
chmod +x certconv-*
sudo mv certconv-<os>-<arch> /usr/local/bin/certconv
```

#### macOS Gatekeeper note

Binaries downloaded via a browser are flagged by macOS and blocked on first run.
Remove the quarantine attribute before (or after) moving the binary:

```bash
xattr -d com.apple.quarantine certconv
```

Alternatively, right-click the binary in Finder and choose **Open**, then confirm.

### Build from source

```bash
make build
./bin/certconv version
```

### Docker

```bash
# Build
make docker

# Use
docker run --rm -v "$PWD:/certs" certconv:dev show /certs/example.pem
```

## Commands

### Inspect

```bash
certconv show cert.pem              # Summary view
certconv show-full cert.pem         # Full openssl x509 -text output
certconv show cert.pfx -p secret    # PFX with password
```

### Convert

```bash
certconv to-der cert.pem out.der        # PEM to DER
certconv from-der cert.der out.pem      # DER to PEM
certconv to-pfx cert.pem key.pem out.pfx  # PEM to PFX
certconv from-pfx bundle.pfx outdir/    # PFX to PEM files
certconv to-base64 file.pfx out.b64     # Binary to Base64
certconv from-base64 out.b64 file.pfx   # Base64 to binary
certconv combine cert.pem key.pem out.pem  # Combine cert + key
certconv from-p7b bundle.p7b outdir/    # PKCS#7 to PEM files
```

### Verify and match

```bash
certconv verify cert.pem ca.pem     # Verify chain
certconv match cert.pem key.pem     # Check cert/key match
certconv expiry cert.pem --days 30  # Check expiry window
```

### Lint

```bash
certconv lint cert.pem              # Check for common issues
certconv lint cert.pem --json       # Machine-readable output
```

Checks: weak-key (RSA < 2048), sha1-signature, missing-sans, expired, not-yet-valid, ca-as-leaf, long-validity (> 398 days).

Exit codes: 0 = clean, 1 = issues found.

### Chain ordering

```bash
certconv chain bundle.pem           # Output ordered PEM (leaf to root)
certconv chain bundle.pem --json    # Structured output with warnings
```

Orders certificates by matching Authority Key Identifier to Subject Key Identifier, with Issuer/Subject DN fallback. Warns on broken chains.

### Local CA discovery

```bash
certconv local-ca                       # Discover mkcert and other local CAs
certconv local-ca --dir ~/my-cas        # Include custom directory
certconv local-ca --json                # Machine-readable output
```

Searches: mkcert CAROOT (via `mkcert -CAROOT`), platform-default mkcert location, and any `--dir` paths or `local_ca_dirs` from config.

### Doctor

```bash
certconv doctor                     # Check external tool availability
certconv doctor --json              # Machine-readable output
```

Reports status of: openssl, fzf.

### Quick DER to stdout

```bash
certconv myfile.pfx -d > myfile.der
printf '%s' "$PFX_PASSWORD" | certconv myfile.pfx -d --password-stdin > myfile.der
```

## TUI

### Launch

```bash
certconv                    # Auto-launch when interactive
certconv tui                # Explicit
certconv tui ~/certs        # Start in specific directory
certconv --tui ~/.ssh       # Flag form
```

Defaults: starts in `CERTCONV_CERTS_DIR`, then config `certs_dir`, then current working directory.

### Keybindings

| Key | Action |
|-----|--------|
| `j`/`k` or arrows | Navigate |
| `Enter` | Select file / open directory |
| `v` | Toggle all files vs cert-only filter |
| `f` or `@` | Open floating file picker |
| `n`/`p` | Next/previous view in content pane |
| `c` | Copy (file path or current view text) |
| `o` | Show openssl command for current view |
| `u` | Help panel |
| `[`/`]` | Resize file pane |
| `-`/`=` | Resize summary pane |
| `q` | Quit (press twice to confirm) |

## Shell completions

certconv uses Cobra, which auto-generates completions for bash, zsh, fish, and PowerShell.

### Zsh

```bash
# Load in the current shell
source <(certconv completion zsh)

# macOS: install for future shells
certconv completion zsh > "$(brew --prefix)/share/zsh/site-functions/_certconv"

# Alternative: install into a custom completions directory
mkdir -p ~/.zsh/completions
certconv completion zsh > ~/.zsh/completions/_certconv

# Add to .zshrc (if not already present)
echo 'fpath=(~/.zsh/completions $fpath)' >> ~/.zshrc
echo 'autoload -Uz compinit && compinit' >> ~/.zshrc

# Reload
source ~/.zshrc
```

### Bash

```bash
# Linux
certconv completion bash > /etc/bash_completion.d/certconv

# macOS (with bash-completion@2 from Homebrew)
certconv completion bash > $(brew --prefix)/etc/bash_completion.d/certconv
```

### Fish

```bash
certconv completion fish > ~/.config/fish/completions/certconv.fish
```

### PowerShell

```powershell
certconv completion powershell > certconv.ps1
# Add to your PowerShell profile:
# . path/to/certconv.ps1
```

## Agent Skill

certconv ships a Codex skill at `skills/use-certconv/` for agent discovery and
non-interactive use. The skill teaches agents to prefer explicit CLI
subcommands, machine-readable output (`--json`, `--plain`), safe secret
handling (`--password-stdin`, `--password-file`), and to avoid the interactive
TUI unless a human explicitly wants it.

To install the skill into a local Codex skills directory:

```bash
mkdir -p "${CODEX_HOME:-$HOME/.codex}/skills"
ln -s "$PWD/skills/use-certconv" "${CODEX_HOME:-$HOME/.codex}/skills/use-certconv"
```

If a symlink is not appropriate for your environment, copy the directory
instead.

## Man pages

Generate man pages for all commands:

```bash
make man
```

Install system-wide:

```bash
sudo cp docs/man/*.1 /usr/local/share/man/man1/
man certconv
```

## Output formatting

- `--no-color` disables ANSI colour output (also disabled when stdout is not a TTY or `NO_COLOR` is set).
- `--ascii` forces ASCII-only output (no Unicode glyphs).
- `--plain` combines `--no-color` and `--ascii`.
- `--json` outputs machine-readable JSON for most commands.
- `-q, --quiet` suppresses status output (errors still print).

## Password handling

Prefer `*-stdin` or `*-file` flags over inline `--password` to avoid leaking secrets via shell history and process args:

```bash
# Stdin (recommended)
printf '%s' "$PASSWORD" | certconv show app.pfx --password-stdin
printf '%s' "$PASSWORD" | certconv from-pfx app.pfx outdir/ --password-stdin

# File
certconv show app.pfx --password-file /path/to/password.txt

# Inline (warns by default; suppress with --no-warn-inline-secrets)
certconv show app.pfx -p mysecret
```

Passwords are passed to external tools via file descriptors (Unix) or temp files (Windows), never via command-line arguments visible in `ps` output.

## CLI path input workflows

For non-interactive pipelines:

- `--path-stdin`: read missing path args from stdin (newline-delimited)
- `--path0-stdin`: read missing path args from stdin (NUL-delimited)

```bash
printf '%s\n' "$HOME/.ssh/id_rsa.pub" | certconv show --path-stdin
printf '%s\n' certs/example.pem | certconv verify --path-stdin certs/ca.pem
```

## Azure Key Vault (PFX Base64)

```bash
certconv to-base64 app.pfx app.pfx.base64
az keyvault secret set --file app.pfx.base64 --name app --vault-name "$KEYVAULT_NAME"
```

## Config

TUI settings can be overridden via `$XDG_CONFIG_HOME/certconv/config.yml` (or the platform-appropriate config directory).

See [config.example.yml](config.example.yml) for all options including key bindings, themes, layout proportions, and `local_ca_dirs`.

## Development

```bash
make prereqs        # Check/install dev tools (golangci-lint v2, govulncheck, etc.)
make build          # Build for current platform
make test           # Run tests with race detector
make check          # Run all quality checks (fmt, vet, lint, test, vuln)
make install        # Install to GOPATH/bin
make man            # Generate man pages
make docker         # Build Docker image
make help           # Show all targets
```

## Legacy

The original shell prototypes are kept for reference in `legacy/`.
