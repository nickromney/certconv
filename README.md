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

Run the TUI:

```bash
go run ./cmd/certconv
```

Build a local binary:

```bash
make build
./bin/certconv
```

Note: running `certconv` with no subcommand only launches the TUI when `stdin` and
`stdout` are interactive TTYs. In CI or when piping, it prints help and exits.

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

### TUI (Explicit)

```bash
./bin/certconv tui
./bin/certconv --tui
```

### Output Formatting

- `--no-color` disables ANSI color output (also disabled automatically when stdout is not a TTY or `NO_COLOR` is set).
- `--ascii` forces ASCII-only output (no Unicode glyphs).
- `--json` outputs machine-readable JSON for most commands. In JSON mode, some checks use exit code `1` (silent) for negative results.

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
