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

