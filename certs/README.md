# Sample Certificates

These files are **test-only** and are safe for local development. They are not trusted by any public CA.

## Sample Files

This repo does not commit private keys. If you want sample inputs for manual testing,
generate them locally:

```bash
make certs
```

This will create:
- `certs/example.pem` (self-signed certificate)
- `certs/example.key` (private key, mode 600)
- `certs/example.pfx` (PFX with empty password)
- `certs/example-pass.pfx` (PFX with password `testpass`)

## Purpose

These are here to:
- validate conversions (PEM ↔ PFX/P12)
- test Key Vault PFX + Base64 workflows
- provide quick local fixtures

## Let’s Encrypt Certificates

See `scripts/download-letsencrypt.sh` to download current Let’s Encrypt root/intermediate certs into `certs/letsencrypt`.

## Regenerate

To regenerate these sample files:

```bash
./scripts/generate-local.sh
```
