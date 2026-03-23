---
name: use-certconv
description: Inspect, verify, lint, reorder, and convert local certificate-related files with the `certconv` CLI. Use when working with PEM, DER, PFX/P12, PKCS#7/P7B, Base64-wrapped cert material, certificate bundles, private keys, public keys, or local CA files; especially when an agent should avoid the interactive TUI and use structured, non-interactive commands instead.
---

# Use Certconv

Use `certconv` as the primary interface for local certificate work when the task can be solved by inspecting or converting files on disk. Treat the TUI as human-only. Use explicit CLI subcommands and prefer structured output.

## Quick Start

Run the binary directly:

```bash
certconv <subcommand> [args...]
```

Prefer these flags in agent workflows:

- Use `--json` whenever the subcommand supports it.
- Use `--plain` to avoid ANSI color and Unicode noise.
- Use `--quiet` only when intermediate status text is not useful.
- Use `--password-stdin` or `--password-file` instead of inline secrets.
- Use `--key-password-stdin` or `--key-password-file` instead of inline key secrets.

Do not launch the TUI. Do not rely on `certconv` with no arguments. Use an explicit subcommand every time.

## Read First

Start with the least destructive command that answers the question.

- Identify or inspect a file: `certconv show FILE --json --plain`
- Read full certificate text: `certconv show-full FILE --plain`
- Check chain validity: `certconv verify CERT CA --json --plain`
- Check cert/key match: `certconv match CERT KEY --json --plain`
- Check expiry window: `certconv expiry CERT --days 30 --json --plain`
- Lint a certificate: `certconv lint CERT --json --plain`
- Reorder a PEM bundle: `certconv chain BUNDLE --json --plain`
- Discover local CA files: `certconv local-ca --json --plain`
- Check external dependencies: `certconv doctor --json --plain`

Use `show --json` first when the file type is uncertain. `certconv` detects common certificate, key, PFX/P12, DER, PKCS#7, Base64, and combined PEM inputs.

## Convert Only On Explicit Request

Treat conversion as a write operation even though `certconv` never overwrites existing files.

Use these commands when the task explicitly asks for a new artifact:

- PEM cert to DER: `certconv to-der cert.pem out.der --json --plain`
- DER cert to PEM: `certconv from-der cert.der out.pem --json --plain`
- PEM cert and key to PFX: `certconv to-pfx cert.pem key.pem out.pfx --json --plain`
- PFX to PEM files: `certconv from-pfx bundle.pfx outdir --json --plain`
- PKCS#7 to PEM files: `certconv from-p7b bundle.p7b outdir --json --plain`
- Binary file to raw Base64: `certconv to-base64 file.pfx out.b64 --json --plain`
- Raw Base64 to binary: `certconv from-base64 file.b64 out.bin --json --plain`
- Combine cert, key, and optional CA PEM: `certconv combine cert.pem key.pem out.pem --json --plain`

Choose a fresh output path or output directory before running conversions. `certconv` fails rather than overwriting an existing file.

## Handle Secrets Safely

Avoid inline secret flags unless there is no practical alternative.

- For PFX input passwords, prefer `--password-stdin` or `--password-file`.
- For encrypted private keys, prefer `--key-password-stdin` or `--key-password-file`.
- If only one secret can come from stdin, use a file for the second secret.
- Do not copy passwords into logs, prose summaries, or shell history.

Example:

```bash
printf '%s' "$PFX_PASSWORD" | certconv show bundle.pfx --json --plain --password-stdin
```

## Interpret Output Correctly

Use machine-readable output when available.

- `show --json` returns a summary object.
- `verify --json`, `match --json`, and `expiry --json` use exit code `1` for a negative result without treating it as a transport failure.
- `lint --json` returns findings; non-JSON lint exits `1` when issues exist.
- `chain --json` returns ordered metadata; without `--json`, it writes reordered PEM to stdout.
- Conversion commands with `--json` report output paths, not file contents.
- `show-full` is raw text, not JSON.

Distinguish operational failure from a valid negative result. A mismatched key or an expiring certificate is often expected business logic, not a crashed command.

## Work In Agent Mode

Follow this decision order:

1. Inspect with `show --json`.
2. Validate with `verify`, `match`, `expiry`, `lint`, or `chain` as needed.
3. Convert only if the user asked for a new artifact.
4. Report the command outcome, key fields, and any created paths.

Prefer concise summaries over dumping raw certificate text. Include exact paths for any created files or directories.

## Troubleshoot

Use these checks when a command fails unexpectedly:

- Run `certconv doctor --json --plain` to confirm `openssl` availability.
- Re-run with `show --json` to confirm the detected file type.
- Supply passwords explicitly if a PFX or encrypted key is involved.
- Use `show-full` only when raw `openssl x509 -text` output is needed for diagnosis.
- Expect some operations to require `openssl`, while `lint`, `chain`, and local CA discovery can often run in pure Go.
