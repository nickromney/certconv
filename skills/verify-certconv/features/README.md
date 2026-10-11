# certconv verification map

This directory is the maintained source for verifying certconv's CLI and TUI. Read this index, then use the matching feature file.

## Baseline preconditions

- `control.sh --execute launch` printed `ready` and `control.sh --execute doctor` prints `OK fixtures=…`.

## Driving conventions

- Pass fixture names relative to the fixture directory, for example `leaf.pem`.
- In the TUI, send only allowlisted keys.

## Proof and skip reporting

- `control.sh --execute verify` runs the **Driven** recipes in these feature files with assertions and prints `VERIFY PASS`. A failed assertion exits non-zero.
- CLI proof is the command, stdout, stderr, the exit code, and created files.
- TUI proof is screen captures plus `CERTCONV_EXIT`.
- PFX and PKCS#7 conversions and `local-ca` discovery are not yet driven. Name them as skipped.

## Feature entry contract

Each feature file has an H1, one paragraph, and then `Sub-features`, `How to get to it (user POV)`, `Driving it with control.sh` and `Gotchas`.

## Features

- [Inspect](./inspect.md): `show` and the TUI summary. **Driven 2026-10-10.**
- [Match and verify](./match-verify.md): key/cert match and chain verification. **Driven 2026-10-10.**
- [Convert](./convert.md): PEM to DER, with no overwrite. **to-der driven 2026-10-10.**
