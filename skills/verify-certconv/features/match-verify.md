# Match and verify

The user checks that a private key belongs to a certificate, and that a certificate chains to a CA.

## Sub-features

- `match-ok`: `match leaf.pem leaf.key` gives "OK  Private key matches certificate", exit 0.
- `match-mismatch`: `match leaf.pem stray.key` gives "Error: key mismatch", exit 1.
- `verify-chain`: `verify leaf.pem ca.pem` gives "OK  Certificate chain verified", exit 0.

## How to get to it (user POV)

- `certconv match CERT KEY`, `certconv verify CERT CA`.

## Driving it with control.sh

Preconditions:

- `doctor` prints `OK`.

- **Match pair.** Run `control.sh --execute cli match leaf.pem leaf.key` and then `control.sh --execute cli match leaf.pem stray.key`. Expect exit 0, then exit 1.
- **Verify.** `control.sh --execute cli verify leaf.pem ca.pem` gives exit 0.

## Gotchas

- An unverifiable chain (for example `verify ca.pem leaf.pem`) is not yet driven.
