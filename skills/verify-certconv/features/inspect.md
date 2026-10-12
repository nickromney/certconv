# Inspect

The user inspects a certificate from the CLI (`certconv show FILE`) or browses a directory in the TUI and reads the summary pane.

## Sub-features

- `inspect-show` prints the subject, issuer, validity dates and serial.
- `inspect-tui-summary` shows the summary pane with SANs, public key and signature algorithm, plus a content pane with the PEM.

## How to get to it (user POV)

- `certconv show leaf.pem`, or `certconv tui ~/certs`, then select a file.

## Driving it with control.sh

Preconditions:

- `doctor` prints `OK`.

- **CLI.** `control.sh --execute cli show leaf.pem` prints `Subject: CN=verify.example.test` and `Issuer: CN=Verify Test CA` with exit 0.
- **TUI.** Run `control.sh --execute tui start`, `control.sh --execute tui keys Down Enter` and `control.sh --execute tui capture selected`. The summary pane shows `[bundle.pem]`, `SANs: verify.example.test, www.verify.example.test`, `Public Key: RSA 2048` and `Sig Algo: SHA256-RSA`. `control.sh --execute tui stop` prints `CERTCONV_EXIT=0`.

## Gotchas

- The file list starts on `..`. Count Down presses from there.
