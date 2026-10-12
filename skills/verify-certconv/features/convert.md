# Convert

The user converts between PEM, DER, PFX/P12, PKCS#7 and Base64. Outputs are created exclusively, so an existing file is never overwritten.

## Sub-features

- `convert-to-der`: `to-der leaf.pem leaf.der` gives "OK  Created: leaf.der".
- `convert-no-overwrite`: repeating to an existing name is refused (not yet driven).

## How to get to it (user POV)

- `certconv to-der IN OUT`, `certconv from-der IN OUT`, `certconv to-pfx …`.

## Driving it with control.sh

Preconditions:

- `leaf.der` does not yet exist in the fixtures.

- **To DER.** `control.sh --execute cli to-der leaf.pem leaf.der` gives exit 0, `created=[leaf.der]`, and `created-leaf.der` in the evidence.

## Gotchas

- `leaf.der` stays in the fixtures for the rest of the run. Use a new output name, or relaunch.
