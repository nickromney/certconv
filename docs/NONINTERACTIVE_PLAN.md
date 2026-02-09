# Non-Interactive + CLI Hardening Plan

Goal: make `certconv` behave predictably in automation (no accidental TUI, no openssl prompts), improve log/scripting friendliness (no forced ANSI/Unicode), and keep the interactive TUI as an explicit/TTY-only feature.

## 1) Interactivity Model

- Default behavior:
  - If invoked with a subcommand: run the subcommand (never start TUI).
  - If invoked with no subcommand:
    - If `stdin` and `stdout` are TTYs: start the TUI (current behavior).
    - Otherwise: print help and exit with code `2` (usage).

- Add explicit TUI entrypoint:
  - `certconv tui` launches the TUI.
  - `certconv --tui` is a global flag alias for `certconv tui`.
  - If `--tui`/`tui` is used without a TTY: error and exit `2`.

## 2) Output Contract (Script-Friendly)

- Respect common conventions:
  - Disable ANSI color when:
    - `stdout` is not a TTY, or
    - `NO_COLOR` is set, or
    - `TERM=dumb`, or
    - `--no-color` is set.
  - Add `--ascii` to force ASCII-only symbols (also default to ASCII when `stdout` is not a TTY).

- Keep stdout/stderr semantics stable:
  - Human-oriented status lines may remain on stdout for now.
  - Errors remain on stderr.

## 3) No Prompts / No Hangs (OpenSSL)

- Prevent openssl from prompting for passphrases in non-interactive contexts by always supplying an explicit `-passin pass:<value>` for private-key operations.
  - If the key is encrypted and no password was provided, openssl fails fast instead of blocking.

- Add `--key-password` where key decryption may be needed:
  - `certconv match` (encrypted PEM keys)
  - `certconv to-pfx` (encrypted PEM keys)
  - `certconv to-der --key` / `from-der --key` (encrypted keys)
  - `certconv combine` (because it verifies key/cert match)

## 4) Exit Codes

- `0`: success
- `1`: operation failed
- `2`: usage / invalid invocation / TUI requested without TTY

## 5) Documentation Updates

- Update `README.md`:
  - Mention TUI only starts by default when interactive.
  - Document `tui` subcommand and `--tui`.
  - Document `--no-color` and `--ascii`.
  - Document `--key-password` where applicable.

## 6) Tests

- CLI package tests:
  - Root command does not run TUI when non-TTY and returns exit code `2`.
  - `--no-color` removes ANSI sequences.
  - `--ascii` removes Unicode glyphs.

Non-goals (for now):
- Adding `--json` output.
- Eliminating password exposure in process args (would require stdin-based passphrase plumbing).
