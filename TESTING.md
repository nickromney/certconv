# Testing

This repo is tested with **deterministic, model-level unit tests**. We avoid flaky, terminal/PTY-driven "screen scraping" tests by treating the Bubble Tea TUI as a pure state machine and asserting on state transitions and emitted messages.

## What We Test

### CLI (Non-Interactive + Output Contract)

Covered in `/Users/nickromney/Developer/personal/certconv/internal/cli/commands_test.go` and `/Users/nickromney/Developer/personal/certconv/internal/cli/output_test.go`:

- Non-interactive behavior:
  - Running `certconv` with no args does **not** start the TUI when stdin/stdout are not TTYs; it prints help and exits `2`.
  - `certconv tui` and `certconv --tui` require a TTY; otherwise exit `2`.
- Secret handling:
  - `--password-stdin`, `--password-file`, `--key-password-stdin`, `--key-password-file`
  - Mutual exclusion between inline/stdin/file secret sources (usage error exit `2`).
  - `to-pfx` disallows sourcing *both* secrets from stdin (stdin can only be read once).
  - Secrets are passed to OpenSSL via inherited file descriptors (no `pass:` in argv).
  - Inline secret flags produce a warning on **TTY stderr only**, with an opt-out flag.
- Output modes:
  - `--plain` disables ANSI and Unicode glyphs.
  - `--quiet` suppresses status lines (errors still print).
  - `--json` output for `show`, `match`, `verify`, `expiry` is valid JSON and has stable exit-code behavior:
    - exit `0` for "good"/matching/valid
    - exit `1` (silent) for negative results

### Engine (Certificate Operations)

Covered in `/Users/nickromney/Developer/personal/certconv/internal/cert/*_test.go`:

- Conversions and extraction:
  - `to-pfx`, `from-pfx`, `to-der`, `from-der`, `to-base64`, `from-base64`, `combine`
- Error classification and helpful errors:
  - PFX legacy/provider retry behavior
  - Bad input handling (fixtures)
- No-overwrite guarantees:
  - Output paths are created exclusively; existing outputs are never clobbered.

### TUI (Bubble Tea Model)

Covered in `/Users/nickromney/Developer/personal/certconv/internal/tui/app_test.go`:

- Focus management:
  - `1/2/3` jump focus to panes, `tab`/`shift+tab` cycles focus (with wrapping).
- Help and action overlay behavior:
  - `ctrl+h` toggles help; `esc` closes help.
  - `?` toggles the action panel; `enter` selects an action and emits `ActionSelectedMsg`.
- Zoom and view cycling:
  - `z` toggles pane 3 zoom and forces focus to pane 3.
  - `n`/`p` cycles pane 3 modes (content/details/parsed/modulus/etc.) with wrapping.

Additional TUI coverage in `/Users/nickromney/Developer/personal/certconv/internal/tui/app_update_test.go` and `/Users/nickromney/Developer/personal/certconv/internal/tui/coverage_more_test.go`:

- `Model.Init` and `Model.Update` dispatcher behavior (window sizing, file focus debounce, action selection).
- Input-mode editing behavior (typing, backspace, ctrl+u, esc, enter).
- Derived views / loaders (details with chain prefix, DER/PFX base64 preview, modulus, parsed view).

These tests assert on model state and returned `tea.Cmd` messages. They do **not** assert on full-screen rendering output.

## What We Don’t Test (On Purpose)

- Terminal emulator correctness (alt-screen behavior, resize, mouse, ANSI quirks).
- End-to-end "drive the real binary via PTY" tests.
- Pixel/line-perfect snapshots of TUI rendering (very brittle).
- Integration tests that require a specific OpenSSL installation/version.

If we add PTY tests later, they should be a small number of **smoke tests** (startup, quit, a couple of keypresses) with generous assertions.

## How To Run

Run everything:

```bash
go test ./...
go vet ./...
```

Using Make targets:

```bash
make prereqs
make test
make test-cover
make cover-html
```

Security scanning (best-effort):

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
```

Run just TUI model tests:

```bash
go test ./internal/tui -run TestUpdateKey -count=1
```

Run just CLI tests:

```bash
go test ./internal/cli -count=1
```
