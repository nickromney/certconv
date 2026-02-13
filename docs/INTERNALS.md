# Internals

Architecture notes for `internal/`. This document covers the structural
decisions and patterns that matter if you're reading or modifying the code.

## Package layout

```
internal/
├── cert/       Engine + all certificate operations (openssl wrapper, detection, conversion)
├── cli/        Cobra command tree, output formatting, secret handling
├── config/     YAML config loading/saving (hand-rolled, no dependency)
└── tui/        Bubbletea TUI (file browser, panes, actions, themes)
```

`cert` has no knowledge of the CLI or TUI. `cli` and `tui` both depend on
`cert` and `config`, but never on each other. This means the CLI and TUI
are two independent frontends over the same engine.

## cert: the Engine pattern

All certificate operations hang off a single `Engine` struct that wraps an
`Executor` interface:

```go
type Executor interface {
    Run(ctx context.Context, args ...string) (stdout, stderr []byte, err error)
    RunWithExtraFiles(ctx context.Context, files []ExtraFile, args ...string) (stdout, stderr []byte, err error)
}

type Engine struct {
    exec Executor
}
```

Production code uses `OSExecutor` (which calls `openssl` via `exec.CommandContext`).
Tests inject a fake executor that returns canned stdout/stderr, so no openssl
binary is needed to exercise the logic. Every public method on `Engine` takes
a `context.Context` as its first argument, which is how the TUI cancels
in-flight loads when the user scrolls past a file.

## File-descriptor secret passing

Passwords are never passed via CLI arguments. On Unix, the pattern is:

1. Create an `os.Pipe()` per secret.
2. Write the password bytes to the write end, then close it.
3. Pass the read end as an `ExtraFile` on `exec.Cmd` (mapped to fd 3, 4, ...).
4. Tell openssl to read from that fd: `-passin fd:3`, `-passout fd:4`.

```go
func fdArg(extraIndex int) string {
    return fmt.Sprintf("fd:%d", 3+extraIndex)
}
```

The password never appears in `argv`. It exists only in kernel pipe buffers
private to the process. Once openssl reads and the pipe closes, the data is
gone. This matters because `argv` is visible to every user on the system via
`ps aux`, `/proc/<pid>/cmdline`, and process accounting.

On Windows, `ExtraFiles` is not supported. The fallback writes each secret to
a temp file with `0o600` permissions, rewrites `fd:N` args to `file:<path>`,
and cleans up via a deferred `cleanup()` function. Less ideal (secrets hit
disk briefly), but still avoids `argv` exposure.

## Atomic no-overwrite file output

Certificate tools handle irreplaceable material (private keys). Accidentally
overwriting `server.key` with a DER-encoded cert means the key is gone. The
codebase uses a three-layer defense to prevent this.

### Layer 1: `ensureNotExists`

Soft check via `os.Stat`. If the file exists, returns an `OutputExistsError`
with a suggested alternative path (`file-1.ext`, `file-2.ext`, etc.). Every
conversion function calls this before doing any work, so the user gets a
helpful error message early.

### Layer 2: `writeFileExclusive`

Used by pure-Go operations (`ToBase64`, `FromBase64`, `CombinePEM`). Calls
`ensureNotExists` first for the friendly message, then opens with
`O_WRONLY|O_CREATE|O_EXCL`. The `O_EXCL` flag is a kernel-level guarantee:
the `open` syscall atomically fails if the path exists. This closes the
TOCTOU (time-of-check-to-time-of-use) race between `stat()` and `open()`.

### Layer 3: `commitTempFile`

Used by operations that shell out to openssl (`ToPFX`, `FromPFX`, `ToDER`,
`FromDER`), where the write is done by a subprocess. The pattern:

1. `newTempPath(dest)` creates a temp file in the **same directory** as the
   destination (so the subsequent link doesn't cross filesystem boundaries).
2. Tell openssl to write to the temp path.
3. `os.Link(tmp, dest)` -- atomic, fails if `dest` exists.
4. `os.Remove(tmp)` to clean up.
5. `defer os.Remove(tmp)` in the caller ensures cleanup on error paths too.

`os.Link` provides the same kernel-level guarantee as `O_EXCL`: it fails
atomically if the destination already exists. The double-check
(`ensureNotExists` + `Link`) gives a user-friendly error in the common case
and a hard guarantee in the race-condition case.

### Suggestion on conflict

When a path exists, `NextAvailablePath` scans `file-1.ext`, `file-2.ext`, ...
up to `file-9999.ext`. The `OutputExistsError` type carries both the original
path and the suggestion, so the CLI/TUI can surface it without re-checking.

## PKCS#12 legacy provider retry

OpenSSL 3 dropped built-in support for older PKCS#12 ciphers. The
`runPKCS12WithExtraFiles` method transparently retries with `-legacy` when the
initial attempt fails with `inner_evp_generic_fetch:unsupported`. This avoids
requiring users to know about OpenSSL provider configuration while staying on
the modern code path by default.

## PFX error classification

`pfxerr.go` pattern-matches openssl's stderr output to produce structured
sentinel errors:

- `ErrPFXIncorrectPassword` -- "mac verify failure", "bad decrypt", etc.
- `ErrPFXNotPKCS12` -- ASN.1 parse failures for non-PKCS#12 input.
- `ErrPFXLegacyUnsupported` -- legacy cipher errors (after the retry above fails).

This lets the CLI print targeted messages and the TUI prompt for a password
rather than showing raw openssl output. The matching is intentionally broad
(covers both OpenSSL and LibreSSL phrasings) since stderr formats differ
across versions and platforms.

## stderr preference

`openssl_err.go` contains a one-liner helper, `preferStderr`, that returns
stderr as the error when available. This avoids surfacing unhelpful
"exit status 1" messages. The same principle applies throughout: every place
that calls openssl checks stderr before falling back to the generic error.

## File type detection

`detect.go` uses a two-pass strategy:

1. **Extension dispatch** for unambiguous types: `.pfx`/`.p12`, `.pub`,
   `.der`, `.b64`/`.base64`.
2. **Content scanning** for everything else: scans for PEM markers
   (`BEGIN CERTIFICATE`, `BEGIN ... PRIVATE KEY`). Files with both are
   `FileTypeCombined`. `.key` files get special treatment -- checked for
   content first, defaulting to `FileTypeKey` on read error.

DER detection (`IsDEREncoded`) checks the first byte for the ASN.1 SEQUENCE
tag (`0x30`). This is a heuristic, not a full parse, but it's sufficient for
the guard in `FromDER` and cheap enough to run on every candidate.

## Dual parsing: openssl + crypto/x509

Certificate summary data is extracted two ways:

1. **openssl x509** (`info.go: Summary`) parses subject, issuer, dates,
   serial via `-noout -subject -issuer -dates -serial`. This works for all
   openssl-supported formats and is the primary path.
2. **Go crypto/x509** (`parsex509.go: ParseCertFile`, `EnrichSummary`) adds
   SANs, signature algorithm, public key info, key usage, ext key usage, CA
   flag, self-signed detection, and SHA-256 fingerprint. This runs after
   openssl succeeds and enriches the summary with fields that would require
   multiple openssl invocations to extract.

The TUI's "Parsed" view (`parsedview.go`) renders the `crypto/x509` data
directly, providing a fully Go-native view that doesn't depend on openssl at
all.

## cli: secret input hierarchy

`secrets.go` enforces mutual exclusion across three input methods for every
secret flag:

- `--password` (inline value -- warned against)
- `--password-stdin` (piped input -- gated on non-TTY stdin to prevent hangs)
- `--password-file` (reads from file, or stdin if `-`)

Only one may be specified. Trimming strips only trailing `\r\n`, not spaces,
because passwords can legitimately contain spaces. The `warnInlineSecretFlag`
function (`warn.go`) nudges users toward `-stdin`/`-file` on TTY stderr, once
per flag per session, and is suppressed in non-interactive contexts.

## cli: output formatting

`output.go` handles the color/unicode/quiet matrix. The approach is
stateful-global (package-level `outStdout`, `outStderr`, `outOpt`) set once
during `PersistentPreRunE`. Color is disabled by `--no-color`, `NO_COLOR` env,
or `TERM=dumb`. Unicode is disabled by `--ascii`. Both are disabled by
`--plain`. The `sym()` helper selects between unicode and ASCII glyphs at each
call site.

## cli: exit codes

`ExitError` carries structured exit codes. `Silent: true` means `main`
should exit with the code but not print "Error: ...". This is used for
`--json` mode where a non-zero exit (e.g., key mismatch, cert expiring) is
the intended signal rather than an error message.

## config: hand-rolled YAML subset parser

`config.go` parses a minimal YAML subset (top-level `key: value` plus one
nested `keys:` section) without importing a YAML library. This keeps the
dependency tree small for a tool that only needs a handful of flat settings.
Boolean parsing accepts `true/false/yes/no/on/off/1/0`.

`save.go` updates config files using line-level text manipulation (find the
`theme:` line and replace it, or insert before `keys:`). It writes atomically
via temp-file-then-rename in the config directory, preserving existing content
and file permissions.

## tui: Elm architecture via Bubbletea

The TUI follows the standard Bubbletea (Elm) architecture: a single `Model`
struct, a pure `Update` function that returns `(Model, Cmd)`, and a pure
`View` function. All side effects happen in `tea.Cmd` functions that return
messages.

### Message types

Every async operation has a dedicated message type (`messages.go`):
`FileContentMsg`, `CertSummaryMsg`, `ContentDetailsMsg`, etc. Each carries a
`Path` field so stale results (from a file the user has already scrolled past)
can be discarded with a simple path comparison at the top of every handler.

### Cancellation and debouncing

When the user scrolls through files, each selection change:

1. Increments `focusSeq` and schedules a `tea.Tick` (160ms debounce).
2. When the tick fires, compares its seq against current -- stale ticks are
   dropped.
3. On commit, cancels the previous `loadCtx` via `context.WithCancel`, so
   in-flight openssl calls are killed and don't waste resources.

This means rapid scrolling doesn't spawn dozens of openssl processes.

### Eager views

When `eagerViews` is true (the default), file selection triggers parallel
loading of multiple derived views (one-line, base64, DER base64, details,
parsed, modulus) via `tea.Batch`. Each result is cached on the `contentPane`
and only re-fetched if missing when the user cycles to that view.

### Auto key matching

When a cert file is selected, `autoMatchKeyCmd` looks in the same directory
for a matching private key. It checks preferred sibling names first
(`<base>.key`, `<base>.pem`), then scans the directory for `.key`/`.pem` files.
For each candidate, it calls `MatchKeyToCert` (public key comparison via
openssl). The search caps at 10 candidates and respects context cancellation.

When a match is found, the TUI eagerly generates a PFX Base64 preview (useful
for Azure Key Vault workflows) and shows the match status in pane 2.

### Grid rendering

`grid.go` renders a lazygit-style three-pane layout with shared Unicode box
borders. Border characters are drawn explicitly (not via lipgloss border
styles) so that adjacent panes share border lines rather than doubling them.
The shared separator column/row uses overlap math:
`rightW = totalW - fileW + 1`, `contentH = totalH - infoH + 1`.

Active/inactive border colors depend on which pane is focused, and shared
borders are active if either adjacent pane is focused.

### Input FSM

Multi-step actions (e.g., "convert to PFX" needs key path, output path, and
password) are driven by a lightweight state machine in `inputfsm.go`. The
`inputState` struct tracks the current mode, prompt, accumulated value, and a
`context` map that carries values between steps. Each step returns a new
action string that `processInputResult` dispatches on.

Password input renders as `*` characters. `ctrl+u` clears the input. `esc`
cancels.

### Context usage: reads vs. writes

Read-only commands in `app.go` (summary, details, modulus, parsed, base64
previews) use `m.ctx()`, which is wired to the cancellable `loadCtx`. When
the user scrolls to a different file, the previous context is cancelled and
in-flight openssl processes are killed.

Write commands in `inputfsm.go` (to-pfx, from-pfx, to-der, from-der,
to-base64, from-base64, combine) deliberately use `context.Background()`
instead. This is intentional: a conversion that has already started writing
to a temp file should not be cancelled mid-flight. A cancelled write could
leave a partial temp file or, worse, race with the `commitTempFile` link
step. The tradeoff is that a conversion continues even if the user navigates
away, but since conversions are fast and the result is a new file (never an
overwrite), this is the safer default.

### Temp file permissions

`newTempPath` creates temp files via `os.CreateTemp`, which defaults to
`0o600` (modulo umask). `commitTempFile` calls `os.Chmod(dest, perm)` after
`os.Link(tmp, dest)`. Between the link and chmod, the file briefly exists at
the destination with the temp file's permissions. This is always safe in the
conservative direction: key files target `0o600` (same as the temp default),
and cert files target `0o644` (briefly more restrictive than intended, never
less).

### Themes

Themes are flat structs mapping semantic roles (accent, dim, text, border,
success, error) to lipgloss colors. `ApplyTheme` sets package-level style
variables. The user cycles themes with `t` (session-only) or `T` (persisted
to config.yml). The high-contrast theme uses yellow pane text and wider color
separation for color-blind accessibility.

### Bag attribute stripping

PFX extraction via openssl often includes "Bag Attributes" metadata blocks
before PEM headers. `bagattrs.go` strips these by scanning for
`Bag Attributes` lines and skipping until the next `-----BEGIN`. The "Details
(No Bag)" content pane view uses this to show cleaner output.
