# certconv Review Follow-Up

Follow-up date: 2026-02-07
Original review: [REVIEW.md](REVIEW.md)

## What Was Addressed

All items from the original review were implemented:

| # | Finding | Status |
|---|---------|--------|
| 1.1 | app.go 2000 lines / input state machine | Done. `inputfsm.go` (424 lines) extracted; `app.go` reduced to 1612. |
| 1.2 | `% 8` magic number | Done. `contentPaneModeCount` sentinel used throughout. |
| 1.3 | Unused `keyMap` struct | Done. Removed. |
| 1.5 | Custom YAML parser / spaces note | Done. Comment added to `config.example.yml`. |
| 4 | Dead code (7 items) | Done. All removed. |
| 5.1 | `truncateEnd` off-by-one | Done. Fixed to `s[:w-3]+"..."`. |
| 6 | Additional parsed views | Done. New `parsedview.go` covers SANs, key usage, ext key usage, signature algo, public key info, AKI/SKI, basic constraints, OCSP/CRL/AIA, fingerprints, certificate policies. Summary pane enriched via `EnrichSummary`. |
| 7 | Color theming | Done. Three themes (default, high-contrast, high-contrast-light) via `theme.go`. Blue/orange for colour-blind users. Config + env var support. |

---

## Remaining Items (from original review)

These were noted as low-priority or accepted-risk in the original review
and remain unchanged.

### R1. Temp file permissions (was 2.1)

`os.CreateTemp` is called in 5 places. Go's stdlib defaults to 0600 on
Unix, so this is safe in practice. However, explicitly calling
`os.Chmod(path, 0600)` would make the security posture self-documenting
and defend against non-Unix platforms.

**Call sites:**
- `internal/cert/info.go:90` (PEM data from PFX)
- `internal/cert/info.go:181` (PEM data for details)
- `internal/cert/preview.go:49` (PFX preview)
- `internal/cert/output.go:109` (atomic write temp)
- `internal/tui/app.go:1596` (fzf selection file)

**Priority:** Low. Defence-in-depth only.

### R2. PFX passwords in process tree (was 2.2)

`"pass:" + password` remains visible via `ps`. Mitigating with
`-passin stdin` would pipe the password instead. Acceptable for a local
tool but worth noting if the tool is ever used in shared environments.

**Priority:** Low.

### R3. Clipboard is macOS-only (was 2.3)

`copyToClipboardCmd` hardcodes `pbcopy`. The legacy shell script already
supports `xclip` and `xsel`. A simple platform-aware fallback:

```
pbcopy (macOS) -> xclip -selection clipboard (Linux/X11)
                -> wl-copy (Linux/Wayland)
                -> clip.exe (Windows/WSL)
```

**Priority:** Medium. Affects anyone running on Linux.

### R4. autoMatchKeyCmd: no cancellation or limit (was 3.1)

The candidate loop at `app.go:717-741` does not check `ctx.Err()` and
has no candidate cap. In a directory with 100+ `.key`/`.pem` files, this
spawns two openssl processes per candidate without any way to abort.

**Priority:** Medium. Easy fix (add `ctx.Err()` check + `maxCandidates`
constant).

### R5. Duplicate DetectType calls (was 1.4)

A single file selection still calls `DetectType` 2-3 times (once in
`engine.Summary`, once in `updateFileSelected`, plus once per candidate
in auto-key matching). Negligible cost per call, but threading the
detected type through would be cleaner.

**Priority:** Low.

---

## New Observations

### N1. Test coverage gaps for new code

Three new files have no dedicated tests:

- `internal/tui/inputfsm.go` (424 lines) -- the `inputState` struct
  methods (`active`, `reset`, `begin`, `beginWithValue`) and the action
  dispatch logic are untested in isolation. The existing `app_test.go`
  exercises some paths indirectly.
- `internal/tui/theme.go` (122 lines) -- `ThemeByName` fallback
  behaviour, `ApplyTheme` side effects on package vars, and the three
  built-in palettes are untested.
- `internal/tui/parsedview.go` (179 lines) -- `renderParsedCert`
  formatting and edge cases (expired cert, no SANs, CA vs leaf) are
  untested.

`internal/cert/parsex509.go` is indirectly tested via existing cert
tests.

**Priority:** Medium. These are the most complex new additions and would
benefit from table-driven unit tests.

### N2. app.go is still 1612 lines

The extraction brought it from ~2040 to 1612, which is a meaningful
improvement. The file is now dominated by:

- Layout and rendering (~400 lines)
- Content loading commands (~200 lines)
- Content mode cycling (~100 lines)
- Auto-key matching (~70 lines)
- Window/pane sizing (~150 lines)
- Help text (~70 lines)
- fzf integration (~50 lines)

Further extraction candidates (only if the file continues to grow):

- **Content loaders:** The `loadFileContent`, `loadContentOneLine`,
  `loadContentBase64`, `loadContentDetails`, `loadContentParsed`,
  `loadContentModulus`, `loadDerivedDERBase64`, `loadDerivedPFXBase64`
  functions (~200 lines) could move to a `loaders.go` file.
- **Layout math:** `paneLayout` and `layoutPanes` (~150 lines) could
  move to `layout.go` (which already exists for grid rendering).

**Priority:** Low. 1612 lines is manageable. Only extract if it grows
past ~1800 again.

### N3. Parsed view: remaining feature gaps from original review

The parsed view now covers all "high value" and most "medium value"
items from the original review. Still missing:

- **CT SCT List** (Certificate Transparency Signed Certificate
  Timestamps, extension OID `1.3.6.1.4.1.11129.2.4.2`). Requires
  parsing raw extensions since Go's `x509` package does not expose SCTs
  directly.
- **Structured Subject/Issuer** (CN, O, OU, C broken out individually).
  Currently shown as the Go `pkix.Name.String()` representation.
- **Inline validity colouring** in the parsed view. The text shows
  "EXPIRED", "Expiring soon", or "Valid" but without colour. Adding
  colour would require returning styled content rather than plain text,
  or post-processing the rendered output.

**Priority:** Low. The current parsed view is comprehensive for daily
use.

### N4. processInputResult still uses string-based action dispatch

The `processInputResult` function (now in `inputfsm.go`) has 15+ string
cases doing structurally identical work. The original review suggested
table-driven dispatch. The extraction to its own file is a good first
step; converting the switch to a `map[string]actionHandler` would reduce
the boilerplate further.

**Priority:** Low. The current switch is clear and correct; a table
would only help if more actions are added.

### N5. fzf is the only file picker

The fzf integration is well-implemented (positional args, temp file for
output, proper cleanup). However:

- fzf is an optional external dependency (`brew install fzf`)
- No fallback for users without fzf installed (just an error message)
- The search is hardcoded to `find -maxdepth 3` with specific extensions

A built-in fuzzy finder using `bubbles/textinput` + directory walking
would remove the external dependency, though fzf's UX is hard to match.

**Priority:** Low. fzf is ubiquitous in the target audience.

---

## Recommended Next Steps (prioritised)

1. **Add tests for `inputfsm.go`, `theme.go`, `parsedview.go`** (N1)
2. **Add `ctx.Err()` check + candidate limit to auto-key match** (R4)
3. **Cross-platform clipboard** (R3)
4. Everything else is low priority and can be addressed as-needed.
