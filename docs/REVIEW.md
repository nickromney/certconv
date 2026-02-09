# certconv Code Review

Review date: 2026-02-07
Reviewer: Claude Opus 4.6

## Overall Assessment

Strong foundation for a day-one project. Clean separation of concerns
(Engine/CLI/TUI/Config), injectable `Executor` for testing, defensive
file-writing (O_EXCL, temp+link), and good test coverage. The architecture
is well-suited to the problem.

---

## 1. Go Practice

### Good

- Clean `internal/` package boundaries
- `Executor` interface enabling testable openssl interactions
- Context propagation throughout the engine
- Proper use of Bubble Tea `Cmd`/`Msg` pattern
- `O_EXCL` and `os.Link` for atomic no-overwrite file creation
- `-race` in tests, build with `-trimpath -w -s`

### Issues Found

#### 1.1 app.go is 2000 lines

The `handleAction`/`processInputResult`/`handleInputKey` logic forms a
state machine that is increasingly hard to follow. `processInputResult`
has 15+ cases doing structurally identical work.

**Fix:** Extract an `inputFSM` struct encapsulating input mode, prompt,
value, action, and context. Use table-driven dispatch for action results.

#### 1.2 contentPaneMode.Next()/Prev() hardcodes `% 8`

If a mode is added, the magic number must be updated manually.

**Fix:** Use a `contentPaneModeCount` sentinel constant (same pattern as
`paneCount`).

#### 1.3 keyMap in keys.go is defined but unused

Key dispatch in `updateKey` uses raw string comparisons. Either use
`key.Matches()` from `bubbles/key` or remove the dead struct.

**Fix:** Remove the unused `keyMap` struct and `keys` variable.

#### 1.4 Duplicate file scanning

`DetectType` is called multiple times for the same file during a single
selection. In the TUI, a single file selection triggers `DetectType`
4-6 times. The result is already stored on `CertSummary.FileType`.

**Recommendation:** Pass detected type through rather than re-detecting.
Low priority since the function is fast (file open + scan a few lines).

#### 1.5 Custom YAML parser

`parseYAMLSubset` does not handle tab indentation. A comment at the top
of `config.example.yml` noting "spaces only" would help. Using
`gopkg.in/yaml.v3` is an alternative.

**Recommendation:** Add a comment to the example config. Low priority.

---

## 2. Security

### Good

- Never overwrites existing files (O_EXCL pattern throughout)
- Private keys written with 0600 permissions
- PFX passwords passed via `pass:` argument (not shell interpolation)
- fzf invocation uses positional args to avoid shell injection
- No network calls, no remote services

### Issues Found

#### 2.1 Temp files may contain sensitive material

`parseCertSummaryFromPEM` and `Details` write PEM data (potentially
including private keys from PFX extraction) to `os.CreateTemp`. These use
`defer os.Remove`, but if the process is killed (SIGKILL, OOM), they
remain in `/tmp` world-readable.

**Recommendation:** Set 0600 on temp files immediately after creation.
Use the same-directory pattern from `newTempPath` consistently.

#### 2.2 PFX passwords visible in process tree

The `"pass:" + password` argument is visible in `/proc`. This is inherent
to openssl CLI design. Mitigating with `-passin stdin` is possible but
low priority for a local inspection tool.

#### 2.3 Clipboard is macOS-only

`pbcopy` is hardcoded. The tool cross-compiles for Linux and Windows.
Currently returns "pbcopy not found" which is acceptable, but platform-
aware clipboard support would improve the cross-platform story.

---

## 3. Performance

No significant issues for a TUI tool. Main observations:

#### 3.1 autoMatchKeyCmd scans all candidates without limit

In a directory with many key files, this spawns two openssl processes
per candidate. The loop does not check `ctx.Err()` for cancellation.

**Recommendation:** Add a candidate limit (e.g. 10) and check
`ctx.Err()` inside the loop.

---

## 4. Dead Code

The following are defined but never used:

- `bold()` in `internal/cli/output.go`
- `copyFileExclusive()` in `internal/cert/output.go`
- `warnStyle` in `internal/tui/styles.go`
- `activePaneStyle` and `inactivePaneStyle` in `internal/tui/styles.go`
- `WindowSizeMsg` in `internal/tui/messages.go` (duplicates `tea.WindowSizeMsg`)
- `RetryInputMsg` in `internal/tui/messages.go` (never handled in `Update`)
- `keyMap` struct and `keys` variable in `internal/tui/keys.go`

---

## 5. Bug

#### 5.1 truncateEnd off-by-one (helppane.go:145)

`s[:w-1] + "..."` produces a string of length `w + 2` (trimmed 1 char,
added 3). Should be `s[:w-3] + "..."` to produce exactly `w` characters.

---

## 6. Feature Recommendations: Additional Details Pane Views

Since `parseCertificates` in `chain.go` already returns
`[]*x509.Certificate`, these can be extracted without additional openssl
calls:

### High value (common daily tasks)

- **Subject Alternative Names (SANs):** `cert.DNSNames`, `cert.IPAddresses`,
  `cert.EmailAddresses`, `cert.URIs`. Show in Summary pane too.
- **Key Usage / Extended Key Usage:** `cert.KeyUsage`, `cert.ExtKeyUsage`.
- **Signature Algorithm:** `cert.SignatureAlgorithm`. Quick SHA-1 vs SHA-256 check.
- **Public Key Info:** `cert.PublicKeyAlgorithm`, key size, EC curve.

### Medium value (chain debugging)

- **AKI / SKI:** `cert.AuthorityKeyId`, `cert.SubjectKeyId`.
- **Is CA / Basic Constraints:** `cert.IsCA`, `cert.MaxPathLen`.
- **OCSP / CRL endpoints:** `cert.OCSPServer`, `cert.CRLDistributionPoints`.
- **CT SCT List:** Extension OID `1.3.6.1.4.1.11129.2.4.2`.

### Nice to have

- **Certificate Policies:** DV/OV/EV classification OIDs.
- **AIA:** Issuer cert URL.
- **Structured Subject/Issuer:** CN, O, OU, C broken out.
- **Inline validity colouring:** Red/yellow/green by days remaining.
- **PEM fingerprints:** `sha256.Sum256(cert.Raw)`.

---

## 7. Accessibility: Color Theming

Add configurable color themes with a high-contrast option for colour-
blind users. Inspired by thesis-useful's approach:

- Default theme: current Tokyo Night palette
- `high-contrast`: high-contrast dark (bold white text, wider colour
  separation, avoid sole red/green distinction)
- `high-contrast-light`: high-contrast light

Configuration via `theme:` key in config.yml.
