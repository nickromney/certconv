---
name: verify-certconv
description: Build certconv from this checkout and drive its CLI and TUI against a sandbox HOME with freshly generated fixtures (test CA, leaf with SANs, matching key, stray key, bundle). Records transcripts, created files and TUI screens. Use when you need to prove an inspect, convert, match, verify or TUI change in the real binary.
---

# Verify certconv

certconv has two user surfaces: CLI subcommands (`show`, `match`, `verify`,
`to-der`, `chain`, `lint`, …) and the TUI (`certconv tui DIR`). It never
calls remote services and never overwrites files, so a fixture directory is
all it needs.

Helper: `skills/verify-certconv/scripts/control.sh`. It is Bash 3.2 compatible
and runs under macOS `/bin/bash`. It uses the standard flags: `--help`,
`--dry-run` and `--execute`. Nothing is built, started or deleted without
`--execute`; a bare call or `--dry-run` prints the plan. Below, `C` adds
`--execute`.

The skill is built on verify-kit. The shared library (`scripts/verify-lib.sh`),
the contract tests (`tests/contract.bats`) and the make targets (`verify.mk`)
are vendored from `harnesses-private/nickromney/verify-kit` and pinned by
`verify-kit.lock`. Never edit those files here; change the kit and re-vendor.
The app-specific parts are `scripts/control.sh` (configuration and hooks) and
`tests/certconv.bats` (the clipboard and key refusals).

```bash
make verify            # full proven cycle: launch, doctor, recipes below, cleanup (cleanup also on failure)
make verify-dry-run    # print what verify would do
make verify-test       # shellcheck on the scripts and every BATS file, then the contract and app tests under /bin/bash 3.2
C() { /bin/bash skills/verify-certconv/scripts/control.sh --execute "$@"; }
```

`make verify` ends with `VERIFY PASS run=<id> evidence=<dir>` only when every
assertion holds. Any failed assertion exits non-zero and still cleans up.

## Launch

```bash
C launch
```

`launch` builds `./cmd/certconv` into `$TMPDIR/verify-certconv/<run>/`. It
then uses openssl to generate the fixtures in `state/home/certs/`:

- `ca.pem` / `ca.key`: a 30-day test CA, "Verify Test CA".
- `leaf.pem` / `leaf.key`: a 10-day leaf for `verify.example.test` with SANs
  `verify.example.test` and `www.verify.example.test`.
- `stray.key`: an unrelated key.
- `bundle.pem`: the leaf, then the CA.

Every run uses `HOME`, `XDG_CONFIG_HOME` and `CERTCONV_CERTS_DIR` set to the
sandbox, so `~/.config/certconv` and `~/certs` are never read.

## Doctor

```bash
C doctor
```

Read-only. It checks that the binary and the five fixtures exist and that
the sandbox HOME is in effect. It also prints the build revision next to the
current HEAD.

## Drive

CLI: each call runs in the fixture directory and records `command.txt`,
`stdout.txt`, `stderr.txt`, `exit-code.txt`, `files-before.txt` and
`files-after.txt`, plus a copy of every file the command created
(`created-<name>`):

```bash
C cli show leaf.pem
C cli match leaf.pem leaf.key        # OK, exit 0
C cli match leaf.pem stray.key       # "Error: key mismatch", exit 1
C cli verify leaf.pem ca.pem         # OK  Certificate chain verified, exit 0
C cli to-der leaf.pem leaf.der       # created=[leaf.der]
```

TUI, in a private tmux server:

```bash
C tui start                    # certconv tui <fixtures>
C tui keys Down Enter          # cursor starts on "..": Down selects bundle.pem
C tui capture selected         # summary shows [bundle.pem], SANs:, verify.example.test
C tui stop                     # q q -> CERTCONV_EXIT=0
```

`tui keys` checks every key against the allowlist before it touches tmux. The
allowlist is `Up Down Left Right Enter Tab BTab Escape j k n p v o u q`. `c` is
refused because it copies to the system clipboard.

## Evidence

Everything goes to `tmp/verify/<run>/` in the repo, which is git-ignored:
`revision.txt`, `build.log` and `fixtures.log`, one `<HHMMSS-NNN>-cli/` per
call, and `tui/NN-<name>.txt` screens with `tui/zz-after-quit.txt`.

Proof standards:

- Pair each claim with its negative (a matching key and a stray key).
- Conversion claims cite `created-<file>`, and ideally a second command that
  reads it back (`C cli show leaf.der`).
- certconv refuses to overwrite. Re-running a conversion to the same name
  must fail, and that is the expected outcome.

## Cleanup

```bash
C cleanup
```

Kills the private tmux server and deletes `$TMPDIR/verify-certconv/<run>`.
Evidence stays. `verify` runs cleanup on success and on failure.

## Tests

`make verify-test` lints `scripts/*.sh` and `tests/*.bats` with shellcheck, then
runs `tests/` under `/bin/bash`:

- `tests/contract.bats` (vendored, shared): usage, dry-run and execute modes,
  exit codes, every sample command, verify failing fast, the lock.
- `tests/certconv.bats` (app-specific): the clipboard key `c` is refused before
  tmux is called, the allowlist, the `tui` and `cli` argument checks, and the
  private tmux socket for cleanup. A fake `tmux` on PATH logs calls, so no test
  builds, launches or touches a real server.

`make check-local` runs the same BATS files and shellcheck (with
`-P SCRIPTDIR`, so sourced libraries are followed) as part of the pre-push gate.

## Gotchas

- The fixtures expire after 10 days (leaf) and 30 days (CA) by design, so
  expiry checks have a near-term date to report. Relaunch for fresh ones.
- `o` shows openssl commands but does not run them.
- The TUI file list starts on `..`. Down moves to the first file.
