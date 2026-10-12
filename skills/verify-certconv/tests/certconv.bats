#!/usr/bin/env bats
# App-specific tests for the certconv verification skill (the shared contract is in contract.bats).
# Runs under macOS /bin/bash 3.2 and never builds, starts tmux or touches real state: a fake tmux
# on PATH records every call.

setup() {
  SCRIPT="$BATS_TEST_DIRNAME/../scripts/control.sh"
  BASH32="${VERIFY_TEST_BASH:-/bin/bash}"
  export VERIFY_BASE_DIR="$BATS_TEST_TMPDIR/base"
  export VERIFY_EVIDENCE_ROOT="$BATS_TEST_TMPDIR/evidence"
  export VERIFY_RUN_ID="app-run"
  FAKE_BIN="$BATS_TEST_TMPDIR/fakebin"
  mkdir -p "$FAKE_BIN"
  {
    printf '#!/bin/sh\n'
    printf 'echo "$*" >> "%s"\n' "$BATS_TEST_TMPDIR/tmux.log"
    printf 'case " $* " in *" has-session "*) exit 1 ;; esac\n'
    printf 'exit 0\n'
  } > "$FAKE_BIN/tmux"
  chmod +x "$FAKE_BIN/tmux"
  export PATH="$FAKE_BIN:$PATH"
}

@test "the clipboard key c is refused before tmux is touched" {
  run "$BASH32" "$SCRIPT" --execute tui keys Enter c
  [ "$status" -eq 2 ]
  [[ "$output" == *"refused key 'c'"* ]]
  [ ! -e "$BATS_TEST_TMPDIR/tmux.log" ]
}

@test "the clipboard key c is refused in preview mode too" {
  run "$BASH32" "$SCRIPT" --dry-run tui keys c
  [ "$status" -eq 2 ]
  [[ "$output" == *"refused key 'c'"* ]]
  [ ! -e "$BATS_TEST_TMPDIR/tmux.log" ]
}

@test "keys outside the allowlist are refused before tmux is touched" {
  run "$BASH32" "$SCRIPT" --execute tui keys Down C
  [ "$status" -eq 2 ]
  [[ "$output" == *"refused key 'C'"* ]]
  [ ! -e "$BATS_TEST_TMPDIR/tmux.log" ]
}

@test "tui keys needs at least one key and never reaches tmux" {
  run "$BASH32" "$SCRIPT" --execute tui keys
  [ "$status" -eq 2 ]
  [[ "$output" == *"tui keys needs at least one key"* ]]
  [ ! -e "$BATS_TEST_TMPDIR/tmux.log" ]
}

@test "tui rejects an unknown subcommand with exit 2" {
  run "$BASH32" "$SCRIPT" --execute tui wiggle
  [ "$status" -eq 2 ]
  [[ "$output" == *"tui needs start, keys, capture or stop"* ]]
}

@test "tui capture needs a name" {
  run "$BASH32" "$SCRIPT" --dry-run tui capture
  [ "$status" -eq 2 ]
  [[ "$output" == *"tui capture needs a name"* ]]
}

@test "cli needs certconv arguments" {
  run "$BASH32" "$SCRIPT" --execute cli
  [ "$status" -eq 2 ]
  [[ "$output" == *"cli needs certconv arguments"* ]]
}

@test "cli names the missing binary when nothing was launched" {
  run "$BASH32" "$SCRIPT" --execute cli show leaf.pem
  [ "$status" -eq 1 ]
  [[ "$output" == *"FAIL: no binary for run=app-run; launch first"* ]]
}

@test "doctor names the missing binary when nothing was launched" {
  run "$BASH32" "$SCRIPT" --execute doctor
  [ "$status" -eq 1 ]
  [[ "$output" == *"FAIL: no binary for run=app-run; launch first"* ]]
}

@test "verify plan names the recipes and the tmp/verify evidence root by default" {
  unset VERIFY_EVIDENCE_ROOT
  run "$BASH32" "$SCRIPT" --dry-run verify
  [ "$status" -eq 0 ]
  [[ "$output" == *"cli recipes (show, match, verify, to-der)"* ]]
  [[ "$output" == *"/tmp/verify/app-run"* ]]
}

@test "cleanup stops only this run's private tmux socket" {
  run "$BASH32" "$SCRIPT" --execute cleanup
  [ "$status" -eq 0 ]
  grep -q -- "-L verify-certconv-app-run kill-server" "$BATS_TEST_TMPDIR/tmux.log"
}

# A launched run's state without building anything: a stand-in binary that answers `version`,
# the five fixture files as non-empty placeholders, and the revision record launch would write.
fake_launch() {
  local state="$VERIFY_BASE_DIR/app-run/state" fix="$VERIFY_BASE_DIR/app-run/state/home/certs"
  mkdir -p "$state/bin" "$fix" "$VERIFY_EVIDENCE_ROOT/app-run"
  printf '#!/bin/sh\necho "certconv test-build"\n' > "$state/bin/certconv"
  chmod +x "$state/bin/certconv"
  local f
  for f in ca.pem leaf.pem leaf.key stray.key bundle.pem; do printf 'fixture %s\n' "$f" > "$fix/$f"; done
  printf '%s\n' "recorded-rev" > "$VERIFY_EVIDENCE_ROOT/app-run/revision.txt"
}

@test "doctor passes for a launched run with the binary, every fixture and the sandbox HOME" {
  fake_launch
  run "$BASH32" "$SCRIPT" --execute doctor
  [ "$status" -eq 0 ]
  [[ "$output" == *"built recorded-rev (now $(git -C "$BATS_TEST_DIRNAME" rev-parse HEAD))"* ]]
  [[ "$output" == *"certconv test-build"* ]]
  [[ "$output" == *"OK fixtures="*"leaf.pem"* ]]
}

@test "doctor fails and names a fixture that is missing" {
  fake_launch
  rm -f "$VERIFY_BASE_DIR/app-run/state/home/certs/leaf.pem"
  run "$BASH32" "$SCRIPT" --execute doctor
  [ "$status" -eq 1 ]
  [[ "$output" == *"FAIL: missing fixture leaf.pem"* ]]
  [[ "$output" != *"OK fixtures="* ]]
}

@test "cli plan without arguments exits 2 and writes nothing" {
  run "$BASH32" "$SCRIPT" --dry-run cli
  [ "$status" -eq 2 ]
  [[ "$output" == *"cli needs certconv arguments"* ]]
  [ ! -e "$VERIFY_BASE_DIR" ]
}

@test "tui plan without a subcommand exits 2 (no shift past the arguments)" {
  run "$BASH32" "$SCRIPT" --dry-run tui
  [ "$status" -eq 2 ]
  [[ "$output" == *"tui needs start, keys, capture or stop"* ]]
  [ ! -e "$BATS_TEST_TMPDIR/tmux.log" ]
}

# Equivalent mutants (accepted): `return 0` after vk_fail (doctor's binary, fixture and HOME
# guards, and cli's binary guard) is unreachable: vk_fail returns 1 and set -e exits first.
# `kill-server ... && true` and `rmdir ... && true` in cleanup fail without errexit (not the last
# command of the && list), leaving the same status and output as the `|| true` original.
@test "cleanup removes the run's sandbox state and keeps the evidence" {
  fake_launch
  run "$BASH32" "$SCRIPT" --execute cleanup
  [ "$status" -eq 0 ]
  [ ! -e "$VERIFY_BASE_DIR/app-run/state" ]
  [ -f "$VERIFY_EVIDENCE_ROOT/app-run/revision.txt" ]
  [[ "$output" == *"evidence kept at $VERIFY_EVIDENCE_ROOT/app-run"* ]]
}
