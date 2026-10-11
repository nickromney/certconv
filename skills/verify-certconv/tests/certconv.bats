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
