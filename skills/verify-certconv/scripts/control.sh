#!/usr/bin/env bash
# Verification harness for certconv's CLI and TUI: a sandbox HOME, openssl-generated fixtures,
# CLI transcripts with created-file copies, and a private tmux server for the TUI.
# Built on verify-kit (scripts/verify-lib.sh). Bash 3.2 compatible. Run with --help for usage.
# shellcheck disable=SC2034 # VK_* settings are read by the sourced verify-lib.sh
set -euo pipefail

VK_SCRIPT="$0"
VK_APP="certconv"
VK_DESCRIPTION="Verification harness for certconv's CLI and TUI: sandbox HOME, generated fixtures, private tmux server."
VK_DEFAULT_EVIDENCE_ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)/tmp/verify"
# shellcheck source=verify-lib.sh disable=SC1091
. "$(cd "$(dirname "$0")" && pwd)/verify-lib.sh"

# Globals set by vk_paths and the recipes.
LAST_CLI_OUT=""
LAST_CLI_EXIT=""
LAST_CAPTURE=""

vk_commands_help() {
  cat <<'HELP'
  launch                 build ./cmd/certconv; generate the fixtures (CA, leaf, keys, bundle)
  doctor                 read-only: binary, fixtures, sandbox HOME, revision
  cli <args...>          run certconv in the fixture dir; record transcript and created files
  tui start [args]       start the TUI in a private tmux server (cwd = fixture dir)
  tui keys <key...>      send allowlisted keys: Up Down Left Right Enter Tab BTab Escape j k n p v o u q
  tui capture <name>     save the TUI screen into evidence
  tui stop               quit (q q), record CERTCONV_EXIT, stop the private tmux server
  cleanup                stop tmux and delete the sandbox; evidence is kept
HELP
}

vk_sample_commands() {
  printf '%s\n' verify launch doctor "cli show leaf.pem" "cli match leaf.pem leaf.key" \
    "cli match leaf.pem stray.key" "tui start" "tui keys Down Enter" "tui capture selected" \
    "tui stop" cleanup
}

vk_paths() {
  STATE="$VK_BASE_DIR/$VK_RUN_ID/state"
  SANDBOX="$STATE/home"
  FIX="$SANDBOX/certs"
  BIN="$STATE/bin/certconv"
  EVIDENCE="$VK_EVIDENCE_ROOT/$VK_RUN_ID"
  SOCKET="verify-certconv-$VK_RUN_ID"
}

die_usage() { vk_err "$1"; exit 2; }
in_sandbox() { (cd "$FIX" && env HOME="$SANDBOX" XDG_CONFIG_HOME="$SANDBOX/.config" CERTCONV_CERTS_DIR="$FIX" TERM=xterm-256color "$@"); }
tmux_v() { tmux -L "$SOCKET" "$@"; }
tui_running() { tmux_v has-session -t tui 2>/dev/null; }

# check_keys <key...>: every key is checked before any key is sent or tmux is touched.
check_keys() {
  [ $# -gt 0 ] || die_usage "tui keys needs at least one key"
  local k
  for k in "$@"; do
    case "$k" in
      Up|Down|Left|Right|Enter|Tab|BTab|Escape|j|k|n|p|v|o|u|q) ;;
      *) echo "refused key '$k' (c copies to the system clipboard; others are unreviewed)" >&2; exit 2 ;;
    esac
  done
}

tui_plan() {
  local sub="${1:-}"
  if [ $# -gt 0 ]; then shift; fi
  case "$sub" in
    start) vk_plan_line "start certconv tui in tmux socket $SOCKET (session tui), cwd $FIX" ;;
    keys) check_keys ${@+"$@"}; vk_plan_line "send keys $* to tmux session tui" ;;
    capture) [ -n "${1:-}" ] || die_usage "tui capture needs a name"; vk_plan_line "save the screen as $EVIDENCE/tui/NN-$1.txt" ;;
    stop) vk_plan_line "send q q, record $EVIDENCE/tui/zz-after-quit.txt, stop tmux socket $SOCKET" ;;
    *) die_usage "tui needs start, keys, capture or stop" ;;
  esac
}

vk_plan() {
  local cmd="$1"
  shift
  case "$cmd" in
    verify) vk_plan_line "launch, doctor, cli recipes (show, match, verify, to-der), tui recipe (start, keys, capture, stop), cleanup; evidence in $EVIDENCE" ;;
    launch) vk_plan_line "go build -o $BIN ./cmd/certconv; generate fixtures in $FIX; evidence in $EVIDENCE" ;;
    doctor) vk_plan_line "check $BIN, the fixtures in $FIX and the sandbox HOME (read-only)" ;;
    cli)
      [ $# -gt 0 ] || die_usage "cli needs certconv arguments"
      vk_plan_line "run certconv $* in $FIX with HOME=$SANDBOX; record transcript and created files under $EVIDENCE"
      ;;
    tui) tui_plan ${@+"$@"} ;;
    cleanup) vk_plan_line "stop tmux socket $SOCKET; remove $STATE; keep $EVIDENCE" ;;
    *) vk_unknown_command ;;
  esac
}

cmd_launch() {
  mkdir -p "$STATE/bin" "$FIX" "$EVIDENCE"
  vk_mark_current
  vk_record_revision "$EVIDENCE/revision.txt"
  (cd "$VK_ROOT" && mise exec -- go build -o "$BIN" ./cmd/certconv) > "$EVIDENCE/build.log" 2>&1 \
    || { vk_fail "go build failed; see $EVIDENCE/build.log"; return 1; }
  gen_fixtures > "$EVIDENCE/fixtures.log" 2>&1 \
    || { vk_fail "fixture generation failed; see $EVIDENCE/fixtures.log"; return 1; }
  rm -f "$FIX/ca.srl"
  vk_say "ready run=$VK_RUN_ID bin=$BIN fixtures=$FIX evidence=$EVIDENCE"
}

# Every openssl step returns 1 on failure: errexit is off inside a function called from ||.
gen_fixtures() {
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$FIX/ca.key" -out "$FIX/ca.pem" -days 30 \
    -subj "/CN=Verify Test CA" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" || return 1
  openssl req -newkey rsa:2048 -nodes -keyout "$FIX/leaf.key" -out "$STATE/leaf.csr" -subj "/CN=verify.example.test" || return 1
  printf 'subjectAltName=DNS:verify.example.test,DNS:www.verify.example.test\n' > "$STATE/leaf.ext" || return 1
  openssl x509 -req -in "$STATE/leaf.csr" -CA "$FIX/ca.pem" -CAkey "$FIX/ca.key" -CAcreateserial \
    -out "$FIX/leaf.pem" -days 10 -extfile "$STATE/leaf.ext" || return 1
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$FIX/stray.key" || return 1
  cat "$FIX/leaf.pem" "$FIX/ca.pem" > "$FIX/bundle.pem" || return 1
}

cmd_doctor() {
  vk_say "run=$VK_RUN_ID fixtures=$FIX"
  [ -x "$BIN" ] || { vk_fail "no binary for run=$VK_RUN_ID; launch first"; return 1; }
  local f
  for f in ca.pem leaf.pem leaf.key stray.key bundle.pem; do
    [ -s "$FIX/$f" ] || { vk_fail "missing fixture $f"; return 1; }
  done
  # shellcheck disable=SC2016 # $HOME must expand inside the sandboxed shell, not here
  [ "$(in_sandbox sh -c 'echo $HOME')" = "$SANDBOX" ] || { vk_fail "HOME is not the sandbox"; return 1; }
  vk_say "built $(head -1 "$EVIDENCE/revision.txt") (now $(git -C "$VK_ROOT" rev-parse HEAD)); $("$BIN" version 2>&1 | head -1)"
  vk_say "OK fixtures=$(find "$FIX" -maxdepth 1 -type f -exec basename {} \; | sort | tr '\n' ' ')"
}

# cmd_cli <certconv args...>: sets LAST_CLI_OUT and LAST_CLI_EXIT for the assertions.
cmd_cli() {
  [ $# -gt 0 ] || die_usage "cli needs certconv arguments"
  [ -x "$BIN" ] || { vk_fail "no binary for run=$VK_RUN_ID; launch first"; return 1; }
  local out code created f
  out="$EVIDENCE/$(vk_stamp)-cli"
  mkdir -p "$out"
  ls -1 "$FIX" > "$out/files-before.txt"
  printf '%q ' certconv "$@" > "$out/command.txt"
  set +e
  in_sandbox "$BIN" "$@" > "$out/stdout.txt" 2> "$out/stderr.txt"
  code=$?
  set -e
  echo "$code" > "$out/exit-code.txt"
  ls -1 "$FIX" > "$out/files-after.txt"
  # Keep copies of any files the command created, so the proof survives cleanup.
  comm -13 "$out/files-before.txt" "$out/files-after.txt" | while IFS= read -r f; do cp "$FIX/$f" "$out/created-$f"; done
  cat "$out/stdout.txt" "$out/stderr.txt"
  created="$(comm -13 "$out/files-before.txt" "$out/files-after.txt" | tr '\n' ' ')"
  vk_say "exit=$code created=[$created] evidence: $out"
  LAST_CLI_OUT="$out"
  LAST_CLI_EXIT="$code"
}

tui_start() {
  [ -x "$BIN" ] || { vk_fail "no binary for run=$VK_RUN_ID; launch first"; return 1; }
  if tui_running; then vk_fail "TUI already running"; return 1; fi
  [ $# -gt 0 ] || set -- tui "$FIX"
  mkdir -p "$EVIDENCE/tui"
  tmux_v new-session -d -s tui -x 160 -y 44 -c "$FIX" \
    "$(printf '%q ' env HOME="$SANDBOX" XDG_CONFIG_HOME="$SANDBOX/.config" CERTCONV_CERTS_DIR="$FIX" TERM=xterm-256color "$BIN" "$@"); echo CERTCONV_EXIT=\$?; sleep 600"
  sleep 2
  vk_say "TUI started (tmux -L $SOCKET attach -t tui to watch)"
}

tui_keys() {
  check_keys ${@+"$@"}
  tui_running || { vk_fail "no TUI running; run tui start first"; return 1; }
  local k
  for k in "$@"; do
    tmux_v send-keys -t tui "$k"
    sleep 0.5
  done
}

# tui_capture <name>: sets LAST_CAPTURE to the saved file.
tui_capture() {
  local name="${1:-}" n
  [ -n "$name" ] || die_usage "tui capture needs a name"
  mkdir -p "$EVIDENCE/tui"
  n="$(find "$EVIDENCE/tui" -type f -name '[0-9]*' | wc -l | tr -d ' ')"
  LAST_CAPTURE="$EVIDENCE/tui/$(printf '%02d' "$n")-$name.txt"
  tmux_v capture-pane -p -t tui > "$LAST_CAPTURE"
  vk_say "captured $LAST_CAPTURE"
}

tui_stop() {
  if tui_running; then
    tmux_v send-keys -t tui q; sleep 0.4
    tmux_v send-keys -t tui q; sleep 1
    tmux_v capture-pane -p -t tui > "$EVIDENCE/tui/zz-after-quit.txt"
    grep -o 'CERTCONV_EXIT=[0-9]*' "$EVIDENCE/tui/zz-after-quit.txt" || vk_say "TUI did not exit"
    tmux_v kill-server
  fi
}

cmd_tui() {
  local sub="${1:-}"
  if [ $# -gt 0 ]; then shift; fi
  case "$sub" in
    start) tui_start ${@+"$@"} ;;
    keys) tui_keys ${@+"$@"} ;;
    capture) tui_capture ${@+"$@"} ;;
    stop) tui_stop ;;
    *) die_usage "tui needs start, keys, capture or stop" ;;
  esac
}

cmd_cleanup() {
  tmux_v kill-server 2>/dev/null || true
  rm -rf "${STATE:?}"
  rmdir "$VK_BASE_DIR/$VK_RUN_ID" 2>/dev/null || true
  vk_clear_current
  vk_say "removed sandbox for run=$VK_RUN_ID; evidence kept at $EVIDENCE"
}

# The CLI assertions read the transcript of the last cli call.
vk_verify_recipes() {
  cmd_cli show leaf.pem
  vk_expect_equals "show exit" "$LAST_CLI_EXIT" 0
  vk_expect_contains "$LAST_CLI_OUT/stdout.txt" "Subject: CN=verify.example.test"

  cmd_cli match leaf.pem leaf.key
  vk_expect_equals "match with the right key: exit" "$LAST_CLI_EXIT" 0
  cmd_cli match leaf.pem stray.key
  vk_expect_equals "match with a stray key: exit" "$LAST_CLI_EXIT" 1
  vk_expect_contains "$LAST_CLI_OUT/stderr.txt" "key mismatch"

  cmd_cli verify leaf.pem ca.pem
  vk_expect_equals "verify against the CA: exit" "$LAST_CLI_EXIT" 0

  cmd_cli to-der leaf.pem leaf.der
  vk_expect_equals "to-der exit" "$LAST_CLI_EXIT" 0
  vk_expect_file "$LAST_CLI_OUT/created-leaf.der"

  cmd_tui start
  cmd_tui keys Down Enter
  cmd_tui capture selected
  vk_expect_contains "$LAST_CAPTURE" "SANs:"
  vk_expect_contains "$LAST_CAPTURE" "verify.example.test"

  cmd_tui stop
  vk_expect_contains "$EVIDENCE/tui/zz-after-quit.txt" "CERTCONV_EXIT=0"
}

vk_dispatch() {
  local cmd="$1"
  shift
  case "$cmd" in
    launch) cmd_launch ;;
    doctor) cmd_doctor ;;
    cli) cmd_cli ${@+"$@"} ;;
    tui) cmd_tui ${@+"$@"} ;;
    cleanup) cmd_cleanup ;;
    *) vk_unknown_command ;;
  esac
}

vk_main "$@"
