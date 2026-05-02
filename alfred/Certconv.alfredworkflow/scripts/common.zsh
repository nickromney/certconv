#!/bin/zsh
set -euo pipefail

certconv_candidates() {
  local script_dir repo_root candidate
  script_dir=${0:A:h}
  repo_root=${script_dir:h:h:h}

  for candidate in \
    "${certconv_bin:-}" \
    "$(command -v certconv 2>/dev/null || true)" \
    "$HOME/Developer/personal/certconv/bin/certconv" \
    "$HOME/Developer/certconv/bin/certconv" \
    "$repo_root/bin/certconv" \
    "$HOME/go/bin/certconv" \
    "/opt/homebrew/bin/certconv" \
    "/usr/local/bin/certconv"
  do
    if [[ -n "$candidate" ]]; then
      print -r -- "$candidate"
    fi
  done
}

resolve_certconv() {
  local candidate
  local -a candidates
  candidates=("${(@f)$(certconv_candidates)}")

  for candidate in "${candidates[@]}"; do
    if [[ -n "$candidate" && -x "$candidate" ]]; then
      print -r -- "$candidate"
      return 0
    fi
  done

  return 1
}

certconv_hint_path() {
  local candidate
  local -a candidates
  candidates=("${(@f)$(certconv_candidates)}")

  for candidate in "${candidates[@]}"; do
    if [[ -n "$candidate" && -e "$candidate" ]]; then
      print -r -- "$candidate"
      return 0
    fi
  done

  print -r -- "/absolute/path/to/certconv"
}

shell_quote() {
  printf "%q" "$1"
}

print_message_command() {
  local title body
  title=${1:-}
  body=${2:-}
  print -r -- "printf '%s\n%s\n' $(shell_quote "$title") $(shell_quote "$body"); printf '%s' $(shell_quote 'Press return to close...'); read"
}
