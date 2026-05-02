#!/bin/zsh
set -euo pipefail

script_dir=${0:A:h}
source "$script_dir/common.zsh"

target=${1:-}
if [[ -z "$target" ]]; then
  print_message_command "No directory selected" "Pick a directory, then Alfred will launch certconv there."
  exit 0
fi
target=${target:A}

if ! certconv_bin_path="$(resolve_certconv)"; then
  hint_path="$(certconv_hint_path)"
  print_message_command "certconv not found" "Set certconv_bin to ${hint_path} or install certconv on PATH."
  exit 0
fi

print -r -- "cd $(shell_quote "$target") && $(shell_quote "$certconv_bin_path") $(shell_quote "$target")"
