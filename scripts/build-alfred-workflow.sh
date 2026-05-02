#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
src_dir="$repo_root/alfred/Certconv.alfredworkflow"
out_dir="$repo_root/dist"
out_file="$out_dir/Certconv.alfredworkflow"

mkdir -p "$out_dir"
rm -f "$out_file"

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

cp -R "$src_dir/." "$tmp_dir/"

(
  cd "$tmp_dir"
  zip -qr "$out_file" .
)

printf '%s\n' "$out_file"
