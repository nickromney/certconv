#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PUBLIC_DIR="$ROOT_DIR/web/public"
GOROOT_DIR="$(go env GOROOT)"

mkdir -p "$PUBLIC_DIR"

cp "$GOROOT_DIR/lib/wasm/wasm_exec.js" "$PUBLIC_DIR/wasm_exec.js"
GOOS=js GOARCH=wasm go build -trimpath -o "$PUBLIC_DIR/certconv.wasm" "$ROOT_DIR/cmd/certconv-web"

printf 'Built %s and %s\n' "$PUBLIC_DIR/certconv.wasm" "$PUBLIC_DIR/wasm_exec.js"
