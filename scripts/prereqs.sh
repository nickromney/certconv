#!/bin/sh
set -eu

echo "Checking prerequisites..."

if ! command -v go >/dev/null 2>&1; then
  echo "Error: 'go' not found in PATH."
  exit 2
fi
echo "go: $(go version)"

if ! command -v openssl >/dev/null 2>&1; then
  echo "Error: 'openssl' not found in PATH (required at runtime)."
  exit 2
fi
echo "openssl: $(openssl version)"

# `go tool cover` must exist for `make cover-html`. Some Go versions exit non-zero
# on "cover -h", so we check existence by asking `go tool` for the tool path.
if ! go tool -n cover >/dev/null 2>&1; then
  echo "Error: 'go tool cover' not available (required for make cover-html)."
  exit 2
fi
echo "go tool cover: OK"

# `go tool covdata` is used by some Go distributions/toolchains for coverage
# plumbing. If it's missing you may see:
#   "Warning: go tool covdata not available; running tests without -coverprofile"
# Fix: install a full official Go toolchain (this repo targets Go 1.25+).
if go tool -n covdata >/dev/null 2>&1; then
  echo "go tool covdata: OK"
else
  echo "go tool covdata: not available (coverage profiles may be disabled on this toolchain)"
fi

if command -v shellcheck >/dev/null 2>&1; then
  # First line is stable across versions.
  echo "shellcheck: $(shellcheck --version | head -n 1)"
else
  echo "shellcheck: not found (optional; required only for make shellcheck)"
fi

if command -v govulncheck >/dev/null 2>&1; then
  echo "govulncheck: OK"
else
  echo "govulncheck: not found (optional; used in CI and for local vuln scanning)"
fi

echo "OK"
