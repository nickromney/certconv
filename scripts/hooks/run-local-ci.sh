#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/hooks/lib.sh
source "${SCRIPT_DIR}/lib.sh"

if hook_skip_requested; then
  hook_print_skip_and_exit
fi

if [[ "${CERTCONV_LOCAL_CI_IN_PROGRESS:-}" == "1" ]]; then
  hook_warn "CERTCONV_LOCAL_CI_IN_PROGRESS=1; skipping run-local-ci.sh to avoid recursive local CI"
  exit 0
fi

cd "${HOOKS_REPO_ROOT}"

cat <<'EOF'
certconv pre-push local CI gate

Running:
  yamllint .github/workflows
  go test -v -race ./...
  go test -v -coverprofile=<temp>/coverage.out ./...
  go vet ./...
  govulncheck ./...
  GOOS=windows GOARCH=amd64 go build ./cmd/certconv
  GOOS=darwin GOARCH=arm64 go build ./cmd/certconv
  golangci-lint run ./...

Skip only when you have a reason:
  LEFTHOOK=0 git push
  CERTCONV_SKIP_HOOKS=1 git push
  git push --no-verify
EOF

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    hook_fail "$1 not found in PATH"
    exit 1
  fi
}

run_gate() {
  local label="$1"
  shift

  if ! "$@"; then
    hook_fail "pre-push gate failed: ${label}"
    exit 1
  fi
}

run_govulncheck() {
  local output

  if output="$(govulncheck ./... 2>&1)"; then
    printf '%s\n' "${output}"
    return 0
  fi

  printf '%s\n' "${output}" >&2
  if grep -Eq 'fetching vulnerabilities|vuln\.go\.dev|no such host|network is unreachable|temporary failure in name resolution' <<<"${output}"; then
    hook_warn "govulncheck could not reach the vulnerability database; skipping in this offline run"
    return 0
  fi

  return 1
}

require_tool yamllint
require_tool go
require_tool govulncheck
require_tool golangci-lint

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

export CERTCONV_LOCAL_CI_IN_PROGRESS=1
export GOCACHE="${GOCACHE:-${tmp_dir}/go-build}"
export GOLANGCI_LINT_CACHE="${GOLANGCI_LINT_CACHE:-${tmp_dir}/golangci-lint}"

run_gate "yamllint .github/workflows" yamllint .github/workflows
run_gate "go test -v -race ./..." go test -v -race ./...
run_gate "go test -v -coverprofile=<temp>/coverage.out ./..." go test -v -coverprofile="${tmp_dir}/coverage.out" ./...
run_gate "go vet ./..." go vet ./...
run_gate "govulncheck ./..." run_govulncheck
run_gate "GOOS=windows GOARCH=amd64 go build ./cmd/certconv" \
  env CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o "${tmp_dir}/certconv-windows-amd64.exe" ./cmd/certconv
run_gate "GOOS=darwin GOARCH=arm64 go build ./cmd/certconv" \
  env CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o "${tmp_dir}/certconv-darwin-arm64" ./cmd/certconv
run_gate "golangci-lint run ./..." golangci-lint run ./...

hook_ok "pre-push gate passed"
