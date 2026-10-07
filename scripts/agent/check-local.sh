#!/usr/bin/env bash
set -euo pipefail
agent_gate_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$agent_gate_root"
# Gates are acceptance, never skip-capable runtime dispatch.
if [[ "${LEFTHOOK:-}" == "0" || "${CERTCONV_SKIP_HOOKS:-}" == "1" || "${CERTCONV_LOCAL_CI_IN_PROGRESS:-}" == "1" ]]; then
  echo "Refusing disabled or recursive acceptance gate" >&2
  exit 1
fi
agent_gate_tmp="$(mktemp -d "${TMPDIR:-/tmp}/agent-local-gate.XXXXXX")"
trap 'rm -rf "$agent_gate_tmp"' EXIT
export GOTOOLCHAIN=local
export GOCACHE="${GOCACHE:-$agent_gate_tmp/go-cache}"
export GOMODCACHE="${GOMODCACHE:-$(go env GOPATH 2>/dev/null)/pkg/mod}"
bats test/hooks/local_ci.bats
scripts/hooks/run-local-ci.sh
shellcheck scripts/*.sh legacy/*.sh
test -z "$(gofmt -l cmd internal test)"
git diff --check
