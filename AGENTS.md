# certconv agent guide

## Verify

- Setup: `make hooks` (installs lefthook). The pre-push hook runs `make check-local`, which runs `scripts/agent/check-local.sh`: bats hook tests, the pre-push gate, shellcheck, gofmt and `git diff --check`.
- The pre-push gate needs `go`, `uv` (runs `yamllint`), `govulncheck`, `golangci-lint`, `shellcheck` and `bats`. A missing tool, or a vulnerability database that cannot be reached, fails the gate; it does not skip it.
- The gate refuses `LEFTHOOK=0`, `CERTCONV_SKIP_HOOKS=1` and nested runs.
- Focused checks: `make test` (race detector) and `make test-domain` (two named engine tests and the hook bats suite).
- `make check` runs fmt, vet, lint, test and vuln. `fmt` rewrites source files, and `vuln` needs network access.
- `make build` writes `bin/certconv`.
