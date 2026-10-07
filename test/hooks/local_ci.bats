#!/usr/bin/env bats

setup() {
  REPO="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
  MOCK_BIN="$BATS_TEST_TMPDIR/bin"
  mkdir -p "$MOCK_BIN"
  for name in go uv golangci-lint; do
    printf '#!/usr/bin/env bash\nexit 0\n' > "$MOCK_BIN/$name"
    chmod +x "$MOCK_BIN/$name"
  done
  printf '#!/usr/bin/env bash\necho "fetching vulnerabilities: network is unreachable" >&2\nexit 1\n' > "$MOCK_BIN/govulncheck"
  chmod +x "$MOCK_BIN/govulncheck"
}

@test "local acceptance refuses an explicit skip" {
  run env CERTCONV_SKIP_HOOKS=1 bash "$REPO/scripts/hooks/run-local-ci.sh"
  [ "$status" -ne 0 ]
  [[ "$output" == *"refusing gate"* ]]
}

@test "local acceptance refuses recursion" {
  run env CERTCONV_SKIP_HOOKS=0 CERTCONV_LOCAL_CI_IN_PROGRESS=1 bash "$REPO/scripts/hooks/run-local-ci.sh"
  [ "$status" -ne 0 ]
  [[ "$output" == *"recursive local CI is not acceptance"* ]]
}

@test "unavailable vulnerability database cannot produce a passing gate" {
  run env PATH="$MOCK_BIN:$PATH" CERTCONV_SKIP_HOOKS=0 CERTCONV_LOCAL_CI_IN_PROGRESS=0 CERTCONV_PINNED_TOOLS=1 bash "$REPO/scripts/hooks/run-local-ci.sh"
  [ "$status" -ne 0 ]
  [[ "$output" == *"vulnerability database unavailable; acceptance is inconclusive"* ]]
}
