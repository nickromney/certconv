# certconv: agent operating model

Adopted 6 October 2026 from local source and command inspection.
Inspect and convert sensitive certificate material through one non-invasive engine.

## Read by intent

Start with the local agent guide and build manifest. For domain or behavior
changes, follow the owners below, then the relevant contract/test. These
documents retain product detail and historical evidence:

- [README.md](../README.md)
- [docs/INTERNALS.md](INTERNALS.md)
- [docs/NONINTERACTIVE_PLAN.md](NONINTERACTIVE_PLAN.md)
- [TESTING.md](../TESTING.md)

## System ownership

| Owner | Responsibility |
| --- | --- |
| [internal/cert/](../internal/cert) | Engine operations, cancellable Executor, exclusive outputs and secret transport |
| [internal/cli/](../internal/cli) | Cobra commands, output formatting and input secrets |
| [internal/tui/](../internal/tui) | Interactive adapter over same engine |
| [internal/config/](../internal/config) | Configuration |

Intent selects the owning policy; that policy produces decisions or artifacts;
adapters perform effects; verification establishes the result. Change the
owner once and keep alternate surfaces on that same contract.

## Invariants

- No overwrite even across TOCTOU race.
- OpenSSL password transport uses file descriptors on Unix; Windows temporary-file fallback.
- Subcommands do not launch TUI.
- No certificate generation or remote certificate discovery in product.

## Existing action interfaces

These are inspected command surfaces, not a report that they ran. Read current
help and recipes for arguments, dependencies and lifecycle hooks before use.
Examples containing placeholder paths or bracketed options are grammar.

| Command | Effects and evidence |
| --- | --- |
| `make build` | Builds bin/certconv |
| `./bin/certconv show cert.pem --json` | Structured local certificate inspection; no remote service |
| `./bin/certconv to-der cert.pem out.der` | Creates new output exclusively; does not overwrite |
| `make test` | Race-detector tests |
| `make check` | Formats/tidies source and runs vet/lint/test/vulnerability tooling; network/toolchain possible |

## Observe, verify and retain

Establish source revision, dirty state and relevant input identity before
choosing an action. Keep intended settings, cached artifacts and observed
runtime state distinct. An existing artifact is not a freshness or readiness
claim. Use the smallest deterministic fixture at the changed seam first;
expand to process, browser, device or deployment checks only when that
claim needs them. Record unavailable evidence explicitly.

Retain the command/configuration, source and input identity, result, limitation
and next discriminating check. Reuse evidence only while its relevant inputs
remain applicable. Promote a reproducible failure to a regression fixture,
a design decision to its owning document, and a repeated operator correction
to one concise guide rule. Keep private observations in private artifacts.

## Implemented plan for this pass

- [x] Map current source ownership and existing interfaces.
- [x] Make command effects and evidence limits discoverable.
- [x] Route agent work here and retain detailed product plans at their owners.

Acceptance: owner paths and document links resolve; current instructions
match inspected source; catalog hashes bind this context to the reviewed
bytes. This is documentation/control navigation acceptance. Product runtime
checks retain their own scope and are not certified by this pass.
