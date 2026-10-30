# Contributing

## Local gates

`make ci` runs the same lint, test, and race commands CI runs: `go vet`,
`golangci-lint run` plus the gofumpt format check, `go mod tidy -diff`,
the 500-line `.go` file cap, `go build`, the full test suite, and the
race suite. Run it before every push. It needs Go 1.26.10 or newer;
`go.mod` is the version of record and CI installs exactly that.

Shell scripts pass `shellcheck` (see the `shell` lane). Keep them
`set -euo pipefail` clean like `scripts/run-conformance.sh`.

## CI lanes

Job names are frozen because branch protection requires `ci-complete`:

| Lane | Runs when |
| --- | --- |
| `lint` | Go sources, `manifest.yaml`, module or lint-config changes, or any unclassified path (see below) |
| `test` | Above, plus fixtures and config the tests read, or any unclassified path |
| `race` | Same inputs as `test` (fixture-only PRs keep the `-race` and floor signal: fixture changes can move coverage), plus a coverage artifact and floor check |
| `shell` | Shell script changes |
| `image` | Go sources (the Dockerfile builds the binary from them), `Dockerfile`, `.dockerignore`, `manifest.yaml`, or module changes (build only, no push) |
| `govulncheck` | Dependency changes, pushes to `main`, weekly schedule, manual dispatch; a failing scheduled run files or updates an issue |
| `gosec` | Pushes to `main`, weekly schedule, and manual dispatch; advisory, SARIF to the Security tab; a scheduled run with findings fails and files or updates an issue |
| `ci-complete` | Always; fails on any needed lane failure, passes on legitimate skips |
| `release` (`release.yml`, not `ci.yml`) | Version tag `v*` push only: builds, signs, and publishes the image plus SBOM and provenance attestations. The tag must point at the `main` head and match the `manifest.yaml` version (`release_version_test.go` enforces both directions) |

Docs-only PRs run no lane and stay mergeable through `ci-complete`.
A manual `workflow_dispatch` run records every lane; the weekly schedule
runs `govulncheck` and `gosec` only.

Unclassified paths fail closed: anything no filter classifies (for
example `.gitignore` or `.github/dependabot.yml`) runs `lint`, `test`,
and `race`. The fixtures filter lists only grep-proven test- or
embed-consumed entries (`testdata/**`, `**/*.json`, `manifest.yaml`,
`grant.example.json`); `config.example.yaml` has no test readers, so it
stays docs-class with the Markdown skip set.

## Coverage floor

The `race` job fails below `COVERAGE_FLOOR` in `ci.yml`. The floor starts
at the measured post-cleanup baseline and may only rise toward the 90%
target as tests land. Never lower it, exclude packages silently, or
delete assertions to move the number.

## Fixture-only CI

PR lanes never touch live AWS: tests run against `testdata/` fixtures.
`manifest.yaml` is embedded into the binary, so editing it runs the full
Go lanes. Base images stay digest-pinned; re-pin with the
`scripts/pin-digest.sh` flow and keep the Go base in sync with `go.mod`.
