# NOT_PORTED.md — `internal/awsruntime`

Ported: `doc.go`. (`limiter.go` is recorded below; `limiter_test.go` went
with it.)

## Blocked: registry, sources, credentials (telemetry / facts / scope / AWS SDK)

| In-tree file | Blocked on | Seam |
|---|---|---|
| `source.go` | `collector.Service`, `facts`, `facts/cloud`, `scope`, `telemetry`, `workflow`, otel | Core claim runtime + SDK Envelope/telemetry/scope surfaces |
| `registry.go` (`SupportsServiceKind`, `DefaultScannerFactory`) | `redact`, `telemetry`, otel | SDK OTEL surface + redaction ruleset |
| `registry_core.go` | AWS SDK + `redact` + `telemetry` + otel | Same, plus boundary allowlist for AWS SDK paths |
| `types.go` (`TargetScope`, runtime config) | AWS SDK + `facts` | Same |
| `credentials.go` | AWS SDK (`aws`, `config`, `stscreds`, `sts`) | Boundary allowlist for AWS SDK paths (no SDK shim needed for the SDK itself, but every credential consumer also needs telemetry) |
| `fixture_source.go` (`FixtureConfig`, `FixtureResource`) | `collector`, `facts`, `scope` | SDK claim-source surface |
| `freshness.go` | `facts`, `facts/cloud` | SDK Envelope surface |
| `record_source.go` | `collector`, `scope`, `workflow` | SDK claim-source + workflow surfaces |
| `scan_status.go` | smithy + `facts` + `facts/cloud` + `telemetry` + otel metric | SDK Envelope + telemetry surfaces |
| `limiter.go` (`AccountLimiter`) | `TargetScope` in blocked `types.go` (transitive) | Ports with `types.go` |
| `*_test.go` (source, registry, fixture, freshness, limiter, scan_status, throttle, trusted_deletion) | Subjects above | Port with their subjects |

## Notes

- `limiter_test.go` was import-clean but references the blocked
  `TargetScope`; it was dropped with `limiter.go` rather than kept failing.
- The AWS SDK is a new dependency the boundary test (`boundary_test.go`)
  currently rejects: every AWS SDK consumer also imports blocked `telemetry`,
  so no `go get` was performed. When the telemetry shim lands, the boundary
  allowlist must gain the AWS SDK paths (`github.com/aws/aws-sdk-go-v2/...`,
  `github.com/aws/smithy-go`) alongside the port.
