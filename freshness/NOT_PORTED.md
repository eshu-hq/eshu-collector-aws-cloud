# NOT_PORTED.md — `freshness`

| In-tree file | Status | Reason / seam |
|---|---|---|
| `doc.go` | ported | — |
| `eventbridge.go` | **not ported** | Uses `awsruntime.SupportsServiceKind`, which lives in blocked `awsruntime/registry.go` (telemetry + redact + otel; no SDK OTEL surface). Ports when the awsruntime registry ports. |
| `types.go` | **not ported** | Imports `go/internal/facts` (`facts.Envelope` in freshness-type signatures). No SDK `Envelope` replacement. |
| `eventbridge_test.go`, `types_test.go`, `aws_bindings_test.go` | **not ported** | Subjects absent (see above; bindings registry absent by design). |

The scaffold `health.go` freshness tracking (`LastDigest`, `Monitor`) is
unchanged; this package will replace it per PORT_PLAN ordering step 7 once
the registry seam lands.
