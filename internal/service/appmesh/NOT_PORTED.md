# NOT_PORTED.md — `internal/service/appmesh`

Ported: `doc.go`, `relationships.go`, `types.go`.

## Not ported (class-c)

| File | Blocked on |
|---|---|
| `awssdk/` (`client.go`, `client_gateways.go`, `client_nodes.go`, `doc.go`, `helpers.go`, `mappers.go`, `mappers_routes.go`, `telemetry.go`) | AWS SDK adapter + `telemetry` spans — no SDK OTEL surface; boundary forbids AWS SDK paths until the telemetry shim lands |
| `runtimebind/` (`bind.go`, `doc.go`) | `awsruntime.Register` in blocked `registry.go` (telemetry + redact) — ports with the registry |
| `observations.go` | transitive: uses `Scanner` from `scanner.go` (facts.Envelope) |
| `redaction.go` | transitive: uses `Scanner`, `awscloud.RedactString`/`ClassifyStackOutput` from `scanner.go`, blocked root `redaction.go` |
| `scanner.go` | `facts.Envelope` — no SDK Envelope surface; `collector.Service` / claim runtime — core-owned; `redact.RuleSet` — SDK has only `IsSensitiveKeyName` |

## Tests not ported (subject absent)

- `scanner_test.go` — exercises an unported subject above.
- `servicekind_test.go` — exercises an unported subject above.
- `awssdk/client_test.go` — exercises an unported subject above.
- `awssdk/fake_api_test.go` — exercises an unported subject above.
- `runtimebind/bind_test.go` — exercises an unported subject above.

Seam: SDK `Envelope` + observation-builder + OTEL + scope surfaces, then re-run the port for the files above.
