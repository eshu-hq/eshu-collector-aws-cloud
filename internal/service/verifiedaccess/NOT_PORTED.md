# NOT_PORTED.md — `internal/service/verifiedaccess`

Ported: `doc.go`, `helpers.go`, `types.go`.

## Not ported (class-c)

| File | Blocked on |
|---|---|
| `awssdk/` (`client.go`, `doc.go`, `mapping.go`) | AWS SDK adapter + `telemetry` spans — no SDK OTEL surface; boundary forbids AWS SDK paths until the telemetry shim lands |
| `runtimebind/` (`bind.go`, `doc.go`) | `awsruntime.Register` in blocked `registry.go` (telemetry + redact) — ports with the registry |
| `relationships.go` | transitive: uses `endpointResourceID` from `scanner.go` (facts.Envelope) |
| `scanner.go` | `facts.Envelope` — no SDK Envelope surface; `collector.Service` / claim runtime — core-owned |

## Tests not ported (subject absent)

- `scanner_test.go` — exercises an unported subject above.
- `servicekind_test.go` — exercises an unported subject above.
- `awssdk/client_test.go` — exercises an unported subject above.
- `awssdk/exclusion_test.go` — exercises an unported subject above.
- `runtimebind/bind_test.go` — exercises an unported subject above.

Seam: SDK `Envelope` + observation-builder + OTEL + scope surfaces, then re-run the port for the files above.
