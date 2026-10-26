# NOT_PORTED.md — `internal/service/ec2`

Ported: `doc.go`, `types.go`.

## Not ported (class-c)

| File | Blocked on |
|---|---|
| `awssdk/` (`client.go`, `doc.go`, `mapper.go`) | AWS SDK adapter + `telemetry` spans — no SDK OTEL surface; boundary forbids AWS SDK paths until the telemetry shim lands |
| `runtimebind/` (`bind.go`, `doc.go`) | `awsruntime.Register` in blocked `registry.go` (telemetry + redact) — ports with the registry |
| `ami_identity.go` | `facts.Envelope` — no SDK Envelope surface; `collector.Service` / claim runtime — core-owned |
| `attributes.go` | transitive: uses `timeOrNil` from `scanner.go` (facts.Envelope) |
| `identity.go` | `facts.Envelope` — no SDK Envelope surface; `collector.Service` / claim runtime — core-owned |
| `posture.go` | `facts.Envelope` — no SDK Envelope surface; `collector.Service` / claim runtime — core-owned |
| `relationships.go` | transitive: uses `securityGroupRuleID/Direction` from `scanner.go` (facts.Envelope) |
| `scanner.go` | `facts.Envelope` — no SDK Envelope surface; `collector.Service` / claim runtime — core-owned |
| `volume.go` | `facts.Envelope` — no SDK Envelope surface; `collector.Service` / claim runtime — core-owned |

## Tests not ported (subject absent)

- `ami_identity_test.go` — exercises an unported subject above.
- `identity_bench_test.go` — exercises an unported subject above.
- `scanner_test.go` — exercises an unported subject above.
- `servicekind_test.go` — exercises an unported subject above.
- `volume_test.go` — exercises an unported subject above.
- `awssdk/client_test.go` — exercises an unported subject above.
- `awssdk/partition_test.go` — exercises an unported subject above.
- `runtimebind/bind_test.go` — exercises an unported subject above.

Seam: SDK `Envelope` + observation-builder + OTEL + scope surfaces, then re-run the port for the files above.
