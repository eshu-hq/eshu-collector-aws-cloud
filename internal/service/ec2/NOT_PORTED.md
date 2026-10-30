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

## Wave 1 emission parity (eshu-hq/eshu#9296)

The files above remain literally unported (no SDK `facts.Envelope`
replacement), but the live path (`internal/live/ec2_*.go` through the root
`NewResourceFact` / `NewRelationshipFact` / Wave 0 specialty seams) now emits
the scanner's full fact set with in-tree-identical stable keys, proven on the
shared fixture `testdata/wave1-ec2-parity.json` (25/25 keys, provenance in
`testdata/stable-key-provenance.md`, Q4(a) in `ec2_wave1_conformance_test.go`):

| In-tree file | Live-path coverage |
|---|---|
| `scanner.go` (call order, VPC/subnet/group/rule/ENI/instance/volume reads) | `listEC2` in `internal/live/services_compute.go` reads the same seven passes in the same order |
| `scanner.go` (rule fallback id, direction) | `securityGroupRuleRecord` in `internal/live/ec2_identity.go` (same fallback hash shape, same ingress/egress mapping) |
| `attributes.go` (CIDR/attachment/SG-ref/private-IP maps) | mirrored builders in `internal/live/ec2_vpc.go`, `ec2_subnet.go`, `ec2_network_interface.go` |
| `identity.go` (instance identity + AMI edge) | `instanceRecord` in `internal/live/ec2_instance.go` |
| `ami_identity.go` (scan-scoped AMI dedup) | `seenAMIIDs` in `listEC2` / `appendInstanceRecords` |
| `posture.go` (instance posture) | `instancePostureObservation` in `internal/live/ec2_instance.go`, fanned out via `EC2Posture` → `AppendLiveEC2InstancePostures` |
| `securityGroupRulePostureObservation` (rule posture) | `securityGroupRulePosture` in `internal/live/ec2_identity.go`, fanned out via `SGPosture` → `AppendLiveSecurityGroupRulePostures` |
| `relationships.go` (all nine EC2 edges) | edges on the record builders, including group→VPC and rule→group |
| `volume.go` (volume + KMS edge) | `volumeRecord` in `internal/live/ec2_volume.go` |
