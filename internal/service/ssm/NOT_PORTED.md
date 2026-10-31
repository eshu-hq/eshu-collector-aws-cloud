# NOT_PORTED.md — `internal/service/ssm`

Ported: `doc.go`, `helpers.go`, `relationships.go`, `types.go`.

## Not ported (class-c)

| File | Blocked on |
|---|---|
| `awssdk/` (`client.go`, `doc.go`, `mapper.go`) | AWS SDK adapter + `telemetry` spans — no SDK OTEL surface; boundary forbids AWS SDK paths until the telemetry shim lands |
| `runtimebind/` (`bind.go`, `doc.go`) | `awsruntime.Register` in blocked `registry.go` (telemetry + redact) — ports with the registry |
| `scanner.go` | `facts.Envelope` — no SDK Envelope surface; `collector.Service` / claim runtime — core-owned |

## Tests not ported (subject absent)

- `scanner_test.go` — exercises an unported subject above.
- `servicekind_test.go` — exercises an unported subject above.
- `awssdk/client_test.go` — exercises an unported subject above.
- `runtimebind/bind_test.go` — exercises an unported subject above.

Seam: SDK `Envelope` + observation-builder + OTEL + scope surfaces, then re-run the port for the files above.

## Wave 1 emission parity (eshu-hq/eshu#9296)

The files above remain literally unported (no SDK `facts.Envelope`
replacement), but the live path (`internal/live/ssm_parameter.go` through the
root `NewResourceFact` / `NewRelationshipFact` seams) already emits the
scanner's full fact set with in-tree-identical stable keys, proven on the
shared fixture `testdata/wave1-ssm-parity.json` (5/5 keys, provenance in
`testdata/stable-key-provenance.md`, Q4(a) in
`internal/live/ssm_wave1_conformance_test.go`
(`TestWave1SSMLiveConformance` over real builder output; root
`ssm_wave1_conformance_test.go` is the schema-admission companion)):

| In-tree file | Live-path coverage |
|---|---|
| `scanner.go` (parameter/KMS reads) | `listSSM` in `internal/live/services_data.go` reads the same passes per parameter |
| `parameterObservation` + `kmsRelationship` | `ssmParameterRecord` in `internal/live/ssm_parameter.go` |
| `awssdk/client.go` (DescribeParameters, ListTagsForResource) | the same SDK calls in `listSSM` (no OTEL spans) |

Deliberate satellite deviation, out of fixture scope: a row with neither ARN
nor name fails where the in-tree mapper trusts the API (locked by
`TestWave1SSMParameterRecordRejectsEmptyIdentity`). Raw descriptions, allowed
patterns, and policy JSON stay excluded on both sides by construction
(locked by `TestWave1SSMParameterAttributeEquality` and the leak check in
`TestWave1SSMPayloadBranches`).

Runtime IAM need (eshu-hq/eshu#9687): beyond `ssm:DescribeParameters`, every
parameter read also calls `ssm:ListTagsForResource`, and any single tag-list
failure fails the whole SSM service read for the claim (the collector keeps
only a warning). Verified live: the collector role
(`argocd/eshu/base/xirsarole-aws-cloud-collector.yaml` in iac-eks-eshu)
already grants both actions, so the overlay was clear when checked
on 2026-10-31. That clearance is point-in-time: re-check the role file
before acting on this paragraph, since nothing in this repo watches it.
