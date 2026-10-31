# NOT_PORTED.md — `internal/service/ecr`

Ported: `doc.go`, `types.go`.

## Not ported (class-c)

| File | Blocked on |
|---|---|
| `awssdk/` (`client.go`, `doc.go`) | AWS SDK adapter + `telemetry` spans — no SDK OTEL surface; boundary forbids AWS SDK paths until the telemetry shim lands |
| `runtimebind/` (`bind.go`, `doc.go`) | `awsruntime.Register` in blocked `registry.go` (telemetry + redact) — ports with the registry |
| `scanner.go` | `facts.Envelope` — no SDK Envelope surface; `collector.Service` / claim runtime — core-owned |

## Tests not ported (subject absent)

- `scanner_test.go` — exercises an unported subject above.
- `servicekind_test.go` — exercises an unported subject above.
- `awssdk/client_test.go` — exercises an unported subject above.
- `awssdk/pagination_checkpoint_test.go` — exercises an unported subject above.
- `runtimebind/bind_test.go` — exercises an unported subject above.

Seam: SDK `Envelope` + observation-builder + OTEL + scope surfaces, then re-run the port for the files above.

## Wave 1 emission parity (eshu-hq/eshu#9296)

The files above remain literally unported (no SDK `facts.Envelope`
replacement), but the live path (`internal/live/ecr_*.go` through the root
`NewResourceFact` / `NewImageReferenceFact` seams) already emits the scanner's
full fact set with in-tree-identical stable keys, proven on the shared
fixture `testdata/wave1-ecr-parity.json` (8/8 keys, provenance in
`testdata/stable-key-provenance.md`, Q4(a) in `internal/live/ecr_wave1_conformance_test.go`
(`TestWave1ECRLiveConformance` over real builder output; root
`ecr_wave1_conformance_test.go` is the schema-admission companion)):

| In-tree file | Live-path coverage |
|---|---|
| `scanner.go` (repository/image/policy reads) | `listECR` in `internal/live/services_compute.go` reads the same passes per repository |
| `repositoryObservation` | `ecrRepositoryRecord` in `internal/live/ecr_repository.go` |
| `imageReferenceEnvelopes` (one reference per tag) | `ecrImageRecords` in `internal/live/ecr_image.go` (untagged digests keep one empty-tag reference) |
| `lifecyclePolicyObservation` | `ecrLifecyclePolicyRecord` in `internal/live/ecr_lifecycle_policy.go` |
| `awssdk/client.go` (Describe/ListTags/DescribeImages/GetLifecyclePolicy) | the same SDK calls in `listECR` (no OTEL spans) |

Deliberate satellite deviation, out of fixture scope: raw lifecycle policy
text stays excluded where the in-tree scan emits it (locked by
`TestECRLifecyclePolicyMetadataOmitsPolicyText`); a missing policy emits
nothing where the in-tree scan also emits nothing, and a denied policy read
fails the ECR service where the in-tree scan fails (locked by
`TestReadECRLifecyclePolicyMissingAndDenied`).
