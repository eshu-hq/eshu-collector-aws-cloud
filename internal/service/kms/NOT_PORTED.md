# NOT_PORTED.md — `internal/service/kms`

Ported: `doc.go`, `types.go`. The bounded live loader also emits typed
`aws_kms_key` metadata from ListKeys and DescribeKey, binding the reported ARN
to the STS-verified account, partition, region, and listed key ID. It does not
read key material, raw policies, tags, or rotation status.
The full SDK adapter and legacy scanner remain unported.

## Not ported (class-c)

| File | Blocked on |
|---|---|
| `awssdk/` (`client.go`, `doc.go`, `mappers.go`, `resource_policy.go`, `telemetry.go`) | AWS SDK adapter + `telemetry` spans — no SDK OTEL surface; boundary forbids AWS SDK paths until the telemetry shim lands |
| `runtimebind/` (`bind.go`, `doc.go`) | `awsruntime.Register` in blocked `registry.go` (telemetry + redact) — ports with the registry |
| `scanner.go` | `facts.Envelope` — no SDK Envelope surface; `collector.Service` / claim runtime — core-owned |

## Tests not ported (subject absent)

- `resource_policy_scanner_test.go` — exercises an unported subject above.
- `scanner_test.go` — exercises an unported subject above.
- `servicekind_test.go` — exercises an unported subject above.
- `awssdk/client_test.go` — exercises an unported subject above.
- `awssdk/fakes_test.go` — exercises an unported subject above.
- `awssdk/mappers_test.go` — exercises an unported subject above.
- `awssdk/resource_policy_test.go` — exercises an unported subject above.
- `runtimebind/bind_test.go` — exercises an unported subject above.

Seam: SDK `Envelope` + observation-builder + OTEL + scope surfaces, then re-run the port for the files above.

## Wave 1 emission parity (eshu-hq/eshu#9296)

The files above remain literally unported (no SDK `facts.Envelope`
replacement), but the live path (`internal/live/kms_key.go` through the root
`NewResourceFact` / `NewRelationshipFact` seams) now emits the scanner's
key/alias/grant fact set with in-tree-identical stable keys, proven on the
shared fixture `testdata/wave1-kms-parity.json` (18/18 keys, provenance in
`testdata/stable-key-provenance.md`, Q4(a) in `internal/live/kms_wave1_conformance_test.go`
(`TestWave1KMSLiveConformance` over real builder output; root
`kms_wave1_conformance_test.go` is the schema-admission companion)):

| In-tree file | Live-path coverage |
|---|---|
| `scanner.go` (key/alias/grant reads) | `listKMS` in `internal/live/kms_key.go` reads the same passes per key |
| `keyObservation` | `kmsKeyRecord` in `internal/live/kms_key.go` |
| `aliasObservation` + `aliasRelationship` | `kmsAliasRecord` in `internal/live/kms_key.go` |
| `grantObservation` + `grantOnKeyRelationship` + `grantGranteeRelationship` | `kmsGrantRecord` in `internal/live/kms_key.go` |
| `awssdk/client.go` (ListKeys, DescribeKey, ListAliases, ListGrants) | the same SDK calls in `listKMS` (no OTEL spans, no per-call telemetry) |

Deliberate satellite deviations, out of fixture scope: key-policy statements,
tags, rotation status, and policy revision names stay unread where the in-tree
scan emits them (no such read exists in `kmsKeyAPI`); an alias ARN outside the
claimed identity and a grant without an ID fail where the in-tree mapper
trusts the API (locked by the `kmsAliasRecord` / `kmsGrantRecord` identity
guards); and an alias-list or grant-list denial fails the service read where
the satellite degrades other reviewed optional reads to partial (locked by
`TestKMSAliasOrGrantReadFailureFailsService`, matching the in-tree
fail-closed scan).
