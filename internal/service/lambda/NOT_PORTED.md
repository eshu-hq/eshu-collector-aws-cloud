# NOT_PORTED.md — `internal/service/lambda`

Ported: `doc.go`, `types.go`.

## Not ported (class-c)

| File | Blocked on |
|---|---|
| `awssdk/` (`client.go`, `doc.go`) | AWS SDK adapter + `telemetry` spans — no SDK OTEL surface; boundary forbids AWS SDK paths until the telemetry shim lands |
| `runtimebind/` (`bind.go`, `doc.go`) | `awsruntime.Register` in blocked `registry.go` (telemetry + redact) — ports with the registry |
| `relationships.go` | transitive: uses `cloneFloatMap`, `containerImageTargetType`, `firstNonEmpty` from `scanner.go` (facts.Envelope) |
| `scanner.go` | `facts.Envelope` — no SDK Envelope surface; `collector.Service` / claim runtime — core-owned; `redact.RuleSet` — SDK has only `IsSensitiveKeyName` |

## Tests not ported (subject absent)

- `scanner_test.go` — exercises an unported subject above.
- `servicekind_test.go` — exercises an unported subject above.
- `awssdk/client_test.go` — exercises an unported subject above.
- `runtimebind/bind_test.go` — exercises an unported subject above.

Seam: SDK `Envelope` + observation-builder + OTEL + scope surfaces, then re-run the port for the files above.

## Wave 1 emission parity (eshu-hq/eshu#9296)

The files above remain literally unported (no SDK `facts.Envelope`
replacement), but the live path (`internal/live/lambda_*.go` through the root
`NewResourceFact` / `NewRelationshipFact` seams) already emits the scanner's
full fact set with in-tree-identical stable keys, proven on the shared
fixture `testdata/wave1-lambda-parity.json` (16/16 keys, provenance in
`testdata/stable-key-provenance.md`, Q4(a) in `internal/live/lambda_wave1_conformance_test.go`
(`TestWave1LambdaLiveConformance` over real builder output; root
`lambda_wave1_conformance_test.go` is the schema-admission companion)):

| In-tree file | Live-path coverage |
|---|---|
| `scanner.go` (function/alias/mapping reads) | `listLambda` in `internal/live/services_compute.go` reads the same passes per function |
| `functionObservation` + `functionRelationships` | `lambdaFunctionRecord` + `lambdaFunctionPlacementRelationships` in `internal/live/lambda_function.go`; the image link stays in `lambdaGetFunctionRecord`, which alone sees the code references |
| `aliasObservation` + `aliasFunctionRelationship` | `lambdaAliasRecord` in `internal/live/lambda_alias.go` |
| `eventSourceMappingObservation` + `eventSourceMappingFunctionRelationship` | `lambdaEventSourceMappingRecord` in `internal/live/lambda_mapping.go` |
| `awssdk/client.go` (List/GetFunctions, aliases, mappings) | the same SDK calls in `listLambda` (no OTEL spans) |

Deliberate satellite deviations, out of fixture scope: environment values,
tags, and alias descriptions stay excluded where the in-tree scan emits them
(locked by `TestLambdaFunctionRecordCarriesListFunctionsMetadata`,
`TestLambdaGetFunctionEnrichesSafeMetadataWithoutSecrets`, and
`TestLambdaAliasRecordPreservesReportedRouting`); GetFunction identity
mismatches and unsafe ECR image or KMS references fail where the in-tree
mapper trusts the API (locked by
`TestLambdaGetFunctionRecordRejectsMismatchedIdentityAndUnsafeReferences`);
and a mapping-list denial degrades to partial plus warning where the in-tree
scan fails (locked by
`TestLambdaMappingDenialKeepsFunctionsAliasesAndOtherMappings`).
