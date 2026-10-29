# NOT_PORTED.md — `internal/service/s3`

Ported: `doc.go`, `types.go`.

The live reader has bounded `GetBucketEncryption`, `GetBucketVersioning`,
`GetPublicAccessBlock`, `GetBucketWebsite`, and `GetBucketLogging` metadata
reads in `internal/live/s3_bucket.go`, plus `GetBucketPolicyStatus` and
`GetBucketOwnershipControls` in `internal/live/s3_policy_ownership.go`.
The legacy S3 scanner, full SDK adapter, and separate typed
`s3_bucket_posture` fact remain unported.

## Not ported (class-c)

| File | Blocked on |
|---|---|
| `awssdk/` (`arn.go`, `client.go`, `doc.go`, `policy.go`, `posture.go`, `resource_policy.go`) | AWS SDK adapter + `telemetry` spans — no SDK OTEL surface; boundary forbids AWS SDK paths until the telemetry shim lands |
| `runtimebind/` (`bind.go`, `doc.go`) | `awsruntime.Register` in blocked `registry.go` (telemetry + redact) — ports with the registry |
| `scanner.go` | `facts.Envelope` — no SDK Envelope surface; `collector.Service` / claim runtime — core-owned |

## Tests not ported (subject absent)

- `contract_test.go` — exercises an unported subject above.
- `partition_test.go` — exercises an unported subject above.
- `resource_policy_scanner_test.go` — exercises an unported subject above.
- `scanner_test.go` — exercises an unported subject above.
- `servicekind_test.go` — exercises an unported subject above.
- `awssdk/client_test.go` — exercises an unported subject above.
- `awssdk/encryption_test.go` — exercises an unported subject above.
- `awssdk/partition_test.go` — exercises an unported subject above.
- `awssdk/policy_test.go` — exercises an unported subject above.
- `awssdk/posture_test.go` — exercises an unported subject above.
- `awssdk/resource_policy_test.go` — exercises an unported subject above.
- `runtimebind/bind_test.go` — exercises an unported subject above.

Seam: SDK `Envelope` + observation-builder + OTEL + scope surfaces, then re-run the port for the files above.
