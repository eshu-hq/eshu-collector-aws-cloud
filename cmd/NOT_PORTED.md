# NOT_PORTED.md — `cmd` (in-tree `collector-aws-cloud` command)

The scaffold owns `cmd/collector` (the only binary); none of the in-tree
command package is ported. Every file is class-(c) on core-owned runtime
machinery:

| In-tree file | Blocked on |
|---|---|
| `main.go` | `app`, `buildinfo`, `runtime` launcher, `storage/postgres`, `telemetry` bootstrap, fixture/live mode wiring |
| `service.go` | `collector.Service`, `workflow` (durable commit/projector path), `storage/postgres/cloud/aws`, `replay/cassette`, `scope`, `telemetry` |
| `record.go` | `storage/postgres/db` |
| `status_committer.go` | `workflow.ClaimMutation` |
| `config.go` | `redact`, `replay/recordpseudo`, `scope`, `workflow` |
| `fixture_config.go` | `awsruntime.FixtureConfig` (blocked: `collector` + `facts` + `scope`; see `internal/awsruntime/NOT_PORTED.md`) |
| `doc.go` | Deliberately skipped: it documents the in-tree binary's claimed-live / fixture modes, which the scaffold binary does not implement. Porting it verbatim would misdocument `cmd/collector`. |

Seam: none in this repo. Binary wiring against the workflow store, the
credential launcher, and the ingestion store is coordinator-owned; this repo
consumes the SDK `collector`/`factschema` modules plus the AWS SDK once the
runtime shims land.
