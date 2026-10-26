# NOT_PORTED.md — `internal/awsruntime/bindings`

Ported: `doc.go`.

`bindings.go` is class-(c): it blank-imports all 133
`service/*/runtimebind` packages to populate the scanner registry from
`init()`. Every `runtimebind/bind.go` calls `awsruntime.Register`, which
lives in blocked `registry.go` (telemetry + redact + otel; no SDK OTEL
surface). The aggregator ports mechanically once the registry ports; until
then this directory intentionally has no registry to aggregate.

Seam: SDK OTEL surface + redaction ruleset (same as `internal/awsruntime`),
then re-run the port for `bindings.go` + all `runtimebind` packages.
