# NOT_PORTED.md — root package (`collector`)

The in-tree `awscloud` root files below are class-(c): they build on
core-owned contracts that have no standalone-SDK replacement. Nothing here is
ported; the shim seam for each is named so a future SDK or core surface can
unblock it mechanically.

## Envelopes (facts/cloud + facts, no SDK replacement)

| In-tree file | Blocked on | Seam |
|---|---|---|
| `envelope.go` | `facts.Envelope`, `facts/cloud` builders | SDK `collector` Envelope + observation-builder surface |
| `dns_envelope.go` | same | same |
| `ec2_posture_envelope.go` | same (+ `catalog`) | same |
| `iam_permission_envelope.go` | same (`factschema/iam/v1` path rewrites cleanly) | same |
| `resource_policy_permission_envelope.go` | same (+ `catalog`) | same |
| `posture_envelope.go` (RDS) | same | same |
| `s3_posture_envelope.go` | same | same |
| `s3_external_principal_grant_envelope.go` | same | same |
| `security_group_rule_envelope.go` | same | same |

The SDK (`eshu-sdk/collector v0.1.0-rc.4`) ships `Fact`/`Result`, not the
`facts.Envelope` shape (stable ID, confidence, boundary binding) the 134
service scanners emit through these builders. Porting the envelopes without
the scanners would strand the only callers; porting the scanners without
`facts` would invent a new envelope contract. Both stay core-owned until the
SDK gains the surface.

## Redaction (`redact`, partial SDK cover)

| In-tree file | Blocked on | Seam |
|---|---|---|
| `redaction.go` (`RedactString`, `ClassifyStackOutput`) | `go/internal/redact` (`RuleSet`, `Key`) | SDK redaction ruleset; today the SDK exposes only `IsSensitiveKeyName` |

The standalone `collector.go` keeps its own `secret`-field behavior (locked
by the scaffold redaction tests); the shared `redact.RuleSet` machinery stays
core-owned.

## Helpers stranded by the above

| In-tree file | Blocked on | Seam |
|---|---|---|
| `factschema_helpers.go` (`awsPayloadAttributes`) | `cloneAnyMap` in blocked `envelope.go` | ports with the envelopes |
| `servicekind_guard_test.go` | walks `service/*/scanner.go` sources, which are absent here | ports with the scanners |

## What did port

`partition.go`, `types.go` (minus `CollectorKind`, which lives in
`collector.go`), `condition_identity.go`, `scan_status.go`, `apicall.go`,
`extractor.go`, `awscloud_doc.go` (from in-tree `doc.go`), plus the ported
in-tree tests and `port_parity_test.go`.
