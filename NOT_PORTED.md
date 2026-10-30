# NOT_PORTED.md — root package (`collector`)

The in-tree `awscloud` root files below are class-(c): they build on
core-owned contracts that have no standalone-SDK replacement. Nothing here is
ported; the shim seam for each is named so a future SDK or core surface can
unblock it mechanically.

## Envelopes (facts/cloud + facts, no SDK replacement)

Wave 0 seam (eshu-hq/eshu#9296) is IN PLACE: every specialty envelope below
has a satellite-side `New*Fact` builder emitting through the same factschema
encoders with byte-identical stable keys (proven per kind against the shared
fixtures). What stays core-owned is the `facts.Envelope` host shape and the
134 service scanners that call the in-tree builders — the seam carries no
live reads. Scanner ports land per kind in later waves.

| In-tree file | Blocked on | Seam |
|---|---|---|
| `envelope.go` | `facts.Envelope`, `facts/cloud` builders | `NewResourceFact`, `NewRelationshipFact`, `NewImageReferenceFact`, `NewWarningFact` (ported earlier) |
| `dns_envelope.go` | same | `NewDNSRecordFact` (`dns_envelope.go`, Wave 0) |
| `ec2_posture_envelope.go` | same (+ `catalog`) | `NewEC2InstancePostureFact` (`ec2_posture_envelope.go`, Wave 0) |
| `iam_permission_envelope.go` | same (`factschema/iam/v1` path rewrites cleanly) | `NewIAMPermissionFact` (`iam_permission_envelope.go`, Wave 0) |
| `resource_policy_permission_envelope.go` | same (+ `catalog`) | `NewResourcePolicyPermissionFact` (`resource_policy_permission_envelope.go`, Wave 0) |
| `posture_envelope.go` (RDS) | same | `NewRDSInstancePostureFact` (`rds_posture_envelope.go`, Wave 0) |
| `s3_posture_envelope.go` | same | `NewS3BucketPostureFact` (`s3_posture.go`, ported earlier; Wave 0 parity lock) |
| `s3_external_principal_grant_envelope.go` | same | `NewS3ExternalPrincipalGrantFact` (`s3_grant_envelope.go`, Wave 0) |
| `security_group_rule_envelope.go` | same | `NewSecurityGroupRuleFact` (`security_group_rule_envelope.go`, Wave 0) |

The SDK (`eshu-sdk/collector v0.1.0-rc.4`) ships `Fact`/`Result`, not the
`facts.Envelope` shape (stable ID, confidence, boundary binding) the 134
service scanners emit through these builders. Porting the scanners without
`facts` would invent a new envelope contract; they stay core-owned until the
SDK gains the surface. `aws_tag_observation` has no envelope and no SDK
encoder (schema-less registry-only kind); Wave 2 decides between a seam and
a retirement census for it.

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
`collector.go`), `condition_identity.go`, `scan_status.go` (plus the Wave 0
`WarningNetworkTimeout` taxonomy addition), `apicall.go`,
`extractor.go`, `awscloud_doc.go` (from in-tree `doc.go`), the specialty
envelope seam (`specialty_envelope.go` plus per-kind `New*Fact` builders),
plus the ported in-tree tests and `port_parity_test.go`.
