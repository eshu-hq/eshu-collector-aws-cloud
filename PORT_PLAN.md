# PORT_PLAN.md — AWS logic port into this standalone repo

Status: SCAFFOLD ONLY. The collection pipeline (`Report`/`Collect`,
`testdata/`, placeholder conformance fixtures) is still the template
placeholder. This plan maps the in-tree implementation to scaffold
locations for the later logic port. Nothing here is ported yet.

Source of truth for paths: `go/internal/collector/awscloud/` in
`eshu-hq/eshu` at the scaffold commit, plus payload schemas in
`eshu-hq/eshu/sdk/go/factschema/schema/` and family declarations in
`go/internal/facts/cloud/`.

## Identity (done in scaffold)

| In-tree | Standalone |
|---|---|
| `contract.Producer{ID: "collector-aws-cloud"}` in `go/internal/facts/cloud/aws.go` (+ posture/grant families) | `ComponentID = "collector-aws-cloud"`, `manifest.yaml` `metadata.id` |
| `awscloud.CollectorKind = "aws"` (`types.go`), `scope.CollectorAWS = "aws"` | `CollectorKind = "aws"`, manifest `spec.collectorKinds: [aws]`, grant `scope: aws` |
| Producer `collector-aws-cloud`, `AuthorityMode: core_issued_grant` | 13 core-issued grants, one per kind × schema `1.0.0` (`grant.example.json`) |
| SDK pair `collector v0.1.0-rc.4 / factschema v0.1.0-rc.7`, protocol `collector-sdk/v1alpha1` | `go.mod` pins, manifest `spec.runtime` |

## Emission contract (declared, not yet emitted)

`Contract()` and `manifest.yaml` declare the 13 AWS kinds at `1.0.0`
`reported` plus 3 transitional placeholder kinds
(`collector-aws-cloud.snapshot/record/warning`). The port:

1. Ports the envelopes below so `Collect` emits the 13 AWS kinds.
2. Deletes the 3 transitional kinds from `Contract()`, `manifest.yaml`,
   `collector.go` constants, and every test that references them.
3. Replaces `testdata/*.json` + `Report`/`LoadReport` with the AWS source
   shape and rewrites the placeholder conformance fixtures to AWS facts.

## Package map

Scaffold layout rule: the repo root is the `collector` package
(`collector.go`, `health.go`, `*_test.go`); `cmd/collector` stays the only
binary; new code goes in matching subdirectories (`internal/...` stays
importable only inside this module, satisfying `boundary_test.go`).

| In-tree (`go/internal/collector/awscloud/…`) | Scaffold target | Notes |
|---|---|---|
| `types.go`, `partition.go`, `condition_identity.go` | `collector.go` (or new `types.go` / `partition.go`) | `CollectorKind`, partition keys stay identical |
| `envelope.go` (+ `envelope_test.go`) | root package | base `aws_resource` envelope + `facts.SourceConfidenceReported` |
| `dns_envelope.go` | root package | `aws_dns_record` |
| `security_group_rule_envelope.go` | root package | `aws_security_group_rule` |
| `iam_permission_envelope.go` | root package | `aws_iam_permission` |
| `resource_policy_permission_envelope.go` | root package | `aws_resource_policy_permission` |
| `ec2_posture_envelope.go` | root package | `ec2_instance_posture` |
| `s3_posture_envelope.go` | root package | `s3_bucket_posture` |
| `posture_envelope.go` (RDS) | root package | `rds_instance_posture` |
| `s3_external_principal_grant_envelope.go` | root package | `s3_external_principal_grant` |
| `extractor.go`, `factschema_helpers.go`, `redaction.go`, `scan_status.go`, `apicall.go` | root package (helpers) + `health.go` for status | redaction must keep the `secret`-field behavior the redaction test locks |
| `recordpolicy/` (`policy.go`) | `recordpolicy/` | per-record bounds |
| `freshness/` (`eventbridge.go`, `types.go`) | `freshness/` | replaces `Digest`/stale logic |
| `catalog/` (service catalog, ~25 files) | `catalog/` | service inventory source |
| `checkpoint/` (`types.go`) | `checkpoint/` | replaces `LastDigest` freshness |
| `awsruntime/` (`credentials.go`, `source.go`, `registry*.go`, `limiter.go`, `freshness.go`, `record_source.go`, `fixture_source.go`, `bindings/`, `internal/guardset/`) | `internal/awsruntime/` (same tree) | AWS SDK + credential handling; **must stay out of payloads/URIs/logs** (boundary + URI-refusal tests) |
| `service/` (133 service scanners: `scanner.go`, `awssdk/client.go`, `runtimebind/bind.go`, `helpers.go`, `relationships.go`, `types.go` per service) | `internal/service/` (same tree) | largest block; port service by service, keep `servicekind` + redaction tests green per service |
| `internal/partitionguard/`, `internal/relguard/` | `internal/...` (same paths) | keep internal-only so `boundary_test.go` still passes |
| Payload schemas `sdk/go/factschema/schema/aws_*.v1.schema.json`, `ec2_instance_posture.v1`, `s3_bucket_posture.v1`, `rds_instance_posture.v1`, `s3_external_principal_grant.v1` | consumed via the pinned `factschema` module (`fixturepack` pattern in `fixturepack_pin_test.go`) | do NOT vendor schemas; bump the `factschema` pin to the version that ships them |
| Family declarations `go/internal/facts/cloud/aws.go`, `ec2_instance_posture.go`, `s3_bucket_posture.go`, `rds_posture.go`, `s3_external_principal_grant.go` | NOT ported | core-owned registry; this repo mirrors kind names + `1.0.0` only |

## Boundary rules for the port (CI-enforced)

- Imports allowed: this module, `github.com/eshu-hq/eshu-sdk/collector`,
  `github.com/eshu-hq/eshu-sdk/factschema`, `gopkg.in/yaml.v3`, stdlib.
  No `go/internal`, no cross-collector imports, no cgo (`boundary_test.go`).
- AWS SDK dependencies enter via `go get` + committed `go.sum`
  (`go mod tidy -diff` is the first conformance gate).
- Every ported envelope keeps: stable keys, scope+generation binding,
  credential-free URIs, secret redaction with recorded reason, terminal
  (not unbounded) budget breaches, idempotent re-emission.
- Grants: 13 live core-issued grants must exist before hosted emission;
  `TestManifestEmissionsAreAuthorized` + `TestGrantExamplesCoverAWSKinds`
  fail closed until they do. Issuance is a coordinator step, not a repo step.

## Ordering

1. Helpers (`types`, `partition`, `redaction`, `scan_status`) + boundary green.
2. Grant issuance (13, grant-first-then-install: core `install`/`verify`
   accept granted core kinds before the manifest declares them).
3. Complete trusted `CoreFacts` host integration (#8909), grant the exact
   producer/kind/schema/collector-kind tuples, then declare the 13 bare AWS
   kinds in `Contract()` + `manifest.yaml`. The standalone SDK supports this
   mechanism; its fixture-only synthetic context is not a live grant.
4. Base envelope (`aws_resource`) + conformance fixture rewrite.
5. Remaining envelopes kind by kind; delete transitional kinds last.
6. `awsruntime` + `service/` scanners service by service.
7. `recordpolicy` / `freshness` / `catalog` / `checkpoint` integration.
8. Image push + `pin-digest.sh`, deployment proof per README.
