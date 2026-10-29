# PORT_PLAN.md — AWS logic port into this standalone repo

Status: PARTIAL PORT. The resource envelope has a typed `NewResourceFact`
seam with historical fixture/key proof. Claim-bound live EC2 reads now append
typed resource identity to transitional placeholder records; STS verifies the
active credentials account before service reads, and live mode ignores the old
placeholder-only freshness digest. ECR repository reads now emit typed
repository observations with reported tags; image and policy facts and the full
scanner port remain unfinished. This plan maps
the remaining in-tree implementation to standalone locations. No live AWS
core-kind output or host grant has been proved.

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

## Emission contract (planned AWS kinds)

`Contract()` and `manifest.yaml` declare `aws_resource`,
`aws_relationship`, and 3 transitional placeholder kinds
(`collector-aws-cloud.snapshot/record/warning`). The port will declare the
remaining AWS kinds at `1.0.0` `reported` and:

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
- Grants: the two currently declared core kinds need live core-issued grants
  before hosted emission. All 13 need grants when their kinds are declared.
  The grant tests check the example requests and manifest coverage; they do
  not prove host issuance. Issuance is a coordinator step, not a repo step.

## Ordering

1. Helpers (`types`, `partition`, `redaction`, `scan_status`) + boundary green.
2. Grant issuance (grant-first-then-install: core `install`/`verify`
   accept granted core kinds). The current manifest already declares two
   core kinds, so both need grants before hosted installation.
3. Complete trusted `CoreFacts` host integration (#8909), grant the exact
   producer/kind/schema/collector-kind tuples, then declare the remaining
   eleven bare AWS kinds in `Contract()` + `manifest.yaml` as their emitters
   land. The standalone SDK supports this mechanism; its fixture-only
   synthetic context is not a live grant.
4. Complete the typed base envelope (`aws_resource`) in claim-bound collection:
   the first EC2 identity slice is wired with fail-closed missing-ID handling
   and the legacy rule-ID fallback; VPC, subnet, security-group, network
   interface, and volume observations carry state, tags, and their reported
   API attributes. Security groups retain group-ID/name anchors; rules carry
   metadata, tags, and rule/group anchors. Network interfaces retain attachment,
   address, and security-group metadata, plus subnet, VPC, security-group, and
   attached-instance relationships from the same DescribeNetworkInterfaces row.
   Instance identity observations carry
   state, launch AMI ID, and an ARN from the verified STS account and partition.
   Volume ARNs and KMS links use that same identity; subnet-to-VPC relationships
   are also emitted. The instance-to-AMI link uses the DescribeInstances row,
   with one typed AMI identity per distinct ID in each regional EC2 scan.
   AMI targets do not add transitional record facts; typed facts still count
   toward the claim's record limit. Remaining EC2 attributes and relationships,
   other services, real host grant proof, and replacement of placeholder
   conformance fixtures remain. ECR repository observations use the existing
   DescribeRepositories pages plus ListTagsForResource per ARN; ECR images and
   lifecycle policies still need their typed kinds.
5. Remaining envelopes kind by kind; delete transitional kinds last.
6. `awsruntime` + `service/` scanners service by service.
7. `recordpolicy` / `freshness` / `catalog` / `checkpoint` integration.
8. Image push + `pin-digest.sh`, deployment proof per README.

## Resource envelope seam status

`NewResourceFact` encodes the shared `aws_resource` identity with the pinned
`factschema/aws/v1.Resource` type. The committed `8852-parity-awscloud.json`
fixture pins the historical key and payload; separate tests cover whitespace
trimming, anchor deduplication, ARN/resource-ID fallback, and required identity
rejection. The SDK decoder classifies an absent `resource_id` as
`input_invalid`. The constructor carries source scope, generation, URI, record
ID, and observation time in the SDK fact. The SDK fact has no fencing-token
field: the host owns the claim and its token.

This seam rejects a sensitive-shaped JSON key such as
`attributes.DatabasePassword` containing a raw value or a redaction marker,
and refuses a credential-bearing source URI. The legacy CloudFormation scanner
uses a different, accepted shape: each output is an entry with fixed `key` and
`redacted` fields, so the string `DatabasePassword` remains as evidence while
its raw value is replaced by a marker. The SDK rc.4 key walker accepts that
shape. It cannot tell whether a raw secret was placed under a fixed `value`
field; the service scanner must redact it first. The envelope test proves
transport of the redacted shape, not the scanner's redaction policy. Scanner
redaction and the host's core-kind authorization must be proved before live
collection uses this seam.

`NewResourceFact` snapshots `Attributes` through their emitted JSON form before
validating or returning the fact. Nested caller maps, slices, pointer-backed
values, and custom marshalers cannot change it afterward. Numeric values use
`json.Number` in the in-memory payload, retaining exact JSON digits above
float64's integer precision; historical `time.Time` attributes become their
RFC3339 JSON strings. Fields hidden by `json:"-"` remain absent, as they are
on the wire. Values that JSON cannot encode, including exposed cycles, fail
closed with no fact.
