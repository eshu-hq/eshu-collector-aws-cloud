# AWS Cloud Collector (`eshu-collector-aws-cloud`)

Standalone Eshu collector for AWS Cloud. Module path
`github.com/eshu-hq/eshu-collector-aws-cloud`; component ID
`collector-aws-cloud`; collector kind `aws`; source system `aws`; metrics
prefix `eshu_dp_aws_cloud_collector_`. Scaffolded from the collector
template; the AWS logic port is tracked in [PORT_PLAN.md](PORT_PLAN.md).

This repo pins the published SDK pair for core `>=0.0.5 <0.2.0`:

- `github.com/eshu-hq/eshu-sdk/collector v0.1.0-rc.4`
- `github.com/eshu-hq/eshu-sdk/factschema v0.1.0-rc.7`

Wire protocol: `collector-sdk/v1alpha1`. There are no `replace` directives:
an out-of-tree clone resolves both modules through the Go module proxy.

## Naming

The directory is `collector` and the binary is `cmd/collector` — the
repository name already says which collector this is, so file, package, and
symbol names do not repeat it (`collector/collector-foo` is rejected in
review). Keep internal helpers private.

## Emission contract

`manifest.yaml` `spec.emittedFacts` declares `aws_resource` and
`aws_relationship` alongside three
transitional placeholder kinds (`collector-aws-cloud.snapshot/record/warning`).
The live EC2 reader emits typed resource identity for VPCs, subnets, security
groups and rules, network interfaces, instances, and volumes, plus a
subnet-to-VPC relationship when both IDs are reported. Before any live
service read, it verifies the active credentials account with STS in each
configured region and fails the claim if it differs from the target account.
Typed EC2 names follow legacy scanner identity rules: stable IDs for VPCs,
subnets, instances, and volumes; group names for security groups. Missing
required source IDs fail the EC2 read, while subnet ARN and security-group-rule
content use the legacy deterministic identity fallbacks. The live
path currently re-emits on every read because the old placeholder digest does
not cover typed facts or service failures. The remaining
AWS service readers still produce placeholder records. The full port removes
those placeholders and declares the other core-owned AWS fact kinds at schema
`1.0.0`, all with
`reported` confidence (the in-tree AWS envelopes record facts returned by
the AWS APIs as reported):

`aws_resource`, `aws_relationship`, `aws_tag_observation`, `aws_dns_record`,
`aws_image_reference`, `aws_security_group_rule`, `aws_iam_permission`,
`aws_resource_policy_permission`, `aws_warning`, `ec2_instance_posture`,
`s3_bucket_posture`, `rds_instance_posture`, `s3_external_principal_grant`.

The remaining bare AWS kinds stay out of the manifest until their typed
emitters are ported and the host supplies a trusted grant snapshot to
conformance (#8909).
The pinned standalone SDK accepts those kinds only through its `CoreFacts`
context; a synthetic context in fixture tests proves the portable mechanism,
not production authorization. The host owns grant issuance and rechecks
emission at runtime. See [PORT_PLAN.md](PORT_PLAN.md).

The typed `aws_resource` envelope is connected to claim-bound live EC2 reads.
VPC, subnet, and volume observations carry reported state, tags, and API
attributes, including CIDR associations and volume attachments. Instance
identity observations carry state and launch AMI ID from the same
`DescribeInstances` response. The subnet-to-VPC edge is the only typed
relationship currently emitted; other EC2 resource types still carry identity
and name only. This is staged implementation, not a full parity or live host
admission claim. Instance ARNs use the account and partition verified by STS
before EC2 reads; a partition mismatch fails before a service read.
Sensitive-shaped resource attribute keys fail closed.
See [PORT_PLAN.md](PORT_PLAN.md#resource-envelope-seam-status) for the
remaining redaction and host-grant boundary.

## Build and test from a clean clone

```bash
go mod tidy -diff
go build ./...
go vet ./...
go test ./... -count=1
go run ./cmd/collector --input ./testdata/complete.json
```

`go.sum` lists only the modules the template's own imports reach. Importing
the `factschema` root package (typed payload structs and encoders) pulls in
that module's own dependencies, and `go mod tidy -diff` then fails until you
run `go mod tidy` and commit the added `go.sum` lines. The conformance script
runs `go mod tidy -diff` first so that drift fails before review.

`scripts/run-conformance.sh` runs the same gate CI runs
(`.github/workflows/ci.yml`, discovered by GitHub Actions because this
directory is a repository root).

## Configuration

Copy `config.example.yaml`. The collector reads one source document
(`source.input`), emits against one credential-free `sourceURI`, and tracks
freshness with `freshness.previousDigest`. All payloads pass
`ValidateShareSafeKeys`; anything sensitive must be redacted before emission
(see `collector.go` and the redaction test).

## Least-privilege credentials

The collector receives only a bounded claim plus local config. It never gets
Postgres, graph, queue, lease, reducer, API, or MCP handles. Source
credentials stay in the collector runtime environment and never enter fact
payloads, source URIs, logs, or statuses. URIs embedding
`user:secret@host` or known credential query keys are refused, including
AWS presigned URL keys such as
`X-Amz-Credential` and `X-Amz-Signature` (even when the key is percent-encoded).
Ordinary credential-free HTTPS queries and `aws:` source URIs remain valid.

## Limits

Default bounds live in `health.go` (`DefaultResourceUse`): 5000 records per
claim, 64 KiB per payload, 300 s claim timeout, 8 queued retries. Tune them
per source and record the values in the cutover issue. Past the retry bound
the collector fails terminal instead of queuing forever.

## Upgrades

Pin exact SDK versions. Before bumping either pin, re-run conformance in
the collector's own CI: a payload shape the new schemas reject fails closed
here before it ever reaches a reducer. Keep the compatibility row in step
with `docs/public/extend/sdk-compatibility.md` in the core repo.

## Producer grants, revocation, and rollback

Core-owned fact kinds require a live #6709 producer grant naming this
producer, version, kind, schema, and scope; namespaced kinds need none.
The planned AWS emission requires thirteen grants, one per core kind at
schema `1.0.0`; the current transitional manifest declares none of those
kinds. `TestManifestEmissionsAreAuthorized` fails when a declared kind is
outside the collector's namespace and has no live grant scoped to a
collector kind. This repo cannot see the core registry, so it treats any
kind outside its namespace as potentially core-owned, including dotted
names such as `incident.record`. The host decides ownership: it enforces
core-ownership at install and again at every emission.
`grant.example.json` is the issuance request set: a JSON array with one
request per AWS kind. A grant's scope is the collector kind
(`CollectorKind`, declared in `spec.collectorKinds`), not a scope ID such
as `host.scope.id`: the host matches the grant against the manifest's
collector kinds, and `grant_test.go` fails when an example drifts from
them. `grant_test.go` also locks the fail-closed matrix (wrong
scope/schema/producer refused). Revocation is a core-side grant revoke
followed by replay from the last committed generation: stop new claims,
expire in-flight leases, revoke, restore the last supported producer,
replay, and verify fact/graph/read truth. Two producers never hold one
scope+generation at once.

Live grant issuance and claim admission for the new typed path are not yet
proven here. The grant request set names the required tuples; the host must
issue and verify them before deployment.

## Releases

Every artifact in `manifest.yaml` is digest-pinned (`@sha256:…`, never
`:latest`). `manifest_test.go` enforces pinning plus manifest validity, and
the all-zero placeholder digest is rejected once the component is renamed —
so the scaffold release flow pins the real pushed digest with
`scripts/pin-digest.sh`. Base images in `Dockerfile` are pinned the same
way; re-pin them when bumping either base.

## Remote proof

The collector never submits results to core. Under the `process` adapter the
host starts `./collector --sdk-stdio`, writes one claim on stdin, reads one SDK
result from stdout, and commits the facts itself. The collector holds no
endpoint, queue, or datastore handle, so there is nothing for it to submit to
and no collector-side script can stand in for the host.

To prove a deployment, run the real component lifecycle against a component
home (see
[Community extension authoring](https://github.com/eshu-hq/eshu/blob/main/docs/public/extend/community-extension-authoring.md)
and
[Component producer grants](https://github.com/eshu-hq/eshu/blob/main/docs/public/reference/component-producer-grants.md)):

```bash
eshu component grant collector-aws-cloud --component-home "$HOME_DIR" \
  --version 0.1.0 --kind <kind> --schema-version 1.0.0 \
  --scope aws --expires-in 720h   # one grant per core-owned kind (13 total)
eshu component install manifest.yaml --component-home "$HOME_DIR" \
  --trust-mode allowlist --allow-id collector-aws-cloud --allow-publisher eshu-hq
eshu component enable collector-aws-cloud --component-home "$HOME_DIR" \
  --instance aws-cloud-primary --mode scheduled --claims --config config.example.yaml
```

Then let the coordinator claim a scope and read the committed facts back
through the target core's own API and MCP surfaces, using the paths in that
core's API reference. Record the tested core version, topology, and evidence
location in the cutover issue; credential-free conformance stays in CI.
