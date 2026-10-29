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

`manifest.yaml` `spec.emittedFacts` declares `aws_resource`,
`aws_relationship`, `aws_image_reference`, `aws_warning`, and the typed
`s3_bucket_posture` alongside three
transitional placeholder kinds (`collector-aws-cloud.snapshot/record/warning`).
The live EC2 reader emits typed resource identity for VPCs, subnets, security
groups and rules, network interfaces, instances, AMI identities, and volumes,
plus subnet-to-VPC, volume-to-KMS, instance-to-AMI, and network-interface
relationships when their IDs are reported. Before any live service read, it
verifies the active credentials account with STS in each configured region and fails the claim
if it differs from the target account.
Typed EC2 names follow legacy scanner identity rules: stable IDs for VPCs,
subnets, instances, AMIs, and volumes; group names for security groups. Missing
required source IDs fail the EC2 read, while subnet ARN and security-group-rule
content use the legacy deterministic identity fallbacks. The live
path currently re-emits on every read because the old placeholder digest does
not cover typed facts or service failures. The ECR reader emits typed
repository observations from DescribeRepositories and ListTagsForResource while
retaining its repository placeholder record. Existing DescribeImages pages emit
one `aws_image_reference` per tag, including an empty tag for untagged images;
the image placeholder record remains. Lambda ListFunctions rows are enriched
by one GetFunction read per function. They emit typed `aws_resource` identity,
configuration metadata, VPC and logging configuration, source KMS key ARN,
ECR image URIs, and a function-to-image relationship for a validated image
URI. The relationship carries the resolved digest reference when reported.
The GetFunction ARN and nonempty function name must match the listed identity.
Only validated ECR image URIs enter attributes and correlation anchors;
unsafe URIs fail the Lambda read without logging the value.
Presigned package download URLs never enter records. Function environment
values and tags remain deferred until this collector has the legacy keyed
redaction path. GetFunction requires `lambda:GetFunction`; AWS may also require
`lambda:ListTags` to populate tags, though this port does not emit them.
ListAliases pages emit typed `aws_lambda_alias` resources and
`lambda_alias_targets_function` relationships with reported version and
additional routing weights. User-authored alias descriptions are omitted.
An alias ARN must match the known parent function ARN and qualifier; without
that parent ARN, the alias read fails rather than attributing a foreign ARN.
A missing alias ARN can still use the known parent ARN and alias name for its
resource ID. The reviewed mapping-denial path retains successful aliases.
The S3 reader emits typed bucket identity, region, and creation time from
regional ListBuckets. It verifies the expected owner with HeadBucket and
reads tags through GetBucketTagging. Only NoSuchTagSet means an empty tag set.
GetBucketEncryption adds reported algorithms, KMS key IDs, and bucket-key state.
GetBucketVersioning and GetPublicAccessBlock add the reported bucket-level
versioning and public-access settings. An absent public-access-block
configuration leaves its four flags unknown. GetBucketPolicyStatus adds the
reported public-policy boolean; a missing policy leaves that boolean unknown.
A separate required GetBucketPolicy read derives policy presence, public
AWS-principal grants, and cross-account AWS-principal grants into the typed
`s3_bucket_posture` fact. The raw document is discarded; malformed or ambiguous
Allow principals fail the S3 read with a sanitized error. No policy is reported
as known absent with unknown grant flags, while an empty successful response
leaves all three flags unknown. This adds one read per bucket and requires
`s3:GetBucketPolicy`; live IAM access, cost, and reducer graph integration
remain unverified. BPA fields are not emitted into the typed posture fact.
GetBucketOwnershipControls adds
reported ownership enum values; missing or empty controls yield null. Both
reads bind the verified bucket owner. Their denials fail the S3 read; live
access and cost remain unverified. GetBucketWebsite records whether hosting is
configured, index/error document presence, redirect host, and routing-rule
count; it excludes document object keys. GetBucketLogging records whether
access logging is configured and its target bucket and prefix; it excludes
target grants and object-key formats. Both reads pass ExpectedBucketOwner,
require `s3:GetBucketWebsite` and `s3:GetBucketLogging`, and add two API calls
per listed bucket. Live IAM access and request cost remain unverified. A
missing website configuration and empty logging response mean disabled;
other errors, including denials, fail the S3 read.
GetBucketReplication adds one `s3:GetReplicationConfiguration` read per listed
bucket with ExpectedBucketOwner. Its replication posture field is
`replication_enabled`: a configuration with any rule reports true even when
the rule status is disabled, the explicit missing-configuration error or an
empty rule list reports false, and a nil successful response leaves it unknown.
The fact has the legacy bucket identity, anchors, and `#posture` source record;
replication rules, destinations, and role never enter facts. A denied read
fails the S3 service read. Live IAM access and request cost remain unverified.
The same typed posture fact now includes reported logging enabled/target,
versioning and MFA-delete state, object ownership and ACL-disabled state, and
default encryption summary from the existing bucket reads. Missing or empty
versioning and ownership responses leave their derived fields unknown.
Encryption fields are populated only after a confirmed response or S3's
explicit missing-configuration error; a denied or nil successful response
leaves them unknown. Public-access and policy-derived posture remain unset
until bucket policy presence and grant derivation are ported. No logging edge
is synthesized by this collector.
For encryption, the explicit missing-configuration response means a known
empty configuration. Encryption AccessDenied leaves those attributes absent,
retains the bucket, emits a typed warning, and makes the SDK result partial.
Versioning and public-access-block denials fail the S3 read; the overall claim
can still be partial when another service returns evidence. ECS
DescribeClusters emits cluster identity, tags, status, and
reported counts. DescribeServices emits service identity, tags, status, counts,
task-definition binding, and load-balancer metadata. DescribeTasks emits
task identity, status, containers, network-interface attachments, and reported
runtime metadata. DescribeTaskDefinition emits task-definition identity,
tags, roles, resource sizing, network mode, compatibilities, revision, and
registration time. Services link to reported task definitions and tasks
link to reported ENIs. Container definitions, environment values, and secret
references remain excluded until keyed redaction and reference handling land.
The live read requires `ecs:DescribeTaskDefinition` and makes one describe
call per distinct listed or service-referenced task definition, including
inactive revisions referenced by services. This increases ECS API request
volume and claim latency.
EKS DescribeCluster emits typed cluster identity, status, tags, version, and
reported control-plane metadata, including
the OIDC issuer URL. DescribeNodegroup emits managed nodegroup identity,
status, tags, version, AMI and capacity type, node role, network placement,
and scaling counts. EKS DescribeAddon emits add-on identity, status, tags,
version, timestamps, and service-account role ARN; its configuration values
are excluded because they may contain secrets. DescribeCluster also emits
reported service-role, subnet, and security-group relationships. Reported
nodegroup and add-on role edges, nodegroup subnet edges, and cluster membership
edges are also typed. Membership uses the observed parent list request and
rejects a nonblank conflicting child cluster name. EKS IAM OIDC provider
enrichment reads the account provider list once per service-region read and
fetches provider metadata, matching only the EKS-reported issuer. It emits a
provider resource and cluster relationship for a match, or an issuer-only
resource and relationship when IAM has no match. An explicit
ListOpenIDConnectProviders permission denial retains the cluster, nodegroup,
add-on, and issuer-only provider observations with a scoped warning and
partial SDK result; other list failures and every
GetOpenIDConnectProvider failure fail the EKS read. This requires iam:ListOpenIDConnectProviders and
iam:GetOpenIDConnectProvider for complete enrichment; live IAM permission and
request cost have not been verified.
ECR GetLifecyclePolicy now emits typed policy metadata after each repository
image read. A missing policy emits nothing; a denied read fails the ECR
service. The policy JSON body is omitted because it can contain user-supplied
values. This adds one API call per repository and requires
`ecr:GetLifecyclePolicy`; the live IAM grant and call cost remain unverified.
The KMS reader emits typed `aws_kms_key` resources from paginated ListKeys and
one DescribeKey per nonblank listed key ID. A blank ListKeys ID is skipped,
matching the legacy scanner. For described keys it verifies the reported ARN
against the listed key ID and the STS-verified account, partition, and region;
missing or conflicting DescribeKey identity fails the service read. The resource
includes only DescribeKey metadata such as manager, state, usage, origin, algorithms,
creation/deletion dates, and multi-Region configuration. It does not read
key material, raw policies, aliases, grants, tags, or rotation status;
legacy `alias_count`, `grant_count`, `policy_revision_names`, and
`rotation_status_known` are therefore absent rather than guessed. The new
read requires `kms:ListKeys` and `kms:DescribeKey`, with one DescribeKey
call per nonblank listed key ID; live IAM access and call cost remain unverified.
The IAM reader emits typed `aws_iam_role` resources from ListRoles, GetRole,
ListAttachedRolePolicies, and ListRolePolicies. It binds each regionless
role ARN to the STS-verified account and partition, and its suffix to the
reported role name. The typed role fact uses the legacy `aws-global` boundary
while the configured region still selects the AWS endpoint and STS verification.
It retains role path, policy references, permissions boundary, and trust-policy
presence. Raw trust documents and normalized permission statements are excluded.
A missing GetRole detail uses
the listed role; read errors fail the IAM service. Enrichment adds at least
three reads per listed role, with pagination possibly adding more. Live IAM
access and request cost remain unverified. The IAM user reader emits typed
`aws_iam_user` resources from ListUsers, ListAttachedUserPolicies,
ListUserPolicies, and GetUser. It binds regionless user ARNs to the verified
account and partition, checks the reported user name, and emits at the
`aws-global` boundary. It retains the legacy path, attached-policy ARN and
inline-policy name lists (including null for empty lists), and permissions
boundary metadata. It excludes policy documents, normalized permission
statements, and credential material. A missing GetUser detail uses the listed
user; any read error fails the IAM service. Each listed user adds at least
three IAM requests, with additional pages increasing the count. The required
IAM actions are `iam:ListUsers`, `iam:ListAttachedUserPolicies`,
`iam:ListUserPolicies`, and `iam:GetUser`; live grants and request cost remain
unverified. Other service readers remain partial ports.
The full port removes those placeholders and declares the other core-owned AWS
fact kinds at schema `1.0.0`, all with
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
attributes, including CIDR associations and volume attachments. Security-group
observations carry the reported group name, tags, description, owner, VPC ID,
and legacy group-ID/name correlation anchors. Security group rule observations
carry rule metadata, tags, and rule/group correlation anchors. Network
interface observations carry status, tags, attachment, address, and security
group metadata. Network interface edges link reported subnets, VPCs, security
groups, and attached instances; attachment targets use the reported owner and
verified partition. Instance identity observations carry state and launch AMI
ID from the same `DescribeInstances` response. These edges, subnet-to-VPC,
volume-to-KMS, and instance-to-AMI are the typed EC2 relationships currently
emitted. AMI identities are deduplicated by ID within each regional EC2 scan.
AMI targets add typed facts without adding transitional record facts; all
emitted facts count toward the claim's record limit.

This is staged implementation, not a full parity or live host admission claim.
Instance and volume ARNs use the account and partition verified by STS before
EC2 reads; a partition mismatch fails before a service read.
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

## EC2 rule-read denial

A permission denial from EC2 `DescribeSecurityGroupRules` makes the live claim
partial. The collector retains VPC, subnet, security-group, network-interface,
instance, and volume observations from successful reads. It omits rule records
if any rule page is denied, emits a typed `aws_warning` naming the operation,
regional resource, and missing-rule effect, and returns SDK `ResultPartial` with
a warning status. Other EC2 API errors keep their existing failure behavior.
The warning does not prove that a security group has no rules.

## Lambda mapping-read denial

An `AccessDenied`, `AccessDeniedException`, or `UnauthorizedOperation` from
Lambda `ListEventSourceMappings` leaves that function's mappings unknown. The
collector discards every mapping page already read for that function, retains
its function and alias facts and facts from other functions, and emits a typed
`aws_warning` naming the operation, function ARN, and missing-mappings effect.
The SDK result is `ResultPartial` with a warning status. Other mapping errors,
and errors from `ListFunctions` or `ListAliases`, fail the Lambda read.

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
The AWS issuance request set contains thirteen grants, one per core kind at
schema `1.0.0`. The current manifest declares `aws_resource`,
`aws_relationship`, `aws_image_reference`, and `aws_warning` alongside three transitional
namespaced kinds.
`TestManifestEmissionsAreAuthorized` fails when a declared kind is
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
