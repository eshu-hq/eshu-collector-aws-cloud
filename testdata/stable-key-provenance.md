# Stable-key parity provenance (Wave 0 specialty seam)

Each frozen stable key in the per-kind `*_test.go` files is re-derivable
without network access: check out the pinned in-tree commit below and run the
listed oracle command over the listed fixture bytes. All eight keys were
re-executed against these exact inputs on 2026-10-30 and match byte for byte,
so no frozen key changes in this fixup.

Oracle repo: `eshu-hq/eshu` at commit `b0371c05d5`
(Merge pull request #9580; oracle re-execution ran on a clean tree at this
commit).

## Shared-fixture keys (8852 parity pack)

Input fixture: `testdata/8852-parity-awscloud.json`
(`sha256:fe77f10c35f00fbcd58618d5fbbcbe7d41bde9335d3afa4b24405bca8a3e1cef`),
byte-identical to the in-tree
`go/internal/collector/awscloud/testdata/8852-parity-awscloud.json`
(verified with `cmp`).

Oracle command (run from the `go/` directory of the pinned commit):

```sh
go test ./internal/collector/awscloud/ \
  -run 'TestParity8852(DNSRecordContract|S3PostureContract|IAMPermissionContract)' \
  -count=1 -v
```

| Satellite frozen const | In-tree oracle const (`source_parity_8852_test.go`) | Frozen key |
|---|---|---|
| `frozenDNSRecordKey` (`dns_envelope_test.go`) | `parity8852DNSRecordKey`, asserted by `TestParity8852DNSRecordContract` | `5bd39ab9…09983e6` |
| `frozenS3BucketPostureKey` (`s3_posture_parity_test.go`) | `parity8852S3PostureKey`, asserted by `TestParity8852S3PostureContract` | `97ae4a36…6f8815` |
| `frozenIAMPermissionKey` (`iam_permission_envelope_test.go`) | `parity8852IAMPermissionKey`, asserted by `TestParity8852IAMPermissionContract` | `147e19d0…c291ab` |

(Full keys are frozen in the per-kind tests; prefixes above are abbreviated.)

## Wave 0 keys (specialty parity pack)

Input fixture: `testdata/wave0-specialty-parity.json`
(`sha256:45a8aaf3efcbc0b09282f5debac1474f30c2f7d12769a399e85ae809f80ebe76`).

Oracle: execute the in-tree builder over the observation the satellite
constructor names, with boundary account `123456789012`, region `us-east-1`,
the fixture scope/generation/instance triple, fencing token `7`, and
observed-at `2026-10-30T12:00:00Z` (the satellite `wave0Boundary` recipe; the
identity maps take only account/region plus kind fields, so scope, generation,
instance, fencing, and observed-at do not enter the key). Source URIs and
source record ids match the satellite constructors and do not enter the key.

| Satellite frozen const | Fixture section | Satellite observation constructor | In-tree oracle builder |
|---|---|---|---|
| `frozenSecurityGroupRuleKey` (`security_group_rule_envelope_test.go`) | `sg_rule` | `sgRuleParityObservation` (service `ec2`) | `NewSecurityGroupRuleEnvelope` |
| `frozenResourcePolicyPermissionKey` (`resource_policy_permission_envelope_test.go`) | `resource_policy` | `resourcePolicyParityObservation` (service `s3`) | `NewResourcePolicyPermissionEnvelope` |
| `frozenEC2InstancePostureKey` (`ec2_posture_envelope_test.go`) | `ec2_posture` | `ec2PostureParityObservation` (service `ec2`) | `NewEC2InstancePostureEnvelope` |
| `frozenRDSInstancePostureKey` (`rds_posture_envelope_test.go`) | `rds_posture` | `rdsPostureParityObservation` (service `rds`) | `NewRDSInstancePostureEnvelope` |
| `frozenS3ExternalPrincipalGrantKey` (`s3_grant_envelope_test.go`) | `s3_grant` | `s3GrantParityObservation` (service `s3`) | `NewS3ExternalPrincipalGrantEnvelope` |

Re-execution on 2026-10-30 returned, in order above:

- `c4c4e019…3d80626`
- `6c5e4d839…ba820c`
- `1d55bc57…a86786`
- `99c0f021…537d6d`
- `57587047…fc3eb`

each equal to the frozen satellite constant. (Prefixes abbreviated; full keys
in the per-kind tests.)

## Wave 1 EKS keys (in-tree scan parity pack)

Input fixture: `testdata/wave1-eks-parity.json`
(`sha256:e7755c553bb27e41d8f435129e127fc586cdb4cd259c9003bca95e3678e60efd`).

Oracle: check out eshu-hq/eshu at commit `6ca3ad9294e2b001583da6f3b50b8161e0a80006`
(Merge pull request #9613), add a throwaway test in
`go/internal/collector/awscloud/service/eks/` that unmarshals the fixture
directly into the scanner-owned types (the rows mirror those structs field for
field), serves them from a fake `Client` (nodegroups/addons filtered by the
requested cluster name), and prints `FactKind` + `StableFactKey` per envelope
from `Scanner.Scan` over boundary account `123456789012`, region `us-east-1`,
service `eks`, scope `aws:123456789012:us-east-1`, generation
`aws:123456789012:us-east-1:wave1:1`, instance `aws-parity-wave1`, fencing
token `7`, observed-at `2026-10-30T12:00:00Z`. Command, from the `go/`
directory of the pinned commit:

```sh
go test ./internal/collector/awscloud/service/eks/ \
  -run 'TestZZWave1EKSOracle' -count=1 -v
```

The scan emits 24 envelopes: cluster A with matched OIDC provider (resource,
edge, role, 2 subnet, 2 security-group edges), nodegroup A (resource,
membership, role, 2 subnet edges), addon A (resource, membership, role edge),
then cluster B with issuer-only OIDC provider (resource, edge, 1 subnet edge;
no role), nodegroup B (resource, membership; no role, no subnets), addon B
(resource, membership; no role). The satellite proves the same 24 keys through
the full production `listEKS` path over stubbed EKS/IAM APIs
(`internal/live/eks_wave1_parity_test.go`), so OIDC matching, membership
guards, and the issuer-only fallback are covered end to end, not just the
builders:

| # | Kind | Frozen key |
|---|---|---|
| 00 | aws_resource (cluster A) | `d93c4756…e2dd2f2` |
| 01 | aws_resource (OIDC provider, matched) | `a7fdc7bc…6649d6a` |
| 02 | aws_relationship (cluster->provider) | `505f4fa7…fd235` |
| 03 | aws_relationship (cluster->role) | `100f93c3…fffe6` |
| 04 | aws_relationship (cluster->subnet a) | `1015e821…137d` |
| 05 | aws_relationship (cluster->subnet b) | `f427e368…96973` |
| 06 | aws_relationship (cluster->security group) | `059886c7…fb47d` |
| 07 | aws_relationship (cluster->cluster security group) | `dd88a0b2…bc561` |
| 08 | aws_resource (nodegroup A) | `dd61effe…97ef46` |
| 09 | aws_relationship (cluster->nodegroup) | `b1855320…d709` |
| 10 | aws_relationship (nodegroup->role) | `c6c2d00c…9191` |
| 11 | aws_relationship (nodegroup->subnet a) | `0398d175…954a` |
| 12 | aws_relationship (nodegroup->subnet b) | `265d7ecd…d60fa` |
| 13 | aws_resource (addon A) | `0aea8263…e2896` |
| 14 | aws_relationship (cluster->addon) | `83d10cb7…f47f1` |
| 15 | aws_relationship (addon->role) | `d73addbe…b2a64` |
| 16 | aws_resource (cluster B) | `25332298…4626f1` |
| 17 | aws_resource (OIDC provider, issuer-only) | `2f9c6c1f…83cd0` |
| 18 | aws_relationship (cluster->provider) | `b9dcddd3…012ca` |
| 19 | aws_relationship (cluster->subnet) | `03ef69c9…fabc` |
| 20 | aws_resource (nodegroup B) | `cef21af4…760e34` |
| 21 | aws_relationship (cluster->nodegroup) | `0e2d87b5…fa04d` |
| 22 | aws_resource (addon B) | `d2fe2944…17e98a` |
| 23 | aws_relationship (cluster->addon) | `c5dfc765…1db28` |

(Full keys are frozen in the test; prefixes above are abbreviated.)
Re-execution on 2026-10-30 returned all 24 keys byte-identical to the frozen
satellite constants. No production change was needed: the EKS live path
already emitted the full in-tree fact set, and this pack locks it. Two
deliberate satellite deviations are out of fixture scope (both documented in
`internal/service/eks/NOT_PORTED.md`): an IAM list denial degrades to an
issuer-only provider plus warning where the in-tree scan fails, and
same-account ARN scoping rejects cross-account provider ARNs the in-tree
matcher would consider.

## Wave 1 EC2 keys (in-tree scan parity pack)

Input fixture: `testdata/wave1-ec2-parity.json`
(`sha256:b996ce9ba05937e784ce66e5865ba3dec3327d1d5fd6090d5940e556eab2ed0b`).

Oracle: check out eshu-hq/eshu at commit `6ca3ad9294e2b001583da6f3b50b8161e0a80006`
(Merge pull request #9613), add a throwaway test in
`go/internal/collector/awscloud/service/ec2/` that unmarshals the fixture
directly into the scanner-owned types (the rows mirror those structs field for
field), serves them from a fake `Client`, and prints `FactKind` +
`StableFactKey` per envelope from `Scanner.Scan` over boundary account
`123456789012`, region `us-east-1`, service `ec2`, scope
`aws:123456789012:us-east-1`, generation
`aws:123456789012:us-east-1:wave1:1`, instance `aws-parity-wave1`, fencing
token `7`, observed-at `2026-10-30T12:00:00Z`. Command, from the `go/`
directory of the pinned commit:

```sh
go test ./internal/collector/awscloud/service/ec2/ \
  -run 'TestZZWave1Oracle' -count=1 -v
```

The scan emits 25 envelopes in call order (VPC; subnet + edge; group + edge;
3 x (rule + edge + posture); interface + 4 edges; instance posture, identity,
AMI edge, AMI; volume + KMS edge). The satellite freezes the same 25 keys
across `internal/live/ec2_wave1_parity_test.go` (21 resource/relationship
keys) and `internal/live/ec2_wave1_gap_test.go` (4 posture keys):

| # | Kind | Satellite frozen test | Frozen key |
|---|---|---|---|
| 00 | aws_resource (vpc) | parity | `17f47113…65a2f8` |
| 01 | aws_resource (subnet) | parity | `adaa5ade…e768de` |
| 02 | aws_relationship (subnet->vpc) | parity | `c4fed8da…6c4b03e` |
| 03 | aws_resource (security group) | parity | `28c16004…61cbc9` |
| 04 | aws_relationship (group->vpc) | parity | `6f8ff0f2…dc400` |
| 05 | aws_resource (rule, with id) | parity | `b621175c…45945` |
| 06 | aws_relationship (rule->group) | parity | `9fc14398…703fd` |
| 07 | aws_security_group_rule (rule 1) | gap | `d4373b5d…88c8b` |
| 08 | aws_resource (rule, legacy fallback id) | parity | `a99604f4…3bc6a480` |
| 09 | aws_relationship (rule->group) | parity | `6e8c480b…5a9b6979` |
| 10 | aws_security_group_rule (rule 2, no id) | gap | `828bdb8d…5e2e3dd` |
| 11 | aws_resource (rule, referenced group) | parity | `5b84b35d…84f3bb5` |
| 12 | aws_relationship (rule->group) | parity | `f4b077ab…959e9779f` |
| 13 | aws_security_group_rule (rule 3) | gap | `31dc36fc…7e126` |
| 14 | aws_resource (network interface) | parity | `3e70715b…49a0c` |
| 15 | aws_relationship (interface->subnet) | parity | `f4e7f902…dc695678` |
| 16 | aws_relationship (interface->vpc) | parity | `68e87405…36b080` |
| 17 | aws_relationship (interface->group) | parity | `5e4b5ae7…3129800` |
| 18 | aws_relationship (interface->instance) | parity | `22614ae8…9168` |
| 19 | ec2_instance_posture | gap | `bccfe99d…72e81b04` |
| 20 | aws_resource (instance identity) | parity | `b3467e6d…2fec5ad` |
| 21 | aws_relationship (instance->AMI) | parity | `32b57dbc…a3531e5f` |
| 22 | aws_resource (AMI) | parity | `83cdc1f7…ffbdb52` |
| 23 | aws_resource (volume) | parity | `347ea629…dfd905` |
| 24 | aws_relationship (volume->KMS key) | parity | `36648f19…2abf20` |

(Full keys are frozen in the two tests; prefixes above are abbreviated.)
Re-execution on 2026-10-30 returned all 25 keys byte-identical to the frozen
satellite constants, including the legacy no-id rule fallback (proving the
satellite's un-normalized fallback hash equals `facts.StableID` for this
identity shape) and the synthesized attachment ARN (proving the satellite's
caller-identity ARN synthesis equals the in-tree mapper's). The full output is
vendored at `testdata/wave1-ec2-oracle.txt` so the claim stays checkable
without eshu-repo access; `TestWave1EC2OracleOutputMatchesFrozenKeys` fails on
any drift between the vendored output and the frozen constants.

## Wave 1 Lambda keys (in-tree scan parity pack)

Input fixture: `testdata/wave1-lambda-parity.json`
(`sha256:cb5ffa829a19ff4aec80e58f3d2f69178bdc24cf6646e4f51afbd31fb2640d29`).

Oracle: check out eshu-hq/eshu at commit `b0371c05d5`
(Merge pull request #9580), add a throwaway test in
`go/internal/collector/awscloud/service/lambda/` that unmarshals the fixture
directly into the scanner-owned types (the rows mirror those structs field for
field, with `FunctionName` grouping aliases and mappings under their parent),
serves them from a fake `Client` (aliases/mappings filtered by the requested
function ARN), and prints `FactKind` + `StableFactKey` per envelope from
`Scanner.Scan` over boundary account `123456789012`, region `us-east-1`,
service `lambda`, scope `aws:123456789012:us-east-1`, generation
`aws:123456789012:us-east-1:wave1:1`, instance `aws-parity-wave1`, fencing
token `7`, observed-at `2026-10-30T12:00:00Z`. Command, from the `go/`
directory of the pinned commit:

```sh
go test ./internal/collector/awscloud/service/lambda/ \
  -run 'TestZZWave1LambdaOracle' -count=1 -v
```

The scan emits 16 envelopes in call order: function A (resource, role edge,
2 subnet edges, security-group edge), alias live A (resource, edge),
ARN-less alias staging A (resource only; the edge needs a source ARN on both
sides), mapping A (resource, edge), function B (resource, image edge; no
role, no VPC), alias live B (resource, edge), UUID-only mapping B (resource,
edge with the parent-derived function link). The satellite proves the same
16 keys through the full production `listLambda` path over the stubbed
Lambda API (`internal/live/lambda_wave1_parity_test.go`), so GetFunction
enrichment, the ARN-less alias fallback, and the UUID-only mapping fallback
are covered end to end, not just the builders:

| # | Kind | Frozen key |
|---|---|---|
| 00 | aws_resource (function A) | `fa37b448…28c09d` |
| 01 | aws_relationship (function->role) | `efae44c5…bb69ca` |
| 02 | aws_relationship (function->subnet a) | `bcc50526…cdc7b3` |
| 03 | aws_relationship (function->subnet b) | `d1edae98…91cdc` |
| 04 | aws_relationship (function->security group) | `e9fb98e7…087cb1` |
| 05 | aws_resource (alias live A) | `0a18e0f2…66df196` |
| 06 | aws_relationship (alias->function) | `6597492b…6e7e2cb` |
| 07 | aws_resource (alias staging A, ARN-less) | `8f1d9720…6d376715` |
| 08 | aws_resource (mapping A) | `0272b442…c1218f59` |
| 09 | aws_relationship (mapping->function) | `798b427f…6624b` |
| 10 | aws_resource (function B) | `4d58f839…a667bc62` |
| 11 | aws_relationship (function->image) | `8a42c89b…fc3b83` |
| 12 | aws_resource (alias live B) | `28b276d0…ad914e` |
| 13 | aws_relationship (alias->function) | `2b5f15a4…1384d1b` |
| 14 | aws_resource (mapping B, UUID-only) | `685dd254…60ec015` |
| 15 | aws_relationship (mapping->function) | `bb934c2e…6972f221` |

(Full keys are frozen in the test; prefixes above are abbreviated.)
Re-execution on 2026-10-30 returned all 16 keys byte-identical to the frozen
satellite constants. Deliberate satellite deviations are out of fixture scope
(both documented in `internal/service/lambda/NOT_PORTED.md`): environment
values, tags, and alias descriptions stay excluded where the in-tree scan
emits them; GetFunction identity mismatches and unsafe image/KMS references
fail where the in-tree mapper trusts the API; and a mapping-list denial
degrades to partial plus warning where the in-tree scan fails.

## Wave 1 ECR keys (in-tree scan parity pack)

Input fixture: `testdata/wave1-ecr-parity.json`
(`sha256:b18a7ff3cb29539870afdab58065c364caee7e979805043b7658c9c83b561340`).

Oracle: check out eshu-hq/eshu at commit `b0371c05d5`
(Merge pull request #9580), add a throwaway test in
`go/internal/collector/awscloud/service/ecr/` that unmarshals the fixture
directly into the scanner-owned types (the rows mirror those structs field for
field, with `ManifestDigest` equal to the image digest exactly as the in-tree
adapter maps DescribeImages rows, which carry no separate manifest digest),
serves them from a fake `Client` (images and policies filtered by the
requested repository ARN), and prints `FactKind` + `StableFactKey` per
envelope from `Scanner.Scan` over boundary account `123456789012`, region
`us-east-1`, service `ecr`, scope `aws:123456789012:us-east-1`, generation
`aws:123456789012:us-east-1:wave1:1`, instance `aws-parity-wave1`, fencing
token `7`, observed-at `2026-10-30T12:00:00Z`. Command, from the `go/`
directory of the pinned commit:

```sh
go test ./internal/collector/awscloud/service/ecr/ \
  -run 'TestZZWave1ECROracle' -count=1 -v
```

The scan emits 8 envelopes in call order: repository A (resource), its
two-tag image (one reference per tag), its untagged image (one empty-tag
reference), policy A (resource), repository B (resource), its image (one
reference), policy B (resource). The satellite proves the same 8 keys through
the full production `listECR` path over the stubbed ECR API
(`internal/live/ecr_wave1_parity_test.go`), so tag fan-out, the untagged
fallback, the absent-timestamp mapping, and the policy-text omission are
covered end to end, not just the builders:

| # | Kind | Frozen key |
|---|---|---|
| 00 | aws_resource (repository A) | `68c5e903…e17cf6` |
| 01 | aws_image_reference (image, tag latest) | `2d65f7ac…26d873` |
| 02 | aws_image_reference (image, tag v1) | `6928e0da…fff215` |
| 03 | aws_image_reference (untagged image) | `235fb188…c9938d` |
| 04 | aws_resource (policy A) | `51e9ec10…103cd5` |
| 05 | aws_resource (repository B) | `a47eb392…f5369a` |
| 06 | aws_image_reference (image, tag prod) | `cf4129ff…7f3a71` |
| 07 | aws_resource (policy B) | `36caf41f…3f50dc` |

(Full keys are frozen in the test; prefixes above are abbreviated.)
Re-execution on 2026-10-30 returned all 8 keys byte-identical to the frozen
satellite constants, including the four image-reference keys (proving the
satellite's image identity hash equals `facts.StableID` for this identity
shape) and the untagged empty-tag fallback on both sides. One deliberate
satellite deviation is out of fixture scope (documented in
`internal/service/ecr/NOT_PORTED.md`): raw lifecycle policy text stays
excluded where the in-tree scan emits it (locked by
`TestECRLifecyclePolicyMetadataOmitsPolicyText`); stable keys hash identity
only, so the omission cannot move a key, and
`TestWave1ECRAttributeEquality` pins the emitted maps plus RED on a
value-swap mutant.

## Wave 1 SSM keys (in-tree scan parity pack)

Input fixture: `testdata/wave1-ssm-parity.json`
(`sha256:b38444ecffcd1e0442d402434cd9963ab7c98f29477d0a471010a72bcd765914`).

Oracle: check out eshu-hq/eshu at commit `b0371c05d5`
(Merge pull request #9580), add a throwaway test in
`go/internal/collector/awscloud/service/ssm/` that unmarshals the fixture
directly into the scanner-owned types (the rows mirror those structs field for
field), serves them from a fake `Client`, and prints `FactKind` +
`StableFactKey` per envelope from `Scanner.Scan` over boundary account
`123456789012`, region `us-east-1`, service `ssm`, scope
`aws:123456789012:us-east-1`, generation
`aws:123456789012:us-east-1:wave1:1`, instance `aws-parity-wave1`, fencing
token `7`, observed-at `2026-10-30T12:00:00Z`. Command, from the `go/`
directory of the pinned commit:

```sh
go test ./internal/collector/awscloud/service/ssm/ \
  -run 'TestZZWave1SSMOracle' -count=1 -v
```

The scan emits 5 envelopes in call order: parameter A (resource, KMS edge),
parameter B (resource, alias-key edge with an empty target ARN), parameter C
(resource only; no key means no edge). The satellite proves the same 5 keys
through the full production `listSSM` path over the stubbed SSM API
(`internal/live/ssm_wave1_parity_test.go`), so DescribeParameters mapping,
the per-parameter ListTagsForResource enrichment, the ARN-less name fallback,
and the alias-key edge are covered end to end, not just the builders:

| # | Kind | Frozen key |
|---|---|---|
| 00 | aws_resource (parameter A, SecureString) | `7b6bc061…956ff8` |
| 01 | aws_relationship (parameter->KMS ARN) | `2d7c3fb7…74104c` |
| 02 | aws_resource (parameter B, alias key) | `39c75ea6…41045e` |
| 03 | aws_relationship (parameter->alias, empty target ARN) | `1c12ea50…761ad5f` |
| 04 | aws_resource (parameter C, ARN-less) | `dde48d93…a1fff08b` |

(Full keys are frozen in the test; prefixes above are abbreviated.)
Derivation on 2026-10-31 returned all 5 keys byte-identical to the frozen
satellite constants, including the ARN-less name fallback and the padded tag
key trim (proving the satellite's tag normalization equals the in-tree
mapper's). The one deliberate satellite deviation is out of fixture scope
(documented in `internal/service/ssm/NOT_PORTED.md`): a row with neither ARN
nor name fails where the in-tree mapper trusts the API. Raw descriptions,
allowed patterns, and policy JSON stay excluded on both sides by construction
(presence booleans and type/status pairs only, locked by
`TestWave1SSMParameterAttributeEquality`).

## Wave 1 KMS keys (in-tree scan parity pack)

Input fixture: `testdata/wave1-kms-parity.json`
(`sha256:bbf5fdb90f47e965945d44d6901e6e5e9c5779038d9bd117748effb41b027c8e`).

Oracle: check out eshu-hq/eshu at commit `b0371c05d54ab19fd03c848d509e55fc506ea81a`,
add a throwaway test in
`go/internal/collector/awscloud/service/kms/` that unmarshals the fixture
`keys` array directly into the scanner-owned `Key` type (the rows use those
exact Go field names; `RetiringPrincipalType` has no scanner counterpart and
is ignored), serves them from a fake `Client`, and prints `FactKind` +
`StableFactKey` per envelope from `Scanner.Scan` over boundary account
`123456789012`, region `us-east-1`, service `kms`, scope
`aws:123456789012:us-east-1`, generation
`aws:123456789012:us-east-1:wave1:1`, instance `aws-parity-wave1`, fencing
token `7`, observed-at `2026-10-30T12:00:00Z`. Command, from the `go/`
directory of the pinned commit:

```sh
go test ./internal/collector/awscloud/service/kms/ \
  -run 'TestZZWave1KMSOracle' -count=1 -v
```

The scan emits 18 envelopes in call order: key A with alias (resource, edge)
and IAM-ARN grant (resource, on-key edge, grantee edge); key B with ARN-less
alias (resource, edge) and two grants — a service-principal grant (resource,
on-key edge, grantee edge with no target ARN) and a grantee-less grant
(resource, on-key edge only); multi-region replica key C alone; AWS-managed
key D with alias (resource, edge). The fixture keys carry no key-policy
statements, tags, or rotation status, so the oracle emits no
resource-policy-permission facts and the satellite proves the same 18 keys
through the full production `listKMS` path over stubbed KMS APIs
(`internal/live/kms_wave1_parity_test.go`):

| # | Kind | Frozen key |
|---|---|---|
| 00 | aws_resource (key A) | `a166e6f4…8e2450` |
| 01 | aws_resource (alias A) | `b0e9de72…7eafa0` |
| 02 | aws_relationship (alias A->key) | `cfd61259…d16d88` |
| 03 | aws_resource (grant A1) | `b43a2e3a…0bfa22` |
| 04 | aws_relationship (grant A1->key) | `6ddea314…563fa9` |
| 05 | aws_relationship (grant A1->grantee) | `548d66f2…eedca8` |
| 06 | aws_resource (key B) | `930e73fa…c6a4a3` |
| 07 | aws_resource (alias B, ARN-less) | `a167a0ec…c46c1d` |
| 08 | aws_relationship (alias B->key) | `5a8efb8c…cb13fe` |
| 09 | aws_resource (grant B1) | `db6af0a3…74debb` |
| 10 | aws_relationship (grant B1->key) | `de7e8b73…5deccc` |
| 11 | aws_relationship (grant B1->grantee, Service) | `3623aa2e…767f33` |
| 12 | aws_resource (grant B2) | `2ec91ad5…459768` |
| 13 | aws_relationship (grant B2->key) | `e955de58…f423ac` |
| 14 | aws_resource (key C, replica) | `76709be6…24e12f` |
| 15 | aws_resource (key D, AWS-managed) | `2e903168…f204cf` |
| 16 | aws_resource (alias D) | `7058a3b6…d73969` |
| 17 | aws_relationship (alias D->key) | `5ed3d2a7…3547c6` |

(Full keys are frozen in the test; prefixes above are abbreviated.)
Re-execution returned all 18 keys byte-identical to the frozen satellite
constants. A hand-copy error on key 17 was caught by the parity test itself
going red; the corrected tail was verified by mechanical re-extraction of the
throwaway run output, and every frozen constant was then re-verified present
in the parity test by script.
Deliberate satellite deviations are out of fixture scope (both documented in
`internal/service/kms/NOT_PORTED.md`): key-policy statements, tags, rotation
status, and policy revision names stay unread where the in-tree scan emits
them; alias ARNs outside the claimed identity and grants without IDs fail
where the in-tree mapper trusts the API.

## Why this closes the common-mode gap

Every parity test still compares its builder against a hardcoded constant, but
the constant is no longer provenance-free: this file pins the oracle commit,
the exact command or builder, and the fixture hash needed to recompute it in a
second repository. A jointly-wrong constant plus builder now fails the
re-execution above, which runs the independent in-tree implementation over the
same fixture bytes.
