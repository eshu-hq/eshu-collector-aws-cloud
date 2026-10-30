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

## Why this closes the common-mode gap

Every parity test still compares its builder against a hardcoded constant, but
the constant is no longer provenance-free: this file pins the oracle commit,
the exact command or builder, and the fixture hash needed to recompute it in a
second repository. A jointly-wrong constant plus builder now fails the
re-execution above, which runs the independent in-tree implementation over the
same fixture bytes.
