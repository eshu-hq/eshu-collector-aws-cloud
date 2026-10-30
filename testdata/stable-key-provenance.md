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

## Why this closes the common-mode gap

Every parity test still compares its builder against a hardcoded constant, but
the constant is no longer provenance-free: this file pins the oracle commit,
the exact command or builder, and the fixture hash needed to recompute it in a
second repository. A jointly-wrong constant plus builder now fails the
re-execution above, which runs the independent in-tree implementation over the
same fixture bytes.
