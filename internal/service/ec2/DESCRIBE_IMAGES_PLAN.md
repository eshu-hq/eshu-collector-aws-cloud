# #9301 DescribeImages plan (IMPLEMENTED typed-only in the live path)

Status: implemented for typed fields in `internal/live/ec2_ami.go` (branch `drive/9301-ami-describe-plan`). The typed EC2 scanner port in this package remains fenced (see NOT_PORTED.md); emission flows through the live record-to-`aws_resource` seam instead. Per the arbiter ruling 2026-10-29 (epic #9295), raw AMI name/description passthrough is REJECTED and stays unimplemented; the exclusion proof lives in `internal/live/ec2_ami_test.go` (`TestAMINameDescriptionNeverSurface`) for #9525.
Revalidated 2026-10-29 against collector `origin/main`: plan holds as-is,
no rebase needed (0 behind).
Sequencing: #9297 (R1 degrade contract) lands before #9301 implementation.
#9297 is OPEN with parallel lanes active (`drive/9297-denial-integrated` at
`744d49a` plus four denial worktrees) but no PR and no confirmed
`WarningKind` (`types.go:316` still a plain string) — do not duplicate.
Prerequisite: #8852 typed EC2 port (PORT_PLAN steps 3–5) restores typed
`aws_resource@1.0.0` emission in this repository first. Nothing new lands in
`eshu` `go/internal/collector/awscloud`, which has no QA activation and is
scheduled for removal.

Related: #9298 (inventory allowlist/readback, owner: #9298 lane, PR #9450 head
`e08fc00879`, open, HELD unmerged per the #9460 sixth-shard ruling — no action
there until the relief lands on main, then rebase + one fresh wave).
Revalidated 2026-10-29: #9471 (readiness refit) is CLOSED; #9460 stays OPEN
with relief PR #9514 (`drive/9460-sixth-shard`, CI wave running, wall evidence
still owed) — the hold has NOT cleared. #9301 must not duplicate that lane's
files (allowlist/readback/golden only).

## 1. What exists today

- The ported EC2 scanner surface is `internal/service/ec2/types.go`
  (`Client`: VPCs, subnets, security groups, rules, ENIs, instances, volumes)
  plus `doc.go`. There is deliberately NO `DescribeImages` call yet.
- The in-tree port source is `go/internal/collector/awscloud/service/ec2/`
  in `eshu-hq/eshu`: `ami_identity.go` (scan-scoped `seenAMIIDs` dedup set,
  identity-only `aws_ec2_ami` fact with `Name` = bare AMI id), `scanner.go`
  (call order; `ListSecurityGroupRules` denial is currently terminal and is
  #9297's case to fix), `catalog/compute.go` (AMI carries identity only;
  enrichment via DescribeImages is a separate, costed change).
- `internal/service/ec2/NOT_PORTED.md` lists `ami_identity.go`,
  `attributes.go`, `identity.go`, `scanner.go` and the rest as not yet ported,
  blocked on the SDK Envelope + observation-builder + OTEL + scope seam.

## 2. Planned DescribeImages call shape

- Source set: the distinct AMI ids observed on `Instance.ImageID` during the
  scan (trimmed, non-blank). Dedup key = AMI id; the scan boundary already
  scopes one account/region, mirroring `amiResourceEnvelopes`' `seenAMIIDs`.
- Batching: EC2 `DescribeImages` takes up to 200 `ImageIds` per call; the
  adapter chunks the deduped set accordingly and concatenates pages. No
  per-instance fan-out (the N+1 the in-tree `doc.go` forbids).
- Cap: a per-scan image cap (value TBD at implementation; AppStream precedent
  scopes reads to account-relevant visibilities instead of the whole catalog).
  When the cap truncates the set, emit one `aws_warning` naming the cap and
  the dropped count; the scan continues with the resolved subset.
- Shared-or-deregistered AMI: `DescribeImages` returns no record for an AMI
  the account cannot see (shared without launch permission, deregistered, or
  cross-account). That AMI keeps its identity-only fact + instance→AMI
  relationship and gains one `aws_warning` (unresolved-image path). No OS
  version is inferred; the reason it was unavailable is not guessed.
- Denied `DescribeImages`: degrades per the #9297 (R1) contract (section 4),
  NOT terminal. Core inventory (instances, AMI identity, relationships) is
  kept. This operation is outside #9297's four named cases
  (`DescribeSecurityGroupRules`, `iam:ListOpenIDConnectProviders`,
  `ListEventSourceMappings`, `GetBucketEncryption`); #9301 adds and tests
  this fifth operation against the same contract.

## 3. Exact field list (attribute keys per the #9298 handshake)

Agreed keys (owner comment 2026-10-28T23:10:34Z on #9301): `name`,
`description`, `platform_details`, `platform`, `architecture`,
`creation_date`, `deprecation_time`, `owner_alias`, `root_device_type`.
The instance's `attributes.ami_id` stays unchanged. New keys are restricted
to `aws_ec2_ami` resources only. Absent or blank values stay omitted.

AWS source mapping (to verify at implementation against the SDK type):

| Attribute key       | AWS `Image` source        | Notes |
|---|---|---|
| `name`              | `Name`                    | REJECTED by arbiter ruling 2026-10-29 — never emitted (#9525) |
| `description`       | `Description`             | REJECTED by arbiter ruling 2026-10-29 — never emitted (#9525) |
| `platform_details`  | `PlatformDetails`         | AWS-reported string; documented examples are not an exhaustive enum — needs its own source contract; record as reported, never infer OS version |
| `platform`          | `Platform`                | AWS-reported enum-ish string (`Windows` or empty for Linux) |
| `architecture`      | `Architecture`            | Bounded enum (`i386`, `x86_64`, `arm64`, `x86_64_mac`, `arm64_mac`) |
| `creation_date`     | `CreationDate`            | Timestamp string; omit when unparseable, never synthesize |
| `deprecation_time`  | `DeprecationTime`         | Timestamp string; absent unless deprecated |
| `owner_alias`       | `ImageOwnerAlias`         | NOT the numeric owner id; absent for most private AMIs |
| `root_device_type`  | `RootDeviceType`          | Bounded enum (`ebs`, `instance-store`) |

## 4. Adapter → scanner → warning/status/readiness contract (for #9297)

To be confirmed with the #9297 owner; this lane's working proposal (draft,
mirrors the AppStream `throttle_sustained` precedent and the Audit Manager
`isAccessDenied` degrade shape):

- Result shape: the EC2 adapter returns `(images []ImageDetail, warnings
  []awscloud.WarningObservation, err error)`. `err != nil` ONLY for
  core-listing failures (DescribeInstances and the existing topology reads)
  and for non-denial DescribeImages transport errors. Optional-call denials
  arrive as warnings, never as `err`.
- Operation/reason fields: each warning sets `WarningKind` to the
  coverage-warning kind #9297 defines (TBD — e.g. `optional_call_denied`;
  this lane does not invent it), `ErrorClass` to the AWS error code
  (`UnauthorizedOperation`, `AccessDenied`, …), `Message` to a sanitized
  one-liner (`SanitizeScanStatusMessage`-bounded, no ARNs/ids), and
  `Attributes` = `{"service_kind": "ec2", "operation": "DescribeImages",
  "effect": <"ami_details_omitted"|"cap_truncated"|"image_unresolved">,
  "ami_id"?: ..., "dropped_count"?: ...}`.
- Dedup rule: one warning per (operation, effect) per scan — NOT one per
  AMI id. A 50-instance fleet on one denied call emits one warning, not 50.
  (Matches the `seenAMIIDs` spirit: bound fact volume at the producer.)
- Core-failure handling: a denial on a CORE listing call stays
  `permission_denied` and terminal (scan fails, no partial inventory). A
  denial on DescribeImages (optional enrichment) keeps every core envelope
  and appends the warning envelope(s) via `NewWarningEnvelope`.
- Status/readiness: `observeScanStatus` already counts `AWSWarningFactKind`
  envelopes into `WarningCount`; #9297 owns extending the
  `ScanStatusPartial` derivation beyond today's
  budget/throttle/org-access cases to the new warning kind, plus the
  readiness and MCP `list_collectors` surfacing. A log line alone does not
  satisfy that bar. This lane consumes that contract; it does not build it.

## 5. Redaction boundary: UNDECIDED (blocks implementation)

AWS lets image creators choose `Name` and change `Description` later
(`CreateImage`, `ModifyImageAttribute`); the values can carry secrets or
private identifiers. The inventory allowlist validates field names and scalar
shapes, not text content (see the #9298-lane review note 2026-10-29T00:55:06Z
and the boundary confirmation 2026-10-29T09:52:50Z: PR #9450 admits ONLY
`ami_id`; its contract test pins `"name": "must-not-surface"` as dropped).

Decision needed before implementation: a source-specific free-text policy
for `name`/`description` that is acceptance-compatible with #9301's
"record the values AWS reports" requirement — e.g. passthrough vs the
existing redacted-marker precedent — including what the proof must cover
(producer emission, stored/replayed facts, AMI-only inventory filtering,
HTTP/MCP, diagnostics, benign + sensitive synthetic text). The other seven
fields are evaluable separately under strict types and documented
value/timestamp constraints. No scope change is assumed here.

## 6. #9298 field-name handshake (agreed, implementation pending both sides)

- Producer (this lane, after #8852 + redaction decision): emit the nine keys
  above on `aws_ec2_ami` `aws_resource@1.0.0` facts only.
- Read side (#9298 owner): extend the closed allowlist deliberately per key
  once the redaction policy settles; update OpenAPI +
  `docs/public/reference/http-api/cloud-inventory.md` + capability row in the
  same PR; prove on golden-corpus cassettes in the scanner payload shape
  (#8852 parity contract). Live QA stays NOT_CHECKED until typed AWS facts
  are admitted in QA (R0).
- No file-boundary conflict: #9298 touches allowlist/readback/golden; this
  lane touches collector emission + scanner fixture goldens under
  `sdk/go/factschema/fixturepack/payloads/`.

## 7. Test plan (at implementation; seeded RED/GREEN per issue)

1. Instance with a resolvable AMI → detail fields land on the AMI fact.
2. Shared/deregistered AMI → identity kept + one unresolved-image warning.
3. Denied `DescribeImages` → core inventory kept + one warning via the #9297
   contract (operation=`DescribeImages`); core-denial control stays terminal.
4. Cap hit → truncation + one cap warning.
5. Input-to-payload golden for the new fields; README no longer "minimal"
   for AMIs; docs updated; QA check (EC2 instance shows AMI platform
   details) after R0.

NOT_CHECKED: implementation, goldens, HTTP/MCP verification, performance,
live QA.
