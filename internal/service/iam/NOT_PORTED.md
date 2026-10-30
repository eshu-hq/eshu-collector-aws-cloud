# NOT_PORTED.md — `internal/service/iam`

Ported: `doc.go`, `types.go`. The live loader also emits a typed
`aws_iam_role` resource from `ListRoles`, `GetRole`,
`ListAttachedRolePolicies`, and `ListRolePolicies`. It retains role ARN,
name, path, policy references, permissions-boundary metadata, and trust-policy
presence. The regionless ARN must match the STS-verified account and partition;
its role suffix must match the reported name. The typed resource uses the legacy
`aws-global` boundary even when endpoint and STS reads use a configured region.
The raw trust document is never emitted.

The live loader also emits a typed `aws_iam_user` resource from `ListUsers`,
`ListAttachedUserPolicies`, `ListUserPolicies`, and `GetUser`. It retains the
user ARN, name, path, attached-policy ARNs, inline-policy names, and
permissions-boundary metadata. The regionless user ARN must match the
STS-verified account and partition, and its suffix must match the reported
name. The resource uses the legacy `aws-global` boundary; empty policy lists
retain the legacy null shape. A `GetUser` response without a user object falls
back to the listed user. Any required read error fails the IAM service scan.
The user enrichment adds at least three requests per listed user, with more
for paginated policy lists. It requires `iam:ListUsers`,
`iam:ListAttachedUserPolicies`, `iam:ListUserPolicies`, and `iam:GetUser`.
Live IAM grants and request cost remain unverified.

## Remaining role gaps

The live typed role resource emits trust-principal counts and identities
derived from the reported trust document (`internal/live/iam_trust.go`,
mirroring the in-tree trust parser with no new API reads), plus
role-trust and attached-policy relationships. Normalized permission
statements, `aws_iam_permission` facts, and `secrets_iam_posture` facts are
not emitted: statement normalization needs policy-document reads (a Wave 2
port gated on the read-grant census), and secrets posture stays core-owned
until an SDK posture-envelope seam exists. IAM role enrichment adds one
`GetRole` plus at least one `ListAttachedRolePolicies` and one
`ListRolePolicies` call per listed role; pagination can add more calls. Any
of those read errors fail the IAM service scan. A successful `GetRole`
response without a role object falls back to the listed role, matching the
legacy adapter.

## Remaining user gaps

The typed user resource does not emit normalized permission statements,
policy attachments or relationships, permission-boundary posture, or other
`secrets_iam_posture` facts. The live reader does not fetch inline or managed
policy documents. Raw policy documents and credential material are never
emitted. These gaps require the legacy policy normalization and envelope seams
below.

## Not ported (class-c)

| File | Blocked on |
|---|---|
| `awssdk/` (`client.go`, `doc.go`, `policy_documents.go`, `policy_normalize.go`) | AWS SDK adapter + `telemetry` spans — no SDK OTEL surface; boundary forbids AWS SDK paths until the telemetry shim lands |
| `runtimebind/` (`bind.go`, `doc.go`) | `awsruntime.Register` in blocked `registry.go` (telemetry + redact) — ports with the registry |
| `scanner.go` | `facts.Envelope` — no SDK Envelope surface; `collector/access/posture` — core-owned; `collector.Service` / claim runtime — core-owned |
| `secrets_observations.go` | `facts.Envelope` — no SDK Envelope surface; `collector/access/posture` — core-owned; `collector.Service` / claim runtime — core-owned |

## Tests not ported (subject absent)

- `scanner_test.go` — exercises an unported subject above.
- `servicekind_test.go` — exercises an unported subject above.
- `awssdk/client_test.go` — exercises an unported subject above.
- `awssdk/policy_documents_test.go` — exercises an unported subject above.
- `awssdk/policy_normalize_test.go` — exercises an unported subject above.
- `runtimebind/bind_test.go` — exercises an unported subject above.

Seam: SDK `Envelope` + observation-builder + OTEL + scope surfaces, then re-run the port for the files above.
