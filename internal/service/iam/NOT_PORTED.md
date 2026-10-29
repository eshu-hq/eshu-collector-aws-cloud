# NOT_PORTED.md — `internal/service/iam`

Ported: `doc.go`, `types.go`. The live loader also emits a typed `aws_iam_role` resource from `ListRoles`, `GetRole`, `ListAttachedRolePolicies`, and `ListRolePolicies`. It retains role ARN/name/path, policy names/ARNs, permissions-boundary metadata, and trust-policy presence. The ARN must match the STS-verified account and partition. The raw trust document is never emitted.

## Remaining role gaps

The live typed role resource does not yet emit trust-principal counts or identities, normalized permission statements, role-policy relationships, or `secrets_iam_posture` facts. Those require the legacy policy normalization and envelope/telemetry seams below. IAM role enrichment adds one `GetRole` plus at least one `ListAttachedRolePolicies` and one `ListRolePolicies` call per listed role; pagination can add more calls. Any of those read errors fail the IAM service scan. A successful `GetRole` response without a role object falls back to the listed role, matching the legacy adapter.

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
