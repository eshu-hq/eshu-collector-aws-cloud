# NOT_PORTED.md — `internal/service/eks`

Ported: `doc.go`, `helpers.go`, `relationships.go`, `types.go`.

## Not ported (class-c)

| File | Blocked on |
|---|---|
| `awssdk/` (`client.go`, `doc.go`, `helpers.go`, `mapper.go`, `oidc.go`, `telemetry.go`) | AWS SDK adapter + `telemetry` spans — no SDK OTEL surface; boundary forbids AWS SDK paths until the telemetry shim lands |
| `runtimebind/` (`bind.go`, `doc.go`) | `awsruntime.Register` in blocked `registry.go` (telemetry + redact) — ports with the registry |
| `nodegroup_addon.go` | `facts.Envelope` — no SDK Envelope surface; `collector.Service` / claim runtime — core-owned |
| `scanner.go` | `facts.Envelope` — no SDK Envelope surface; `collector.Service` / claim runtime — core-owned |

## Tests not ported (subject absent)

- `scanner_test.go` — exercises an unported subject above.
- `servicekind_test.go` — exercises an unported subject above.
- `awssdk/client_test.go` — exercises an unported subject above.
- `runtimebind/bind_test.go` — exercises an unported subject above.

Seam: SDK `Envelope` + observation-builder + OTEL + scope surfaces, then re-run the port for the files above.

## Wave 1 emission parity (eshu-hq/eshu#9296)

The files above remain literally unported (no SDK `facts.Envelope`
replacement), but the live path (`internal/live/eks_*.go` through the root
`NewResourceFact` / `NewRelationshipFact` seams) already emits the scanner's
full fact set with in-tree-identical stable keys, proven on the shared
fixture `testdata/wave1-eks-parity.json` (24/24 keys, provenance in
`testdata/stable-key-provenance.md`, Q4(a) in `eks_wave1_conformance_test.go`):

| In-tree file | Live-path coverage |
|---|---|
| `scanner.go` (cluster/nodegroup/addon reads + OIDC) | `listEKS` in `internal/live/services_compute.go` reads the same passes per cluster |
| `nodegroup_addon.go` (nodegroup/addon observations + membership) | `eksNodegroupRecord` / `eksAddonRecord` in `internal/live/eks_nodegroup.go` / `eks_addon.go`, membership via `eksMembershipRelationship` |
| `relationships.go` (all nine EKS edges) | `eksClusterRelationships` / `eksNodegroupRelationships` / `eksAddonRelationships` in `internal/live/eks_relationships.go` plus membership edges |
| `awssdk/oidc.go` (provider matching) | `eksOIDCReader` in `internal/live/eks_oidc.go` (same normalize-and-match semantics on same-account providers) |

Deliberate satellite deviations, out of fixture scope: an IAM list denial
degrades to an issuer-only provider plus warning where the in-tree scan fails
(locked by `TestEKSOIDCListDenialKeepsClustersAndWarns`); provider ARNs are
same-account scoped where the in-tree matcher considers any ARN; membership
rejects a nonblank conflicting child cluster name where the in-tree scanner
always emits.
