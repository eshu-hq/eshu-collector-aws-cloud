# NOT_PORTED.md — `recordpolicy`

| In-tree file | Status | Reason / seam |
|---|---|---|
| `doc.go` | ported | — |
| `policy.go` | **not ported** | Returns `replay/recordpseudo.Policy`: the replay/record engine is core-owned workflow machinery with no SDK replacement. A standalone per-record bound needs an SDK record-policy surface first. |

No test ports: the in-tree policy tests exercise the core replay engine.
