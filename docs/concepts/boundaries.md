# Boundaries

## What it reads, and what it won't

Live mode reads control-plane metadata only: names, ids, and
settings, never contents. Per `awscloud_doc.go` and
`internal/live/doc.go`, it doesn't read secret values,
message bodies, or parameter values, doesn't save raw policy
documents, and calls no mutation APIs. Before any reads, it
checks with STS that the credentials belong to the target
account.

Environment values from ECS and Lambda, plus some account
contact fields, are redacted before any fact is built.
Source URIs that embed credentials are refused outright.
Access is bounded by three allowlists: one account, named
regions, named services. Credentials come from the ambient
AWS chain only; the details are in
[configuration](../reference/configuration.md).

## What it never touches

The collector talks to AWS service APIs (reads only) and to
its own stdin and stdout. It never touches Postgres, the
graph, queues, leases, or any Eshu API, and it never starts
itself on a schedule. `doc.go` states the import boundary
and `boundary_test.go` enforces it: only the published SDK
modules get imported.
