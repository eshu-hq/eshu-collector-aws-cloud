# Documentation

Welcome in. This is the map for `eshu-collector-aws-cloud`,
the Eshu collector that reads one AWS account and reports
what exists there: resources, links between them, and
security-relevant settings. It reads metadata only, makes no
writes to AWS, and never looks at data contents.

New here? Start with getting started (fixture mode needs no
AWS account), then read the concepts. Seeding, grants, or a
run that's coming back partial? The guides have you.

| Start here | What's in it |
|---|---|
| [Getting started](getting-started/README.md) | Run fixture mode locally, then see how the host runs it |
| [Guides](guides/README.md) | Operate, troubleshoot, seed, and release |
| [Concepts](concepts/README.md) | The claim contract, denial handling, and boundaries |
| [Reference](reference/README.md) | Config fields, credentials, limits, and every fact kind |
| [Architecture](architecture/README.md) | Where this collector sits in Eshu |
| [Diagrams](diagrams/README.md) | Every diagram, with captions and text versions |
| [Decisions](decisions/README.md) | Architecture decision records |
| [Contributing](contributing/README.md) | Local gates before you open a pull request |

A claim is one unit of work with a time budget, a fact is
one stored observation with a kind like `aws_resource`, and
the host is the Eshu process that starts this collector.
The [top-level README](../README.md) keeps the short version
and one overview diagram.
