# Decisions

This folder holds architecture decision records (ADRs) for eshu-collector-aws-cloud.
An ADR is a short note that captures one decision, why we made it,
and what follows from it, so future readers don't have to dig the
reasoning out of old pull requests.

## Index

`ADR-0001` is recorded and listed here. We only write an ADR for a decision
that was actually made and recorded; we don't backfill imaginary
ones to fill the folder.

| ADR | Title | Status |
|---|---|---|
| [ADR-0001](ADR-0001-collect-once-paged-emission.md) | Collect-once paged emission for Class-3 walks | proposed |

## Format for a new ADR

Name the file `ADR-NNNN-short-title.md`, numbering from `0001`,
and use this shape:

```markdown
# ADR-NNNN: Short title

- Status: proposed | accepted | superseded by ADR-NNNN
- Date: YYYY-MM-DD

## Context

What forced a decision. Stick to facts from the code and the
deployment, not aspirations.

## Decision

What we chose, in plain terms.

## Consequences

What becomes easier, what becomes harder, and what to watch.
Link the docs that readers should update alongside it.
```

Add your ADR to the index table above in the same change.
If a later ADR replaces an earlier one, mark the old one
superseded rather than editing its decision away.
