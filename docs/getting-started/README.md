# Getting started

You can run this collector end to end without an AWS
account. Fixture mode reads a recorded report instead of
live APIs:

```bash
go run ./cmd/collector --input testdata/complete.json
```

If that works, the basics are intact. Tests run the same
way: fixtures only, never live AWS.

## How Eshu runs it

Four lines cover it. The host starts the image entry point,
`/usr/local/bin/collector --sdk-stdio`, once per claim. It
writes one JSON request to stdin (`collector-sdk/v1alpha1`
or `v1alpha3`) with the claim and the config. The collector
reads AWS and writes one JSON result, or one page of it, to
stdout. The host commits the facts, and re-invokes with a
cursor if more pages remain.

Live mode needs the three allowlists: one account, named
regions, named services. A minimal config block is in
[configuration](../reference/configuration.md), and the
annotated shape lives in
[config.example.yaml](../../config.example.yaml).
