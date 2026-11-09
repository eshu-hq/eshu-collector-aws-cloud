# Configuration reference: AWS Cloud collector

Settings arrive in the host request config. The annotated shape
lives in [config.example.yaml](../../config.example.yaml), and the
live-mode fields below are parsed in `internal/live/config.go`.

The shape of the thing: one account, a list of regions you're
allowed to touch, a list of services you're allowed to touch. All
three allowlists are required. Leave one out and the run fails
before it reads anything, which is what you'd hope for.

## Live-mode fields

| Field | Required | What it means |
|---|---|---|
| `target_scopes.account_id` | Yes | One 12-digit AWS account per claim |
| `allowed_regions` | Yes | Non-empty region allowlist |
| `allowed_services` | Yes | Non-empty list, drawn from the 20 supported names |
| `target_scopes.assume_role` | No | Cross-account mode: `mode: central_assume_role`, `role_arn`, `external_id` |
| `source.sourceURI` | No | Label for emitted facts. Defaults to `aws://<account>`. Must carry no credentials |
| `source.redactionKeyEnv` | With `ecs` | Must be exactly `ESHU_AWS_REDACTION_KEY`. It names the env var, never the key value |
| `freshness.previousDigest` | No | Prior digest hint. Currently ignored on the live path |
| `limits.maxRecordsPerClaim` | No | Fact cap per claim. Default `5000` |
| `limits.maxPayloadBytes` | No | Bytes per fact payload. Default `65536` |
| `limits.claimTimeoutSeconds` | No | Wall-time cap per claim. Default `300` |
| `limits.maxPageBytes` | No | Bytes per result page. Default `4128768` |

The supported service names are listed in
[how it works](../concepts/contracts.md). Anything else in
`allowed_services` is rejected, so a typo fails loudly instead of
silently collecting less than you asked for.

## Time and size budgets

One claim must finish within `claimTimeoutSeconds`, 300 seconds by
default. A run that outruns it fails instead of emitting late
evidence. Defaults live in `DefaultResourceUse` (`health.go`).

`maxPageBytes` needs a word of care. Its default, `4128768`, is the
host's 4 MiB stdout cap minus 64 KiB of framing. Raise it only
together with the host cap. Raise it alone and you'll meet the host
admission error instead.

The local `--input` mode exposes the same limits as flags
(`--max-records`, `--max-payload-bytes`, `--claim-timeout-seconds`,
`--max-page-bytes`), where `0` means "use the default." Negative
values are refused.

## Credentials, exactly as the code allows

Short version: the ambient AWS chain only. An instance or task role,
IRSA web identity, or environment credentials. Static credential
values in config are never accepted, and there's no flag to change
that. If you're about to paste an access key into a config file,
don't. The collector won't take it, and you shouldn't want it to.

With an `assume_role` block, the collector exchanges the ambient
credentials through STS AssumeRole for a role in the same account as
the scope, and keeps those session credentials in memory for the
claim. A role in a different account is rejected at parse time. The
`external_id` goes along for the exchange, as you'd expect.

Before reading anything, the collector checks with STS that the
credentials it ended up with really belong to the target account.
Wrong account, no reads.

This repo doesn't publish an IAM policy. The reads it makes are the
list, describe, and get calls behind the services you allow, and
denials surface as failures or warnings (the
[how it works](../concepts/contracts.md) doc explains which). Grant only what
your chosen services need, and no write actions. The collector has
no use for them and will never call them.

## Secrets and redaction

Two things to keep straight:

- `source.redactionKeyEnv` names an environment variable. It never
  holds the key itself, and it must be exactly
  `ESHU_AWS_REDACTION_KEY` when `ecs` is in your service list. The
  key material lives in the process environment, supplied by
  whoever runs the collector.
- Environment values from ECS and Lambda, plus some account contact
  fields, get redacted before any fact is built. And a
  `source.sourceURI` with credentials embedded in it is refused, so
  a careless URI can't smuggle a secret into emitted facts.

## A minimal live config

Skipping the host envelope, the config block for one account, one
region, three services:

```yaml
target_scopes:
  account_id: "111122223333"
allowed_regions:
  - us-east-1
allowed_services:
  - iam
  - ec2
  - s3
```

Add the `assume_role` block under `target_scopes` if you're reading
across accounts, and add `source.redactionKeyEnv` the moment `ecs`
joins the list. The full annotated version, including file mode, is
in [config.example.yaml](../../config.example.yaml).
