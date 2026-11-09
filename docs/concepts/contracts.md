# The claim contract

A collector is a program Eshu runs for one job at a time.
This one looks at one AWS account, in the regions and
services the config names, and reports what exists. Eshu
core stores and connects those reports later. The
collector's whole job is to look carefully and report
honestly, including about the things it couldn't see.

See [diagrams](../diagrams/README.md) for the placement
diagram and the one-claim sequence, with captions and text
versions.

## One claim, start to finish

Data in is one claim (ids, scope, attempt, deadline) plus
config. The collector parses the config, confirms the
credentials belong to the target account through STS, then
reads each allowed service in each allowed region. Data out
is one result holding facts and statuses, with a state of
complete, partial (some reads were denied), or terminal
(failed for good).

Large results split into pages on `v1alpha3`. The host
re-invokes with a continuation cursor until the final page,
and a resumed call re-collects and checks the data still
matches what earlier pages were built from. If it drifted,
the run fails so the host retries from the start, rather
than committing torn evidence. `v1alpha1` keeps the older
single-result shape.

Two modes: live mode (config has no `source.input`) lists
live AWS resources; file mode (`source.input` names a JSON
report like `testdata/complete.json`) exists for fixtures
and local runs. A present-but-empty value counts as absent.

## What it can read

The collector can read 20 services, per `SupportedServices`
in `internal/live/config.go`: `apigateway`, `cloudfront`,
`cloudwatchlogs`, `dynamodb`, `ec2`, `ecr`, `ecs`, `eks`,
`elbv2`, `eventbridge`, `iam`, `lambda`, `kms`, `rds`,
`route53`, `s3`, `secretsmanager`, `sns`, `sqs`, and `ssm`.
Other names are rejected. Reader depth varies by service,
so read that list as "what the code can read," not "every
setting gets reported."

Fact kinds are in [facts](../reference/facts.md), which
mirrors `manifest.yaml`.

## When AWS says no

Permission denials get handled two ways. A denial on a core
listing call fails that service's read. A denial on a small
set of reviewed optional calls degrades instead: the result
becomes partial, an `aws_warning` names the denied call, and
the unread setting stays unknown rather than being reported
as "off." Today that optional set is EC2
`DescribeSecurityGroupRules` and `DescribeImages`, EKS's
`iam:ListOpenIDConnectProviders`, Lambda
`ListEventSourceMappings`, and S3 `GetBucketEncryption`.

Hold onto this rule: a warning proves a thing was unread. It
never proves the thing is absent.
