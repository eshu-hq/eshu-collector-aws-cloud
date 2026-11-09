# Fact kinds

This page mirrors `spec.emittedFacts` in
[manifest.yaml](../../manifest.yaml): 15 kinds, all at
schema `1.0.0`. Confidence is `reported` unless noted.
Update this page whenever you change `manifest.yaml`. They
have to move together.

| Kind | What one fact says |
|---|---|
| `aws_resource` | One AWS thing exists (a bucket, a function, a VPC, ...) |
| `aws_relationship` | One link between two AWS things |
| `aws_image_reference` | One container image tag or digest seen in ECR |
| `aws_warning` | Something couldn't be read, and what's missing |
| `s3_bucket_posture` | One bucket's safety settings, summarised |
| `aws_dns_record` | One Route 53 DNS record |
| `aws_security_group_rule` | One firewall rule on a security group |
| `aws_iam_permission` | One IAM permission statement |
| `aws_resource_policy_permission` | One permission statement from a resource policy |
| `ec2_instance_posture` | One EC2 instance's safety settings |
| `rds_instance_posture` | One RDS database instance's safety settings |
| `s3_external_principal_grant` | One bucket-policy grant to an outside account |
| `collector-aws-cloud.snapshot` | Temporary placeholder: file-mode snapshot marker |
| `collector-aws-cloud.record` | Temporary placeholder: one file-mode record (`observed`) |
| `collector-aws-cloud.warning` | Temporary placeholder: one file-mode warning |

The last three are transitional and go away when the port
completes (see [PORT_PLAN.md](../../PORT_PLAN.md)).
`aws_tag_observation` isn't declared. The manifest notes it
has no SDK schema yet, so don't go looking for it in output.

Which services feed these kinds, and how denials degrade, is
in [contracts](../concepts/contracts.md). Grants for the
core kinds are in the [seed guide](../guides/seed.md).
