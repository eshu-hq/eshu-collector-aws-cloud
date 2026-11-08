# Troubleshoot the AWS Cloud collector

A few failures come up again and again:

- The run fails immediately on config. Check the three
  allowlists first. Missing or empty `allowed_regions` or
  `allowed_services` fails the run by design, and an
  unsupported service name gets rejected by name. Fields are
  in [configuration](../reference/configuration.md).
- The STS check fails. Your credentials don't belong to the
  account in `target_scopes.account_id`, or the
  `assume_role` role lives in a different account than the
  scope. The collector won't read an account its credentials
  don't match.
- Everything comes back partial. Read the `aws_warning`
  facts. They name the denied calls. Either grant those
  reads or accept the gap, but don't read "unread" as
  "absent" or "off." Which denials degrade is explained in
  [contracts](../concepts/contracts.md).
- A big account keeps timing out. You're hitting
  `claimTimeoutSeconds`. Narrow the regions or services per
  claim before you reach for a bigger timeout.
- The host rejects pages. `limits.maxPageBytes` was raised
  without raising the host's stdout cap to match. They move
  together or not at all.
- File mode locally: `go run ./cmd/collector --input
  testdata/complete.json` should always work. If it doesn't,
  you've broken something basic. Start there.
