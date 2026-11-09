# Seed the AWS Cloud collector

```bash
collector seed --dest DIR --image-ref NAME@sha256:DIGEST
```

Seed writes `DIR/collector` and `DIR/manifest.yaml`,
stamping the digest-pinned image reference into the manifest.
If you leave off `--image-ref` it falls back to the
`COLLECTOR_IMAGE_REF` environment value. Re-running is safe.
A malformed reference fails before any file is written, and
the error won't echo the value back at you.

One honest limit: this repo doesn't prove the core-side
grant, install, and enable commands. Follow core's component
docs for those, using
[grant.example.json](../../grant.example.json) as the grant
request set.

## Producer grants, in plain words

A grant is core's permission record saying "this producer,
at this version, may emit this fact kind under scope `aws`."
Fact kinds owned by core need a live grant before the host
will commit them. `grant.example.json` requests 13 of them:
one per core kind at schema `1.0.0`, producer
`collector-aws-cloud`, version `0.1.0`.

Two wrinkles. The grant set includes `aws_tag_observation`,
which the manifest doesn't declare yet, so the two lists
aren't identical and that's expected for now. And grants can
be revoked core-side. Rollback means stopping new claims,
revoking, restoring the prior producer, and replaying from
the last committed generation. Live grant issuance is a
core-side step this repo can't prove from here.

Fact kinds are listed in [facts](../reference/facts.md).
