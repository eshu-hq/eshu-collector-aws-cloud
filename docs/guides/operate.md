# Operate the AWS Cloud collector

There's no service to run here. Operating this collector
means building the image, seeding it (see [seed](seed.md)),
making sure core has granted it permission to emit, and
reading the signals each run leaves behind.

## The image

```bash
docker build -t eshu-collector-aws-cloud .
```

The Dockerfile pins the build to `linux/amd64`. The image
holds `/usr/local/bin/collector`, the manifest at
`/etc/collector/manifest.yaml`, and the sample input at
`/var/lib/collector/complete.json`. It runs as user `65532`
with entry point `collector --sdk-stdio`. No port, no
long-running mode. The host launches it per claim and that's
the whole lifecycle.

## Reading a run

Each run leaves you three things:

- A health line on stderr: `collector health: {...}` with
  `alive`, `last_success_at`, `last_digest`,
  `consecutive_failures`, `last_error`, retry depth, and the
  effective limits actually in force.
- An exit code: non-zero on failure, with
  `collector: <error>` on stderr. Errors never echo URIs,
  payloads, or credentials.
- Result statuses inside the committed result, which is what
  the host shows as collector status. A partial result with
  `aws_warning` facts means "read what we could, these calls
  were denied." Treat partial as information, not failure.

The manifest declares a metrics prefix
(`eshu_dp_aws_cloud_collector_`), but let's be clear: this
one-shot binary serves no metrics endpoint. Don't go looking
for a port to scrape.

Diagrams live in [diagrams](../diagrams/README.md).
