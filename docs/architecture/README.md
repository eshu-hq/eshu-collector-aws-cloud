# Architecture

## Place in Eshu

This collector is a leaf reader in Eshu. Core issues claims,
the host starts this binary once per claim, the collector
reads one AWS account and writes one result to stdout, and
the host commits the facts for core to store and answer
over. Keeping AWS reads in their own collector lets core
stay source-neutral, and lets this code ship and be pinned
on its own. The collector writes nothing to Eshu storage
itself (status: standalone collector, version `0.1.0`; the
manifest still declares three temporary placeholder fact
kinds while the AWS port finishes).

Diagrams live in [diagrams](../diagrams/README.md). The
[top-level README](../../README.md) keeps one overview
diagram.

## Shape of the collector

- Image entry point `/usr/local/bin/collector --sdk-stdio`,
  speaking `collector-sdk/v1alpha1` or `v1alpha3` (paged
  results on `v1alpha3`).
- Manifest compatibility with core `>=0.0.5 <0.2.0`
  ([manifest.yaml](../../manifest.yaml)).
- Go `1.26.10` pinned in `go.mod` (module
  `github.com/eshu-hq/eshu-collector-aws-cloud`); SDK pins
  `eshu-sdk/collector v0.1.0-rc.4` and
  `eshu-sdk/factschema v0.1.0-rc.7`.
- No endpoint, queue, or datastore handle. See
  [boundaries](../concepts/boundaries.md).

## Related repos

- [eshu](https://github.com/eshu-hq/eshu): core. It issues
  claims, stores the facts, and answers questions over them.
- [eshu-sdk](https://github.com/eshu-hq/eshu-sdk): the
  collector contract this binary speaks.
- [eshu-extension-host](https://github.com/eshu-hq/eshu-extension-host):
  the standalone host that can run component collectors like
  this one.
