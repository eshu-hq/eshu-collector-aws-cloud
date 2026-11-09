# Release the AWS Cloud collector

The `manifest.yaml` version and the git tag must match:
`v0.1.0` for `0.1.0`. A `v*` tag at the `main` head runs
`release.yml`, which builds, signs, and publishes the image
with SBOM and provenance records. Pushes to `main` publish
`:main`, `:latest`, and `:sha-<long-sha>`. Manifest artifact
references must be digest-pinned. Use
`scripts/pin-digest.sh` when you're re-pinning.

Standing reminder: if you change `manifest.yaml`, update
[facts](../reference/facts.md) in the same change. They have
to move together.

Run `make ci` before you tag; see
[contributing](../contributing/README.md). Port state lives
in [PORT_PLAN.md](../../PORT_PLAN.md) and
[NOT_PORTED.md](../../NOT_PORTED.md).
