# Contributing

Thanks for helping. Read [CONTRIBUTING.md](../../CONTRIBUTING.md)
before opening a pull request; this is the short version.

Go version is pinned in `go.mod` (`go 1.26.10`, module
`github.com/eshu-hq/eshu-collector-aws-cloud`). Tests run on
fixtures only and never call live AWS, so `make ci` is safe
to run anywhere.

```bash
make ci     # vet, lint, fmt, tidy, cap, build, test, race
make vet    # go vet
make lint   # golangci-lint (v2.12.2, via go run)
make build  # go build ./...
make test   # go test ./... -count=1
make race   # race suite
```

If you change `manifest.yaml`, update
[facts](../reference/facts.md) in the same change.

There's no SECURITY.md or LICENSE file in this repo. Source
files carry `SPDX-License-Identifier: MIT`.
