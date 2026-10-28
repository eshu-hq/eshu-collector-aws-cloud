// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package synthetics

import (
	"strings"
)

// canaryResourceID returns the resource_id the canary node publishes. It prefers
// the synthesized canary ARN and falls back to the canary name, so a canary's
// own edges key on the same value the canary node publishes.

// bucketNameFromArtifactLocation extracts the S3 bucket name from a Synthetics
// artifact location. AWS reports the location as a "bucket/prefix/..." path (it
// may carry a leading "s3://" scheme), never an ARN, so the bucket is the first
// path segment. It returns "" when no bucket segment is present.
func bucketNameFromArtifactLocation(location string) string {
	location = strings.TrimSpace(location)
	if location == "" {
		return ""
	}
	location = strings.TrimPrefix(location, "s3://")
	location = strings.TrimPrefix(location, "/")
	segment := location
	if idx := strings.IndexByte(segment, '/'); idx >= 0 {
		segment = segment[:idx]
	}
	return strings.TrimSpace(segment)
}

// arnForBucket synthesizes the partition-aware S3 bucket ARN for name, or
// returns an already-formed ARN unchanged. S3 buckets have no API ARN, so the
// scanner synthesizes one carrying the boundary partition (aws / aws-cn /
// aws-us-gov) so the canary->bucket target matches the S3 scanner's published
// bucket resource_id in every partition instead of dangling the graph edge.
func arnForBucket(partition, name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if strings.HasPrefix(name, "arn:") {
		return name
	}
	return "arn:" + partition + ":s3:::" + name
}

// firstNonEmpty returns the first trimmed non-empty value, or "" when none.

// timeOrNil returns the UTC time when value is set, or nil for the zero time so
// the attribute payload omits an unknown timestamp instead of emitting an epoch.

// cloneStringMap returns a trimmed-key copy of input, or nil when it is empty or
// every key trims to empty, keeping omitempty-style payload behavior consistent.

// cloneStrings returns a trimmed copy of input with empty and duplicate entries
// dropped, or nil when nothing survives. De-duplication keeps repeated subnet or
// security group identifiers from emitting duplicate edges.
