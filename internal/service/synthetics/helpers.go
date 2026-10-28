// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package synthetics

import (
	"strings"
)

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
