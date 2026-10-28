// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package codebuild

import (
	"strings"

	awscloud "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// s3BucketARNFromLocation derives the S3 bucket ARN from a CodeBuild S3 source
// or artifact location of the form "bucket-name/path/prefix". It matches the S3
// scanner identity, which emits the bucket ARN as its resource_id, so the edge
// joins the bucket node. When the location is a bare bucket/path, the partition
// is derived from the scan boundary's region; when it is already an S3 ARN, the
// source ARN's partition is preserved. A hardcoded commercial partition would
// dangle the project->S3 edge in GovCloud and China.
func s3BucketARNFromLocation(boundary awscloud.Boundary, location string) string {
	location = strings.TrimSpace(location)
	if location == "" {
		return ""
	}
	if strings.HasPrefix(location, "arn:") {
		// Already an ARN; reduce to the bucket ARN to match the S3 scanner.
		return bucketARNFromObjectARN(location)
	}
	bucket := location
	if slash := strings.IndexByte(location, '/'); slash >= 0 {
		bucket = location[:slash]
	}
	bucket = strings.TrimSpace(bucket)
	if bucket == "" {
		return ""
	}
	return "arn:" + awscloud.PartitionForBoundary(boundary) + ":s3:::" + bucket
}

// bucketARNFromObjectARN trims an S3 object ARN down to the bucket ARN so the
// edge joins the S3 bucket node rather than a non-existent object node. It
// preserves the source ARN's partition (aws / aws-cn / aws-us-gov) by matching
// the partition-agnostic `:s3:::` segment rather than only the commercial
// `arn:aws:s3:::` prefix, so a GovCloud or China object ARN still reduces to the
// correct bucket node instead of being passed through whole.
func bucketARNFromObjectARN(arn string) string {
	const marker = ":s3:::"
	trimmed := strings.TrimSpace(arn)
	if !strings.HasPrefix(trimmed, "arn:") {
		return trimmed
	}
	idx := strings.Index(trimmed, marker)
	if idx < 0 {
		return trimmed
	}
	prefix := trimmed[:idx+len(marker)]
	rest := trimmed[idx+len(marker):]
	if slash := strings.IndexByte(rest, '/'); slash >= 0 {
		rest = rest[:slash]
	}
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return trimmed
	}
	return prefix + rest
}
