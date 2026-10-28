// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package storagegateway

import (
	"strings"
)

// firstNonEmpty returns the first trimmed non-empty value, or "" when every
// value is blank. It mirrors the per-scanner helper used across the AWS cloud
// collector so identity fallbacks read the same way.
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// isARN reports whether value is ARN-shaped (carries the canonical `arn:`
// scheme prefix), matching the isARN helpers spread across the scanner
// packages.
func isARN(value string) bool {
	return strings.HasPrefix(strings.TrimSpace(value), "arn:")
}

// s3BucketARNFromLocation derives the partition-aware S3 bucket ARN and the
// optional object-key prefix from a file-share LocationARN. Storage Gateway
// reports LocationARN as a bucket ARN (`arn:<partition>:s3:::bucket[/prefix/]`).
// The scanner reduces it to the bucket-only ARN the S3 scanner publishes as its
// resource_id so the file-share->bucket edge joins instead of dangling, and
// inherits the partition from the source ARN rather than hardcoding it. It
// returns ok=false when location is not a recognizable S3 bucket ARN (for
// example an S3 access-point ARN, which has a different identity shape).

// S3 bucket ARNs have the empty region/account segments form
// arn:<partition>:s3:::<bucket>[/<key>]. Access-point ARNs carry a region
// and account and an `accesspoint/` resource, so they are not bucket ARNs.

// vpcEndpointID reports the bare VPC endpoint identifier (vpce-...) carried by a
// gateway's reported VPCEndpoint value, or "" when the value is not a `vpce-`
// identifier. DescribeGatewayInformation reports VPCEndpoint as a configuration
// string that is only a join key to the VPC scanner's endpoint node when it is
// the bare `vpce-` ID that node publishes as its resource_id; DNS-hostname or
// IP forms cannot join and are skipped.

// Reject anything beyond the bare ID (a DNS name like vpce-abc123.s3...).

// cloneStringMap returns a copy of input with blank keys dropped, or nil when no
// safe entries remain so omitempty-style payload behavior stays consistent.
func cloneStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	output := make(map[string]string, len(input))
	for key, value := range input {
		if trimmed := strings.TrimSpace(key); trimmed != "" {
			output[trimmed] = value
		}
	}
	if len(output) == 0 {
		return nil
	}
	return output
}
