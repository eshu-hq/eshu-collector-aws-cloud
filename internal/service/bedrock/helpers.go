// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package bedrock

import (
	"strings"
)

// firstNonEmpty returns the first trimmed non-empty value, or "" when every
// candidate is blank. Scanner identity selection prefers ARNs over names.
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// s3BucketARN synthesizes an `arn:<partition>:s3:::<bucket>` ARN, taking the
// partition from sourceARN so GovCloud and China resources do not get a
// commercial-partition target.
func s3BucketARN(partition, bucket string) string {
	return "arn:" + partition + ":s3:::" + bucket
}
