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

// isARN reports whether value looks like an AWS ARN. The scanner uses it to
// guard relationship targets so a free-form name is never emitted as an ARN.

// parseS3URL splits an `s3://bucket[/key]` URL into the bucket name and
// optional object key. It returns ok=false when the input is not an `s3://`
// URL or carries no bucket segment.

// s3BucketARN synthesizes an `arn:<partition>:s3:::<bucket>` ARN, taking the
// partition from sourceARN so GovCloud and China resources do not get a
// commercial-partition target.
func s3BucketARN(partition, bucket string) string {
	return "arn:" + partition + ":s3:::" + bucket
}

// cloneStringMap copies a string map, dropping blank keys, and returns nil for
// an empty result so emitted payloads stay stable across observations.

// cloneStrings copies a slice, dropping blank entries and de-duplicating, and
// returns nil for an empty result.

// timeOrNil returns the UTC time for a non-zero value or nil so emitted
// payloads omit unknown timestamps rather than carrying a zero value.
