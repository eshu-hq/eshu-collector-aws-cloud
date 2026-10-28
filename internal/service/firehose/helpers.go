// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package firehose

import "strings"

// destinationKindS3 classifies an Amazon S3 (or extended S3) Firehose
// destination.
const destinationKindS3 = "s3"

// destinationKindRedshift classifies an Amazon Redshift Firehose destination.
const destinationKindRedshift = "redshift"

// destinationKindOpenSearch classifies an Amazon OpenSearch Service (or legacy
// Elasticsearch) Firehose destination.
const destinationKindOpenSearch = "opensearch"

// firstNonEmpty returns the first trimmed, non-empty string in values, or "" if
// every value is blank. The scanner uses it to prefer an ARN identity over a
// bare name without persisting an empty identity.
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// isARN reports whether value has the canonical AWS ARN prefix. The scanner
// emits ARN-keyed relationships only when the reported target identity is
// ARN-shaped so the edge joins the ARN-keyed target node.
func isARN(value string) bool {
	return strings.HasPrefix(strings.TrimSpace(value), "arn:")
}
