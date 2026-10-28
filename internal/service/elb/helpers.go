// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package elb

import "strings"

// ec2InstanceTargetType is the target_type for the load-balancer-registers-
// instance edge. Eshu does not emit an aws_ec2_instance resource yet, so this
// is a documented forward reference in relguard.KnownTargetTypeAllowlist; the
// id keyed is the bare instance id (i-...).

// iamServerCertificateTargetType is the target_type for an HTTPS/SSL listener
// whose certificate is an IAM server certificate. Eshu does not scan an IAM
// server-certificate resource yet, so this is a documented forward reference
// in relguard.KnownTargetTypeAllowlist.

// isARN reports whether value has the canonical AWS ARN prefix.
func isARN(value string) bool {
	return strings.HasPrefix(strings.TrimSpace(value), "arn:")
}

// arnService returns the service segment of an ARN
// (arn:partition:service:region:account:resource), or "" when value is not an
// ARN with at least the service field. It lower-cases the segment so the caller
// can compare against canonical service names.

// dedupe trims, drops empties, and removes duplicate values while preserving
// first-seen order. It keeps relationship emission idempotent when AWS reports
// the same id twice.

// nonEmptyStrings returns the trimmed, non-empty values from input, preserving
// order and duplicates.

// cloneStrings returns a defensive copy of input, or nil when input is empty, so
// attribute maps do not alias scanner-owned slices.
func cloneStrings(input []string) []string {
	if len(input) == 0 {
		return nil
	}
	output := make([]string, len(input))
	copy(output, input)
	return output
}
