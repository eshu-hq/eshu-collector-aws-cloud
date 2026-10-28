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
