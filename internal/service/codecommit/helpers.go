// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package codecommit

import (
	"strings"
	"time"
)

// firstNonEmpty returns the first trimmed non-empty value, or the empty string
// when every value is blank.
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// timeOrNil returns the UTC time, or nil when the time is the zero value, so a
// missing timestamp serializes as a null attribute rather than the Go zero
// date.
func timeOrNil(input time.Time) any {
	if input.IsZero() {
		return nil
	}
	return input.UTC()
}

// isARN reports whether value has the canonical AWS ARN prefix. The scanner
// uses it to decide whether a reported KMS key id or trigger destination is an
// ARN-keyed join target.
func isARN(value string) bool {
	return strings.HasPrefix(strings.TrimSpace(value), "arn:")
}

// cloneStringMap returns a copy of input with blank keys dropped, or nil when no
// usable entries remain so omitempty-style payload behavior stays consistent.
func cloneStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	output := make(map[string]string, len(input))
	for key, value := range input {
		trimmed := strings.TrimSpace(key)
		if trimmed == "" {
			continue
		}
		output[trimmed] = value
	}
	if len(output) == 0 {
		return nil
	}
	return output
}
