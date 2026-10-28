// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package appsync

import (
	"strings"
	"time"
)

// firstNonEmpty returns the first trimmed-non-empty value, or "" when all are
// empty.
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// cloneStrings returns a trimmed copy of the input slice with empty entries
// dropped, or nil when nothing remains.
func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	output := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			output = append(output, trimmed)
		}
	}
	if len(output) == 0 {
		return nil
	}
	return output
}

// cloneStringMap returns a shallow copy of the tag map, or nil when empty.
func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	output := make(map[string]string, len(values))
	for key, value := range values {
		output[key] = value
	}
	return output
}

// timeOrNil returns the RFC3339 timestamp string for non-zero times, or nil so
// emitted attributes omit unset timestamps.
func timeOrNil(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC().Format(time.RFC3339)
}
