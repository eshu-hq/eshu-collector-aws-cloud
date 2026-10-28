// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package fms

import (
	"strings"
)

// firstNonEmpty returns the first trimmed, non-empty value, or the empty string
// when every value is blank.
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// sortedUnique returns the trimmed, deduplicated, lexically sorted set of the
// input values. The scanner uses it for member account ids so the emitted
// relationship set is stable and never keyed on AWS response order; a stable
// order keeps the generation-to-generation fact set deterministic.
