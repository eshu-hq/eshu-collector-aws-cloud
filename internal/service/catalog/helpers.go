// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package servicecatalog

import (
	"strings"
	"time"
)

// firstNonEmpty returns the first trimmed, non-empty value in values, or the
// empty string when every value is blank. The scanner sources a resource's own
// outgoing edges on the same identifier it publishes as the node resource_id
// (firstNonEmpty(arn, id)), so the edge resolves to the node instead of
// dangling.
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func timeOrNil(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}
