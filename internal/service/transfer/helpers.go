// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package transfer

import (
	"strings"
)

// isARN reports whether value is an ARN, matching the isARN helpers the other
// scanner packages use to gate ARN-keyed relationship emission.
func isARN(value string) bool {
	return strings.HasPrefix(strings.TrimSpace(value), "arn:")
}
