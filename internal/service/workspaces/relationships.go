// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package workspaces

import (
	"strings"
)

// arnOrEmpty returns value when it is ARN-shaped, otherwise "". It keeps a bare
// id from being copied into a target_arn/source_arn field where an ARN is
// expected.
func arnOrEmpty(value string) string {
	if isARN(value) {
		return strings.TrimSpace(value)
	}
	return ""
}
