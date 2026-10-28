// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package keyspaces

import (
	"strings"
)

func isARN(value string) bool {
	return strings.HasPrefix(strings.TrimSpace(value), "arn:")
}
