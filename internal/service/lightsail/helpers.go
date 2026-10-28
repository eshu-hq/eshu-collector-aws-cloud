// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package lightsail

import (
	"time"
)

// timeOrNil returns value in UTC, or nil when it is the zero time, so optional
// timestamp attributes stay absent rather than serializing a zero value.
func timeOrNil(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}
