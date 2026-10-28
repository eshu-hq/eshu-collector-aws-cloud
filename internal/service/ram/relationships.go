// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package ram

import (
	"time"
)

func timeOrNil(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}
