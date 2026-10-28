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

// int32OrNil returns the pointed-to int32, or nil when value is nil, so optional
// numeric attributes stay absent rather than serializing a zero value.

// cloneStringSlice returns a trimmed copy of input with blank entries dropped,
// or nil when nothing survives, keeping the omitempty-style payload behavior
// consistent across services.

// cloneInt32Slice returns a copy of input, or nil when input is empty, so
// optional numeric-list attributes stay absent rather than serializing an empty
// slice.
