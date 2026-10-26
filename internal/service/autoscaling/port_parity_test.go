// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package autoscaling

import (
	"testing"
	"time"
)

// This file pins the ported behavior of package autoscaling against the in-tree
// counterpart. Every vector below is frozen: the const pins repeat the exact
// in-tree literals, and the helper tables encode the verified canonical
// semantics (see the generator notes in the port report).

func TestPortParity_Int32PtrOrNil(t *testing.T) {
	t.Parallel()
	if got := int32PtrOrNil(nil); got != nil {
		t.Fatalf("int32PtrOrNil(nil) = %#v, want nil", got)
	}
	five := int32(5)
	if got, want := int32PtrOrNil(&five), any(int32(5)); got != want {
		t.Fatalf("int32PtrOrNil(&5) = %#v, want %#v", got, want)
	}
}

func TestPortParity_TimeOrNil(t *testing.T) {
	t.Parallel()
	if got := timeOrNil(time.Time{}); got != nil {
		t.Fatalf("timeOrNil(zero) = %#v, want nil", got)
	}
	in := time.Date(2026, 3, 4, 5, 6, 7, 0, time.FixedZone("X", 2*3600))
	want := time.Date(2026, 3, 4, 3, 6, 7, 0, time.UTC)
	if got, ok := timeOrNil(in).(time.Time); !ok || !got.Equal(want) {
		t.Fatalf("timeOrNil() = %#v, want %v", timeOrNil(in), want)
	}
}
