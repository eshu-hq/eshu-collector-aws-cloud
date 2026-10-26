// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package codeartifact

import (
	"testing"
	"time"
)

// This file pins the ported behavior of package codeartifact against the in-tree
// counterpart. Every vector below is frozen: the const pins repeat the exact
// in-tree literals, and the helper tables encode the verified canonical
// semantics (see the generator notes in the port report).

func TestPortParity_FirstNonEmpty(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		values []string
		want   string
	}{
		{"none", nil, ""},
		{"blank only", []string{"", "  ", "\t"}, ""},
		{"first wins trimmed", []string{"", "  a ", "b"}, "a"},
		{"single", []string{"x"}, "x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := firstNonEmpty(tc.values...); got != tc.want {
				t.Fatalf("firstNonEmpty(%q) = %q, want %q", tc.values, got, tc.want)
			}
		})
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
