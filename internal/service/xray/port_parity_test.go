// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package xray

import (
	"testing"
)

// This file pins the ported behavior of package xray against the in-tree
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

func TestPortParity_IsARN(t *testing.T) {
	t.Parallel()
	cases := []struct {
		value string
		want  bool
	}{
		{"arn:aws:s3:::b", true},
		{"  arn:aws:iam::123:role/x ", true},
		{"", false},
		{"arn", false},
		{"ARN:aws:s3:::b", false},
	}
	for _, tc := range cases {
		if got := isARN(tc.value); got != tc.want {
			t.Errorf("isARN(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}
