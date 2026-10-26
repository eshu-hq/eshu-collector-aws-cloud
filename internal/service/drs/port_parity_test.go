// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package drs

import (
	"reflect"
	"testing"
)

// This file pins the ported behavior of package drs against the in-tree
// counterpart. Every vector below is frozen: the const pins repeat the exact
// in-tree literals, and the helper tables encode the verified canonical
// semantics (see the generator notes in the port report).

func TestPortParity_CloneStringMap(t *testing.T) {
	t.Parallel()
	if got := cloneStringMap(nil); got != nil {
		t.Fatalf("cloneStringMap(nil) = %#v, want nil", got)
	}
	if got := cloneStringMap(map[string]string{"  ": "x"}); got != nil {
		t.Fatalf("cloneStringMap(blank keys) = %#v, want nil", got)
	}
	got := cloneStringMap(map[string]string{" k ": " v "})
	want := map[string]string{"k": " v "}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cloneStringMap() = %#v, want %#v (keys trimmed, values kept)", got, want)
	}
}

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
