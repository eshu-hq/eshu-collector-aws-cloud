// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package vpclattice

import (
	"reflect"
	"testing"
	"time"
)

// This file pins the ported behavior of package vpclattice against the in-tree
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

func TestPortParity_CloneStrings(t *testing.T) {
	t.Parallel()
	if got := cloneStrings(nil); got != nil {
		t.Fatalf("cloneStrings(nil) = %#v, want nil", got)
	}
	if got := cloneStrings([]string{"  ", ""}); got != nil {
		t.Fatalf("cloneStrings(blanks) = %#v, want nil", got)
	}
	got := cloneStrings([]string{" x ", "", "x"})
	want := []string{"x", "x"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cloneStrings() = %#v, want %#v (trimmed, duplicates kept)", got, want)
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
