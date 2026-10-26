// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package apprunner

import (
	"reflect"
	"testing"
	"time"
)

// This file pins the ported behavior of package apprunner against the in-tree
// counterpart. Every vector below is frozen: the const pins repeat the exact
// in-tree literals, and the helper tables encode the verified canonical
// semantics (see the generator notes in the port report).

func TestPortParity_ArnOrEmpty(t *testing.T) {
	t.Parallel()
	if got, want := arnOrEmpty("  arn:aws:s3:::b "), "arn:aws:s3:::b"; got != want {
		t.Fatalf("arnOrEmpty() = %q, want %q", got, want)
	}
	if got := arnOrEmpty("bucket"); got != "" {
		t.Fatalf("arnOrEmpty(non-ARN) = %q, want empty", got)
	}
	if got := arnOrEmpty(""); got != "" {
		t.Fatalf("arnOrEmpty(empty) = %q, want empty", got)
	}
}

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

func TestPortParity_DedupeStrings(t *testing.T) {
	t.Parallel()
	if got := dedupeStrings(nil); got != nil {
		t.Fatalf("dedupeStrings(nil) = %#v, want nil", got)
	}
	got := dedupeStrings([]string{"  ", ""})
	if got == nil || len(got) != 0 {
		t.Fatalf("dedupeStrings(blanks) = %#v, want empty non-nil slice", got)
	}
	want := []string{"a", "b"}
	if got := dedupeStrings([]string{"a", "", "a", "b "}); !reflect.DeepEqual(got, want) {
		t.Fatalf("dedupeStrings() = %#v, want %#v", got, want)
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
