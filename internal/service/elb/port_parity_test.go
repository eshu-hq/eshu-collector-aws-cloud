// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package elb

import (
	"reflect"
	"testing"
)

// This file pins the ported behavior of package elb against the in-tree
// counterpart. Every vector below is frozen: the const pins repeat the exact
// in-tree literals, and the helper tables encode the verified canonical
// semantics (see the generator notes in the port report).

func TestPortParity_CloneStrings(t *testing.T) {
	t.Parallel()
	if got := cloneStrings(nil); got != nil {
		t.Fatalf("cloneStrings(nil) = %#v, want nil", got)
	}
	got := cloneStrings([]string{"b", "", "a"})
	want := []string{"b", "", "a"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cloneStrings() = %#v, want %#v (plain copy preserves entries)", got, want)
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
