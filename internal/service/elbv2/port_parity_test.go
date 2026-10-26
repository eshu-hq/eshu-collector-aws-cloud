// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package elbv2

import (
	"reflect"
	"testing"
)

// This file pins the ported behavior of package elbv2 against the in-tree
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
