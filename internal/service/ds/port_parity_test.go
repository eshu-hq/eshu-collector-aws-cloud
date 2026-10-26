// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package ds

import (
	"reflect"
	"testing"
)

// This file pins the ported behavior of package ds against the in-tree
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

func TestPortParity_RelationshipRecordID(t *testing.T) {
	t.Parallel()
	if got, want := relationshipRecordID(" s ", "uses ", " id "), "s->uses:id"; got != want {
		t.Fatalf("relationshipRecordID() = %q, want %q", got, want)
	}
}
