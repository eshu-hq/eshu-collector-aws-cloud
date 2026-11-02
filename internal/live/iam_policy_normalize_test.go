// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"reflect"
	"testing"
)

func TestNormalizeIAMEffectCanonicalizesCasing(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"Allow": "Allow", "allow": "Allow", " ALLOW ": "Allow",
		"Deny": "Deny", "deny": "Deny",
		"": "", "Permit": "", "all": "",
	}
	for in, want := range cases {
		if got := normalizeIAMEffect(in); got != want {
			t.Fatalf("normalizeIAMEffect(%q) = %q, want %q", in, got, want)
		}
	}
	if got := normalizeIAMEffect(42); got != "" {
		t.Fatalf("normalizeIAMEffect(non-string) = %q, want empty", got)
	}
}

func TestIAMStringListCoercesBothJSONForms(t *testing.T) {
	t.Parallel()

	if got := iamStringList("s3:GetObject"); !reflect.DeepEqual(got, []string{"s3:GetObject"}) {
		t.Fatalf("string form = %v", got)
	}
	if got := iamStringList("   "); got != nil {
		t.Fatalf("blank string = %v, want nil", got)
	}
	if got := iamStringList([]any{"a", " b ", "", 42, nil}); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("array form = %v, want [a b]", got)
	}
	if got := iamStringList(42); got != nil {
		t.Fatalf("non-string form = %v, want nil", got)
	}
	if got := iamStringField("  x  "); got != "x" {
		t.Fatalf("iamStringField = %q, want x", got)
	}
	if got := iamStringField(42); got != "" {
		t.Fatalf("iamStringField(non-string) = %q, want empty", got)
	}
}
