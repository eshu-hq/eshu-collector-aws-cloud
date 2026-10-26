// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"reflect"
	"testing"
)

// TestCollectorKindMatchesInTree pins the relocated CollectorKind constant.
// In-tree, CollectorKind ("aws") is declared in package awscloud (types.go);
// this port declares it once in collector.go. The value is the durable
// collector_kind carried by every AWS fact.
func TestCollectorKindMatchesInTree(t *testing.T) {
	t.Parallel()
	if got, want := CollectorKind, "aws"; got != want {
		t.Fatalf("CollectorKind = %q, want %q", got, want)
	}
}

// TestAddConditionSummaryIdentityParity freezes the behavior of the ported
// addConditionSummaryIdentity helper: unconditional statements keep their
// identity untouched, conditioned statements gain the joined key/operator
// summaries. Vectors mirror the in-tree contract.
func TestAddConditionSummaryIdentityParity(t *testing.T) {
	t.Parallel()
	t.Run("empty leaves identity untouched", func(t *testing.T) {
		t.Parallel()
		identity := map[string]any{"Service": "s3"}
		addConditionSummaryIdentity(identity, nil, nil)
		want := map[string]any{"Service": "s3"}
		if !reflect.DeepEqual(identity, want) {
			t.Fatalf("identity = %#v, want %#v", identity, want)
		}
	})
	t.Run("nil map with no conditions does not panic", func(t *testing.T) {
		t.Parallel()
		addConditionSummaryIdentity(nil, nil, nil)
	})
	t.Run("keys and operators are comma-joined", func(t *testing.T) {
		t.Parallel()
		identity := map[string]any{}
		addConditionSummaryIdentity(identity,
			[]string{"aws:PrincipalOrgID", "s3:prefix"},
			[]string{"StringEquals", "StringLike"})
		want := map[string]any{
			"condition_keys":      "aws:PrincipalOrgID,s3:prefix",
			"condition_operators": "StringEquals,StringLike",
		}
		if !reflect.DeepEqual(identity, want) {
			t.Fatalf("identity = %#v, want %#v", identity, want)
		}
	})
	t.Run("keys without operators still extend", func(t *testing.T) {
		t.Parallel()
		identity := map[string]any{}
		addConditionSummaryIdentity(identity, []string{"aws:SourceVpce"}, nil)
		if got := identity["condition_keys"]; got != "aws:SourceVpce" {
			t.Fatalf("condition_keys = %#v, want %q", got, "aws:SourceVpce")
		}
		if got := identity["condition_operators"]; got != "" {
			t.Fatalf("condition_operators = %#v, want empty", got)
		}
	})
}
