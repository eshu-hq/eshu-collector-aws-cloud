// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package main

import (
	"testing"

	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// TestHealthDigestPrefersTypedOutcomeDigest pins the freshness decoupling:
// the health digest comes from the live typed-evidence digest when the live
// path supplies one, and falls back to the transitional snapshot-fact scan
// only for file mode. Terminal, unchanged, and non-final pages observe
// nothing, exactly like the snapshot scan did for them.
func TestHealthDigestPrefersTypedOutcomeDigest(t *testing.T) {
	t.Parallel()

	complete := sdk.Result{State: sdk.ResultComplete, Facts: []sdk.Fact{
		{Kind: collector.FactKindSnapshot, StableKey: "snapshot:legacy"},
	}}
	finalPage := (*collector.ResultPage)(nil)

	if got := healthDigest("typed:abc", complete, finalPage); got != "typed:abc" {
		t.Fatalf("healthDigest(live) = %q, want typed:abc", got)
	}
	if got := healthDigest("", complete, finalPage); got != "snapshot:legacy" {
		t.Fatalf("healthDigest(file) = %q, want snapshot:legacy", got)
	}
	if got := healthDigest("typed:abc", sdk.Result{State: sdk.ResultTerminal}, finalPage); got != "" {
		t.Fatalf("healthDigest(terminal) = %q, want empty", got)
	}
	if got := healthDigest("typed:abc", sdk.Result{State: sdk.ResultUnchanged}, finalPage); got != "" {
		t.Fatalf("healthDigest(unchanged) = %q, want empty", got)
	}
	if got := healthDigest("typed:abc", complete, &collector.ResultPage{More: true}); got != "" {
		t.Fatalf("healthDigest(non-final page) = %q, want empty", got)
	}
}

// TestUnchangedOutcomeMatchesTypedDigest pins live unchanged detection on
// the typed-evidence digest: a matching previous digest short-circuits to
// ResultUnchanged with no facts, anything else proceeds.
func TestUnchangedOutcomeMatchesTypedDigest(t *testing.T) {
	t.Parallel()

	claim := demoClaim()
	unchanged, done := unchangedOutcome(claim, "typed:abc", "typed:abc")
	if !done {
		t.Fatal("matching digest did not short-circuit")
	}
	if unchanged.State != sdk.ResultUnchanged || len(unchanged.Facts) != 0 {
		t.Fatalf("short-circuit state = %v facts = %d, want Unchanged with 0 facts", unchanged.State, len(unchanged.Facts))
	}
	if _, done := unchangedOutcome(claim, "typed:abc", "typed:def"); done {
		t.Fatal("mismatched digest short-circuited")
	}
	if _, done := unchangedOutcome(claim, "", "typed:abc"); done {
		t.Fatal("empty previous digest short-circuited")
	}
}
