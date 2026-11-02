// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"testing"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// TestCollectTypedOnlySuppressesTransitionalFacts pins the PR-D opt-in:
// with TypedOnly set, file-mode collection emits no snapshot, record, or
// warning facts, while the result state is unchanged. Production keeps
// dual emission until the row census reaches zero unwaived gaps.
func TestCollectTypedOnlySuppressesTransitionalFacts(t *testing.T) {
	t.Parallel()

	result, err := Collect(testClaim(), mustLoadReport(t, "complete.json"), CollectOptions{
		ObservedAt: testObservedAt(),
		SourceURI:  "https://example.invalid/source/aws-cloud",
		TypedOnly:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.State != sdk.ResultComplete {
		t.Fatalf("state = %v, want Complete", result.State)
	}
	for _, fact := range result.Facts {
		t.Fatalf("transitional fact emitted under TypedOnly: %v", fact.Kind)
	}
}

// TestCollectPartialTypedOnlyKeepsWarningStatus pins that the opt-in drops
// the warning fact but preserves the warning status the host reads.
func TestCollectPartialTypedOnlyKeepsWarningStatus(t *testing.T) {
	t.Parallel()

	partial, err := CollectPartial(testClaim(), mustLoadReport(t, "partial.json"), CollectOptions{
		ObservedAt: testObservedAt(),
		SourceURI:  "https://example.invalid/source/aws-cloud",
		TypedOnly:  true,
	}, "source-degraded")
	if err != nil {
		t.Fatal(err)
	}
	if partial.State != sdk.ResultPartial {
		t.Fatalf("state = %v, want Partial", partial.State)
	}
	for _, fact := range partial.Facts {
		t.Fatalf("transitional fact emitted under TypedOnly: %v", fact.Kind)
	}
	found := false
	for _, status := range partial.Statuses {
		if status.Class == sdk.StatusWarning && status.Partial {
			found = true
		}
	}
	if !found {
		t.Fatal("warning status lost under TypedOnly")
	}
}
