// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"strings"
	"testing"
	"time"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// TestPageBoundForStdoutDerivesBound proves the per-page bound is the host
// stdout limit minus fixed envelope headroom, and non-positive or headroom-
// only limits fail closed instead of silently shrinking the page to nothing.
func TestPageBoundForStdoutDerivesBound(t *testing.T) {
	t.Parallel()

	bound, err := PageBoundForStdout(4 * 1024 * 1024)
	if err != nil {
		t.Fatalf("PageBoundForStdout(4MiB) error = %v", err)
	}
	if want := int64(4*1024*1024 - 64*1024); bound != want {
		t.Fatalf("bound = %d, want %d", bound, want)
	}
	if DefaultMaxPageBytes != bound {
		t.Fatalf("DefaultMaxPageBytes = %d, want stdout-derived %d", DefaultMaxPageBytes, bound)
	}
	for _, limit := range []int64{0, -1, 64 * 1024, 1} {
		if _, err := PageBoundForStdout(limit); err == nil {
			t.Fatalf("PageBoundForStdout(%d) error = nil, want failure", limit)
		}
	}
}

// TestSplitFactsRespectsByteBudget proves pages preserve order without loss
// or duplication while every page stays within the byte bound.
func TestSplitFactsRespectsByteBudget(t *testing.T) {
	t.Parallel()

	observedAt := time.Now().UTC()
	facts := []sdk.Fact{
		sizedFact("a", 300, observedAt),
		sizedFact("b", 300, observedAt),
		sizedFact("c", 300, observedAt),
		sizedFact("d", 300, observedAt),
	}
	oneWire, err := FactWireBytes(facts[0])
	if err != nil {
		t.Fatalf("FactWireBytes error = %v", err)
	}
	pages, err := SplitFacts(facts, int64(oneWire*2))
	if err != nil {
		t.Fatalf("SplitFacts error = %v", err)
	}
	if len(pages) < 2 {
		t.Fatalf("len(pages) = %d, want at least 2", len(pages))
	}
	var reassembled []sdk.Fact
	for _, page := range pages {
		if len(page) == 0 {
			t.Fatal("SplitFacts emitted an empty page")
		}
		var total int
		for _, fact := range page {
			size, err := FactWireBytes(fact)
			if err != nil {
				t.Fatalf("FactWireBytes error = %v", err)
			}
			total += size
		}
		if int64(total) > int64(oneWire*2) {
			t.Fatalf("page wire bytes = %d, exceeds bound %d", total, oneWire*2)
		}
		reassembled = append(reassembled, page...)
	}
	if len(reassembled) != len(facts) {
		t.Fatalf("reassembled %d facts, want %d", len(reassembled), len(facts))
	}
	for i := range facts {
		if reassembled[i].StableKey != facts[i].StableKey {
			t.Fatalf("fact %d = %q, want order-preserved %q", i, reassembled[i].StableKey, facts[i].StableKey)
		}
	}
}

// TestSplitFactsRejectsOversizeFact proves a single fact larger than the
// whole bound fails closed naming its kind, stable key, and size: callers
// fix the producer, never silently drop the fact.
func TestSplitFactsRejectsOversizeFact(t *testing.T) {
	t.Parallel()

	fact := sizedFact("huge", 2000, time.Now().UTC())
	size, err := FactWireBytes(fact)
	if err != nil {
		t.Fatalf("FactWireBytes error = %v", err)
	}
	_, err = SplitFacts([]sdk.Fact{fact}, int64(size-1))
	if err == nil {
		t.Fatal("SplitFacts(oversize) error = nil, want failure")
	}
	for _, want := range []string{fact.Kind, fact.StableKey} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("oversize error %q misses %q", err.Error(), want)
		}
	}
}

// TestSplitFactsRejectsEmptyAndNonPositive proves empty input and a
// non-positive bound fail closed instead of emitting an empty stream.
func TestSplitFactsRejectsEmptyAndNonPositive(t *testing.T) {
	t.Parallel()

	if _, err := SplitFacts(nil, 1024); err == nil {
		t.Fatal("SplitFacts(nil) error = nil, want failure")
	}
	fact := sizedFact("a", 10, time.Now().UTC())
	if _, err := SplitFacts([]sdk.Fact{fact}, 0); err == nil {
		t.Fatal("SplitFacts(zero bound) error = nil, want failure")
	}
}

// TestPageCursorRoundTrip proves the opaque continuation token survives a
// host round trip with its resume position, pinned generation, and content
// digest intact.
func TestPageCursorRoundTrip(t *testing.T) {
	t.Parallel()

	observedAt := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	facts := []sdk.Fact{sizedFact("a", 10, observedAt), sizedFact("b", 10, observedAt)}
	encoded, err := encodePageCursor(pageCursor{
		Version:         pageCursorVersion,
		NextPage:        2,
		TotalFacts:      len(facts),
		GenerationID:    "generation-1",
		ObservedAtNanos: observedAt.UnixNano(),
		Digest:          PageDigest(facts),
	})
	if err != nil {
		t.Fatalf("encodePageCursor error = %v", err)
	}
	if strings.ContainsAny(encoded, "+/=") {
		t.Fatalf("cursor %q is not URL-safe for JSON transport", encoded)
	}
	decoded, err := decodePageCursor(encoded)
	if err != nil {
		t.Fatalf("decodePageCursor error = %v", err)
	}
	if decoded.NextPage != 2 || decoded.TotalFacts != 2 || decoded.GenerationID != "generation-1" ||
		decoded.ObservedAtNanos != observedAt.UnixNano() || decoded.Digest != PageDigest(facts) {
		t.Fatalf("decoded cursor = %+v, want fields preserved", decoded)
	}
}

// TestPageCursorRejectsGarbage proves malformed, truncated, and wrong-version
// cursors fail closed instead of resuming at an attacker-chosen offset.
func TestPageCursorRejectsGarbage(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"", "!!!", "bm90LWpzb24="} {
		if _, err := decodePageCursor(raw); err == nil {
			t.Fatalf("decodePageCursor(%q) error = nil, want failure", raw)
		}
	}
	encoded, err := encodePageCursor(pageCursor{Version: pageCursorVersion + 1, NextPage: 1})
	if err != nil {
		t.Fatalf("encodePageCursor error = %v", err)
	}
	if _, err := decodePageCursor(encoded); err == nil {
		t.Fatal("decodePageCursor(wrong version) error = nil, want failure")
	}
}
