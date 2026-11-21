// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"fmt"
	"testing"
	"time"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// TestResumeTimestampLengthDriftKeepsReassemblyWhole is the Class-1
// regression for eshu-hq/eshu#11085 (post-repin recurrence, 4186
// reassembled vs 4187 declared, delta -1): every continuation call
// re-collects with a fresh generation stamp, and Go marshals time.Time
// as RFC3339Nano with trailing zeros trimmed, so a whole-second stamp
// is 10 wire bytes shorter per fact than a nanos stamp. The cursor
// admission (length + kind/key digest) passes on the byte-drifted set,
// the resume re-splits at shifted page boundaries, and the host
// reassembles pages cut from two different groupings: one fact short.
func TestResumeTimestampLengthDriftKeepsReassemblyWhole(t *testing.T) {
	t.Parallel()

	const total = 4187
	// Nanos first, whole second on resume: the resume wire is shorter,
	// so the re-split packs one extra fact onto page zero and the walk
	// below reassembles exactly one fact short (the live -1 shape).
	firstObserved := time.Date(2026, time.November, 1, 12, 0, 0, 123456789, time.UTC)
	resumeObserved := time.Date(2026, time.November, 1, 12, 1, 0, 0, time.UTC)

	ids := make([]string, 0, total)
	for i := 0; i < total; i++ {
		ids = append(ids, fmt.Sprintf("%04d", i))
	}
	firstFacts := make([]sdk.Fact, 0, total)
	for _, id := range ids {
		firstFacts = append(firstFacts, sizedFact(id, 10, firstObserved))
	}
	resumeFacts := make([]sdk.Fact, 0, total)
	for _, id := range ids {
		resumeFacts = append(resumeFacts, sizedFact(id, 10, resumeObserved))
	}

	firstWire, err := FactWireBytes(firstFacts[0])
	if err != nil {
		t.Fatalf("FactWireBytes error = %v", err)
	}
	resumeWire, err := FactWireBytes(resumeFacts[0])
	if err != nil {
		t.Fatalf("FactWireBytes error = %v", err)
	}
	if firstWire <= resumeWire {
		t.Fatalf("wire drift = %d -> %d, want the resume wire strictly shorter (nanos vs whole second)", firstWire, resumeWire)
	}

	// Isolate a bound where the old split holds exactly m on page zero
	// and the re-split holds exactly m+1: one fact crosses the page-0
	// boundary on resume, the live -1 shape, nothing else.
	bound := int64(0)
	head := 0
	for m := 2; m < total-1; m++ {
		candidate := int64(m) * int64(firstWire)
		if int(candidate/int64(resumeWire)) == m+1 {
			bound, head = candidate, m
			break
		}
	}
	if bound == 0 {
		t.Fatalf("no single-crossing bound: first wire %d, resume wire %d", firstWire, resumeWire)
	}

	first, firstPage, err := PaginateResult(pagedResult(firstFacts, firstObserved), ProtocolVersionV1Alpha3, nil, bound)
	if err != nil {
		t.Fatalf("first PaginateResult error = %v", err)
	}
	if firstPage == nil || !firstPage.More {
		t.Fatalf("first page = %+v, want a multi-page head", firstPage)
	}
	if firstPage.TotalFacts != total {
		t.Fatalf("declared total = %d, want %d", firstPage.TotalFacts, total)
	}
	if len(first.Facts) != head {
		t.Fatalf("first page holds %d facts, want isolated head %d", len(first.Facts), head)
	}

	// Host-style walk: every continuation re-collects (the drifted set)
	// and serves its cursor's page.
	assembled := append([]sdk.Fact{}, first.Facts...)
	continuation := &PageContinuation{Cursor: firstPage.Cursor}
	for range total + 10 {
		out, page, err := PaginateResult(pagedResult(resumeFacts, resumeObserved), ProtocolVersionV1Alpha3, continuation, bound)
		if err != nil {
			t.Fatalf("resume PaginateResult error = %v", err)
		}
		if page == nil {
			t.Fatalf("resume page is nil, want a continuation page")
		}
		if page.TotalFacts != firstPage.TotalFacts {
			t.Fatalf("resume total = %d, want pinned %d", page.TotalFacts, firstPage.TotalFacts)
		}
		assembled = append(assembled, out.Facts...)
		if !page.More {
			break
		}
		continuation = &PageContinuation{Cursor: page.Cursor}
	}

	if len(assembled) != firstPage.TotalFacts {
		t.Fatalf("reassembled %d facts, want declared total %d", len(assembled), firstPage.TotalFacts)
	}
}

// TestResumeLegacyCursorFailsClosed proves a version-1 cursor (minted
// before the page-zero split pinning) fails closed on resume instead of
// re-splitting: an in-flight cursor across a satellite rollout retries
// the claim from page zero, never tears the reassembly.
func TestResumeLegacyCursorFailsClosed(t *testing.T) {
	t.Parallel()

	observedAt := time.Date(2026, time.November, 1, 12, 0, 0, 0, time.UTC)
	facts := []sdk.Fact{sizedFact("a", 300, observedAt), sizedFact("b", 300, observedAt)}
	oneWire, err := FactWireBytes(facts[0])
	if err != nil {
		t.Fatalf("FactWireBytes error = %v", err)
	}
	bound := int64(oneWire + oneWire/2)
	legacy, err := encodePageCursor(pageCursor{
		Version:         pageCursorVersion - 1,
		NextPage:        1,
		TotalFacts:      len(facts),
		GenerationID:    "generation-1",
		ObservedAtNanos: observedAt.UnixNano(),
		Digest:          PageDigest(facts),
	})
	if err != nil {
		t.Fatalf("encodePageCursor error = %v", err)
	}
	if _, _, err := PaginateResult(pagedResult(facts, observedAt), ProtocolVersionV1Alpha3,
		&PageContinuation{Cursor: legacy}, bound); err == nil {
		t.Fatal("resume with legacy cursor error = nil, want failure")
	}
}

// TestResumeTamperedPinFailsClosed proves a cursor whose pinned split no
// longer partitions the bound total fails closed instead of slicing out
// of range or emitting a short page.
func TestResumeTamperedPinFailsClosed(t *testing.T) {
	t.Parallel()

	observedAt := time.Date(2026, time.November, 1, 12, 0, 0, 0, time.UTC)
	facts := []sdk.Fact{sizedFact("a", 300, observedAt), sizedFact("b", 300, observedAt)}
	oneWire, err := FactWireBytes(facts[0])
	if err != nil {
		t.Fatalf("FactWireBytes error = %v", err)
	}
	bound := int64(oneWire + oneWire/2)
	_, firstPage, err := PaginateResult(pagedResult(facts, observedAt), ProtocolVersionV1Alpha3, nil, bound)
	if err != nil {
		t.Fatalf("first PaginateResult error = %v", err)
	}
	if firstPage == nil || !firstPage.More {
		t.Fatalf("first page = %+v, want a multi-page head", firstPage)
	}
	cursor, err := decodePageCursor(firstPage.Cursor)
	if err != nil {
		t.Fatalf("decodePageCursor error = %v", err)
	}
	cursor.PageSizes = []int{1}
	tampered, err := encodePageCursor(cursor)
	if err != nil {
		t.Fatalf("encodePageCursor error = %v", err)
	}
	if _, _, err := PaginateResult(pagedResult(facts, observedAt), ProtocolVersionV1Alpha3,
		&PageContinuation{Cursor: tampered}, bound); err == nil {
		t.Fatal("resume with tampered pin error = nil, want failure")
	}
}
