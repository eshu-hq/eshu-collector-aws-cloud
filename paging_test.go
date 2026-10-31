// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// sizedFact builds one record fact with a payload of about size bytes for
// page-budget tests. The wire size is what SplitFacts accounts.
func sizedFact(id string, size int, observedAt time.Time) sdk.Fact {
	payload := map[string]any{"id": id, "pad": strings.Repeat("x", size)}
	return sdk.Fact{
		Kind:             FactKindRecord,
		SchemaVersion:    "1.0.0",
		StableKey:        "record:" + id,
		SourceConfidence: sdk.SourceConfidenceObserved,
		ObservedAt:       observedAt,
		SourceRef: sdk.SourceRef{
			SourceSystem: SourceSystem,
			ScopeID:      "component:aws-cloud-primary",
			GenerationID: "generation-1",
			FactKey:      "record:" + id,
			URI:          "https://example.invalid/source/aws-cloud#" + id,
			RecordID:     id,
		},
		Payload: payload,
	}
}

func pagedClaim() sdk.Claim {
	return sdk.Claim{
		ComponentID:   ComponentID,
		InstanceID:    "aws-cloud-primary",
		CollectorKind: CollectorKind,
		SourceSystem:  SourceSystem,
		Scope:         sdk.Scope{ID: "component:aws-cloud-primary", Kind: "component"},
		SourceRunID:   "run-1",
		GenerationID:  "generation-1",
		WorkItemID:    "work-1",
		FencingToken:  "fence-1",
		Attempt:       1,
		Deadline:      time.Now().UTC().Add(time.Hour),
		ConfigHandle:  "component-config:aws-cloud",
	}
}

func pagedResult(facts []sdk.Fact, observedAt time.Time) sdk.Result {
	return sdk.Result{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		State:           sdk.ResultComplete,
		Claim:           pagedClaim(),
		Generation:      sdk.Generation{ID: "generation-1", ObservedAt: observedAt},
		Facts:           facts,
		Statuses:        []sdk.Status{{Class: sdk.StatusComplete, FactCount: len(facts)}},
	}
}

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

// TestPaginateLegacyProtocolPassesThrough proves v1alpha1 requests keep the
// exact legacy single-shot shape: no page envelope, untouched protocol.
func TestPaginateLegacyProtocolPassesThrough(t *testing.T) {
	t.Parallel()

	observedAt := time.Now().UTC()
	result := pagedResult([]sdk.Fact{sizedFact("a", 10, observedAt)}, observedAt)
	out, page, err := PaginateResult(result, sdk.ProtocolVersionV1Alpha1, nil, 64)
	if err != nil {
		t.Fatalf("PaginateResult(v1alpha1) error = %v", err)
	}
	if page != nil {
		t.Fatalf("v1alpha1 page = %+v, want nil", page)
	}
	if out.ProtocolVersion != sdk.ProtocolVersionV1Alpha1 || len(out.Facts) != 1 {
		t.Fatalf("v1alpha1 result mutated: protocol=%q facts=%d", out.ProtocolVersion, len(out.Facts))
	}
}

// TestPaginateSinglePageFinalEnvelope proves a small v1alpha3 result emits
// one self-describing final page: no cursor, More false, declared total.
func TestPaginateSinglePageFinalEnvelope(t *testing.T) {
	t.Parallel()

	observedAt := time.Now().UTC()
	result := pagedResult([]sdk.Fact{sizedFact("a", 10, observedAt)}, observedAt)
	out, page, err := PaginateResult(result, ProtocolVersionV1Alpha3, nil, DefaultMaxPageBytes)
	if err != nil {
		t.Fatalf("PaginateResult error = %v", err)
	}
	if page == nil {
		t.Fatal("v1alpha3 page = nil, want final envelope")
	}
	if page.More || page.Cursor != "" || page.PageIndex != 0 || page.TotalFacts != 1 {
		t.Fatalf("final page = %+v, want index 0, total 1, no continuation", page)
	}
	if out.ProtocolVersion != ProtocolVersionV1Alpha3 {
		t.Fatalf("protocol = %q, want v1alpha3", out.ProtocolVersion)
	}
	if len(out.Statuses) != 1 {
		t.Fatalf("final page statuses = %d, want outcome preserved", len(out.Statuses))
	}
}

// TestPaginateFirstPageCarriesContinuation proves an over-budget v1alpha3
// result emits page zero with a resume cursor the host accepts: nonempty
// cursor, More true, gapless index, declared total, and no statuses yet
// (the host sums per-page statuses, so only the final page carries them).
func TestPaginateFirstPageCarriesContinuation(t *testing.T) {
	t.Parallel()

	observedAt := time.Now().UTC()
	facts := []sdk.Fact{
		sizedFact("a", 300, observedAt),
		sizedFact("b", 300, observedAt),
		sizedFact("c", 300, observedAt),
	}
	result := pagedResult(facts, observedAt)
	oneWire, err := FactWireBytes(facts[0])
	if err != nil {
		t.Fatalf("FactWireBytes error = %v", err)
	}
	bound := int64(oneWire + oneWire/2)
	out, page, err := PaginateResult(result, ProtocolVersionV1Alpha3, nil, bound)
	if err != nil {
		t.Fatalf("PaginateResult error = %v", err)
	}
	if page == nil || !page.More || page.Cursor == "" || page.PageIndex != 0 || page.TotalFacts != 3 {
		t.Fatalf("first page = %+v, want continuation at index 0 with total 3", page)
	}
	if len(out.Statuses) != 0 {
		t.Fatalf("non-final page statuses = %d, want none (host sums per page)", len(out.Statuses))
	}
	if len(out.Facts) == 0 || len(out.Facts) == len(facts) {
		t.Fatalf("first page facts = %d, want a strict prefix of %d", len(out.Facts), len(facts))
	}
	for i, fact := range out.Facts {
		if fact.StableKey != facts[i].StableKey {
			t.Fatalf("page fact %d = %q, want stable order %q", i, fact.StableKey, facts[i].StableKey)
		}
	}
	if _, err := decodePageCursor(page.Cursor); err != nil {
		t.Fatalf("first page cursor decodes: %v", err)
	}
}

// TestPaginateContinuationResumesWithPinnedGeneration proves a resumed call
// re-collects, verifies the cursor digest, pins the first page's generation
// (not the re-collection time), and serves the cursored page to completion.
func TestPaginateContinuationResumesWithPinnedGeneration(t *testing.T) {
	t.Parallel()

	firstObservedAt := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	facts := []sdk.Fact{
		sizedFact("a", 300, firstObservedAt),
		sizedFact("b", 300, firstObservedAt),
		sizedFact("c", 300, firstObservedAt),
	}
	oneWire, err := FactWireBytes(facts[0])
	if err != nil {
		t.Fatalf("FactWireBytes error = %v", err)
	}
	bound := int64(oneWire + oneWire/2)
	first, firstPage, err := PaginateResult(pagedResult(facts, firstObservedAt), ProtocolVersionV1Alpha3, nil, bound)
	if err != nil {
		t.Fatalf("first PaginateResult error = %v", err)
	}
	if !firstPage.More {
		t.Fatalf("first page More = false with bound %d, want continuation", bound)
	}

	// The host re-invokes a fresh process: re-collection observes a later
	// time, but the cursor pins the original generation across pages.
	secondObservedAt := firstObservedAt.Add(time.Minute)
	resumed := pagedResult(facts, secondObservedAt)
	second, secondPage, err := PaginateResult(resumed, ProtocolVersionV1Alpha3,
		&PageContinuation{Cursor: firstPage.Cursor}, bound)
	if err != nil {
		t.Fatalf("resume PaginateResult error = %v", err)
	}
	if !second.Generation.ObservedAt.Equal(first.Generation.ObservedAt) {
		t.Fatalf("resumed generation at %v, want pinned %v",
			second.Generation.ObservedAt, first.Generation.ObservedAt)
	}
	if secondPage == nil {
		t.Fatal("resumed page = nil, want page 1")
	}
	// Walk every cursor to the final page and reassemble the fact stream.
	var reassembled []sdk.Fact
	reassembled = append(reassembled, first.Facts...)
	reassembled = append(reassembled, second.Facts...)
	cursor := secondPage.Cursor
	more := secondPage.More
	for more {
		next, nextPage, err := PaginateResult(pagedResult(facts, secondObservedAt),
			ProtocolVersionV1Alpha3, &PageContinuation{Cursor: cursor}, bound)
		if err != nil {
			t.Fatalf("walk PaginateResult error = %v", err)
		}
		if !next.Generation.ObservedAt.Equal(first.Generation.ObservedAt) {
			t.Fatalf("walked generation at %v, want pinned %v",
				next.Generation.ObservedAt, first.Generation.ObservedAt)
		}
		reassembled = append(reassembled, next.Facts...)
		if nextPage == nil {
			t.Fatal("walked page = nil before final, want envelope")
		}
		cursor, more = nextPage.Cursor, nextPage.More
		if !more {
			if nextPage.Cursor != "" {
				t.Fatalf("final page cursor = %q, want empty", nextPage.Cursor)
			}
			if len(next.Statuses) == 0 {
				t.Fatal("final page carries no statuses, want outcome preserved")
			}
			if nextPage.TotalFacts != len(facts) {
				t.Fatalf("final total = %d, want %d", nextPage.TotalFacts, len(facts))
			}
		}
	}
	if len(reassembled) != len(facts) {
		t.Fatalf("reassembled %d facts, want %d", len(reassembled), len(facts))
	}
	for i := range facts {
		if reassembled[i].StableKey != facts[i].StableKey {
			t.Fatalf("reassembled fact %d = %q, want %q", i, reassembled[i].StableKey, facts[i].StableKey)
		}
	}
}

// TestPaginateContinuationRejectsDrift proves facts that moved between the
// first and resumed call fail closed instead of emitting a page the host
// would reject mid-stream as an identity/total mismatch.
func TestPaginateContinuationRejectsDrift(t *testing.T) {
	t.Parallel()

	observedAt := time.Now().UTC()
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
	if !firstPage.More {
		t.Fatalf("first page More = false with bound %d, want continuation", bound)
	}
	drifted := []sdk.Fact{sizedFact("a", 300, observedAt), sizedFact("CHANGED", 300, observedAt)}
	_, _, err = PaginateResult(pagedResult(drifted, observedAt), ProtocolVersionV1Alpha3,
		&PageContinuation{Cursor: firstPage.Cursor}, bound)
	if err == nil {
		t.Fatal("resume after drift error = nil, want failure")
	}
	if _, _, err = PaginateResult(pagedResult(facts, observedAt), sdk.ProtocolVersionV1Alpha1,
		&PageContinuation{Cursor: "bogus"}, 0); err == nil {
		t.Fatal("legacy resume with cursor error = nil, want failure")
	}
}

// TestPaginateOversizeFactFailsTerminal proves a single fact larger than
// the whole page bound becomes a terminal page-budget result (matching the
// existing record/payload budget posture), never a silently dropped fact
// and never an over-budget page write.
func TestPaginateOversizeFactFailsTerminal(t *testing.T) {
	t.Parallel()

	observedAt := time.Now().UTC()
	fact := sizedFact("huge", 2000, observedAt)
	size, err := FactWireBytes(fact)
	if err != nil {
		t.Fatalf("FactWireBytes error = %v", err)
	}
	out, page, err := PaginateResult(pagedResult([]sdk.Fact{fact}, observedAt),
		ProtocolVersionV1Alpha3, nil, int64(size-1))
	if err != nil {
		t.Fatalf("PaginateResult(oversize) error = %v, want terminal result", err)
	}
	if page != nil {
		t.Fatalf("oversize page = %+v, want nil", page)
	}
	if out.State != sdk.ResultTerminal {
		t.Fatalf("oversize state = %q, want terminal", out.State)
	}
	terminal := false
	for _, status := range out.Statuses {
		if status.Class == sdk.StatusFailure && status.FailureClass == FailureClassPageBudgetExceeded {
			terminal = true
		}
	}
	if !terminal {
		t.Fatalf("oversize statuses = %+v, want page-budget-exceeded failure", out.Statuses)
	}
}

// TestPaginateNonCompletableStatesSkipPaging proves unchanged, retryable,
// and terminal results never carry a page envelope: only completable states
// may ask the host for continuation.
func TestPaginateNonCompletableStatesSkipPaging(t *testing.T) {
	t.Parallel()

	observedAt := time.Now().UTC()
	for _, state := range []sdk.ResultState{sdk.ResultUnchanged, sdk.ResultRetryable, sdk.ResultTerminal} {
		result := pagedResult([]sdk.Fact{sizedFact("a", 10, observedAt)}, observedAt)
		result.State = state
		out, page, err := PaginateResult(result, ProtocolVersionV1Alpha3, nil, 64)
		if err != nil {
			t.Fatalf("PaginateResult(%s) error = %v", state, err)
		}
		if page != nil {
			t.Fatalf("PaginateResult(%s) page = %+v, want nil", state, page)
		}
		if out.ProtocolVersion != ProtocolVersionV1Alpha3 {
			t.Fatalf("PaginateResult(%s) protocol = %q, want stamped v1alpha3", state, out.ProtocolVersion)
		}
	}
}

// TestResultPageJSONTagsMatchHostContract pins the page envelope wire shape
// field-for-field against the host's v1alpha3 intake (extensionhost
// pagination.go ResultPage): cursor, more, page_index, total_facts. The
// pinned SDK predates pagination, so this test is the cross-module pin.
func TestResultPageJSONTagsMatchHostContract(t *testing.T) {
	t.Parallel()

	raw, err := json.Marshal(ResultPage{Cursor: "resume-1", More: true, PageIndex: 1, TotalFacts: 30})
	if err != nil {
		t.Fatalf("json.Marshal(ResultPage) error = %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(page) error = %v", err)
	}
	want := map[string]any{"cursor": "resume-1", "more": true, "page_index": 1.0, "total_facts": 30.0}
	if len(decoded) != len(want) {
		t.Fatalf("page keys = %v, want exactly %v", decoded, want)
	}
	for key, value := range want {
		if decoded[key] != value {
			t.Fatalf("page[%q] = %v, want %v", key, decoded[key], value)
		}
	}
	var wire PagedResult
	wire.Result = pagedResult(nil, time.Now().UTC())
	wire.Page = &ResultPage{Cursor: "c", More: true}
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("json.Marshal(PagedResult) error = %v", err)
	}
	if !strings.Contains(string(encoded), `"page":{"cursor":"c","more":true}`) {
		t.Fatalf("paged wire %s misses the page envelope", encoded)
	}
}
