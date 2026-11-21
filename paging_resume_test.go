// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"encoding/json"
	"testing"
	"time"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// TestResumeOrderShiftKeepsReassemblyWhole proves the v1alpha3 resume path
// serves pages from the same logical split as page zero when a
// re-collection returns the identical fact set in a different order (AWS
// list APIs order nothing; every continuation call re-collects). The
// cursor digest is order-insensitive by design (PageDigest sorts), so the
// drifted-order resume passes admission and the host reassembles torn
// pages: duplicated keys with per-call timestamps (a host-side conflicting
// duplicate, eshu-hq/eshu#11085 class 2) and a reassembled count that no
// longer matches the declared total (class 1). The satellite must emit
// pages from a canonical fact order so identical sets always split
// identically, whatever order the source returned them in.
func TestResumeOrderShiftKeepsReassemblyWhole(t *testing.T) {
	t.Parallel()

	firstObserved := time.Date(2026, time.November, 1, 12, 0, 0, 0, time.UTC)
	resumeObserved := firstObserved.Add(time.Minute)

	ids := []string{"a", "b", "c", "d", "e", "f"}
	pads := []int{10, 10, 400, 200, 300, 200}
	firstFacts := make([]sdk.Fact, 0, len(ids))
	for i, id := range ids {
		firstFacts = append(firstFacts, sizedFact(id, pads[i], firstObserved))
	}
	// Same set, reversed: what a re-collection may legally return.
	resumeFacts := make([]sdk.Fact, 0, len(ids))
	for i := len(ids) - 1; i >= 0; i-- {
		resumeFacts = append(resumeFacts, sizedFact(ids[i], pads[i], resumeObserved))
	}

	// Bound the pages so the forward split is [3,2,1] while the reversed
	// split regroups to [2,2,2]: the resume then serves a page the first
	// call never cut.
	wires := make([]int, len(firstFacts))
	for i, fact := range firstFacts {
		size, err := FactWireBytes(fact)
		if err != nil {
			t.Fatalf("FactWireBytes error = %v", err)
		}
		wires[i] = size
	}
	// forward: a+b+c <= B < a+b+c+d; d+e <= B < d+e+f.
	// reversed: f+e <= B < f+e+d; d+c <= B < d+c+b; b+a <= B.
	lower := wires[0] + wires[1] + wires[2]
	if s := wires[3] + wires[4]; s > lower {
		lower = s
	}
	if s := wires[5] + wires[4]; s > lower {
		lower = s
	}
	if s := wires[3] + wires[2]; s > lower {
		lower = s
	}
	upper := wires[0] + wires[1] + wires[2] + wires[3]
	if s := wires[3] + wires[4] + wires[5]; s < upper {
		upper = s
	}
	if s := wires[5] + wires[4] + wires[3]; s < upper {
		upper = s
	}
	if s := wires[3] + wires[2] + wires[1]; s < upper {
		upper = s
	}
	if lower >= upper {
		t.Fatalf("pads do not separate groupings: lower=%d upper=%d wires=%v", lower, upper, wires)
	}
	bound := int64((lower + upper) / 2)

	assertGrouping := func(name string, facts []sdk.Fact, want []int) {
		t.Helper()
		pages, err := SplitFacts(facts, bound)
		if err != nil {
			t.Fatalf("%s SplitFacts error = %v", name, err)
		}
		if len(pages) != len(want) {
			t.Fatalf("%s pages = %d, want %d", name, len(pages), len(want))
		}
		for i, w := range want {
			if len(pages[i]) != w {
				t.Fatalf("%s page %d holds %d facts, want %d", name, i, len(pages[i]), w)
			}
		}
	}
	assertGrouping("forward", firstFacts, []int{3, 2, 1})
	assertGrouping("reversed", resumeFacts, []int{2, 2, 2})

	first, firstPage, err := PaginateResult(pagedResult(firstFacts, firstObserved), ProtocolVersionV1Alpha3, nil, bound)
	if err != nil {
		t.Fatalf("first PaginateResult error = %v", err)
	}
	if firstPage == nil || !firstPage.More {
		t.Fatalf("first page = %+v, want a multi-page head", firstPage)
	}
	if firstPage.TotalFacts != len(ids) {
		t.Fatalf("declared total = %d, want %d", firstPage.TotalFacts, len(ids))
	}

	// Host-style walk: every continuation re-collects (the reversed set)
	// and serves its cursor's page.
	assembled := append([]sdk.Fact{}, first.Facts...)
	continuation := &PageContinuation{Cursor: firstPage.Cursor}
	for range 10 {
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
	seen := make(map[string]string, len(assembled))
	for _, fact := range assembled {
		raw, err := json.Marshal(fact)
		if err != nil {
			t.Fatalf("marshal fact: %v", err)
		}
		key := fact.Kind + "\x00" + fact.StableKey
		if prev, ok := seen[key]; ok && prev != string(raw) {
			t.Fatalf("fact %q reassembled twice with different payloads", key)
		}
		seen[key] = string(raw)
	}
	if len(seen) != len(ids) {
		t.Fatalf("reassembled %d unique keys, want %d", len(seen), len(ids))
	}
}

// TestCountPagedFactsTotalsSplit pins the PaginateResult fail-closed
// self-check counter (eshu-hq/eshu#11085 review P2): it totals whatever
// a split holds, so a dropped page reports fewer than the assembled
// total and the guard fires. The guard's error branch itself is
// unreachable-by-construction unless SplitFacts regresses on its
// set-preservation contract (proven by
// TestResumeOrderShiftKeepsReassemblyWhole); this test pins the counter
// the branch decides on.
func TestCountPagedFactsTotalsSplit(t *testing.T) {
	t.Parallel()

	observed := time.Date(2026, time.November, 1, 12, 0, 0, 0, time.UTC)
	facts := []sdk.Fact{
		sizedFact("a", 400, observed),
		sizedFact("b", 400, observed),
		sizedFact("c", 400, observed),
	}
	pages, err := SplitFacts(facts, 1000)
	if err != nil {
		t.Fatalf("SplitFacts: %v", err)
	}
	if len(pages) < 2 {
		t.Fatalf("want multi-page split, got %d page(s)", len(pages))
	}
	if got := countPagedFacts(pages); got != len(facts) {
		t.Fatalf("countPagedFacts = %d, want %d", got, len(facts))
	}
	if got := countPagedFacts(pages[:len(pages)-1]); got == len(facts) {
		t.Fatalf("dropped page still totals %d, want fewer", got)
	}
	if got := countPagedFacts(nil); got != 0 {
		t.Fatalf("countPagedFacts(nil) = %d, want 0", got)
	}
}
