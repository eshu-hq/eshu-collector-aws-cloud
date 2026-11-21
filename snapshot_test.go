// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// walkFixture builds a multi-page fact set: six facts whose wire sizes let
// the caller force at least two pages with any bound between the largest
// single fact and the whole stream.
func walkFixture(observedAt time.Time) []sdk.Fact {
	pads := []int{10, 10, 400, 200, 300, 200}
	ids := []string{"a", "b", "c", "d", "e", "f"}
	facts := make([]sdk.Fact, 0, len(ids))
	for i, id := range ids {
		facts = append(facts, sizedFact(id, pads[i], observedAt))
	}
	return facts
}

// walkBound returns a byte bound that splits the fixture into at least two
// pages while every fact still fits.
func walkBound(t *testing.T, facts []sdk.Fact) int64 {
	t.Helper()
	maxSingle, total := 0, 0
	for _, fact := range facts {
		size, err := FactWireBytes(fact)
		if err != nil {
			t.Fatalf("FactWireBytes error = %v", err)
		}
		total += size
		if size > maxSingle {
			maxSingle = size
		}
	}
	bound := int64(maxSingle + (total-maxSingle)/2)
	if int64(maxSingle) >= bound {
		t.Fatalf("fixture does not page: maxSingle=%d total=%d", maxSingle, total)
	}
	return bound
}

func newWalkStore(t *testing.T) *SnapshotStore {
	t.Helper()
	store, err := NewSnapshotStore(SnapshotConfig{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSnapshotStore error = %v", err)
	}
	return store
}

// walkAll resumes a walk to its final page, returning every served page of
// facts in order. It never touches the source: the store is the walk.
func walkAll(t *testing.T, store *SnapshotStore, cursor string, ambientBound int64) [][]sdk.Fact {
	t.Helper()
	var served [][]sdk.Fact
	if cursor == "" {
		return served
	}
	for i := 0; i < 10; i++ {
		out, page, err := store.ResumeWalk(&PageContinuation{Cursor: cursor}, ambientBound)
		if err != nil {
			t.Fatalf("ResumeWalk error = %v", err)
		}
		if page == nil {
			t.Fatal("ResumeWalk page = nil, want a continuation page")
		}
		served = append(served, out.Facts)
		if !page.More {
			return served
		}
		cursor = page.Cursor
	}
	t.Fatal("walk did not terminate within 10 resumes")
	return nil
}

// TestRecollectPathServesMutatedSource pins today's defect as the witness
// the collect-once tests must invert: PaginateResult re-collects per page,
// so a mid-walk source change (same keys, new payloads) passes the key-only
// digest check and serves bytes the first page never cut.
func TestRecollectPathServesMutatedSource(t *testing.T) {
	t.Parallel()

	firstObserved := time.Date(2026, time.November, 1, 12, 0, 0, 0, time.UTC)
	facts := walkFixture(firstObserved)
	bound := walkBound(t, facts)

	first, firstPage, err := PaginateResult(pagedResult(facts, firstObserved), ProtocolVersionV1Alpha3, nil, bound)
	if err != nil {
		t.Fatalf("first PaginateResult error = %v", err)
	}
	if firstPage == nil || !firstPage.More {
		t.Fatalf("first page = %+v, want a multi-page head", firstPage)
	}
	pinned := mustMarshalFact(t, first.Facts[0])

	mutatedObserved := firstObserved.Add(time.Minute)
	mutated := walkFixture(mutatedObserved)
	out, _, err := PaginateResult(pagedResult(mutated, mutatedObserved), ProtocolVersionV1Alpha3,
		&PageContinuation{Cursor: firstPage.Cursor}, bound)
	if err != nil {
		t.Fatalf("resume PaginateResult error = %v", err)
	}
	// Same keys, so the key-only digest admits the re-collection; the
	// payloads moved, so the served page is not the pinned instant.
	for _, fact := range out.Facts {
		if fact.StableKey == first.Facts[0].StableKey {
			if mustMarshalFact(t, fact) == pinned {
				t.Fatal("re-collected page matches the pinned instant, want the drift this test witnesses")
			}
		}
	}
}

func mustMarshalFact(t *testing.T, fact sdk.Fact) string {
	t.Helper()
	raw, err := json.Marshal(fact)
	if err != nil {
		t.Fatalf("marshal fact: %v", err)
	}
	return string(raw)
}

// TestWalkMidWalkSourceChangeServesPinnedInstant is ADR-0001 STEP 2 test 1:
// after the single collect, the source may churn freely; later pages are
// byte-identical to the committed snapshot's split and the content digest
// still verifies.
func TestWalkMidWalkSourceChangeServesPinnedInstant(t *testing.T) {
	t.Parallel()

	store := newWalkStore(t)
	observed := time.Date(2026, time.November, 1, 12, 0, 0, 0, time.UTC)
	facts := walkFixture(observed)
	bound := walkBound(t, facts)

	first, firstPage, err := store.CommitWalk(pagedResult(facts, observed), bound)
	if err != nil {
		t.Fatalf("CommitWalk error = %v", err)
	}
	if firstPage == nil || !firstPage.More {
		t.Fatalf("first page = %+v, want a multi-page head", firstPage)
	}
	if firstPage.TotalFacts != len(facts) {
		t.Fatalf("declared total = %d, want %d", firstPage.TotalFacts, len(facts))
	}

	// The source churns after the collect: new payloads, one extra fact.
	// The walk must never observe it.
	_ = walkFixture(observed.Add(time.Hour))
	served := walkAll(t, store, firstPage.Cursor, bound)
	assembled := first.Facts
	for _, page := range served {
		assembled = append(assembled, page...)
	}
	pinned, err := SplitFacts(canonicalFactOrder(facts), bound)
	if err != nil {
		t.Fatalf("SplitFacts error = %v", err)
	}
	var want []sdk.Fact
	for _, page := range pinned {
		want = append(want, page...)
	}
	if len(assembled) != len(want) {
		t.Fatalf("walk served %d facts, want pinned %d", len(assembled), len(want))
	}
	for i := range want {
		if mustMarshalFact(t, assembled[i]) != mustMarshalFact(t, want[i]) {
			t.Fatalf("walk fact %d drifted from the pinned snapshot", i)
		}
	}
}

// TestWalkRestartResumesIdenticalBytes is ADR-0001 STEP 2 test 2a: one
// satellite process serves each page call, so dropping all process state
// between pages (a fresh store handle on the same directory) must serve
// the identical next page. Restart is resume, not recovery.
func TestWalkRestartResumesIdenticalBytes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	observed := time.Date(2026, time.November, 1, 12, 0, 0, 0, time.UTC)
	facts := walkFixture(observed)
	bound := walkBound(t, facts)

	firstStore, err := NewSnapshotStore(SnapshotConfig{Dir: dir})
	if err != nil {
		t.Fatalf("NewSnapshotStore error = %v", err)
	}
	_, firstPage, err := firstStore.CommitWalk(pagedResult(facts, observed), bound)
	if err != nil {
		t.Fatalf("CommitWalk error = %v", err)
	}

	// Fresh handle, zero shared process state.
	secondStore, err := NewSnapshotStore(SnapshotConfig{Dir: dir})
	if err != nil {
		t.Fatalf("NewSnapshotStore error = %v", err)
	}
	want := walkAll(t, firstStore, firstPage.Cursor, bound)
	got := walkAll(t, secondStore, firstPage.Cursor, bound)
	if len(got) != len(want) {
		t.Fatalf("restarted walk served %d pages, want %d", len(got), len(want))
	}
	for i := range want {
		if len(got[i]) != len(want[i]) {
			t.Fatalf("restarted walk page %d holds %d facts, want %d", i, len(got[i]), len(want[i]))
		}
		for j := range want[i] {
			if mustMarshalFact(t, got[i][j]) != mustMarshalFact(t, want[i][j]) {
				t.Fatalf("restarted walk page %d fact %d differs", i, j)
			}
		}
	}
}

// TestWalkSnapshotLossFailsClosed is ADR-0001 STEP 2 test 2b: a dead
// snapshot (disk gone, wrong volume, TTL expiry, corrupt file) fails the
// walk closed with a retry-from-zero error, and page zero then starts a new
// self-consistent walk under a new digest. The walk never limps on.
func TestWalkSnapshotLossFailsClosed(t *testing.T) {
	t.Parallel()

	store := newWalkStore(t)
	observed := time.Date(2026, time.November, 1, 12, 0, 0, 0, time.UTC)
	facts := walkFixture(observed)
	bound := walkBound(t, facts)

	_, firstPage, err := store.CommitWalk(pagedResult(facts, observed), bound)
	if err != nil {
		t.Fatalf("CommitWalk error = %v", err)
	}
	oldCursor, err := decodePageCursor(firstPage.Cursor)
	if err != nil {
		t.Fatalf("decodePageCursor error = %v", err)
	}

	entries, err := os.ReadDir(store.Dir())
	if err != nil {
		t.Fatalf("ReadDir error = %v", err)
	}
	for _, entry := range entries {
		if err := os.Remove(filepath.Join(store.Dir(), entry.Name())); err != nil {
			t.Fatalf("Remove error = %v", err)
		}
	}
	if _, _, err := store.ResumeWalk(&PageContinuation{Cursor: firstPage.Cursor}, bound); err == nil {
		t.Fatal("ResumeWalk after snapshot loss error = nil, want fail-closed")
	} else if !strings.Contains(err.Error(), "retry the claim") {
		t.Fatalf("ResumeWalk error = %v, want retry-from-zero shape", err)
	}

	// Page zero starts a new self-consistent walk; the dead cursor stays
	// bound to the dead snapshot and can never attach to the new walk.
	later := observed.Add(time.Hour)
	second, secondPage, err := store.CommitWalk(pagedResult(walkFixture(later), later), bound)
	if err != nil {
		t.Fatalf("second CommitWalk error = %v", err)
	}
	newCursor, err := decodePageCursor(secondPage.Cursor)
	if err != nil {
		t.Fatalf("decodePageCursor error = %v", err)
	}
	if newCursor.Snapshot == oldCursor.Snapshot {
		t.Fatal("new walk reuses the dead snapshot digest, want a new lineage")
	}
	served := walkAll(t, store, secondPage.Cursor, bound)
	if secondPage.TotalFacts != len(walkFixture(later)) {
		t.Fatalf("new walk total = %d, want %d", secondPage.TotalFacts, len(walkFixture(later)))
	}
	assembled := append([]sdk.Fact{}, second.Facts...)
	for _, page := range served {
		assembled = append(assembled, page...)
	}
	if len(assembled) != secondPage.TotalFacts {
		t.Fatalf("new walk reassembled %d facts, want declared %d", len(assembled), secondPage.TotalFacts)
	}
	for _, fact := range assembled {
		if !fact.ObservedAt.Equal(later) {
			t.Fatalf("new walk serves fact observed at %v, want pinned %v", fact.ObservedAt, later)
		}
	}
}

// TestWalkConcurrentPageZeroStaysSelfConsistent is ADR-0001 STEP 2 test 4:
// a host retry racing a live walk mints two page-zero snapshots for one
// generation. Digest addressing means the commits never clobber: the newer
// snapshot supersedes the older, the superseded cursor fails closed with a
// retry-from-zero error (never a torn page), and the new walk serves its
// own pinned instant under its own cursor.
func TestWalkConcurrentPageZeroStaysSelfConsistent(t *testing.T) {
	t.Parallel()

	store := newWalkStore(t)
	observed := time.Date(2026, time.November, 1, 12, 0, 0, 0, time.UTC)
	bound := walkBound(t, walkFixture(observed))

	_, pageA, err := store.CommitWalk(pagedResult(walkFixture(observed), observed), bound)
	if err != nil {
		t.Fatalf("CommitWalk A error = %v", err)
	}
	later := observed.Add(time.Hour)
	_, pageB, err := store.CommitWalk(pagedResult(walkFixture(later), later), bound)
	if err != nil {
		t.Fatalf("CommitWalk B error = %v", err)
	}
	cursorA, err := decodePageCursor(pageA.Cursor)
	if err != nil {
		t.Fatalf("decodePageCursor A error = %v", err)
	}
	cursorB, err := decodePageCursor(pageB.Cursor)
	if err != nil {
		t.Fatalf("decodePageCursor B error = %v", err)
	}
	if cursorA.Snapshot == "" || cursorB.Snapshot == "" {
		t.Fatalf("walk cursors bind snapshots %+v %+v, want both bound", cursorA, cursorB)
	}
	if cursorA.Snapshot == cursorB.Snapshot {
		t.Fatal("racing page-zero walks share a snapshot digest, want distinct lineages")
	}
	// The superseded walk fails closed; the new walk serves its instant.
	if _, _, err := store.ResumeWalk(&PageContinuation{Cursor: pageA.Cursor}, bound); err == nil {
		t.Fatal("ResumeWalk superseded error = nil, want fail-closed")
	} else if !strings.Contains(err.Error(), "retry the claim") {
		t.Fatalf("ResumeWalk superseded error = %v, want retry-from-zero shape", err)
	}
	served := walkAll(t, store, pageB.Cursor, bound)
	for _, page := range served {
		for _, fact := range page {
			if !fact.ObservedAt.Equal(later) {
				t.Fatalf("walk B serves fact observed at %v, want pinned %v", fact.ObservedAt, later)
			}
		}
	}
}
