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

// TestSnapshotContentDigestCoversPayload is review advisory (a): snapshot
// integrity needs a content digest over the canonical wire bytes, not the
// key-only PageDigest. Same keys with different payloads must digest
// differently (PageDigest collides by design), and any payload tamper must
// fail a resume closed.
func TestSnapshotContentDigestCoversPayload(t *testing.T) {
	t.Parallel()

	observed := time.Date(2026, time.November, 1, 12, 0, 0, 0, time.UTC)
	before := walkFixture(observed)
	after := walkFixture(observed.Add(time.Minute))

	if PageDigest(before) != PageDigest(after) {
		t.Fatal("PageDigest differs across same-key payloads, want the key-only collision this test contrasts")
	}
	if SnapshotContentDigest(before) == SnapshotContentDigest(after) {
		t.Fatal("SnapshotContentDigest collides across payloads, want content coverage")
	}
	// Order-insensitive like the emission order it pins: identical sets in
	// any arrival order digest identically.
	reversed := append([]sdk.Fact{}, before...)
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	if SnapshotContentDigest(before) != SnapshotContentDigest(reversed) {
		t.Fatal("SnapshotContentDigest varies with arrival order, want canonical-order stability")
	}

	// A tampered snapshot file fails the resume closed: rewrite the
	// committed file with an altered payload under the same name.
	store := newWalkStore(t)
	bound := walkBound(t, before)
	_, firstPage, err := store.CommitWalk(pagedResult(before, observed), bound)
	if err != nil {
		t.Fatalf("CommitWalk error = %v", err)
	}
	entries, err := os.ReadDir(store.Dir())
	if err != nil || len(entries) != 1 {
		t.Fatalf("ReadDir = %v, %v; want exactly one snapshot file", entries, err)
	}
	name := filepath.Join(store.Dir(), entries[0].Name())
	raw, err := os.ReadFile(name) // #nosec G304 -- name comes from the store's own directory listing in a hermetic test
	if err != nil {
		t.Fatalf("ReadFile error = %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	facts, ok := doc["facts"].([]any)
	if !ok || len(facts) == 0 {
		t.Fatalf("snapshot doc facts = %v, want the committed stream", doc["facts"])
	}
	firstFact, ok := facts[0].(map[string]any)
	if !ok {
		t.Fatalf("snapshot fact[0] = %T, want an object", facts[0])
	}
	firstFact["payload"] = map[string]any{"id": "tampered"}
	forged, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal forged snapshot: %v", err)
	}
	if err := os.WriteFile(name, forged, 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}
	if _, _, err := store.ResumeWalk(&PageContinuation{Cursor: firstPage.Cursor}, bound); err == nil {
		t.Fatal("ResumeWalk tampered error = nil, want fail-closed")
	} else if !strings.Contains(err.Error(), "retry the claim") {
		t.Fatalf("ResumeWalk tampered error = %v, want retry-from-zero shape", err)
	}
}

// TestWalkSnapshotCapTripsTerminal is ADR-0001 STEP 2 test 5: an oversized
// snapshot trips terminal snapshot-budget-exceeded, never an over-budget
// page write. A single fact over the page bound still trips the existing
// page-budget terminal first (precedence preserved).
func TestWalkSnapshotCapTripsTerminal(t *testing.T) {
	t.Parallel()

	observed := time.Date(2026, time.November, 1, 12, 0, 0, 0, time.UTC)
	facts := walkFixture(observed)
	wire := 0
	for _, fact := range facts {
		size, err := FactWireBytes(fact)
		if err != nil {
			t.Fatalf("FactWireBytes error = %v", err)
		}
		wire += size
	}

	capped, err := NewSnapshotStore(SnapshotConfig{Dir: t.TempDir(), MaxBytes: int64(wire - 1)})
	if err != nil {
		t.Fatalf("NewSnapshotStore error = %v", err)
	}
	out, page, err := capped.CommitWalk(pagedResult(facts, observed), walkBound(t, facts))
	if err != nil {
		t.Fatalf("CommitWalk cap error = %v, want a terminal result not an error", err)
	}
	if page != nil {
		t.Fatalf("cap page = %+v, want nil (no page write)", page)
	}
	if out.State != sdk.ResultTerminal {
		t.Fatalf("cap state = %q, want terminal", out.State)
	}
	terminal := false
	for _, status := range out.Statuses {
		if status.Class == sdk.StatusFailure && status.FailureClass == FailureClassSnapshotBudgetExceeded {
			terminal = true
		}
	}
	if !terminal {
		t.Fatalf("cap statuses = %+v, want snapshot-budget-exceeded", out.Statuses)
	}
	entries, err := os.ReadDir(capped.Dir())
	if err != nil {
		t.Fatalf("ReadDir error = %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("snapshot dir holds %d files, want none (no over-budget persist)", len(entries))
	}

	// Precedence: a single over-bound fact is still a page-budget
	// terminal even when the snapshot cap would also trip.
	tinyPage, err := NewSnapshotStore(SnapshotConfig{Dir: t.TempDir(), MaxBytes: 1})
	if err != nil {
		t.Fatalf("NewSnapshotStore error = %v", err)
	}
	single := pagedResult([]sdk.Fact{sizedFact("huge", 400, observed)}, observed)
	out, page, err = tinyPage.CommitWalk(single, 64)
	if err != nil {
		t.Fatalf("CommitWalk precedence error = %v", err)
	}
	if page != nil || out.State != sdk.ResultTerminal {
		t.Fatalf("precedence = (%v, %q), want (nil, terminal)", page, out.State)
	}
	for _, status := range out.Statuses {
		if status.FailureClass == FailureClassSnapshotBudgetExceeded {
			t.Fatalf("precedence statuses = %+v, want page-budget not snapshot-budget", out.Statuses)
		}
	}
}

// TestWalkResumeServesStoredBoundary is review advisory (d): the resume
// serves the cursor-pinned page bound (the stored boundary from page zero),
// never the ambient bound of the resume call. A resume arriving with a
// wildly different ambient bound serves the identical pages.
func TestWalkResumeServesStoredBoundary(t *testing.T) {
	t.Parallel()

	store := newWalkStore(t)
	observed := time.Date(2026, time.November, 1, 12, 0, 0, 0, time.UTC)
	facts := walkFixture(observed)
	stored := walkBound(t, facts)

	_, firstPage, err := store.CommitWalk(pagedResult(facts, observed), stored)
	if err != nil {
		t.Fatalf("CommitWalk error = %v", err)
	}
	if firstPage == nil || !firstPage.More {
		t.Fatalf("first page = %+v, want a multi-page head", firstPage)
	}
	cursor, err := decodePageCursor(firstPage.Cursor)
	if err != nil {
		t.Fatalf("decodePageCursor error = %v", err)
	}
	if cursor.PageBound != stored {
		t.Fatalf("cursor bound = %d, want stored %d", cursor.PageBound, stored)
	}

	pinned := walkAll(t, store, firstPage.Cursor, stored)
	ambientHuge := walkAll(t, store, firstPage.Cursor, DefaultMaxPageBytes)
	if len(ambientHuge) != len(pinned) {
		t.Fatalf("ambient-bound walk served %d pages, want stored-boundary %d", len(ambientHuge), len(pinned))
	}
	for i := range pinned {
		if len(ambientHuge[i]) != len(pinned[i]) {
			t.Fatalf("ambient-bound walk page %d holds %d facts, want %d", i, len(ambientHuge[i]), len(pinned[i]))
		}
		for j := range pinned[i] {
			if mustMarshalFact(t, ambientHuge[i][j]) != mustMarshalFact(t, pinned[i][j]) {
				t.Fatalf("ambient-bound walk page %d fact %d differs from stored boundary", i, j)
			}
		}
	}
}

// TestWalkExpiredSnapshotFailsClosed pins the TTL half of the deletion
// rule: a snapshot older than the TTL fails the resume closed even though
// its bytes are intact.
func TestWalkExpiredSnapshotFailsClosed(t *testing.T) {
	t.Parallel()

	store, err := NewSnapshotStore(SnapshotConfig{Dir: t.TempDir(), TTL: time.Hour})
	if err != nil {
		t.Fatalf("NewSnapshotStore error = %v", err)
	}
	observed := time.Date(2026, time.November, 1, 12, 0, 0, 0, time.UTC)
	facts := walkFixture(observed)
	bound := walkBound(t, facts)
	_, firstPage, err := store.CommitWalk(pagedResult(facts, observed), bound)
	if err != nil {
		t.Fatalf("CommitWalk error = %v", err)
	}
	entries, err := os.ReadDir(store.Dir())
	if err != nil || len(entries) != 1 {
		t.Fatalf("ReadDir = %v, %v; want exactly one snapshot file", entries, err)
	}
	name := filepath.Join(store.Dir(), entries[0].Name())
	aged := observed.Add(-2 * time.Hour)
	if err := os.Chtimes(name, aged, aged); err != nil {
		t.Fatalf("Chtimes error = %v", err)
	}
	if _, _, err := store.ResumeWalk(&PageContinuation{Cursor: firstPage.Cursor}, bound); err == nil {
		t.Fatal("ResumeWalk expired error = nil, want fail-closed")
	} else if !strings.Contains(err.Error(), "retry the claim") {
		t.Fatalf("ResumeWalk expired error = %v, want retry-from-zero shape", err)
	}
}

// TestWalkSweepReapsExpired pins the sweeper: expired snapshots are
// unlinked and reported, live ones survive.
func TestWalkSweepReapsExpired(t *testing.T) {
	t.Parallel()

	store, err := NewSnapshotStore(SnapshotConfig{Dir: t.TempDir(), TTL: time.Hour})
	if err != nil {
		t.Fatalf("NewSnapshotStore error = %v", err)
	}
	observed := time.Date(2026, time.November, 1, 12, 0, 0, 0, time.UTC)
	facts := walkFixture(observed)
	bound := walkBound(t, facts)
	if _, _, err := store.CommitWalk(pagedResult(facts, observed), bound); err != nil {
		t.Fatalf("CommitWalk error = %v", err)
	}
	entries, err := os.ReadDir(store.Dir())
	if err != nil || len(entries) != 1 {
		t.Fatalf("ReadDir = %v, %v; want exactly one snapshot file", entries, err)
	}
	name := filepath.Join(store.Dir(), entries[0].Name())
	aged := time.Now().UTC().Add(-2 * time.Hour)
	if err := os.Chtimes(name, aged, aged); err != nil {
		t.Fatalf("Chtimes error = %v", err)
	}
	removed, err := store.Sweep()
	if err != nil {
		t.Fatalf("Sweep error = %v", err)
	}
	if removed != 1 {
		t.Fatalf("Sweep removed = %d, want 1", removed)
	}
	entries, err = os.ReadDir(store.Dir())
	if err != nil {
		t.Fatalf("ReadDir error = %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("snapshot dir holds %d files after sweep, want 0", len(entries))
	}
}

// TestSnapshotStoreRejectsUnwritableDir pins fail-closed construction: a
// path that cannot host the directory errors instead of serving walks with
// no persistence behind them.
func TestSnapshotStoreRejectsUnwritableDir(t *testing.T) {
	t.Parallel()

	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}
	if _, err := NewSnapshotStore(SnapshotConfig{Dir: filepath.Join(blocker, "snapshots")}); err == nil {
		t.Fatal("NewSnapshotStore unwritable error = nil, want failure")
	}
}

// TestSnapshotDefaultsPinParameters pins the STEP-2 parameters review
// advisory (b) arbitrates: a 2 h default TTL (the 1200 s G2 walk bound is
// 20 min; twice that is 40 min; the default carries retry-spacing headroom
// past 40 min, stated exactly) and the 256 MiB snapshot cap (64 pages at
// 4 MiB, the prior ceiling arithmetic).
func TestSnapshotDefaultsPinParameters(t *testing.T) {
	t.Parallel()

	if DefaultSnapshotTTL != 2*time.Hour {
		t.Fatalf("DefaultSnapshotTTL = %v, want 2h", DefaultSnapshotTTL)
	}
	if MaxSnapshotBytes != int64(256<<20) {
		t.Fatalf("MaxSnapshotBytes = %d, want 256MiB", MaxSnapshotBytes)
	}
	cfg := DefaultSnapshotConfig()
	if cfg.TTL != DefaultSnapshotTTL || cfg.MaxBytes != MaxSnapshotBytes {
		t.Fatalf("DefaultSnapshotConfig = %+v, want TTL and cap defaults", cfg)
	}
	if strings.TrimSpace(cfg.Dir) == "" {
		t.Fatal("DefaultSnapshotConfig.Dir is empty, want a default path")
	}
}
