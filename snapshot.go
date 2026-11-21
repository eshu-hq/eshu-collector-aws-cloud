// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// FailureClassSnapshotBudgetExceeded is the terminal failure class when one
// walk's snapshot exceeds the snapshot byte cap. It mirrors
// FailureClassPageBudgetExceeded: a satellite-minted bounded-failure shape
// the host admission path already handles, so no new host vocabulary is
// required.
const FailureClassSnapshotBudgetExceeded = "snapshot-budget-exceeded"

// DefaultSnapshotTTL bounds how long a walk snapshot survives unacked. The
// 1200 s G2 walk bound is 20 minutes, so twice that bound is 40 minutes;
// the default carries headroom past 40 minutes for host retry spacing and
// for the final page, whose delivery is never acked. A snapshot older than
// the TTL fails its resume closed; the sweeper unlinks it.
const DefaultSnapshotTTL = 2 * time.Hour

// MaxSnapshotBytes caps one walk snapshot file: 64 pages at 4 MiB, the
// prior ceiling arithmetic. Typical walks (~37 MiB at resource scale) sit
// 7x under it; all-large policy-scale walks (~140 MB) fit. Exceeding it is
// a terminal snapshot-budget-exceeded failure, never a partial persist.
const MaxSnapshotBytes = int64(256 << 20)

// snapshotFileVersion versions the on-disk snapshot document. A future
// shape bumps it; older satellites fail closed on unknown versions.
const snapshotFileVersion = 1

// SnapshotContentDigest returns the stable identity of one generation's
// fact stream over the canonical wire bytes: every fact's exact JSON in
// emission order, length-framed so no payload can smuggle a separator.
// Unlike the key-only PageDigest (which collides across same-key payload
// churn by design), any payload change moves this digest, so a tampered
// snapshot file fails its resume closed.
func SnapshotContentDigest(facts []sdk.Fact) string {
	ordered := canonicalFactOrder(facts)
	writer := sha256.New()
	var frame [4]byte
	for _, fact := range ordered {
		raw, err := json.Marshal(fact)
		if err != nil {
			continue
		}
		frame[0] = byte(len(raw) >> 24)
		frame[1] = byte(len(raw) >> 16)
		frame[2] = byte(len(raw) >> 8)
		frame[3] = byte(len(raw))
		writer.Write(frame[:])
		writer.Write(raw)
	}
	return hex.EncodeToString(writer.Sum(nil))
}

// snapshotDoc is the on-disk walk snapshot: everything a stateless resume
// needs to serve any page without re-collecting. Claim, generation,
// statuses, and the ordered fact stream are pinned at page zero; the
// resume serves slices of exactly these bytes.
type snapshotDoc struct {
	Version      int            `json:"v"`
	Instance     string         `json:"instance"`
	GenerationID string         `json:"generation"`
	Total        int            `json:"total"`
	Digest       string         `json:"digest"`
	KeyDigest    string         `json:"key_digest"`
	PageBound    int64          `json:"bound"`
	State        string         `json:"state"`
	Claim        sdk.Claim      `json:"claim"`
	Generation   sdk.Generation `json:"generation_doc"`
	Statuses     []sdk.Status   `json:"statuses"`
	Facts        []sdk.Fact     `json:"facts"`
}

// sanitizeFileComponent keeps snapshot filenames (which carry instance
// and generation identities) to a safe alphabet. Counts and shapes may
// appear in logs; raw cloud identifiers never do.
func sanitizeFileComponent(value string) string {
	var kept strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			kept.WriteRune(r)
		default:
			kept.WriteByte('_')
		}
	}
	out := kept.String()
	if out == "" {
		return "x"
	}
	if len(out) > 64 {
		return out[:64]
	}
	return out
}

func snapshotFilePrefix(instance, generation string) string {
	return "walk-" + sanitizeFileComponent(instance) + "-" + sanitizeFileComponent(generation) + "-"
}

func snapshotFileName(instance, generation, digest string) string {
	return snapshotFilePrefix(instance, generation) + digest + ".json"
}

func retryZero(format string, args ...any) error {
	return fmt.Errorf("snapshot walk is stale, retry the claim from page zero: "+format, args...)
}

// CommitWalk serves page zero of a walk from one fresh collect: it
// canonical-orders the facts, splits at the page bound, persists the
// ordered stream as a digest-addressed snapshot before serving, and mints
// a cursor binding the snapshot, the declared total, the generation, and
// the bound used. A single over-bound fact is still a page-budget
// terminal (precedence preserved); an over-cap snapshot is a
// snapshot-budget terminal with no page write and no persist.
func (s *SnapshotStore) CommitWalk(result sdk.Result, pageBound int64) (sdk.Result, *ResultPage, error) {
	result.ProtocolVersion = ProtocolVersionV1Alpha3
	if result.State != sdk.ResultComplete && result.State != sdk.ResultPartial {
		return result, nil, nil
	}
	if len(result.Facts) == 0 {
		return result, nil, nil
	}
	result.Facts = canonicalFactOrder(result.Facts)
	bound := effectivePageBound(pageBound)
	pages, err := SplitFacts(result.Facts, bound)
	if err != nil {
		return pageBudgetExceeded(result), nil, nil
	}
	if paged := countPagedFacts(pages); paged != len(result.Facts) {
		return sdk.Result{}, nil, fmt.Errorf(
			"paging split holds %d facts, want assembled total %d",
			paged, len(result.Facts),
		)
	}
	var wire int64
	for _, fact := range result.Facts {
		size, err := FactWireBytes(fact)
		if err != nil {
			return sdk.Result{}, nil, err
		}
		wire += int64(size)
	}
	if wire > s.maxBytes {
		out := result
		out.Facts = nil
		return snapshotBudgetExceeded(out), nil, nil
	}
	instance := strings.TrimSpace(result.Claim.InstanceID)
	if instance == "" {
		instance = "unknown-instance"
	}
	digest := SnapshotContentDigest(result.Facts)
	doc := snapshotDoc{
		Version:      snapshotFileVersion,
		Instance:     instance,
		GenerationID: result.Generation.ID,
		Total:        len(result.Facts),
		Digest:       digest,
		KeyDigest:    PageDigest(result.Facts),
		PageBound:    bound,
		State:        string(result.State),
		Claim:        result.Claim,
		Generation:   result.Generation,
		Statuses:     result.Statuses,
		Facts:        result.Facts,
	}
	if err := s.persist(instance, result.Generation.ID, digest, doc); err != nil {
		return sdk.Result{}, nil, err
	}
	total := len(result.Facts)
	if len(pages) == 1 {
		result.Facts = pages[0]
		return result, &ResultPage{PageIndex: 0, TotalFacts: total}, nil
	}
	cursor, err := encodePageCursor(pageCursor{
		Version:         pageCursorVersion,
		NextPage:        1,
		TotalFacts:      total,
		GenerationID:    result.Generation.ID,
		ObservedAtNanos: result.Generation.ObservedAt.UTC().UnixNano(),
		FreshnessHint:   result.Generation.FreshnessHint,
		TrustedDeletion: result.Generation.TrustedDeletion,
		Digest:          PageDigest(result.Facts),
		Snapshot:        digest,
		PageBound:       bound,
		InstanceID:      instance,
	})
	if err != nil {
		return sdk.Result{}, nil, err
	}
	result.Facts = pages[0]
	return result, &ResultPage{Cursor: cursor, More: true, PageIndex: 0, TotalFacts: total}, nil
}

// persist writes one snapshot atomically (temp + fsync + rename, 0600:
// files carry fact payloads), supersedes older snapshots of the same
// instance and generation, and sweeps TTL-expired files. Digest addressing
// makes concurrent page-zero commits safe: files never clobber, and each
// walk's cursor binds its own digest.
func (s *SnapshotStore) persist(instance, generation, digest string, doc snapshotDoc) (err error) {
	name := snapshotFileName(instance, generation, digest)
	path := filepath.Join(s.dir, name)
	tmp, err := os.CreateTemp(s.dir, ".walk-*.tmp")
	if err != nil {
		return fmt.Errorf("snapshot temp file: %w", err)
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			// Best effort: the TTL sweep reaps orphaned temp files, so a
			// removal failure joins the error already in flight instead
			// of replacing it.
			if removeErr := os.Remove(tmpName); removeErr != nil && !os.IsNotExist(removeErr) {
				err = errors.Join(err, fmt.Errorf("snapshot remove temp: %w", removeErr))
			}
		}
	}()
	encoder := json.NewEncoder(tmp)
	if err := encoder.Encode(doc); err != nil {
		if closeErr := tmp.Close(); closeErr != nil {
			return errors.Join(fmt.Errorf("snapshot encode: %w", err), fmt.Errorf("snapshot close temp: %w", closeErr))
		}
		return fmt.Errorf("snapshot encode: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		if closeErr := tmp.Close(); closeErr != nil {
			return errors.Join(fmt.Errorf("snapshot fsync: %w", err), fmt.Errorf("snapshot close temp: %w", closeErr))
		}
		return fmt.Errorf("snapshot fsync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("snapshot close: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("snapshot chmod: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("snapshot commit: %w", err)
	}
	committed = true
	// Supersede: a newer snapshot for the same instance and generation
	// ends the older walk's lineage. Stale cursors keep failing closed;
	// they can never attach to the new walk because the digest differs.
	prefix := snapshotFilePrefix(instance, generation)
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return fmt.Errorf("snapshot supersede list: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) || entry.Name() == name {
			continue
		}
		if err := os.Remove(filepath.Join(s.dir, entry.Name())); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("snapshot supersede remove: %w", err)
		}
	}
	// Reap or report: load-time TTL checks already fail expired walks
	// closed, so a sweep failure delays unlinking rather than corrupting
	// state — but it is still reported instead of swallowed.
	if _, err := s.Sweep(); err != nil {
		return fmt.Errorf("snapshot sweep: %w", err)
	}
	return nil
}

// ResumeWalk serves the cursor's page from the committed snapshot without
// touching the source: the snapshot is loaded by its digest, the content
// digest and fact count are verified against the cursor, and the split
// reuses the cursor-pinned page bound (the stored boundary), never the
// resume call's ambient bound. Any miss or mismatch fails the walk closed
// with the retry-from-zero error shape the host already consumes.
func (s *SnapshotStore) ResumeWalk(continuation *PageContinuation, ambientBound int64) (sdk.Result, *ResultPage, error) {
	_ = ambientBound
	if continuation == nil || strings.TrimSpace(continuation.Cursor) == "" {
		return sdk.Result{}, nil, retryZero("no resume cursor")
	}
	cursor, err := decodePageCursor(continuation.Cursor)
	if err != nil {
		return sdk.Result{}, nil, err
	}
	if strings.TrimSpace(cursor.Snapshot) == "" || cursor.PageBound <= 0 || strings.TrimSpace(cursor.InstanceID) == "" {
		return sdk.Result{}, nil, retryZero("cursor predates snapshot binding")
	}
	path := filepath.Join(s.dir, snapshotFileName(cursor.InstanceID, cursor.GenerationID, cursor.Snapshot))
	info, err := os.Stat(path)
	if err != nil {
		return sdk.Result{}, nil, retryZero("snapshot %q is gone", cursor.Snapshot)
	}
	if info.ModTime().Add(s.ttl).Before(time.Now()) {
		return sdk.Result{}, nil, retryZero("snapshot %q is older than the TTL", cursor.Snapshot)
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- path is the store's own directory joined with cursor-bound names
	if err != nil {
		return sdk.Result{}, nil, retryZero("snapshot %q is gone", cursor.Snapshot)
	}
	var doc snapshotDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return sdk.Result{}, nil, retryZero("snapshot %q is corrupt", cursor.Snapshot)
	}
	if doc.Version != snapshotFileVersion {
		return sdk.Result{}, nil, retryZero("snapshot version %d is unsupported", doc.Version)
	}
	if doc.Digest != cursor.Snapshot || SnapshotContentDigest(doc.Facts) != cursor.Snapshot {
		return sdk.Result{}, nil, retryZero("snapshot content moved")
	}
	if doc.KeyDigest != cursor.Digest || PageDigest(doc.Facts) != cursor.Digest {
		return sdk.Result{}, nil, retryZero("snapshot key set moved")
	}
	if doc.Total != cursor.TotalFacts || len(doc.Facts) != cursor.TotalFacts {
		return sdk.Result{}, nil, retryZero("snapshot binds %d facts, cursor declares %d", len(doc.Facts), cursor.TotalFacts)
	}
	if doc.GenerationID != cursor.GenerationID {
		return sdk.Result{}, nil, retryZero("snapshot generation moved")
	}
	// The stored boundary serves: the resume call's ambient bound never
	// re-splits a pinned walk.
	pages, err := SplitFacts(canonicalFactOrder(doc.Facts), cursor.PageBound)
	if err != nil {
		return sdk.Result{}, nil, retryZero("stored boundary no longer pages the snapshot")
	}
	if paged := countPagedFacts(pages); paged != cursor.TotalFacts {
		return sdk.Result{}, nil, retryZero("stored split holds %d facts, want %d", paged, cursor.TotalFacts)
	}
	if cursor.NextPage >= len(pages) {
		return sdk.Result{}, nil, retryZero("cursor resumes at page %d of %d", cursor.NextPage, len(pages))
	}
	result := sdk.Result{
		ProtocolVersion: ProtocolVersionV1Alpha3,
		State:           sdk.ResultState(doc.State),
		Claim:           doc.Claim,
		Generation: sdk.Generation{
			ID:              cursor.GenerationID,
			ObservedAt:      doc.Generation.ObservedAt,
			FreshnessHint:   cursor.FreshnessHint,
			TrustedDeletion: cursor.TrustedDeletion,
		},
		Statuses: doc.Statuses,
	}
	index := cursor.NextPage
	result.Facts = pages[index]
	if index == len(pages)-1 {
		return result, &ResultPage{PageIndex: index, TotalFacts: cursor.TotalFacts}, nil
	}
	next, err := encodePageCursor(pageCursor{
		Version:         pageCursorVersion,
		NextPage:        index + 1,
		TotalFacts:      cursor.TotalFacts,
		GenerationID:    cursor.GenerationID,
		ObservedAtNanos: cursor.ObservedAtNanos,
		FreshnessHint:   cursor.FreshnessHint,
		TrustedDeletion: cursor.TrustedDeletion,
		Digest:          cursor.Digest,
		Snapshot:        cursor.Snapshot,
		PageBound:       cursor.PageBound,
		InstanceID:      cursor.InstanceID,
	})
	if err != nil {
		return sdk.Result{}, nil, err
	}
	return result, &ResultPage{Cursor: next, More: true, PageIndex: index, TotalFacts: cursor.TotalFacts}, nil
}

// Sweep unlinks TTL-expired walk snapshots and reports how many it
// reaped. Load-time TTL checks already fail expired walks closed, so the
// sweeper only bounds directory growth; it never decides correctness.
func (s *SnapshotStore) Sweep() (int, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return 0, fmt.Errorf("snapshot sweep list: %w", err)
	}
	now := time.Now()
	reaped := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, "walk-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if !info.ModTime().Add(s.ttl).Before(now) {
			continue
		}
		if err := os.Remove(filepath.Join(s.dir, name)); err != nil {
			continue
		}
		reaped++
	}
	return reaped, nil
}

// snapshotBudgetExceeded converts an over-cap snapshot into the
// bounded-failure shape the page budget uses: explicit terminal state with
// a failure class, never an ambiguous complete and never a partial persist
// the host could mistake for a servable walk.
func snapshotBudgetExceeded(result sdk.Result) sdk.Result {
	return sdk.Result{
		ProtocolVersion: ProtocolVersionV1Alpha3,
		State:           sdk.ResultTerminal,
		Claim:           result.Claim,
		Generation:      result.Generation,
		Statuses: []sdk.Status{{
			Class: sdk.StatusFailure, FailureClass: FailureClassSnapshotBudgetExceeded,
		}},
	}
}
