// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// walkInput copies the complete fixture into an isolated temp file so a
// test can destroy the source after page zero: a collect-once resume must
// still serve every page, which a re-collecting resume could never do.
func walkInput(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/complete.json") // #nosec G304 -- fixed hermetic fixture path
	if err != nil {
		t.Fatalf("ReadFile(fixture) error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("WriteFile(input) error = %v", err)
	}
	return path
}

func walkConfig(t *testing.T, input, snapDir string, extra map[string]any) map[string]any {
	t.Helper()
	config := map[string]any{
		"source":   map[string]any{"input": input},
		"snapshot": map[string]any{"dir": snapDir},
	}
	for key, value := range extra {
		config[key] = value
	}
	return config
}

// runWalkStdio runs one stdio call and reports the run error instead of
// failing: walk tests must assert fail-closed resumes as errors.
func runWalkStdio(t *testing.T, request sdkRequest) (stdioPagedResult, string, error) {
	t.Helper()
	var stdin bytes.Buffer
	if err := json.NewEncoder(&stdin).Encode(request); err != nil {
		t.Fatalf("json.Encode(request) error = %v", err)
	}
	var stdout, stderr bytes.Buffer
	err := run([]string{"--sdk-stdio"}, &stdin, &stdout, &stderr)
	if err != nil {
		return stdioPagedResult{}, stderr.String(), err
	}
	decoder := json.NewDecoder(&stdout)
	decoder.DisallowUnknownFields()
	var decoded stdioPagedResult
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatalf("decode stdio result: %v\nstdout: %s", err, stdout.String())
	}
	return decoded, stderr.String(), nil
}

// walkBoundFor forces a multi-page walk over the fixture: a bound between
// the largest single fact and the whole stream.
func walkBoundFor(t *testing.T, facts []sdk.Fact) float64 {
	t.Helper()
	maxSingle, total := 0, 0
	for _, fact := range facts {
		size, err := collector.FactWireBytes(fact)
		if err != nil {
			t.Fatalf("FactWireBytes error = %v", err)
		}
		total += size
		if size > maxSingle {
			maxSingle = size
		}
	}
	if maxSingle >= total {
		t.Fatalf("fixture does not page: maxSingle=%d total=%d", maxSingle, total)
	}
	return float64(maxSingle + (total-maxSingle)/2)
}

// TestStdioWalkSurvivesSourceDestruction is the end-to-end collect-once
// proof: after page zero commits the snapshot, the source file is
// destroyed, yet every resume serves its pinned page and the walk
// reassembles the exact page-zero stream. One collect per walk.
func TestStdioWalkSurvivesSourceDestruction(t *testing.T) {
	t.Parallel()

	input := walkInput(t)
	snapDir := t.TempDir()
	claim := sdk.Claim{Scope: sdk.Scope{ID: "component:aws-cloud-primary", Kind: "component"}}
	probe, _, err := runWalkStdio(t, sdkRequest{
		ProtocolVersion: collector.ProtocolVersionV1Alpha3,
		Claim:           claim,
		Config:          walkConfig(t, input, snapDir, nil),
	})
	if err != nil {
		t.Fatalf("probe run error = %v", err)
	}
	bound := walkBoundFor(t, probe.Facts)

	paged := func(cursor string, limit float64) (stdioPagedResult, string, error) {
		config := walkConfig(t, input, snapDir, map[string]any{"limits": map[string]any{"maxPageBytes": limit}})
		request := sdkRequest{
			ProtocolVersion: collector.ProtocolVersionV1Alpha3,
			Claim:           claim,
			Config:          config,
		}
		if cursor != "" {
			request.Continuation = &collector.PageContinuation{Cursor: cursor}
		}
		return runWalkStdio(t, request)
	}
	first, _, err := paged("", bound)
	if err != nil {
		t.Fatalf("page-zero run error = %v", err)
	}
	if first.Page == nil || !first.Page.More {
		t.Fatalf("first page = %+v, want a multi-page head", first.Page)
	}
	pinnedTotal := first.Page.TotalFacts

	// Destroy the source: no resume may re-collect from here on.
	if err := os.Remove(input); err != nil {
		t.Fatalf("Remove(input) error = %v", err)
	}

	var reassembled []sdk.Fact
	reassembled = append(reassembled, first.Facts...)
	cursor := first.Page.Cursor
	for cursor != "" {
		next, _, err := paged(cursor, bound)
		if err != nil {
			t.Fatalf("resume run error = %v", err)
		}
		if next.Page == nil {
			t.Fatal("resumed page envelope = nil, want page sequence")
		}
		if next.Page.TotalFacts != pinnedTotal {
			t.Fatalf("resumed total = %d, want pinned %d", next.Page.TotalFacts, pinnedTotal)
		}
		if next.Generation.ID != first.Generation.ID ||
			!next.Generation.ObservedAt.Equal(first.Generation.ObservedAt) {
			t.Fatalf("resumed generation = %+v, want pinned %+v", next.Generation, first.Generation)
		}
		reassembled = append(reassembled, next.Facts...)
		cursor = next.Page.Cursor
	}
	if len(reassembled) != pinnedTotal {
		t.Fatalf("reassembled %d facts, want declared %d", len(reassembled), pinnedTotal)
	}
}

// TestStdioWalkSnapshotLossFailsClosed proves a resume with no snapshot
// behind it fails the run (host retries from page zero) instead of
// emitting a page from an untrusted offset.
func TestStdioWalkSnapshotLossFailsClosed(t *testing.T) {
	t.Parallel()

	input := walkInput(t)
	snapDir := t.TempDir()
	claim := sdk.Claim{Scope: sdk.Scope{ID: "component:aws-cloud-primary", Kind: "component"}}
	probe, _, err := runWalkStdio(t, sdkRequest{
		ProtocolVersion: collector.ProtocolVersionV1Alpha3,
		Claim:           claim,
		Config:          walkConfig(t, input, snapDir, nil),
	})
	if err != nil {
		t.Fatalf("probe run error = %v", err)
	}
	bound := walkBoundFor(t, probe.Facts)
	first, _, err := runWalkStdio(t, sdkRequest{
		ProtocolVersion: collector.ProtocolVersionV1Alpha3,
		Claim:           claim,
		Config:          walkConfig(t, input, snapDir, map[string]any{"limits": map[string]any{"maxPageBytes": bound}}),
	})
	if err != nil {
		t.Fatalf("page-zero run error = %v", err)
	}
	if first.Page == nil || !first.Page.More {
		t.Fatalf("first page = %+v, want a multi-page head", first.Page)
	}
	entries, err := os.ReadDir(snapDir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("ReadDir = %v, %v; want the committed snapshot", entries, err)
	}
	for _, entry := range entries {
		if err := os.Remove(filepath.Join(snapDir, entry.Name())); err != nil {
			t.Fatalf("Remove error = %v", err)
		}
	}
	_, _, err = runWalkStdio(t, sdkRequest{
		ProtocolVersion: collector.ProtocolVersionV1Alpha3,
		Claim:           claim,
		Config:          walkConfig(t, input, snapDir, nil),
		Continuation:    &collector.PageContinuation{Cursor: first.Page.Cursor},
	})
	if err == nil {
		t.Fatal("resume after snapshot loss error = nil, want fail-closed")
	}
	if !strings.Contains(err.Error(), "retry the claim") {
		t.Fatalf("resume error = %v, want retry-from-zero shape", err)
	}
}

// TestStdioWalkServesStoredBoundary proves the resume serves the
// page-zero-pinned bound even when the resume call names a different
// ambient maxPageBytes: the stored boundary serves, not the ambient one.
func TestStdioWalkServesStoredBoundary(t *testing.T) {
	t.Parallel()

	input := walkInput(t)
	snapDir := t.TempDir()
	claim := sdk.Claim{Scope: sdk.Scope{ID: "component:aws-cloud-primary", Kind: "component"}}
	probe, _, err := runWalkStdio(t, sdkRequest{
		ProtocolVersion: collector.ProtocolVersionV1Alpha3,
		Claim:           claim,
		Config:          walkConfig(t, input, snapDir, nil),
	})
	if err != nil {
		t.Fatalf("probe run error = %v", err)
	}
	bound := walkBoundFor(t, probe.Facts)
	first, _, err := runWalkStdio(t, sdkRequest{
		ProtocolVersion: collector.ProtocolVersionV1Alpha3,
		Claim:           claim,
		Config:          walkConfig(t, input, snapDir, map[string]any{"limits": map[string]any{"maxPageBytes": bound}}),
	})
	if err != nil {
		t.Fatalf("page-zero run error = %v", err)
	}
	if first.Page == nil || !first.Page.More {
		t.Fatalf("first page = %+v, want a multi-page head", first.Page)
	}
	// Resume naming the default (much larger) ambient bound must serve the
	// identical next page the stored boundary cuts.
	pinnedNext, _, err := runWalkStdio(t, sdkRequest{
		ProtocolVersion: collector.ProtocolVersionV1Alpha3,
		Claim:           claim,
		Config:          walkConfig(t, input, snapDir, map[string]any{"limits": map[string]any{"maxPageBytes": bound}}),
		Continuation:    &collector.PageContinuation{Cursor: first.Page.Cursor},
	})
	if err != nil {
		t.Fatalf("pinned resume error = %v", err)
	}
	ambientNext, _, err := runWalkStdio(t, sdkRequest{
		ProtocolVersion: collector.ProtocolVersionV1Alpha3,
		Claim:           claim,
		Config:          walkConfig(t, input, snapDir, nil),
		Continuation:    &collector.PageContinuation{Cursor: first.Page.Cursor},
	})
	if err != nil {
		t.Fatalf("ambient resume error = %v", err)
	}
	if len(ambientNext.Facts) != len(pinnedNext.Facts) {
		t.Fatalf("ambient resume page holds %d facts, want stored-boundary %d",
			len(ambientNext.Facts), len(pinnedNext.Facts))
	}
	for i := range pinnedNext.Facts {
		if ambientNext.Facts[i].StableKey != pinnedNext.Facts[i].StableKey {
			t.Fatalf("ambient resume fact %d = %q, want %q", i,
				ambientNext.Facts[i].StableKey, pinnedNext.Facts[i].StableKey)
		}
	}
}

// TestStdioSnapshotConfigMalformedFailsClosed proves a malformed snapshot
// block fails the run instead of silently selecting defaults.
func TestStdioSnapshotConfigMalformedFailsClosed(t *testing.T) {
	t.Parallel()

	input := walkInput(t)
	config := walkConfig(t, input, t.TempDir(), nil)
	config["snapshot"] = map[string]any{"ttlSeconds": "soon"}
	_, _, err := runWalkStdio(t, sdkRequest{
		ProtocolVersion: collector.ProtocolVersionV1Alpha3,
		Claim:           sdk.Claim{Scope: sdk.Scope{ID: "component:aws-cloud-primary", Kind: "component"}},
		Config:          config,
	})
	if err == nil {
		t.Fatal("malformed snapshot config error = nil, want failure")
	}
}

func TestServeSnapshotPageReportsBadStore(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "file")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	cfg := collector.SnapshotConfig{Dir: f.Name()}
	if _, _, err := serveSnapshotPage(cfg, false, nil, sdk.Result{}, 1<<20); err == nil {
		t.Fatal("expected store construction error")
	}
}
