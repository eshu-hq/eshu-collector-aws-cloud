// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// stdioPagedResult decodes one stdout document with its optional v1alpha3
// page envelope, mirroring the host intake shape.
type stdioPagedResult struct {
	sdk.Result
	Page *collector.ResultPage `json:"page,omitempty"`
}

func stdioFileConfig(t *testing.T, extra map[string]any) map[string]any {
	t.Helper()
	config := map[string]any{
		"source": map[string]any{"input": "../../testdata/complete.json"},
	}
	for key, value := range extra {
		config[key] = value
	}
	return config
}

func runStdio(t *testing.T, request sdkRequest) (stdioPagedResult, string) {
	t.Helper()
	var stdin bytes.Buffer
	if err := json.NewEncoder(&stdin).Encode(request); err != nil {
		t.Fatalf("json.Encode(request) error = %v", err)
	}
	var stdout, stderr bytes.Buffer
	if err := run([]string{"--sdk-stdio"}, &stdin, &stdout, &stderr); err != nil {
		t.Fatalf("run(--sdk-stdio) error = %v", err)
	}
	decoder := json.NewDecoder(&stdout)
	decoder.DisallowUnknownFields()
	var decoded stdioPagedResult
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatalf("decode stdio result: %v\nstdout: %s", err, stdout.String())
	}
	return decoded, stderr.String()
}

// TestStdioV1Alpha1HasNoPageEnvelope proves legacy requests keep the exact
// single-shot shape: v1alpha1 protocol, facts inline, no page key.
func TestStdioV1Alpha1HasNoPageEnvelope(t *testing.T) {
	t.Parallel()

	request := sdkRequest{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		Claim:           sdk.Claim{Scope: sdk.Scope{ID: "component:aws-cloud-primary", Kind: "component"}},
		Config:          stdioFileConfig(t, nil),
	}
	decoded, _ := runStdio(t, request)
	if decoded.Page != nil {
		t.Fatalf("v1alpha1 page = %+v, want nil", decoded.Page)
	}
	if decoded.ProtocolVersion != sdk.ProtocolVersionV1Alpha1 {
		t.Fatalf("protocol = %q, want v1alpha1", decoded.ProtocolVersion)
	}
	if len(decoded.Facts) == 0 {
		t.Fatal("v1alpha1 facts empty, want the complete fixture stream")
	}
}

// TestStdioV1Alpha3SinglePageFinalEnvelope proves a small v1alpha3 result
// emits one self-describing final page: declared total, no cursor.
func TestStdioV1Alpha3SinglePageFinalEnvelope(t *testing.T) {
	t.Parallel()

	request := sdkRequest{
		ProtocolVersion: collector.ProtocolVersionV1Alpha3,
		Claim:           sdk.Claim{Scope: sdk.Scope{ID: "component:aws-cloud-primary", Kind: "component"}},
		Config:          stdioFileConfig(t, nil),
	}
	decoded, _ := runStdio(t, request)
	if decoded.ProtocolVersion != collector.ProtocolVersionV1Alpha3 {
		t.Fatalf("protocol = %q, want v1alpha3", decoded.ProtocolVersion)
	}
	if decoded.Page == nil {
		t.Fatal("v1alpha3 page = nil, want final envelope")
	}
	if decoded.Page.More || decoded.Page.Cursor != "" || decoded.Page.PageIndex != 0 {
		t.Fatalf("final page = %+v, want index 0 with no continuation", decoded.Page)
	}
	if decoded.Page.TotalFacts != len(decoded.Facts) {
		t.Fatalf("total_facts = %d, want emitted %d", decoded.Page.TotalFacts, len(decoded.Facts))
	}
}

// TestStdioV1Alpha3WalksContinuationToGreen proves the satellite lane of
// eshu-hq/eshu#9716 end to end: an over-budget first scan splits into
// bounded pages, every continuation cursor resumes the pinned generation,
// and walking every cursor reassembles the exact single-shot fact stream
// with the outcome preserved on the final page.
func TestStdioV1Alpha3WalksContinuationToGreen(t *testing.T) {
	t.Parallel()

	claim := sdk.Claim{Scope: sdk.Scope{ID: "component:aws-cloud-primary", Kind: "component"}}
	first, _ := runStdio(t, sdkRequest{
		ProtocolVersion: collector.ProtocolVersionV1Alpha3,
		Claim:           claim,
		Config:          stdioFileConfig(t, nil),
	})
	if len(first.Facts) < 3 {
		t.Fatalf("fixture facts = %d, want at least 3 to force paging", len(first.Facts))
	}
	maxSingle := 0
	total := 0
	for _, fact := range first.Facts {
		size, err := collector.FactWireBytes(fact)
		if err != nil {
			t.Fatalf("FactWireBytes error = %v", err)
		}
		total += size
		if size > maxSingle {
			maxSingle = size
		}
	}
	// A bound between the largest single fact and the whole stream forces
	// at least two pages while every fact still fits.
	bound := float64(maxSingle + (total-maxSingle)/2)
	paged := func(cursor string) stdioPagedResult {
		config := stdioFileConfig(t, map[string]any{"limits": map[string]any{"maxPageBytes": bound}})
		request := sdkRequest{
			ProtocolVersion: collector.ProtocolVersionV1Alpha3,
			Claim:           claim,
			Config:          config,
		}
		if cursor != "" {
			request.Continuation = &collector.PageContinuation{Cursor: cursor}
		}
		decoded, _ := runStdio(t, request)
		return decoded
	}
	page := paged("")
	if page.Page == nil || !page.Page.More || page.Page.Cursor == "" {
		t.Fatalf("first page = %+v, want continuation", page.Page)
	}
	var reassembled []sdk.Fact
	reassembled = append(reassembled, page.Facts...)
	pinnedGeneration := page.Generation
	cursor := page.Page.Cursor
	for cursor != "" {
		next := paged(cursor)
		if !next.Generation.ObservedAt.Equal(pinnedGeneration.ObservedAt) ||
			next.Generation.ID != pinnedGeneration.ID {
			t.Fatalf("resumed generation = %+v, want pinned %+v", next.Generation, pinnedGeneration)
		}
		reassembled = append(reassembled, next.Facts...)
		if next.Page == nil {
			t.Fatal("resumed page envelope = nil, want page sequence")
		}
		if next.Page.TotalFacts != len(first.Facts) {
			t.Fatalf("resumed total = %d, want %d", next.Page.TotalFacts, len(first.Facts))
		}
		cursor = next.Page.Cursor
		if cursor == "" {
			if len(next.Statuses) == 0 {
				t.Fatal("final page carries no statuses, want outcome preserved")
			}
			if next.State != sdk.ResultComplete {
				t.Fatalf("final state = %q, want complete", next.State)
			}
		} else if len(next.Statuses) != 0 {
			t.Fatalf("non-final page carries %d statuses, want none", len(next.Statuses))
		}
	}
	if len(reassembled) != len(first.Facts) {
		t.Fatalf("reassembled %d facts, want single-shot %d", len(reassembled), len(first.Facts))
	}
	for i := range first.Facts {
		if reassembled[i].StableKey != first.Facts[i].StableKey {
			t.Fatalf("reassembled fact %d = %q, want %q", i, reassembled[i].StableKey, first.Facts[i].StableKey)
		}
	}
}

// TestStdioRejectsUnknownProtocol proves a host speaking a newer wire
// contract fails closed instead of emitting against a guessed shape.
func TestStdioRejectsUnknownProtocol(t *testing.T) {
	t.Parallel()

	request := sdkRequest{
		ProtocolVersion: "collector-sdk/v9alpha9",
		Claim:           sdk.Claim{Scope: sdk.Scope{ID: "component:aws-cloud-primary", Kind: "component"}},
		Config:          stdioFileConfig(t, nil),
	}
	var stdin bytes.Buffer
	if err := json.NewEncoder(&stdin).Encode(request); err != nil {
		t.Fatalf("json.Encode(request) error = %v", err)
	}
	var stdout, stderr bytes.Buffer
	if err := run([]string{"--sdk-stdio"}, &stdin, &stdout, &stderr); err == nil {
		t.Fatal("run(unknown protocol) error = nil, want failure")
	} else if !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("run(unknown protocol) error = %v, want unsupported protocol", err)
	}
}

// TestStdioRejectsMisplacedContinuation proves a resume cursor on a legacy
// protocol fails closed at the boundary instead of resuming at an
// untrusted offset.
func TestStdioRejectsMisplacedContinuation(t *testing.T) {
	t.Parallel()

	request := sdkRequest{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		Claim:           sdk.Claim{Scope: sdk.Scope{ID: "component:aws-cloud-primary", Kind: "component"}},
		Config:          stdioFileConfig(t, nil),
		Continuation:    &collector.PageContinuation{Cursor: "bogus"},
	}
	var stdin bytes.Buffer
	if err := json.NewEncoder(&stdin).Encode(request); err != nil {
		t.Fatalf("json.Encode(request) error = %v", err)
	}
	var stdout, stderr bytes.Buffer
	if err := run([]string{"--sdk-stdio"}, &stdin, &stdout, &stderr); err == nil {
		t.Fatal("run(legacy cursor) error = nil, want failure")
	}
}

// TestStdioRejectsGarbageCursor proves a malformed v1alpha3 resume token
// fails the run (host retries the claim from page zero) instead of emitting
// a page from an untrusted offset.
func TestStdioRejectsGarbageCursor(t *testing.T) {
	t.Parallel()

	request := sdkRequest{
		ProtocolVersion: collector.ProtocolVersionV1Alpha3,
		Claim:           sdk.Claim{Scope: sdk.Scope{ID: "component:aws-cloud-primary", Kind: "component"}},
		Config:          stdioFileConfig(t, nil),
		Continuation:    &collector.PageContinuation{Cursor: "!!!not-a-cursor"},
	}
	var stdin bytes.Buffer
	if err := json.NewEncoder(&stdin).Encode(request); err != nil {
		t.Fatalf("json.Encode(request) error = %v", err)
	}
	var stdout, stderr bytes.Buffer
	if err := run([]string{"--sdk-stdio"}, &stdin, &stdout, &stderr); err == nil {
		t.Fatal("run(garbage cursor) error = nil, want failure")
	}
}

// TestStdioOversizeFactFailsTerminal proves a fact larger than the whole
// page bound becomes an explicit terminal page-budget result — never a
// silently dropped fact and never an over-budget page write that would only
// surface at the host stdout cap.
func TestStdioOversizeFactFailsTerminal(t *testing.T) {
	t.Parallel()

	config := stdioFileConfig(t, map[string]any{"limits": map[string]any{"maxPageBytes": 1.0}})
	request := sdkRequest{
		ProtocolVersion: collector.ProtocolVersionV1Alpha3,
		Claim:           sdk.Claim{Scope: sdk.Scope{ID: "component:aws-cloud-primary", Kind: "component"}},
		Config:          config,
	}
	decoded, _ := runStdio(t, request)
	if decoded.State != sdk.ResultTerminal {
		t.Fatalf("state = %q, want terminal for over-bound fact", decoded.State)
	}
	if decoded.Page != nil {
		t.Fatalf("oversize page = %+v, want nil", decoded.Page)
	}
	terminal := false
	for _, status := range decoded.Statuses {
		if status.Class == sdk.StatusFailure && status.FailureClass == collector.FailureClassPageBudgetExceeded {
			terminal = true
		}
	}
	if !terminal {
		t.Fatalf("statuses = %+v, want page-budget-exceeded", decoded.Statuses)
	}
}

// TestNestedLimitsParsesMaxPageBytes proves the per-page byte budget travels
// the same config path as the existing bounds, with malformed values
// failing closed.
func TestNestedLimitsParsesMaxPageBytes(t *testing.T) {
	t.Parallel()

	limits, err := nestedLimits(map[string]any{"limits": map[string]any{"maxPageBytes": 1000.0}})
	if err != nil {
		t.Fatalf("nestedLimits(maxPageBytes) error = %v", err)
	}
	if limits.MaxPageBytes != 1000 {
		t.Fatalf("MaxPageBytes = %d, want 1000", limits.MaxPageBytes)
	}
	absent, err := nestedLimits(map[string]any{})
	if err != nil {
		t.Fatalf("nestedLimits(absent) error = %v", err)
	}
	if absent.MaxPageBytes != int(collector.DefaultMaxPageBytes) {
		t.Fatalf("default MaxPageBytes = %d, want %d", absent.MaxPageBytes, collector.DefaultMaxPageBytes)
	}
	if _, err := nestedLimits(map[string]any{"limits": map[string]any{"maxPageBytes": "many"}}); err == nil {
		t.Fatal("nestedLimits(malformed) error = nil, want failure")
	}
}
