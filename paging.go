// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// ProtocolVersionV1Alpha3 is the third collector extension wire contract. It
// mirrors collector.ProtocolVersionV1Alpha3 in the host's sdk/go/collector
// module: the pinned standalone SDK (see go.mod) predates pagination, so the
// satellite carries its own mirror exactly as the host's extensionhost
// package mirrors the page envelope. The string values must stay identical;
// TestResultPageJSONTagsMatchHostContract pins the wire shape.
const ProtocolVersionV1Alpha3 = "collector-sdk/v1alpha3"

// FailureClassPageBudgetExceeded is the terminal failure class when one
// fact exceeds the whole per-page byte bound. It matches the bounded-token
// shape the host admission path requires.
const FailureClassPageBudgetExceeded = "page-budget-exceeded"

// pageCursorVersion versions the opaque continuation token. A future cursor
// shape bumps it; older satellites fail closed on unknown versions.
// Version 2 pins the page-zero split (fact count per page) so resumed
// calls slice the same pages instead of re-splitting drifted wire bytes
// (eshu-hq/eshu#11085 class 1); version-1 cursors fail closed here and
// the host retries the claim from page zero.
const pageCursorVersion = 2

const (
	// DefaultStdoutLimitBytes mirrors the host process runner's default
	// stdout cap (extensionhost defaultStdoutLimitBytes): one bounded
	// stdout write per satellite call. The per-page bound derives from it,
	// so pages the satellite emits fit the host intake that reads them.
	DefaultStdoutLimitBytes = int64(4 * 1024 * 1024)
	// PageEnvelopeHeadroomBytes reserves wire space around one page's
	// facts for the repeated claim and generation, the page envelope,
	// statuses, and JSON framing. It mirrors the host SDK's page headroom
	// so a satellite-sized page always fits the host's stdout limit.
	PageEnvelopeHeadroomBytes = int64(64 * 1024)
	// DefaultMaxPageBytes is the documented per-page byte budget on
	// default caps: the default host stdout limit minus envelope
	// headroom. Operators who raise the host stdout_limit_bytes raise
	// limits.maxPageBytes to match; a page that still exceeds the host
	// cap trips the host admission error with byte sizes (#9653).
	DefaultMaxPageBytes = int64(DefaultStdoutLimitBytes - PageEnvelopeHeadroomBytes)
)

// ResultPage carries versioned multi-call continuation for one result page.
// It mirrors the host intake shape field-for-field (extensionhost.ResultPage
// in eshu-hq/eshu): the satellite repeats claim and generation on every
// page, carries its facts in stable order, and names the resume cursor
// while more pages remain. JSON tags must stay identical with the host
// type; TestResultPageJSONTagsMatchHostContract pins them.
type ResultPage struct {
	// Cursor is the opaque satellite-minted resume token. It is required
	// while More is true and empty on the final page.
	Cursor string `json:"cursor,omitempty"`
	// More reports whether the host must re-invoke the satellite with
	// Cursor to fetch the next page.
	More bool `json:"more,omitempty"`
	// PageIndex is the zero-based page sequence. The first page is 0.
	PageIndex int `json:"page_index,omitempty"`
	// TotalFacts is the satellite-declared fact total across all pages of
	// the generation. It is always declared on paged output so the host
	// can verify the reassembled fact count.
	TotalFacts int `json:"total_facts,omitempty"`
}

// PageContinuation carries the resume cursor back to the satellite. It
// mirrors the host request shape (extensionhost.PageContinuation): absent
// on the first call, present with the previous page's cursor on every
// continuation call.
type PageContinuation struct {
	// Cursor is the opaque token the satellite minted on the previous page.
	Cursor string `json:"cursor,omitempty"`
}

// PagedResult is the v1alpha3 stdout document: one SDK result plus its page
// envelope. The pinned SDK result type predates pagination, so the envelope
// rides alongside exactly as the host decodes it (pagedWireResult).
type PagedResult struct {
	sdk.Result
	Page *ResultPage `json:"page,omitempty"`
}

// PageBoundForStdout derives the explicit per-call page byte bound from the
// host's stdout limit: the limit minus fixed envelope headroom. It mirrors
// the host SDK's PageBoundForStdout so satellite and host agree on the
// bound without sharing code.
func PageBoundForStdout(stdoutLimitBytes int64) (int64, error) {
	if stdoutLimitBytes <= 0 {
		return 0, fmt.Errorf("stdout limit must be positive")
	}
	bound := stdoutLimitBytes - PageEnvelopeHeadroomBytes
	if bound <= 0 {
		return 0, fmt.Errorf("stdout limit %d leaves no page bytes after %d headroom",
			stdoutLimitBytes, PageEnvelopeHeadroomBytes)
	}
	return bound, nil
}

// FactWireBytes returns the exact JSON wire size of one SDK fact: the bytes
// a page carries for it. It mirrors the host SDK's FactWireBytes.
func FactWireBytes(fact sdk.Fact) (int, error) {
	raw, err := json.Marshal(fact)
	if err != nil {
		return 0, fmt.Errorf("marshal fact %q: %w", fact.Kind, err)
	}
	return len(raw), nil
}

// SplitFacts partitions facts into pages whose summed wire bytes each fit
// maxPageBytes. Order is preserved, no fact is lost or duplicated, and
// every page carries at least one fact. A single fact larger than the whole
// bound fails closed naming its kind, stable key, and size: callers fix the
// producer, never silently drop the fact. It mirrors the host SDK's
// SplitFacts, including the proportional page backing that keeps first-scan
// scale off the worker the paging contract exists to protect.
func SplitFacts(facts []sdk.Fact, maxPageBytes int64) ([][]sdk.Fact, error) {
	if len(facts) == 0 {
		return nil, fmt.Errorf("at least one fact is required to page")
	}
	if maxPageBytes <= 0 {
		return nil, fmt.Errorf("page bound must be positive")
	}
	pages := make([][]sdk.Fact, 0, 1)
	var current []sdk.Fact
	var currentBytes int64
	flush := func() {
		if len(current) > 0 {
			pages = append(pages, current)
			current = nil
			currentBytes = 0
		}
	}
	for _, fact := range facts {
		size, err := FactWireBytes(fact)
		if err != nil {
			return nil, err
		}
		if int64(size) > maxPageBytes {
			return nil, fmt.Errorf(
				"fact %q stable key %q is %d bytes above page bound %d",
				fact.Kind, fact.StableKey, size, maxPageBytes,
			)
		}
		if len(current) > 0 && currentBytes+int64(size) > maxPageBytes {
			flush()
		}
		current = append(current, fact)
		currentBytes += int64(size)
	}
	flush()
	return pages, nil
}

// canonicalFactOrder returns the facts in one deterministic emission order:
// kind, then stable key, then the full wire JSON as the final tiebreak so
// same-key facts with different payloads still order identically. The
// input slice is never mutated; page splits of identical sets are then
// identical across stateless calls. It mirrors the PageDigest keying so
// the digest a cursor pins always describes this same order.
func canonicalFactOrder(facts []sdk.Fact) []sdk.Fact {
	type keyed struct {
		fact sdk.Fact
		key  string
		wire string
	}
	ordered := make([]keyed, 0, len(facts))
	for _, fact := range facts {
		raw, err := json.Marshal(fact)
		wire := ""
		if err == nil {
			wire = string(raw)
		}
		ordered = append(ordered, keyed{
			fact: fact,
			key:  fact.Kind + "\x00" + fact.StableKey,
			wire: wire,
		})
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].key != ordered[j].key {
			return ordered[i].key < ordered[j].key
		}
		return ordered[i].wire < ordered[j].wire
	})
	sorted := make([]sdk.Fact, 0, len(facts))
	for _, item := range ordered {
		sorted = append(sorted, item.fact)
	}
	return sorted
}

// countPagedFacts totals the facts a split holds. SplitFacts preserves the
// input set by contract; the count pins that contract at the paging
// boundary so a future split regression fails closed here instead of
// reaching the host as a declared-total mismatch.
func countPagedFacts(pages [][]sdk.Fact) int {
	total := 0
	for _, page := range pages {
		total += len(page)
	}
	return total
}

// PageDigest returns the stable identity of one generation's fact stream:
// kind and stable key of every fact in emission order. The cursor carries
// it so a resumed call proves the source did not move before serving a
// later page.
func PageDigest(facts []sdk.Fact) string {
	parts := make([]string, 0, len(facts))
	for _, fact := range facts {
		parts = append(parts, fact.Kind+"\x00"+fact.StableKey)
	}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x01")))
	return hex.EncodeToString(sum[:])
}

// effectivePageBound resolves the per-page byte budget: an explicit
// positive bound wins, anything else selects the documented default.
func effectivePageBound(maxPageBytes int64) int64 {
	if maxPageBytes > 0 {
		return maxPageBytes
	}
	return DefaultMaxPageBytes
}

// PaginateResult selects the one page this satellite call must emit for a
// host request. On a legacy (non-v1alpha3) protocol it returns the result
// untouched with no envelope, preserving the exact single-shot shape. On
// v1alpha3 it stamps the negotiated protocol, splits completable results
// into bounded pages, and serves either page zero (minting the resume
// cursor) or the cursored page (verifying the cursor digest against the
// re-collected facts and pinning the first page's generation). Every page
// carries the result statuses: the host validates each page as a standalone
// result, so stripping them from non-final pages fails partial claims on
// page zero (the host sums per-page statuses on reassembly, so the warning
// status repeats once per page). A single fact larger than the bound
// becomes a terminal page-budget result; source drift across calls is a
// hard error so the host retries the claim from page zero instead of
// committing a torn generation.
func PaginateResult(result sdk.Result, protocol string, continuation *PageContinuation, maxPageBytes int64) (sdk.Result, *ResultPage, error) {
	if strings.TrimSpace(protocol) != ProtocolVersionV1Alpha3 {
		if continuation != nil && strings.TrimSpace(continuation.Cursor) != "" {
			return sdk.Result{}, nil, fmt.Errorf("continuation requires protocol %q", ProtocolVersionV1Alpha3)
		}
		return result, nil, nil
	}
	result.ProtocolVersion = ProtocolVersionV1Alpha3
	if result.State != sdk.ResultComplete && result.State != sdk.ResultPartial {
		return result, nil, nil
	}
	if len(result.Facts) == 0 {
		return result, nil, nil
	}
	// Every continuation call re-collects, and the source orders nothing:
	// the identical fact set may arrive in a different order. The cursor
	// digest is order-insensitive, so the resume would split a regrouped
	// stream and the host would reassemble torn pages (duplicated keys, a
	// count off the declared total — eshu-hq/eshu#11085). Sorting first
	// gives every call one deterministic order to cut pages from.
	// Sorting alone is not enough: per-call wire-length drift (fresh
	// ObservedAt stamps marshal to different byte lengths under
	// RFC3339Nano trimming) still moves split boundaries on a resume
	// re-split with admission passing. The cursor therefore pins the
	// page-zero split and the resume slices at those boundaries instead
	// of re-splitting, so a pinned walk always partitions the admitted
	// set and reassembles exactly the declared total.
	result.Facts = canonicalFactOrder(result.Facts)
	bound := effectivePageBound(maxPageBytes)
	if continuation != nil {
		return emitResumePage(result, continuation, bound)
	}
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
	return emitFirstPage(result, pages)
}

// emitFirstPage serves page zero and mints the resume cursor when more
// pages remain. The cursor pins this call's generation and the full fact
// digest so resumed calls prove continuity.
func emitFirstPage(result sdk.Result, pages [][]sdk.Fact) (sdk.Result, *ResultPage, error) {
	total := len(result.Facts)
	if len(pages) == 1 {
		result.Facts = pages[0]
		return result, &ResultPage{PageIndex: 0, TotalFacts: total}, nil
	}
	digest := PageDigest(result.Facts)
	sizes := make([]int, 0, len(pages))
	for _, page := range pages {
		sizes = append(sizes, len(page))
	}
	cursor, err := encodePageCursor(pageCursor{
		Version:         pageCursorVersion,
		NextPage:        1,
		TotalFacts:      total,
		GenerationID:    result.Generation.ID,
		ObservedAtNanos: result.Generation.ObservedAt.UTC().UnixNano(),
		FreshnessHint:   result.Generation.FreshnessHint,
		TrustedDeletion: result.Generation.TrustedDeletion,
		Digest:          digest,
		PageSizes:       sizes,
	})
	if err != nil {
		return sdk.Result{}, nil, err
	}
	result.Facts = pages[0]
	// Statuses ride every page, not just the final one: the host validates
	// each page as a standalone result, so a partial first page without its
	// warning status fails the whole claim (eshu-hq/eshu#8852 production
	// proof). Reassembly sums per-page statuses by design.
	return result, &ResultPage{Cursor: cursor, More: true, PageIndex: 0, TotalFacts: total}, nil
}

// emitResumePage serves the cursor's page after proving the re-collected
// facts still match the first page's stream. The generation repeats the
// cursor-pinned values, never the re-collection time, so the host's
// generation pin holds across pages. The page is sliced at the pinned
// page-zero boundaries, never re-split: per-call wire-length drift
// cannot regroup pages mid-walk, so the walk always partitions the
// admitted set and reassembles exactly the declared total
// (eshu-hq/eshu#11085 class 1).
func emitResumePage(result sdk.Result, continuation *PageContinuation, maxPageBytes int64) (sdk.Result, *ResultPage, error) {
	cursor, err := decodePageCursor(continuation.Cursor)
	if err != nil {
		return sdk.Result{}, nil, err
	}
	if cursor.TotalFacts != len(result.Facts) || PageDigest(result.Facts) != cursor.Digest {
		return sdk.Result{}, nil, fmt.Errorf(
			"page cursor binds %d facts, re-collection produced %d: source moved, retry the claim",
			cursor.TotalFacts, len(result.Facts),
		)
	}
	pinned := 0
	for _, size := range cursor.PageSizes {
		if size <= 0 {
			return sdk.Result{}, nil, fmt.Errorf(
				"page cursor pins an empty page: source moved, retry the claim",
			)
		}
		pinned += size
	}
	if len(cursor.PageSizes) == 0 || pinned != cursor.TotalFacts {
		return sdk.Result{}, nil, fmt.Errorf(
			"page cursor pins %d facts across %d pages, want bound total %d: source moved, retry the claim",
			pinned, len(cursor.PageSizes), cursor.TotalFacts,
		)
	}
	if cursor.NextPage >= len(cursor.PageSizes) {
		return sdk.Result{}, nil, fmt.Errorf(
			"page cursor resumes at page %d of %d: source moved, retry the claim",
			cursor.NextPage, len(cursor.PageSizes),
		)
	}
	result.Generation = sdk.Generation{
		ID:              cursor.GenerationID,
		ObservedAt:      time.Unix(0, cursor.ObservedAtNanos).UTC(),
		FreshnessHint:   cursor.FreshnessHint,
		TrustedDeletion: cursor.TrustedDeletion,
	}
	index := cursor.NextPage
	offset := 0
	for _, size := range cursor.PageSizes[:index] {
		offset += size
	}
	result.Facts = result.Facts[offset : offset+cursor.PageSizes[index]]
	// A pinned page can outgrow the byte bound when the re-collection
	// marshals longer than page zero did. Failing closed retries the
	// claim from page zero, where a fresh split absorbs the growth;
	// emitting it would only trip the host cap instead.
	var pageBytes int64
	for _, fact := range result.Facts {
		size, err := FactWireBytes(fact)
		if err != nil {
			return sdk.Result{}, nil, err
		}
		pageBytes += int64(size)
	}
	if pageBytes > maxPageBytes {
		return sdk.Result{}, nil, fmt.Errorf(
			"page %d re-collected at %d bytes above page bound %d, retry the claim",
			index, pageBytes, maxPageBytes,
		)
	}
	if index == len(cursor.PageSizes)-1 {
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
		PageSizes:       cursor.PageSizes,
	})
	if err != nil {
		return sdk.Result{}, nil, err
	}
	// Same every-page statuses rule as emitFirstPage: intermediate pages
	// must validate standalone on the host.
	return result, &ResultPage{Cursor: next, More: true, PageIndex: index, TotalFacts: cursor.TotalFacts}, nil
}

// pageBudgetExceeded converts an unpageable fact into the bounded-failure
// shape the existing record and payload budgets use: explicit terminal
// state with a failure class, never an ambiguous complete and never an
// over-budget page write that would only surface at the host cap.
func pageBudgetExceeded(result sdk.Result) sdk.Result {
	return sdk.Result{
		ProtocolVersion: ProtocolVersionV1Alpha3,
		State:           sdk.ResultTerminal,
		Claim:           result.Claim,
		Generation:      result.Generation,
		Statuses: []sdk.Status{{
			Class: sdk.StatusFailure, FailureClass: FailureClassPageBudgetExceeded,
		}},
	}
}
