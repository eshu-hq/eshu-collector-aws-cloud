// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package main

import (
	"strings"

	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// snapshotMode reports whether this v1alpha3 call opens a snapshot walk
// (page zero collects once and commits) or resumes one (a continuation
// cursor serves its page from the committed snapshot). Non-v1alpha3 calls
// take neither path and keep the legacy paged or single-shot shapes.
func snapshotMode(protocol string, continuation *collector.PageContinuation) (walk, resume bool) {
	if protocol != collector.ProtocolVersionV1Alpha3 {
		return false, false
	}
	if continuation != nil && strings.TrimSpace(continuation.Cursor) != "" {
		return false, true
	}
	return true, false
}

// serveSnapshotPage serves one v1alpha3 page through the collect-once walk
// snapshot: page zero commits the collected result and serves from it,
// while a resume call serves its cursor's page with no new collection.
// Snapshot store construction failures fail the run closed like any other
// paging error.
func serveSnapshotPage(cfg collector.SnapshotConfig, resume bool, continuation *collector.PageContinuation, result sdk.Result, maxPageBytes int64) (sdk.Result, *collector.ResultPage, error) {
	store, err := collector.NewSnapshotStore(cfg)
	if err != nil {
		return sdk.Result{}, nil, err
	}
	if resume {
		return store.ResumeWalk(continuation, maxPageBytes)
	}
	return store.CommitWalk(result, maxPageBytes)
}
