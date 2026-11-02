// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package main

import (
	"time"

	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// healthDigest selects the digest the health monitor records for one
// emitted result. The live path supplies the typed-evidence digest, which
// covers exactly the typed facts the host admits; file mode supplies none
// and falls back to the transitional snapshot-fact scan, preserving its
// exact legacy behavior. Terminal and unchanged outcomes record nothing,
// and neither does a non-final page: previously the page carried no
// snapshot fact so the scan found nothing, and the explicit gate keeps
// that shape now that the digest arrives out of band.
func healthDigest(outcomeDigest string, result sdk.Result, page *collector.ResultPage) string {
	digest := outcomeDigest
	if digest == "" {
		for _, fact := range result.Facts {
			if fact.Kind == collector.FactKindSnapshot {
				digest = fact.StableKey
				break
			}
		}
	}
	if result.State == sdk.ResultTerminal || result.State == sdk.ResultUnchanged {
		return ""
	}
	if page != nil && page.More {
		return ""
	}
	return digest
}

// unchangedOutcome short-circuits a live claim whose typed evidence has
// not moved since the previous digest the host recorded. It reports the
// unchanged shape with no facts, leaving the host's digest alone. An
// empty previous or outcome digest never matches: the first claim after
// the digest decoupling always performs a full collection.
func unchangedOutcome(claim sdk.Claim, previousDigest, outcomeDigest string) (sdk.Result, bool) {
	if previousDigest == "" || outcomeDigest == "" || previousDigest != outcomeDigest {
		return sdk.Result{}, false
	}
	now := time.Now().UTC()
	return sdk.Result{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		State:           sdk.ResultUnchanged,
		Claim:           claim,
		Generation:      sdk.Generation{ID: claim.GenerationID, ObservedAt: now, FreshnessHint: "unchanged-digest"},
	}, true
}
