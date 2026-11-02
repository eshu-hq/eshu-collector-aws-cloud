// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// TestAppendOutcomeFactsReturnsTypedEvidenceDigest pins the decoupling
// contract: the shared fan-out reports a digest over exactly the typed
// evidence it appended, so freshness keying no longer reads the
// transitional snapshot fact. Deterministic for identical evidence and
// sensitive to added facts; empty typed evidence yields the empty digest.
func TestAppendOutcomeFactsReturnsTypedEvidenceDigest(t *testing.T) {
	t.Parallel()

	observedAt := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	claim := sdk.Claim{
		ComponentID: collector.ComponentID, InstanceID: "aws-parity-digest",
		CollectorKind: collector.CollectorKind, SourceSystem: collector.SourceSystem,
		Scope:       sdk.Scope{ID: "aws:123456789012:us-east-1", Kind: "component"},
		SourceRunID: "digest-run", GenerationID: "aws:123456789012:us-east-1:digest:1",
		WorkItemID: "digest-work", FencingToken: "digest-token",
		Attempt: 1, Deadline: observedAt.Add(time.Hour), ConfigHandle: "component-config:aws-cloud",
	}
	newResult := func() sdk.Result {
		return sdk.Result{
			ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
			State:           sdk.ResultComplete,
			Claim:           claim,
			Generation:      sdk.Generation{ID: claim.GenerationID, ObservedAt: observedAt},
		}
	}
	dnsOutcome := Outcome{
		DNSRecords: []collector.DNSRecordObservation{{
			Boundary:     collector.Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "route53"},
			HostedZoneID: "/hostedzone/Z123", RecordName: "example.com.", RecordType: "A",
		}},
	}

	first, firstDigest, err := AppendOutcomeFacts(newResult(), dnsOutcome, "aws:route53:us-east-1:digest", collector.DefaultResourceUse())
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest == "" {
		t.Fatal("typed evidence digest is empty for one DNS fact")
	}
	secondDigest := ""
	if _, secondDigest, err = AppendOutcomeFacts(newResult(), dnsOutcome, "aws:route53:us-east-1:digest", collector.DefaultResourceUse()); err != nil {
		t.Fatal(err)
	}
	if secondDigest != firstDigest {
		t.Fatalf("digest not deterministic: %q vs %q", firstDigest, secondDigest)
	}
	// The digest must bind every emitted typed fact: recompute it from
	// the result's own facts, not from the helper under test, so a
	// production change that drops or alters a covered fact fails here.
	var covered []string
	for _, fact := range first.Facts {
		switch fact.Kind {
		case collector.FactKindSnapshot, collector.FactKindRecord, collector.FactKindWarning:
			continue
		}
		if fact.StableKey == "" {
			continue
		}
		covered = append(covered, fact.Kind+"\x00"+fact.StableKey)
	}
	if len(covered) == 0 {
		t.Fatal("expected at least one typed fact in the pipeline result")
	}
	sort.Strings(covered)
	sum := sha256.Sum256([]byte(strings.Join(covered, "\x01")))
	if want := hex.EncodeToString(sum[:]); firstDigest != want {
		t.Fatalf("digest %q does not cover the %d emitted typed facts", firstDigest, len(covered))
	}

	twoRecords := dnsOutcome
	twoRecords.DNSRecords = append(append([]collector.DNSRecordObservation{}, dnsOutcome.DNSRecords...), collector.DNSRecordObservation{
		Boundary:     collector.Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "route53"},
		HostedZoneID: "/hostedzone/Z123", RecordName: "www.example.com.", RecordType: "A",
	})
	if _, grownDigest, err := AppendOutcomeFacts(newResult(), twoRecords, "aws:route53:us-east-1:digest", collector.DefaultResourceUse()); err != nil {
		t.Fatal(err)
	} else if grownDigest == firstDigest {
		t.Fatal("digest unchanged after adding a DNS fact")
	}

	emptyOutcome := Outcome{}
	if _, emptyDigest, err := AppendOutcomeFacts(newResult(), emptyOutcome, "aws:route53:us-east-1:digest", collector.DefaultResourceUse()); err != nil {
		t.Fatal(err)
	} else if emptyDigest != "" {
		t.Fatalf("empty typed evidence digest = %q, want empty", emptyDigest)
	}

	_ = first
}

// TestTypedOnlyOptInPreservesTypedEvidence proves the PR-D opt-in is
// behavior-neutral on typed truth: the same outcome appended after a
// dual-mode Collect and after a TypedOnly Collect yields identical typed
// fact keys and an identical digest, differing only in transitional facts.
func TestTypedOnlyOptInPreservesTypedEvidence(t *testing.T) {
	t.Parallel()

	observedAt := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	claim := sdk.Claim{
		ComponentID: collector.ComponentID, InstanceID: "aws-parity-typedd-only",
		CollectorKind: collector.CollectorKind, SourceSystem: collector.SourceSystem,
		Scope:       sdk.Scope{ID: "aws:123456789012:us-east-1", Kind: "component"},
		SourceRunID: "typed-only-run", GenerationID: "aws:123456789012:us-east-1:typed-only:1",
		WorkItemID: "typed-only-work", FencingToken: "typed-only-token",
		Attempt: 1, Deadline: observedAt.Add(time.Hour), ConfigHandle: "component-config:aws-cloud",
	}
	report := collector.Report{
		GeneratedAt: observedAt, Source: "aws",
		Records: []collector.Record{{
			ID: "aws:route53:us-east-1:typed-only", Name: "example.com.",
			Detail: "service=route53 region=us-east-1 kind=record-set",
		}},
	}
	opts := func(typedOnly bool) collector.CollectOptions {
		return collector.CollectOptions{ObservedAt: observedAt, SourceURI: "aws:route53:us-east-1:typed-only", TypedOnly: typedOnly, Limits: collector.DefaultResourceUse()}
	}
	outcome := Outcome{
		DNSRecords: []collector.DNSRecordObservation{{
			Boundary:     collector.Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "route53"},
			HostedZoneID: "/hostedzone/Z123", RecordName: "example.com.", RecordType: "A",
		}},
	}
	dual, err := collector.Collect(claim, report, opts(false))
	if err != nil {
		t.Fatal(err)
	}
	dual, dualDigest, err := AppendOutcomeFacts(dual, outcome, "aws:route53:us-east-1:typed-only", collector.DefaultResourceUse())
	if err != nil {
		t.Fatal(err)
	}
	typed, err := collector.Collect(claim, report, opts(true))
	if err != nil {
		t.Fatal(err)
	}
	if len(typed.Facts) != 0 {
		t.Fatalf("typed-only facts = %d, want 0 transitional", len(typed.Facts))
	}
	typed, typedDigest, err := AppendOutcomeFacts(typed, outcome, "aws:route53:us-east-1:typed-only", collector.DefaultResourceUse())
	if err != nil {
		t.Fatal(err)
	}
	if dualDigest == "" || typedDigest == "" {
		t.Fatal("empty digest on a non-empty typed outcome")
	}
	if dualDigest != typedDigest {
		t.Fatalf("digest moved under opt-in: %q vs %q", dualDigest, typedDigest)
	}
	typedKeys := func(result sdk.Result) []string {
		var keys []string
		for _, fact := range result.Facts {
			switch fact.Kind {
			case collector.FactKindSnapshot, collector.FactKindRecord, collector.FactKindWarning:
				continue
			}
			keys = append(keys, fact.Kind+"\x00"+fact.StableKey)
		}
		sort.Strings(keys)
		return keys
	}
	if !reflect.DeepEqual(typedKeys(dual), typedKeys(typed)) {
		t.Fatalf("typed keys moved under opt-in:\ndual=%v\ntyped=%v", typedKeys(dual), typedKeys(typed))
	}
}
