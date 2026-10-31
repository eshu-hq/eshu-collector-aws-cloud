// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"testing"
	"time"

	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/collector/conformance"
)

// TestWave1KMSLiveConformance is the Wave 1 KMS Q4(a) gate over real builder
// output: every fact the production listKMS path emits for the shared fixture
// (all three resource kinds, all three relationship kinds) validates against
// its checked-in JSON Schema through the public fixture harness. The
// companion parity test proves the same facts carry in-tree-identical stable
// keys (Q4(b)).
func TestWave1KMSLiveConformance(t *testing.T) {
	t.Parallel()

	fixture := loadWave1KMSFixture(t)
	cfg := wave1KMSStubConfig(t, fixture)
	records, err := listKMS(context.Background(), cfg, VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	if err != nil {
		t.Fatal(err)
	}

	const accountID = "123456789012"
	observedAt := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	result := sdk.Result{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		State:           sdk.ResultComplete,
		Claim: sdk.Claim{
			ComponentID: collector.ComponentID, InstanceID: "aws-parity-wave1",
			CollectorKind: collector.CollectorKind, SourceSystem: collector.SourceSystem,
			Scope:        sdk.Scope{ID: "aws:123456789012:us-east-1", Kind: "component"},
			GenerationID: "aws:123456789012:us-east-1:wave1:1",
			FencingToken: "wave1-parity-token",
			SourceRunID:  "run-wave1", WorkItemID: "work-wave1",
			Attempt: 1, Deadline: observedAt.Add(time.Hour), ConfigHandle: "component-config:aws-cloud",
		},
		Generation: sdk.Generation{ID: "aws:123456789012:us-east-1:wave1:1", ObservedAt: observedAt},
	}
	resourceTypes := map[string]bool{}
	relationshipTypes := map[string]bool{}
	for _, item := range records {
		if edge := item.Relationship; edge != nil {
			relationshipTypes[edge.RelationshipType] = true
			fact, err := collector.NewRelationshipFact(kmsWave1Relationship(accountID, *edge))
			if err != nil {
				t.Fatal(err)
			}
			result.Facts = append(result.Facts, fact)
		}
		for _, edge := range item.Relationships {
			relationshipTypes[edge.RelationshipType] = true
			fact, err := collector.NewRelationshipFact(kmsWave1Relationship(accountID, edge))
			if err != nil {
				t.Fatal(err)
			}
			result.Facts = append(result.Facts, fact)
		}
		if item.Resource == nil {
			continue
		}
		resourceTypes[item.Resource.ResourceType] = true
		fact, err := collector.NewResourceFact(kmsWave1Resource(accountID, item.Resource))
		if err != nil {
			t.Fatal(err)
		}
		result.Facts = append(result.Facts, fact)
	}
	if len(result.Facts) != 18 {
		t.Fatalf("live facts = %d, want 18", len(result.Facts))
	}
	if len(resourceTypes) != 3 || len(relationshipTypes) != 3 {
		t.Fatalf("live types = %d resources %d relationships, want 3+3", len(resourceTypes), len(relationshipTypes))
	}
	if _, err := sdk.NewValidator(collector.Contract()).ValidateResult(result); err != nil {
		t.Fatalf("SDK rejected live KMS result: %v", err)
	}
	report := conformance.Run(wave1LiveConformanceRequest(t, []sdk.Result{result}))
	if !report.OK() {
		t.Fatalf("live KMS conformance findings = %#v, want passed", report.Findings)
	}
}
