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

// TestWave1ECRLiveConformance is the Wave 1 ECR Q4(a) gate over real builder
// output: every fact the production listECR path emits for the shared fixture
// (both resource kinds plus image references) validates against its
// checked-in JSON Schema through the public fixture harness. The companion
// parity test proves the same facts carry in-tree-identical stable keys
// (Q4(b)).
func TestWave1ECRLiveConformance(t *testing.T) {
	t.Parallel()

	fixture := loadWave1ECRFixture(t)
	cfg := wave1ECRStubConfig(t, fixture)
	records, err := listECR(context.Background(), cfg)
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
	imageReferences := 0
	for _, item := range records {
		if item.Relationship != nil || len(item.Relationships) != 0 {
			t.Fatalf("ECR record %q carries relationships, want none", item.ID)
		}
		if item.Resource != nil {
			resourceTypes[item.Resource.ResourceType] = true
			fact, err := collector.NewResourceFact(ecrWave1Resource(accountID, item.Resource))
			if err != nil {
				t.Fatal(err)
			}
			result.Facts = append(result.Facts, fact)
		}
		if item.ImageReference != nil {
			imageReferences++
			fact, err := collector.NewImageReferenceFact(ecrWave1ImageReference(accountID, item.ImageReference))
			if err != nil {
				t.Fatal(err)
			}
			result.Facts = append(result.Facts, fact)
		}
	}
	if len(result.Facts) != 8 {
		t.Fatalf("live facts = %d, want 8", len(result.Facts))
	}
	if len(resourceTypes) != 2 || imageReferences != 4 {
		t.Fatalf("live types = %d resources %d image references, want 2+4", len(resourceTypes), imageReferences)
	}
	if _, err := sdk.NewValidator(collector.Contract()).ValidateResult(result); err != nil {
		t.Fatalf("SDK rejected live ECR result: %v", err)
	}
	report := conformance.Run(wave1LiveConformanceRequest(t, []sdk.Result{result}))
	if !report.OK() {
		t.Fatalf("live ECR conformance findings = %#v, want passed", report.Findings)
	}
}
