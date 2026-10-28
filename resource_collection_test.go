// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"strings"
	"testing"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
	awsv1 "github.com/eshu-hq/eshu-sdk/factschema/aws/v1"
)

func TestAppendLiveResourcesBindsClaimAndDeduplicates(t *testing.T) {
	claim := testClaim()
	base := mustCollect(t, "complete.json", claim, testObservedAt(), "")
	observation := ResourceObservation{
		Boundary:   Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "ec2"},
		ResourceID: "vpc-123", ResourceType: awsv1.ResourceTypeEC2VPC, Name: "example",
		State: "available", Tags: map[string]string{"environment": "qa"},
		Attributes: map[string]any{"cidr_block": "10.0.0.0/16"},
	}
	result, err := AppendLiveResources(base, []ResourceObservation{observation, observation}, "aws://123456789012", ResourceUse{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Facts) != len(base.Facts)+1 {
		t.Fatalf("facts = %d, want %d", len(result.Facts), len(base.Facts)+1)
	}
	fact := result.Facts[len(result.Facts)-1]
	if fact.Kind != AWSKindResource || fact.SourceRef.ScopeID != claim.Scope.ID || fact.SourceRef.GenerationID != claim.GenerationID {
		t.Fatalf("typed resource is not bound to claim: %#v", fact.SourceRef)
	}
	if fact.SourceRef.URI != "aws://123456789012" || strings.Contains(fact.SourceRef.URI, claim.FencingToken) {
		t.Fatalf("unsafe resource provenance URI %q", fact.SourceRef.URI)
	}
	if got := fact.Payload["resource_type"]; got != awsv1.ResourceTypeEC2VPC {
		t.Fatalf("resource_type = %v", got)
	}
	if got := fact.Payload["state"]; got != "available" {
		t.Fatalf("state = %v", got)
	}
	tags, ok := fact.Payload["tags"].(map[string]string)
	if !ok || tags["environment"] != "qa" {
		t.Fatalf("tags = %#v", fact.Payload["tags"])
	}
	attrs, ok := fact.Payload["attributes"].(map[string]any)
	if !ok {
		t.Fatalf("attributes = %#v", fact.Payload["attributes"])
	}
	if attrs["cidr_block"] != "10.0.0.0/16" {
		t.Fatalf("source attributes = %#v", attrs)
	}
	for _, status := range result.Statuses {
		if status.FactCount != len(result.Facts) {
			t.Fatalf("status fact count %d != %d", status.FactCount, len(result.Facts))
		}
	}
	if _, err := sdk.NewValidator(Contract()).ValidateResult(result); err != nil {
		t.Fatalf("SDK rejected claim-bound typed result: %v", err)
	}
}

func TestAppendLiveResourcesBoundsAndUnchanged(t *testing.T) {
	base := mustCollect(t, "complete.json", testClaim(), testObservedAt(), "")
	observation := ResourceObservation{
		Boundary:   Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "ec2"},
		ResourceID: "vpc-123", ResourceType: awsv1.ResourceTypeEC2VPC,
	}
	bounded, err := AppendLiveResources(base, []ResourceObservation{observation}, "aws://123456789012", ResourceUse{
		MaxRecordsPerClaim: len(base.Facts), MaxPayloadBytes: 65536,
	})
	if err != nil || bounded.State != sdk.ResultTerminal || len(bounded.Facts) != 0 {
		t.Fatalf("bounded result = %#v, error = %v, want terminal without facts", bounded, err)
	}
	unchanged := base
	unchanged.State = sdk.ResultUnchanged
	unchanged.Facts = nil
	got, err := AppendLiveResources(unchanged, []ResourceObservation{observation}, "aws://123456789012", ResourceUse{})
	if err != nil || got.State != sdk.ResultUnchanged || len(got.Facts) != 0 {
		t.Fatalf("unchanged result = %#v, error = %v", got, err)
	}
}
