// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"testing"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

func TestAppendLiveRelationshipsBindsSubnetVPCClaim(t *testing.T) {
	claim := testClaim()
	base := mustCollect(t, "complete.json", claim, testObservedAt(), "")
	relationship := RelationshipObservation{
		Boundary:         Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "ec2"},
		RelationshipType: "ec2_subnet_in_vpc",
		SourceResourceID: "subnet-123", SourceARN: "arn:aws:ec2:us-east-1:123456789012:subnet/subnet-123",
		TargetResourceID: "vpc-123", TargetType: "aws_ec2_vpc",
		SourceRecordID: "subnet-123#vpc#vpc-123",
	}
	got, err := AppendLiveRelationships(base, []RelationshipObservation{relationship, relationship}, "aws://123456789012", ResourceUse{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Facts) != len(base.Facts)+1 {
		t.Fatalf("facts = %d", len(got.Facts))
	}
	fact := got.Facts[len(got.Facts)-1]
	if fact.Kind != AWSKindRelationship || fact.SourceRef.ScopeID != claim.Scope.ID || fact.SourceRef.GenerationID != claim.GenerationID {
		t.Fatalf("relationship not claim bound: %#v", fact)
	}
	if fact.SourceRef.URI != "aws://123456789012" || fact.SourceRef.RecordID != "subnet-123#vpc#vpc-123" {
		t.Fatalf("relationship source ref = %#v", fact.SourceRef)
	}
	if fact.Payload["relationship_type"] != relationship.RelationshipType || fact.Payload["source_resource_id"] != "subnet-123" || fact.Payload["target_resource_id"] != "vpc-123" {
		t.Fatalf("relationship payload = %#v", fact.Payload)
	}
	if _, err := sdk.NewValidator(Contract()).ValidateResult(got); err != nil {
		t.Fatalf("SDK rejected result: %v", err)
	}
}

func TestAppendLiveRelationshipsBoundsAndInvalidIdentity(t *testing.T) {
	base := mustCollect(t, "complete.json", testClaim(), testObservedAt(), "")
	relationship := RelationshipObservation{
		Boundary:         Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "ec2"},
		RelationshipType: "ec2_subnet_in_vpc", SourceResourceID: "subnet-123",
		TargetResourceID: "vpc-123", TargetType: "aws_ec2_vpc",
	}
	bounded, err := AppendLiveRelationships(base, []RelationshipObservation{relationship}, "aws://123456789012", ResourceUse{MaxRecordsPerClaim: len(base.Facts), MaxPayloadBytes: 65536})
	if err != nil || bounded.State != sdk.ResultTerminal || len(bounded.Facts) != 0 {
		t.Fatalf("bounded result = %#v, err = %v", bounded, err)
	}
	relationship.TargetResourceID = ""
	if _, err := AppendLiveRelationships(base, []RelationshipObservation{relationship}, "aws://123456789012", ResourceUse{}); err == nil {
		t.Fatal("missing target identity accepted")
	}
}
