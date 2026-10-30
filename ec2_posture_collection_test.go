// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"testing"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

func TestAppendLiveSecurityGroupRulePosturesBindsClaimAndDeduplicates(t *testing.T) {
	claim := testClaim()
	base := mustCollect(t, "complete.json", claim, testObservedAt(), "")
	observation := SecurityGroupRuleObservation{
		Boundary:    Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "ec2"},
		RuleID:      "sgr-123",
		GroupID:     "sg-123",
		IPProtocol:  "tcp",
		FromPort:    int32Ptr(443),
		ToPort:      int32Ptr(443),
		CIDRIPv4:    "0.0.0.0/0",
		Description: "https",
	}
	result, err := AppendLiveSecurityGroupRulePostures(base, []SecurityGroupRuleObservation{observation, observation}, "aws://123456789012", ResourceUse{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Facts) != len(base.Facts)+1 {
		t.Fatalf("facts = %d, want %d", len(result.Facts), len(base.Facts)+1)
	}
	fact := result.Facts[len(result.Facts)-1]
	if fact.Kind != AWSKindSecurityGroupRule || fact.SourceRef.ScopeID != claim.Scope.ID || fact.SourceRef.GenerationID != claim.GenerationID {
		t.Fatalf("rule posture is not bound to claim: %#v", fact.SourceRef)
	}
	if _, err := sdk.NewValidator(Contract()).ValidateResult(result); err != nil {
		t.Fatalf("SDK rejected claim-bound posture result: %v", err)
	}
}

func TestAppendLiveEC2InstancePosturesBindsClaimAndDeduplicates(t *testing.T) {
	claim := testClaim()
	base := mustCollect(t, "complete.json", claim, testObservedAt(), "")
	required := true
	observation := EC2InstancePostureObservation{
		Boundary:       Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "ec2"},
		ARN:            "arn:aws:ec2:us-east-1:123456789012:instance/i-123",
		InstanceID:     "i-123",
		State:          "running",
		IMDSv2Required: &required,
		HTTPEndpoint:   "enabled",
		SourceRecordID: "i-123",
	}
	result, err := AppendLiveEC2InstancePostures(base, []EC2InstancePostureObservation{observation, observation}, "aws://123456789012", ResourceUse{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Facts) != len(base.Facts)+1 {
		t.Fatalf("facts = %d, want %d", len(result.Facts), len(base.Facts)+1)
	}
	fact := result.Facts[len(result.Facts)-1]
	if fact.Kind != AWSKindEC2InstancePosture || fact.SourceRef.ScopeID != claim.Scope.ID || fact.SourceRef.GenerationID != claim.GenerationID {
		t.Fatalf("instance posture is not bound to claim: %#v", fact.SourceRef)
	}
	if _, err := sdk.NewValidator(Contract()).ValidateResult(result); err != nil {
		t.Fatalf("SDK rejected claim-bound posture result: %v", err)
	}
}

func TestAppendLivePosturesRequiresFencingToken(t *testing.T) {
	claim := testClaim()
	claim.FencingToken = ""
	base := mustCollect(t, "complete.json", claim, testObservedAt(), "")
	sgObservation := SecurityGroupRuleObservation{
		Boundary: Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "ec2"},
		GroupID:  "sg-123",
	}
	if _, err := AppendLiveSecurityGroupRulePostures(base, []SecurityGroupRuleObservation{sgObservation}, "aws://123456789012", ResourceUse{}); err == nil {
		t.Fatal("rule posture append without fencing token succeeded, want fail-closed error")
	}
	ec2Observation := EC2InstancePostureObservation{
		Boundary:   Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "ec2"},
		InstanceID: "i-123",
	}
	if _, err := AppendLiveEC2InstancePostures(base, []EC2InstancePostureObservation{ec2Observation}, "aws://123456789012", ResourceUse{}); err == nil {
		t.Fatal("instance posture append without fencing token succeeded, want fail-closed error")
	}
}

func int32Ptr(value int32) *int32 {
	return &value
}
