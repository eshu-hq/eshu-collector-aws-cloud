// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"testing"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/collector/conformance"
)

// TestWave1EC2Conformance is the Wave 1 EC2 Q4(a) gate over the hand-built
// vectors below: every kind the completed EC2 live path emits validates
// against its checked-in JSON Schema through the public fixture harness,
// using only the published SDK modules. The observations below mirror the
// shared wave1 fixture vectors (testdata/wave1-ec2-parity.json); the
// companion live tests prove the same builders emit in-tree-identical stable
// keys (Q4(b)). Hand-built vectors cannot exercise builder-derived edge
// shapes, so TestWave1EC2BuilderConformance in internal/live runs the real
// builder output for both new posture kinds (legacy blank-rule-id and
// nil-port prefix-list fallback rules; the instance row) through the SDK
// validator and the conformance harness.
func TestWave1EC2Conformance(t *testing.T) {
	t.Parallel()

	claim := testClaim()
	observedAt := testObservedAt()
	base := mustCollect(t, "complete.json", claim, observedAt, "")
	sourceURI := "aws://123456789012"

	resources := []ResourceObservation{{
		Boundary:     Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "ec2"},
		ARN:          "arn:aws:ec2:us-east-1:123456789012:instance/i-wave1",
		ResourceID:   "i-wave1",
		ResourceType: "aws_ec2_instance",
		Name:         "i-wave1",
		State:        "running",
		Attributes:   map[string]any{"ami_id": "ami-wave1"},
		CorrelationAnchors: []string{
			"i-wave1", "arn:aws:ec2:us-east-1:123456789012:instance/i-wave1",
		},
		SourceRecordID: "i-wave1",
	}}
	relationships := []RelationshipObservation{{
		Boundary:         Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "ec2"},
		RelationshipType: "ec2_security_group_in_vpc",
		SourceResourceID: "sg-wave1",
		TargetResourceID: "vpc-wave1",
		TargetType:       "aws_ec2_vpc",
		SourceRecordID:   "sg-wave1#vpc#vpc-wave1",
	}}
	sgPostures := []SecurityGroupRuleObservation{{
		Boundary:     Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "ec2"},
		RuleID:       "sgr-wave1a",
		GroupID:      "sg-wave1",
		GroupOwnerID: "123456789012",
		IPProtocol:   "tcp",
		FromPort:     int32Ptr(443),
		ToPort:       int32Ptr(443),
		CIDRIPv4:     "0.0.0.0/0",
		Description:  "wave1 https",
	}}
	ec2Postures := []EC2InstancePostureObservation{{
		Boundary:           Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "ec2"},
		ARN:                "arn:aws:ec2:us-east-1:123456789012:instance/i-wave1",
		InstanceID:         "i-wave1",
		State:              "running",
		IMDSv2Required:     boolPtr(true),
		HTTPEndpoint:       "enabled",
		DetailedMonitoring: true,
		EBSOptimized:       true,
		SourceRecordID:     "i-wave1",
	}}

	result := base
	var err error
	result, err = AppendLiveResources(result, resources, sourceURI, ResourceUse{})
	if err != nil {
		t.Fatal(err)
	}
	result, err = AppendLiveRelationships(result, relationships, sourceURI, ResourceUse{})
	if err != nil {
		t.Fatal(err)
	}
	result, err = AppendLiveSecurityGroupRulePostures(result, sgPostures, sourceURI, ResourceUse{})
	if err != nil {
		t.Fatal(err)
	}
	result, err = AppendLiveEC2InstancePostures(result, ec2Postures, sourceURI, ResourceUse{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sdk.NewValidator(Contract()).ValidateResult(result); err != nil {
		t.Fatalf("SDK rejected wave1 EC2 result: %v", err)
	}
	report := conformance.Run(coreFixtureRequest(t, loadManifest(t), []sdk.Result{result}))
	if !report.OK() {
		t.Fatalf("wave1 EC2 conformance findings = %#v, want passed", report.Findings)
	}
}

func boolPtr(value bool) *bool {
	return &value
}
